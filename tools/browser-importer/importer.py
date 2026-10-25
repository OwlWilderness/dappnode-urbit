"""Private stopped-pier import engine. Deliberately has no runtime execution path."""
from pathlib import Path
import json
import os
import uuid
import threading
import fcntl
import re
import stat
import ctypes
import sys
import hmac


def rename_without_replace(source_fd, source_name, target_fd, target_name):
    """Require OS no-replace rename; never downgrade to check-then-rename."""
    library = ctypes.CDLL(None, use_errno=True)
    if sys.platform == 'darwin':
        function = library.renameatx_np
        flags = 0x00000004  # RENAME_EXCL, verified in platform SDK sys/stdio.h.
    elif sys.platform.startswith('linux'):
        function = library.renameat2
        flags = 1  # RENAME_NOREPLACE, Linux UAPI fs.h.
    else:
        raise ImportError('Atomic non-overwriting commit is unsupported on this platform.')
    function.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    function.restype = ctypes.c_int
    if function(source_fd, os.fsencode(source_name), target_fd, os.fsencode(target_name), flags) != 0:
        raise ImportError('Atomic commit was refused; existing state is never overwritten.')


def remove_stage(parent_fd, name):
    """Remove only an exact job staging tree, with no symlink traversal."""
    fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
    try:
        for entry in os.listdir(fd):
            info = os.stat(entry, dir_fd=fd, follow_symlinks=False)
            if stat.S_ISDIR(info.st_mode):
                remove_stage(fd, entry)
            else:
                os.unlink(entry, dir_fd=fd)
        os.fsync(fd)
    finally:
        os.close(fd)
    os.rmdir(name, dir_fd=parent_fd)
    os.fsync(parent_fd)


def private_root(path):
    """Walk from / with held descriptors; never follow a root/ancestor link."""
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        parts = Path(os.path.abspath(path)).parts[1:]
        if not parts:
            raise ImportError('A dedicated private directory is required.')
        for part in parts:
            try:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            except FileNotFoundError:
                os.mkdir(part, mode=0o700, dir_fd=fd)
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        info = os.fstat(fd)
        if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o077:
            raise ImportError('Storage roots must be private and owned by this service.')
        return fd
    except Exception:
        os.close(fd)
        raise


class ImportError(Exception):
    """A safe, aggregate operator-facing import failure."""


class Importer:
    def __init__(self, pier, uploads, control, *, reserve_bytes=1024**3,
                 max_upload_bytes=8 * 1024**3, max_expanded_bytes=64 * 1024**3):
        self.pier = Path(pier)
        self.uploads = Path(uploads)
        self.control = Path(control)
        self.reserve_bytes = reserve_bytes
        self.max_upload_bytes = max_upload_bytes
        self.max_expanded_bytes = max_expanded_bytes
        self.mutex = threading.RLock()
        self.fds = []
        self.lock_fd = None
        self.worker = None
        self.job = None
        self.journal = self.control / 'job.json'
        roots = [os.path.abspath(p) for p in (self.pier, self.uploads, self.control)]
        for i, first in enumerate(roots):
            for second in roots[i + 1:]:
                if os.path.commonpath([first, second]) in (first, second):
                    raise ImportError('Storage roots must be separate non-nested directories.')
        try:
            self.pier_fd, self.upload_fd, self.control_fd = [self._open_root(p) for p in roots]
            # Lock the actual target inode as well as its control journal, so
            # another importer cannot evade exclusion with a different control root.
            fcntl.flock(self.pier_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.lock_fd = os.open('writer.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW,
                                   0o600, dir_fd=self.control_fd)
            fcntl.flock(self.lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            try:
                fd = os.open('job.json', os.O_RDONLY | os.O_NOFOLLOW, dir_fd=self.control_fd)
            except FileNotFoundError:
                fd = None
            if fd is not None:
                with os.fdopen(fd, 'rb') as journal:
                    record = journal.read(65537)
                if len(record) > 65536:
                    raise ImportError('Import journal needs operator recovery.')
                self.job = json.loads(record)
                if self.job is not None:
                    if (not re.fullmatch('[a-f0-9]{32}', self.job['id']) or
                            self.job['state'] not in ('UPLOADING', 'VALIDATING', 'COMMITTING',
                                                       'READY_LOCKED', 'FAILED', 'RECOVERY_REQUIRED', 'CANCELLING') or
                            type(self.job['offset']) is not int or
                            type(self.job['total_bytes']) is not int or
                            not 0 <= self.job['offset'] <= self.job['total_bytes'] <= self.max_upload_bytes or
                            type(self.job['expanded_limit']) is not int or
                            not 0 < self.job['expanded_limit'] <= self.max_expanded_bytes):
                        raise ImportError('Import journal needs operator recovery.')
                    if self.job['state'] == 'UPLOADING':
                        with self._open_archive() as archive:
                            if os.fstat(archive.fileno()).st_size < self.job['offset']:
                                raise ImportError('Upload data is shorter than its acknowledged journal.')
                            archive.truncate(self.job['offset'])
                            os.fsync(archive.fileno())
                    elif self.job['state'] in ('VALIDATING', 'COMMITTING'):
                        # Never continue extraction or execute a runtime on process restart.
                        self.job['state'] = ('FAILED' if self.job['state'] == 'VALIDATING' and
                                             'ship' not in os.listdir(self.pier_fd) else 'RECOVERY_REQUIRED')
                        self.job['error'] = 'Import was interrupted. Ship start remains unavailable.'
                        self._persist()
                    elif self.job['state'] == 'CANCELLING':
                        self._finish_cancel()
        except Exception as error:
            self.close()
            if isinstance(error, ImportError):
                raise
            raise ImportError('Storage is unsafe, busy or has an invalid journal.') from None

    def _open_root(self, path):
        fd = private_root(path)
        self.fds.append(fd)
        return fd

    def _open_archive(self):
        if self.job is None:
            raise ImportError('No upload job.')
        fd = os.open(f"{self.job['id']}.zip", os.O_RDWR | os.O_NOFOLLOW, dir_fd=self.upload_fd)
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            os.close(fd)
            raise ImportError('Upload must be a regular file.')
        return os.fdopen(fd, 'r+b')

    def _archive(self):
        if self.job is None:
            raise ImportError('No upload job.')
        return self.uploads / f"{self.job['id']}.zip"

    def _persist(self):
        pending = f'.journal-{uuid.uuid4().hex}'
        fd = os.open(pending, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=self.control_fd)
        try:
            with os.fdopen(fd, 'w') as output:
                json.dump(self.job, output)
                output.flush()
                os.fsync(output.fileno())
            os.replace(pending, 'job.json', src_dir_fd=self.control_fd, dst_dir_fd=self.control_fd)
            os.fsync(self.control_fd)
        finally:
            try:
                os.unlink(pending, dir_fd=self.control_fd)
            except FileNotFoundError:
                pass

    def capacity(self):
        upload = os.fstatvfs(self.upload_fd)
        pier = os.fstatvfs(self.pier_fd)
        return {'upload_free': upload.f_bavail * upload.f_frsize,
                'pier_free': pier.f_bavail * pier.f_frsize,
                'same_filesystem': os.fstat(self.upload_fd).st_dev == os.fstat(self.pier_fd).st_dev,
                'free_inodes': min(upload.f_favail, pier.f_favail)}

    def _space(self, compressed, expanded):
        space = self.capacity()
        if space['same_filesystem']:
            enough = min(space['upload_free'], space['pier_free']) >= compressed + expanded + self.reserve_bytes
        else:
            enough = (space['upload_free'] >= compressed + self.reserve_bytes and
                      space['pier_free'] >= expanded + self.reserve_bytes)
        if not enough or space['free_inodes'] < 2:
            raise ImportError('Insufficient reserved disk space or inodes for this import.')

    def create(self, *, total_bytes, expanded_limit, stopped):
        with self.mutex:
            if self.job is not None:
                raise ImportError('An import job already exists.')
            if stopped is not True:
                raise ImportError('Declare that the source is stopped before importing.')
            if (type(total_bytes) is not int or not 0 < total_bytes <= self.max_upload_bytes or
                    type(expanded_limit) is not int or not 0 < expanded_limit <= self.max_expanded_bytes):
                raise ImportError('Invalid compressed size or expanded extraction budget.')
            if os.listdir(self.pier_fd):
                raise ImportError('Target pier storage must be empty; existing state is never overwritten.')
            self._space(total_bytes, expanded_limit)
            self.job = {'id': uuid.uuid4().hex, 'state': 'UPLOADING',
                        'offset': 0, 'total_bytes': total_bytes,
                        'expanded_limit': expanded_limit, 'expanded_bytes': 0, 'files': 0}
            fd = os.open(f"{self.job['id']}.zip", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o600, dir_fd=self.upload_fd)
            os.close(fd)
            os.fsync(self.upload_fd)
            self._persist()
            return dict(self.job)

    def append(self, job_id, offset, data):
        with self.mutex:
            if not self.job or job_id != self.job['id'] or self.job['state'] != 'UPLOADING':
                raise ImportError('No matching upload job.')
            if offset != self.job['offset']:
                raise ImportError('Upload offset does not match the durable acknowledged offset.')
            if not data or len(data) > 1024**2 or offset + len(data) > self.job['total_bytes']:
                raise ImportError('Invalid upload chunk size.')
            self._space(len(data), self.job['expanded_limit'])
            with self._open_archive() as archive:
                archive.seek(offset)
                archive.write(data)
                archive.flush()
                os.fsync(archive.fileno())
            self.job['offset'] += len(data)
            try:
                self._persist()
            except OSError:
                # The journal replace may or may not have reached disk. Do not
                # acknowledge guessed progress; a reopen uses the actual journal.
                self.job['offset'] = offset
                self.job['state'] = 'RECOVERY_REQUIRED'
                self.job['error'] = 'Journal durability failed; restart the importer before resuming.'
                raise ImportError('Journal durability failed. Upload progress was not acknowledged.') from None
            return dict(self.job)

    def verify(self, job_id, offset, data):
        with self.mutex:
            if not self.job or job_id != self.job['id'] or self.job['state'] != 'UPLOADING':
                raise ImportError('No matching upload job.')
            if (type(offset) is not int or offset < 0 or not data or len(data) > 1024**2 or
                    offset + len(data) > self.job['offset']):
                raise ImportError('Invalid retained-prefix verification range.')
            with self._open_archive() as archive:
                archive.seek(offset)
                retained = archive.read(len(data))
            if not hmac.compare_digest(retained, data):
                raise ImportError('Selected file does not match the retained upload prefix.')
            return {'verified': offset + len(data)}

    def cancel(self, job_id):
        with self.mutex:
            if self.job is None or job_id != self.job['id']:
                raise ImportError('No matching import job.')
            if self.job['state'] not in ('UPLOADING', 'FAILED'):
                raise ImportError('Only incomplete inactive jobs can be cancelled.')
            self.job['state'] = 'CANCELLING'
            self._persist()
            self._finish_cancel()

    def _finish_cancel(self):
        assert self.job is not None and self.job['state'] == 'CANCELLING'
        stage = f".import-{self.job['id']}"
        if stage in os.listdir(self.pier_fd):
            remove_stage(self.pier_fd, stage)
        try:
            os.unlink(f"{self.job['id']}.zip", dir_fd=self.upload_fd)
        except FileNotFoundError:
            pass
        os.fsync(self.upload_fd)
        self.job = None
        self._persist()

    def begin_validate(self, job_id):
        with self.mutex:
            if (not self.job or self.job['id'] != job_id or self.job['state'] != 'UPLOADING' or
                    self.job['offset'] != self.job['total_bytes'] or
                    (self.worker is not None and self.worker.is_alive())):
                raise ImportError('A complete inactive upload is required before validation.')

            def run():
                try:
                    self.validate(job_id)
                except ImportError:
                    pass
                except Exception:
                    sys.stderr.write('Import validation stopped; ship start remains unavailable.\n')

            self.worker = threading.Thread(target=run, name='archive-validation')
            self.worker.start()
            return dict(self.job)

    def validate(self, job_id, *, extractor=None):
        with self.mutex:
            if (not self.job or self.job['id'] != job_id or self.job['state'] != 'UPLOADING' or
                    self.job['offset'] != self.job['total_bytes']):
                raise ImportError('A complete matching upload is required before validation.')
            if os.listdir(self.pier_fd):
                raise ImportError('Target pier storage is no longer empty.')
            self._space(0, self.job['expanded_limit'])
            self.job['state'] = 'VALIDATING'
            self._persist()
            stage_name = f'.import-{job_id}'
            os.mkdir(stage_name, mode=0o700, dir_fd=self.pier_fd)
            os.fsync(self.pier_fd)
            stage = self.pier / stage_name

        def progress(result):
            with self.mutex:
                assert self.job is not None
                self.job['expanded_bytes'] = result['expanded_bytes']
                self.job['files'] = result['files']

        stage_fd = None
        committed = False
        try:
            if extractor is None:
                from archive import extract_zip
                extractor = extract_zip
            result = extractor(self._archive(), stage,
                               max_expanded_bytes=self.job['expanded_limit'], progress=progress)
            with self.mutex:
                stage_fd = os.open(stage_name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                   dir_fd=self.pier_fd)
                if os.listdir(stage_fd) != ['ship']:
                    raise ImportError('Invalid staged pier layout.')
                ship_fd = os.open('ship', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=stage_fd)
                try:
                    marker_fd = os.open('.urb', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=ship_fd)
                    os.close(marker_fd)
                    os.fsync(ship_fd)
                finally:
                    os.close(ship_fd)
                os.fsync(stage_fd)
                self.job.update(result)
                self.job['state'] = 'COMMITTING'
                self._persist()
                rename_without_replace(stage_fd, 'ship', self.pier_fd, 'ship')
                committed = True
                os.fsync(self.pier_fd)
                os.close(stage_fd)
                stage_fd = None
                os.rmdir(stage_name, dir_fd=self.pier_fd)
                os.fsync(self.pier_fd)
                if os.listdir(self.pier_fd) != ['ship']:
                    raise ImportError('Committed storage needs operator recovery.')
                os.unlink(f'{job_id}.zip', dir_fd=self.upload_fd)
                os.fsync(self.upload_fd)
                self.job['state'] = 'READY_LOCKED'
                self._persist()
                return dict(self.job)
        except Exception:
            with self.mutex:
                self.job['state'] = 'RECOVERY_REQUIRED' if committed else 'FAILED'
                self.job['error'] = 'Archive validation or commit failed. Ship start remains unavailable.'
                self._persist()
            raise ImportError('Archive validation or commit failed. Ship start remains unavailable.') from None
        finally:
            if stage_fd is not None:
                os.close(stage_fd)

    def status(self):
        with self.mutex:
            return {'state': self.job['state'] if self.job else 'LOCKED',
                    'start_available': False, 'chunk_bytes': 1024**2,
                    'security_gate': 'BLOCKED_EMBEDDED_OPENSSL',
                    'job': dict(self.job) if self.job else None}

    def start(self, *, confirmed_stopped=False):
        raise ImportError('Ship start is unavailable: runtime security and separate boot authorization are required.')

    def close(self):
        if self.worker is not None and self.worker is not threading.current_thread():
            self.worker.join()
            self.worker = None
        if self.lock_fd is not None:
            os.close(self.lock_fd)
            self.lock_fd = None
        for fd in self.fds:
            os.close(fd)
        self.fds = []

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
