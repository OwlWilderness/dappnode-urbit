"""Explicit runtime lifecycle; import completion never starts a runtime.

ManagedImporter owns durable pier/control intent, locks and one runtime child.
The trusted adapter seam returns exactly True only for whole-scope settlement.
Production managed_service establishes one Linux subreaper before HTTP/import
threads and prohibits unrelated process launches. After king-only TERM and direct
child reap, adopted descendants must all exit and be reaped (ECHILD) before a
STOPPED record is written. A surviving descendant is bounded fail-closed.

Version 3 intent is paired in control/runtime.json and pier/.runtime-owner.json;
boot/inode metadata is diagnostic/binding information, never crash/replay proof.
No in-process live adoption or crash clearance is supplied. The separate root
host maintenance_provider may migrate intact imports only after enforced prior
scope destruction under continuous exact-storage admission. A clean paired
STOPPED generation may reopen; Start always remains explicit.

Assumes trusted service code, private stable local storage and cooperating
writers, not hostile same-UID/root mutation or simultaneous storage rollback.
Inherited locked pier FDs improve exclusion but do not prove descendants retain
FDs. Durable unresolved pier intent therefore blocks alternate control roots even
if all inherited FDs close. Shutdown monotonically closes admission and retains
locks/intent on uncertain scope. Tests inject trusted platform seams, not caller
proof checkboxes; Linux kernel behavior requires separate qualification.
"""
import os
import json
import stat
import uuid
import hashlib
import subprocess
import sys
import socket
import struct
import time
import re
import threading
import copy

from importer import Importer, ImportError, private_root


OFFICIAL_SHA256 = '47ad302e8934271dfc00dcdab1d553c6d6460b105e3099ff47e0e4e4231bb26d'


def _boot_id():
    """Linux host boot identity, not PID/container identity. Unavailable is unsafe."""
    if not sys.platform.startswith('linux'):
        return None
    try:
        with open('/proc/sys/kernel/random/boot_id', 'r', encoding='ascii') as source:
            value = source.read(38).strip()
        return value if re.fullmatch(r'[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}', value) else None
    except (OSError, UnicodeError):
        return None


def _jam(noun):
    """Encode our fixed request as jam (LSB-first, with backreferences)."""
    bits, seen = [], {}

    def put(value, count):
        bits.extend((value >> i) & 1 for i in range(count))

    def mat(value):
        length = value.bit_length()
        if not length:
            put(1, 1)
        else:
            width = length.bit_length()
            put(1 << width, width + 1)
            put(length, width - 1)
            put(value, length)

    def encode(value):
        previous = seen.get(value)
        if previous is not None and (isinstance(value, tuple) or value.bit_length() > previous.bit_length()):
            put(3, 2)
            mat(previous)
            return
        seen.setdefault(value, len(bits))
        if isinstance(value, tuple):
            put(1, 2)
            encode(value[0])
            encode(value[1])
        else:
            put(0, 1)
            mat(value)
    encode(noun)
    result = bytearray((len(bits) + 7) // 8)
    for i, bit in enumerate(bits):
        result[i // 8] |= bit << (i % 8)
    return bytes(result)


def _cue(data):
    """Bounded jam decoder: at most 4096 bytes, 1024 nodes, depth 64."""
    if not 0 < len(data) <= 4096:
        raise ValueError()
    value, position, seen, nodes = int.from_bytes(data, 'little'), 0, {}, 0

    def take(count):
        nonlocal position
        if position + count > len(data) * 8:
            raise ValueError()
        result = (value >> position) & ((1 << count) - 1)
        position += count
        return result

    def rub():
        width = 0
        while not take(1):
            width += 1
            if width > 13:
                raise ValueError()
        if not width:
            return 0
        length = (1 << (width - 1)) | take(width - 1)
        if length > 4096:
            raise ValueError()
        return take(length)

    def decode(depth=0):
        nonlocal nodes
        nodes += 1
        if depth > 64 or nodes > 1024:
            raise ValueError()
        start = position
        if not take(1):
            result = rub()
        elif not take(1):
            result = (decode(depth + 1), decode(depth + 1))
        else:
            reference = rub()
            if reference not in seen:
                raise ValueError()
            return seen[reference]
        seen[start] = result
        return result
    result = decode()
    if (position + 7) // 8 != len(data) or value >> position:
        raise ValueError()
    return result


def _request_access_code(connection):
    # Exact +code example from official conn documentation; no interpolated input.
    expression = ('=/  m  (strand ,vase)  ;<  our=@p  bind:m  get-our  '
                  ';<  code=@p  bind:m  (scry @p /j/code/(scot %p our))  '
                  '(pure:m !>((crip (slag 1 (scow %p code)))))')
    atom = lambda text: int.from_bytes(text.encode('ascii'), 'little')
    request = (0, (atom('fyrd'), (atom('base'), (atom('khan-eval'),
               (atom('noun'), (atom('ted-eval'), atom(expression)))))))
    payload = _jam(request)
    deadline = time.monotonic() + 5

    def budget():
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError()
        connection.settimeout(remaining)

    budget()
    connection.sendall(b'\0' + len(payload).to_bytes(4, 'little') + payload)

    def read(size):
        result = bytearray()
        while len(result) < size:
            budget()
            chunk = connection.recv(size - len(result))
            if not chunk:
                raise ValueError()
            result.extend(chunk)
        return bytes(result)
    header = read(5)
    length = int.from_bytes(header[1:], 'little')
    if header[0] != 0 or not 0 < length <= 4096:
        raise ValueError()
    result = _cue(read(length))
    # Exactly [0 %avow %& %noun cord]; reject goofs without rendering them.
    for expected in (0, atom('avow'), 0, atom('noun')):
        if not isinstance(result, tuple) or result[0] != expected:
            raise ValueError()
        result = result[1]
    if not isinstance(result, int) or result.bit_length() > 216:
        raise ValueError()
    code = result.to_bytes((result.bit_length() + 7) // 8, 'little').decode('ascii')
    if not re.fullmatch(r'(?:[a-z]{3}|[a-z]{6}(?:-[a-z]{6}){0,3})', code):
        raise ValueError()
    return code


class LinuxChildKernel:
    """Private platform seam. No process enumeration is settlement evidence."""

    def __init__(self):
        import ctypes
        import signal
        if (not sys.platform.startswith('linux') or threading.active_count() != 1 or
                threading.current_thread() is not threading.main_thread() or
                len(os.listdir('/proc/self/task')) != 1 or
                signal.getsignal(signal.SIGCHLD) != signal.SIG_DFL):
            raise ValueError('Exclusive child ownership unavailable.')
        with open(f'/proc/self/task/{os.getpid()}/children', encoding='ascii') as source:
            if source.read().strip():
                raise ValueError('Existing children cannot be adopted as owned.')
        self.ctypes = ctypes
        self.libc = ctypes.CDLL(None, use_errno=True)
        self.libc.prctl.argtypes = [ctypes.c_int, *([ctypes.c_ulong] * 4)]
        self.libc.prctl.restype = ctypes.c_int
        if self.libc.prctl(36, 1, 0, 0, 0) != 0 or not self.subreaper():
            raise ValueError('Subreaper setup was refused.')

    def subreaper(self):
        import signal
        value = self.ctypes.c_int()
        return (signal.getsignal(signal.SIGCHLD) == signal.SIG_DFL and
                self.libc.prctl(37, self.ctypes.addressof(value), 0, 0, 0) == 0 and
                value.value == 1)

    def wait(self):
        # __WALL also covers non-SIGCHLD clone children; WNOHANG alone only
        # selects ordinary fork children on Linux.
        return os.waitpid(-1, os.WNOHANG | 0x40000000)


class OwnedChildScope:
    """One managed-service process, one spawn/reaping owner, one live generation.

    prepare() runs before HTTP/import threads, after TLS helper subprocesses have
    completed. The process audit guard prohibits all other Python launch paths.
    This is an internal trusted-code contract, not a sandbox against ctypes/root.
    """
    _prepared = False

    def __init__(self, kernel):
        self.kernel = kernel
        self.child = None
        self._uncertain = False
        self._settled_child = None
        self._spawn_thread = None
        self._spawn_event = False
        self._lock = threading.RLock()

    @classmethod
    def prepare(cls):
        if cls._prepared:
            raise ValueError('Only one production coordinator is permitted.')
        kernel = LinuxChildKernel()
        scope = cls(kernel)
        sys.addaudithook(scope._audit)
        cls._prepared = True
        return scope

    def _audit(self, event, args):
        if event in ('subprocess.Popen', 'os.fork', 'os.forkpty', 'os.posix_spawn', 'os.system'):
            # Popen's private fork_exec is part of this single permitted event;
            # direct fork/posix_spawn/system never belong to the production path.
            if (event != 'subprocess.Popen' or self._spawn_thread != threading.get_ident() or
                    self._spawn_event):
                raise RuntimeError('Unowned process launch refused.')
            self._spawn_event = True

    def spawn(self, launch):
        with self._lock:
            if self.child is not None or self._uncertain or not self.kernel.subreaper():
                raise ValueError('Child scope is not available.')
            self._uncertain = True  # any launch exception is unresolved
            self._spawn_thread = threading.get_ident()
            self._spawn_event = False
            try:
                self.child = launch()
                self._settled_child = None
                self._uncertain = False
                return self.child
            finally:
                self._spawn_thread = None

    def settled(self, child, *, timeout=5):
        with self._lock:
            if (self._uncertain or child.returncode is None or
                    not self.kernel.subreaper()):
                return False
            if child is self._settled_child:
                return True
            if child is not self.child:
                return False
            # Direct child MUST have been reaped through its sole Popen handle
            # first. ECHILD now proves no living/zombie adopted descendants under
            # the exclusive spawn + verified living subreaper contract.
            deadline = time.monotonic() + timeout
            while True:
                try:
                    pid, _ = self.kernel.wait()
                except ChildProcessError:
                    self._settled_child, self.child = child, None
                    return True
                if time.monotonic() >= deadline:
                    return False
                if pid == 0:
                    time.sleep(min(.01, max(0, deadline - time.monotonic())))


class OfficialRuntimeAdapter:
    """Fixed-binary adapter; production scope comes only from managed_service."""

    def __init__(self, *, scope=None):
        self.scope = scope

    def reveal_access_code(self, ship_fd, child):
        # No .http.ports, TCP fallback, .run invocation or filesystem payload read.
        # Linux SO_PEERCRED binds this conn listener to the exact owned Vere king.
        if (not sys.platform.startswith('linux') or child is None or
                type(child.pid) is not int or child.pid <= 0 or child.poll() is not None):
            raise ValueError()
        directory = os.open('.urb', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=ship_fd)
        try:
            info = os.stat('conn.sock', dir_fd=directory, follow_symlinks=False)
            if not stat.S_ISSOCK(info.st_mode) or info.st_uid != os.geteuid():
                raise ValueError()
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                connection.settimeout(2)
                connection.connect(f'/proc/self/fd/{directory}/conn.sock')
                # SO_PEERCRED=17 in Linux UAPI; pid_t, uid_t, gid_t are 32 bits.
                pid, uid, _ = struct.unpack('3i', connection.getsockopt(socket.SOL_SOCKET, 17, 12))
                if pid != child.pid or uid != os.geteuid() or child.poll() is not None:
                    raise ValueError()
                return _request_access_code(connection)
        finally:
            os.close(directory)

    def scope_settled(self, child):
        return self.scope is not None and self.scope.settled(child)

    def launch(self, ship_fd, *, lock_fd=None):
        if self.scope is None or lock_fd is None:
            raise ImportError('Verified exclusive runtime coordinator is required.')
        return self.scope.spawn(lambda: self._launch_verified(ship_fd, lock_fd))

    def _launch_verified(self, ship_fd, lock_fd):
        fd = None
        try:
            fd = os.open('/bin/urbit', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) & 0o022 or
                    not stat.S_IMODE(info.st_mode) & 0o111):
                raise ValueError()
            digest = hashlib.sha256()
            while True:
                chunk = os.read(fd, 1024**2)
                if not chunk:
                    break
                digest.update(chunk)
            if digest.hexdigest() != OFFICIAL_SHA256:
                raise ValueError()
            after = os.fstat(fd)
            if ((info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns) !=
                    (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
                    or not sys.platform.startswith('linux')):
                raise ValueError()
            # Linux procfs executes the hashed inode and resolves the held ship inode.
            # argv[0] stays exactly the fixed official executable; no creation flags.
            return subprocess.Popen(['/bin/urbit', '-t', '-p', '34343', '--http-port', '8081',
                                     '--http-ip', '127.0.0.1',
                                     '--loom', '31', '--snap-time', '2', '--no-dock',
                                     f'/proc/self/fd/{ship_fd}'],
                                    executable=f'/proc/self/fd/{fd}', pass_fds=(fd, ship_fd, lock_fd),
                                    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL, shell=False, close_fds=True,
                                    cwd='/')
        except Exception:
            raise ImportError('Pinned official runtime verification or launch was refused.') from None
        finally:
            if fd is not None:
                os.close(fd)


class ManagedImporter(Importer):
    @staticmethod
    def _preflight_import(pier, control):
        """Do not let Importer repair/truncate a job under unresolved old intent.

        Ordinary pre-runtime resumable uploads retain their existing behavior.
        Existing runtime/pier ownership plus interrupted import is never cleared
        by selecting another control root or by constructing the import engine.
        """
        from maintenance_provider import read_raw, decode
        control_fd = pier_fd = None
        try:
            try:
                control_fd = private_root(control, create=False)
            except FileNotFoundError:
                return
            job_raw = read_raw(control_fd, 'job.json', uid=os.geteuid(), limit=65536)
            if job_raw is None:
                return
            job = decode(job_raw)
            if not isinstance(job, dict) or job.get('state') not in (
                    'UPLOADING', 'VALIDATING', 'COMMITTING', 'CANCELLING'):
                return
            runtime_raw = read_raw(control_fd, 'runtime.json', uid=os.geteuid(), limit=4096)
            try:
                pier_fd = private_root(pier, create=False)
            except FileNotFoundError:
                pier_fd = None
            prior_pier = pier_fd is not None and bool(set(os.listdir(pier_fd)) & {'ship', '.runtime-owner.json'})
            if runtime_raw is not None or prior_pier:
                raise ValueError()
        except Exception:
            raise ImportError('Import/runtime preflight refused: IMPORT_STATE_UNPROVABLE.') from None
        finally:
            for fd in (pier_fd, control_fd):
                if fd is not None:
                    os.close(fd)

    def __init__(self, pier, uploads, control, *, runtime_adapter=None, **limits):
        self._preflight_import(pier, control)
        self.runtime_adapter = OfficialRuntimeAdapter() if runtime_adapter is None else runtime_adapter
        self.runtime = {'state': 'STOPPED'}
        self.child = None
        self._closing = False
        self._closed = False
        self._close_lock = threading.Lock()
        self._fresh_pier = False
        # A retained runtime intent is never an invitation to recreate storage.
        existing = False
        probe = None
        try:
            probe = private_root(control, create=False)
            os.stat('runtime.json', dir_fd=probe, follow_symlinks=False)
            existing = True
        except FileNotFoundError:
            pass
        except Exception:
            raise ImportError('Runtime storage inspection was refused.') from None
        finally:
            if probe is not None:
                os.close(probe)
        super().__init__(pier, uploads, control, create_roots=not existing, **limits)
        try:
            record = self._load_runtime()
            owner = self._load_runtime(self.pier_fd, '.runtime-owner.json')
            self._fresh_pier = record is None and owner is None and 'ship' not in os.listdir(self.pier_fd)
            self._runtime_records = {'runtime.json': [record], '.runtime-owner.json': [owner]}
            if record is None and owner is None and not self._fresh_pier:
                self.runtime = {'state': 'RECOVERY_REQUIRED'}
            if record is not None or owner is not None:
                self.runtime = record or {'state': 'RECOVERY_REQUIRED'}
                if not (record is not None and record.get('version') == 3 and
                        record == owner and record['state'] == 'STOPPED' and
                        record['storage'] == self._storage_identity() and
                        self.job and self.job['state'] == 'READY_LOCKED'):
                    # Missing/foreign/replayed control intent, legacy STOPPED and
                    # unknown crash/reboot are never positive settlement evidence.
                    self.runtime = dict(self.runtime, state='RECOVERY_REQUIRED')
        except Exception:
            Importer.close(self)
            raise ImportError('Runtime journal needs operator recovery.') from None

    def _load_runtime(self, directory=None, name='runtime.json'):
        try:
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                         dir_fd=self.control_fd if directory is None else directory)
        except FileNotFoundError:
            return None
        with os.fdopen(fd, 'rb') as source:
            info = os.fstat(source.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or
                    stat.S_IMODE(info.st_mode) & 0o077 or info.st_size > 4096):
                raise ValueError()
            raw = source.read(4097)
            if not raw.lstrip().startswith(b'{'):
                raise ValueError()
            def unique(pairs):
                result = dict(pairs)
                if len(result) != len(pairs):
                    raise ValueError()
                return result
            record = json.loads(raw, object_pairs_hook=unique)
        if record.get('state') not in ('STOPPED', 'STARTING', 'RUNNING', 'FAULT', 'RECOVERY_REQUIRED'):
            raise ValueError()
        if set(record) == {'state'}:
            return record
        if (set(record) != {'version', 'state', 'generation', 'boot_id', 'storage'} or
                type(record['version']) is not int or record['version'] not in (2, 3) or
                not isinstance(record['generation'], str) or
                not re.fullmatch('[a-f0-9]{32}', record['generation']) or
                not isinstance(record['boot_id'], str) or
                not re.fullmatch(r'[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}', record['boot_id']) or
                not isinstance(record['storage'], dict) or
                set(record['storage']) != {'pier', 'control', 'ship'}):
            raise ValueError()
        for identity in record['storage'].values():
            if (not isinstance(identity, list) or len(identity) != 2 or
                    any(type(number) is not int or number < 0 for number in identity)):
                raise ValueError()
        return record

    def _storage_identity(self):
        ship_fd = self._safe_ship()
        try:
            return {name: [os.fstat(fd).st_dev, os.fstat(fd).st_ino]
                    for name, fd in (('pier', self.pier_fd), ('control', self.control_fd), ('ship', ship_fd))}
        finally:
            os.close(ship_fd)

    def _persist_runtime(self):
        # Pier-bound intent is committed first. A crash between the two writes
        # leaves a mismatch (refused), never a falsely clean lifecycle.
        targets = [(self.control_fd, 'runtime.json')]
        if self.runtime.get('version') == 3:
            targets.insert(0, (self.pier_fd, '.runtime-owner.json'))
        for directory, name in targets:
            # A failed write may have renamed before directory fsync failed.
            # Remember only exact records this coordinator actually attempted;
            # successful completion retires the older candidates for this slot.
            expected = self._runtime_records[name]
            attempted = copy.deepcopy(self.runtime)
            if attempted not in expected:
                expected.append(attempted)
            self._write_runtime(directory, name)
            self._runtime_records[name] = [attempted]

    def _validate_runtime_ownership(self):
        storage = self._storage_identity()
        if self.runtime.get('version') != 3 or self.runtime.get('storage') != storage:
            raise ValueError()
        for directory, name in ((self.pier_fd, '.runtime-owner.json'),
                                (self.control_fd, 'runtime.json')):
            record = self._load_runtime(directory, name)
            if (record is None or record not in self._runtime_records[name] or
                    record.get('generation') != self.runtime.get('generation') or
                    record.get('storage') != storage):
                raise ValueError()

    def _write_runtime(self, directory, name):
        # A killed owner write must not contaminate the exact pier layout.
        # Retain staging evidence on failure; maintenance never deletes it.
        staging = self.control_fd
        if os.fstat(staging).st_dev != os.fstat(directory).st_dev:
            raise ValueError('runtime staging requires one local filesystem')
        pending = '.runtime-' + uuid.uuid4().hex
        fd = os.open(pending, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=staging)
        with os.fdopen(fd, 'w') as output:
            json.dump(self.runtime, output)
            output.flush()
            os.fsync(output.fileno())
        os.replace(pending, name, src_dir_fd=staging, dst_dir_fd=directory)
        os.fsync(directory)
        if staging != directory:
            os.fsync(staging)

    def _safe_ship(self):
        ship_fd = None
        try:
            # Check the names still identify our locked inodes, not replacement roots.
            for path, held in ((self.pier, self.pier_fd), (self.control, self.control_fd)):
                current = private_root(path, create=False)
                try:
                    first, second = os.fstat(current), os.fstat(held)
                    if (first.st_dev, first.st_ino) != (second.st_dev, second.st_ino):
                        raise ValueError()
                finally:
                    os.close(current)
            if set(os.listdir(self.pier_fd)) - {'.runtime-owner.json'} != {'ship'}:
                raise ValueError()
            ship_fd = os.open('ship', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                              dir_fd=self.pier_fd)
            marker = os.open('.urb', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                             dir_fd=ship_fd)
            os.close(marker)
            return ship_fd
        except Exception:
            if ship_fd is not None:
                os.close(ship_fd)
            raise ImportError('Committed pier layout is unsafe; start was refused.') from None

    def _admit(self, operation, *args, **kwargs):
        with self.mutex:
            if self._closing or self._closed:
                raise ImportError('Runtime coordinator is closing; new work was refused.')
            return operation(*args, **kwargs)

    def create(self, **params):
        return self._admit(super().create, **params)

    def append(self, job_id, offset, data):
        return self._admit(super().append, job_id, offset, data)

    def verify(self, job_id, offset, data):
        return self._admit(super().verify, job_id, offset, data)

    def cancel(self, job_id):
        return self._admit(super().cancel, job_id)

    def begin_validate(self, job_id):
        return self._admit(super().begin_validate, job_id)

    def _on_ready(self):
        # This callback is inside Importer.validate's mutex. No Start can race
        # between READY_LOCKED and this durable no-writer-ever-owned settlement.
        if not self._fresh_pier or self.runtime != {'state': 'STOPPED'}:
            raise ImportError('Imported pier ownership needs recovery.')
        self.runtime = {'version': 3, 'state': 'STOPPED', 'generation': uuid.uuid4().hex,
                        'boot_id': _boot_id() or '00000000-0000-0000-0000-000000000000',
                        'storage': self._storage_identity()}
        try:
            self._persist_runtime()
        except Exception:
            self.runtime = dict(self.runtime, state='RECOVERY_REQUIRED')
            raise

    def start(self, *, confirmed_stopped=False):
        with self.mutex:
            if (self._closed or self._closing or confirmed_stopped is not True or not self.job or
                    self.job['state'] != 'READY_LOCKED' or self.runtime['state'] != 'STOPPED'):
                raise ImportError('Explicit stopped confirmation and an inactive ready import are required.')
            try:
                record = self._load_runtime()
                owner = self._load_runtime(self.pier_fd, '.runtime-owner.json')
                virgin = self._fresh_pier and self.runtime == {'state': 'STOPPED'}
                if (owner != record or
                        (record != self.runtime and not (virgin and record is None))):
                    raise ValueError()
                if not virgin:
                    self._validate_runtime_ownership()
            except Exception:
                self.runtime = {'state': 'RECOVERY_REQUIRED'}
                raise ImportError('Runtime journal needs operator recovery.') from None
            ship_fd = self._safe_ship()
            try:
                boot = _boot_id()
                if boot is None:
                    raise ValueError()
                self.runtime = {'version': 3, 'state': 'STARTING', 'generation': uuid.uuid4().hex,
                                'boot_id': boot, 'storage': self._storage_identity()}
                self._persist_runtime()
                if isinstance(self.runtime_adapter, OfficialRuntimeAdapter):
                    # This is the descriptor carrying the pier-root flock, not
                    # the different ship-directory descriptor. Descendants may
                    # close it; durable pier intent remains authoritative then.
                    self.child = self.runtime_adapter.launch(ship_fd, lock_fd=self.pier_fd)
                else:
                    self.child = self.runtime_adapter.launch(ship_fd)
                self.runtime = dict(self.runtime, state='RUNNING')
                self._persist_runtime()
            except Exception:
                self.runtime = dict(self.runtime, state='FAULT')
                try:
                    self._validate_runtime_ownership()
                    self._persist_runtime()
                except Exception:
                    pass  # Retain partial or anomalous intent; never repair it by guessing.
                raise ImportError('Runtime launch is uncertain; operator recovery is required.') from None
            finally:
                os.close(ship_fd)
            return self.status()

    def reveal_access_code(self):
        """Read only from the live child we own; serialize against stop/close."""
        with self.mutex:
            ship_fd = None
            try:
                if (self._closed or self._closing or self.runtime['state'] != 'RUNNING' or
                        self.child is None or self.child.poll() is not None):
                    raise ValueError()
                ship_fd = self._safe_ship()
                code = self.runtime_adapter.reveal_access_code(ship_fd, self.child)
                if self.child.poll() is not None:
                    raise ValueError()
                return code
            except Exception:
                raise ImportError('Access code unavailable.') from None
            finally:
                if ship_fd is not None:
                    os.close(ship_fd)

    def stop(self):
        with self.mutex:
            if self._closed:
                raise ImportError('Runtime coordinator is closed.')
            if self.runtime['state'] == 'STOPPED':
                if self.runtime.get('version') == 3:
                    try:
                        self._validate_runtime_ownership()
                    except Exception:
                        self.runtime = dict(self.runtime, state='FAULT')
                        raise ImportError('Runtime ownership is uncertain; storage remains locked.') from None
                return self.status()
            if self.child is None:
                raise ImportError('Runtime ownership is uncertain; operator recovery is required.')
            try:
                if self.child.poll() is None:
                    self.child.terminate()
                try:
                    self.child.wait(timeout=120)
                except (TimeoutError, subprocess.TimeoutExpired):
                    self.child.kill()
                    self.child.wait(timeout=5)
                # Waiting for the leader is necessary but never sufficient.
                if self.runtime_adapter.scope_settled(self.child) is not True:
                    raise ValueError()
                self._validate_runtime_ownership()
                self.runtime = dict(self.runtime, state='STOPPED')
                self._persist_runtime()
                self.child = None
            except Exception:
                self.runtime = dict(self.runtime, state='FAULT')
                try:
                    self._validate_runtime_ownership()
                    self._persist_runtime()
                except Exception:
                    pass
                raise ImportError('Runtime stop is uncertain; storage remains locked.') from None
            return self.status()

    def begin_close(self):
        # Signal-safe Python assignment: never wait for a request's lifecycle lock.
        # Once closed, admission cannot be reopened by a failed drain.
        self._closing = True

    def close(self):
        self.begin_close()
        # Serialize drain/release; join the worker without its mutex.
        with self._close_lock:
            with self.mutex:
                if self._closed:
                    return
                if self.runtime['state'] in ('FAULT', 'RECOVERY_REQUIRED', 'STARTING') and self.child is None:
                    raise ImportError('Runtime ownership is uncertain; storage remains locked.')
                if self.child is not None:
                    self.stop()
            Importer.close(self)
            with self.mutex:
                self._closed = True

    def status(self):
        with self.mutex:
            result = super().status()
            result['security_gate'] = 'OWNER_SELECTED_OFFICIAL_RISK'
            result['runtime'] = dict(self.runtime)
            result['start_available'] = bool(not self._closed and not self._closing and
                                             self.job and self.job['state'] == 'READY_LOCKED'
                                             and self.runtime['state'] == 'STOPPED')
            return result
