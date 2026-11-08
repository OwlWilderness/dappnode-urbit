"""Explicit importer/runtime lifecycle; import completion never starts a runtime.

API: ManagedImporter(pier, uploads, control, *, runtime_adapter=None, **limits),
start(*, confirmed_stopped=False), stop(), status(), close(). The adapter seam is
launch(ship_fd) -> a Popen-compatible child (poll/terminate/wait(timeout)).
The fd is borrowed for launch only; an adapter must preserve its own child handle.
Any launch exception is uncertain, even if it probably failed before execution.

RUNNING means the owned child was last observed live, not boot or health acceptance.
Graceful Stop requires terminate plus an acknowledged zero exit within 120 seconds;
there is no force-kill fallback. Child/parent exit alone is not host cessation proof.
Unexpected exit preserves durable intent and fails closed; it never auto-starts.
Production launch requires Linux procfs and the pinned official AMD64 binary;
there is no executable-path/hash override or adoption. Authenticated local recovery
reconciles its launch-time subreaper scope or a verified PID1 management boot.
Service-owned private storage and a trusted administrator are assumed: these locks
coordinate cooperating writers, not hostile same-UID/root mutation. Quiesce HTTP
requests before close; close joins the existing import worker without its mutex.
Unsettled children/ownership keep both lifetime flocks held and close refuses.
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
from contextlib import contextmanager

from importer import Importer, ImportError, private_root
from local_child import LinuxChildBoundary
from local_recovery import RecoveryJournal
from boot_boundary import ManagementBootBoundary
from legacy_evidence import validate_native_history


OFFICIAL_SHA256 = '47ad302e8934271dfc00dcdab1d553c6d6460b105e3099ff47e0e4e4231bb26d'


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


class OfficialRuntimeAdapter:
    """Lazy fixed-binary adapter; construction does no I/O or execution."""

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

    expected_sha256 = OFFICIAL_SHA256

    def launch(self, ship_fd):
        return self._verified_launch(ship_fd)

    def _verified_launch(self, ship_fd, *, creation=None):
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
            if digest.hexdigest() != self.expected_sha256:
                raise ValueError()
            after = os.fstat(fd)
            if ((info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns) !=
                    (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
                    or not sys.platform.startswith('linux')):
                raise ValueError()
            # Execute the hashed inode. Secret bytes are never argv/environment.
            args = ['/bin/urbit', '-t', '-p', '34343', '--http-port', '8081',
                    '--http-ip', '127.0.0.1', '--loom', '31', '--snap-time', '2', '--no-dock']
            inherited = (fd, ship_fd)
            if creation is None:
                args += [f'/proc/self/fd/{ship_fd}']
            else:
                identity, key_fd = creation
                if (type(self) is not UpdatedRuntimeAdapter or
                        not re.fullmatch(r'~[a-z]{6}-[a-z]{6}', identity) or type(key_fd) is not int):
                    raise ValueError()
                args += ['-w', identity[1:], '-k', f'/proc/self/fd/{key_fd}',
                         '-x', '-c', f'/proc/self/fd/{ship_fd}/ship']
                inherited += (key_fd,)
            return subprocess.Popen(args,
                                    executable=f'/proc/self/fd/{fd}', pass_fds=inherited,
                                    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL, shell=False, close_fds=True,
                                    cwd='/')
        except Exception:
            raise ImportError('Pinned official runtime verification or launch was refused.') from None
        finally:
            if fd is not None:
                os.close(fd)


class UpdatedRuntimeAdapter(OfficialRuntimeAdapter):
    """Explicit issue3 selection; never an environment/path/hash override."""
    expected_sha256 = '58d07af97926e04bc17184bc18f53e5fb11d84fed63bd9daf2fe4ceb04c86698'

    def create(self, pier_fd, identity, key_fd):
        return self._verified_launch(pier_fd, creation=(identity, key_fd))


class ManagedImporter(Importer):
    def __init__(self, pier, uploads, control, *, runtime_adapter=None, **limits):
        self.runtime_adapter = OfficialRuntimeAdapter() if runtime_adapter is None else runtime_adapter
        self.runtime = {'state': 'STOPPED'}
        self.child = None
        self._stop_result = 'NOT_REQUESTED'
        self._closing = False
        self._closed = False
        self._child_boundary = None
        self._recovery_fault = False
        self.recovery_journal = None
        self._boot_boundary = None
        try:
            validate_native_history(pier, uploads, control)
        except Exception:
            raise ImportError('Native recovery history needs operator reconciliation; preserve all evidence.') from None
        super().__init__(pier, uploads, control, **limits)
        try:
            self._boot_boundary = ManagementBootBoundary.receive()
            record = self._load_runtime()
            if record is not None:
                self.runtime = record
                if record['state'] != 'STOPPED':
                    # Preserve the original durable intent; reopen never rewrites it.
                    self.runtime = {'state': 'RECOVERY_REQUIRED'}
            self.recovery_journal = RecoveryJournal(self.control_fd)
        except Exception:
            if self._boot_boundary is not None:
                self._boot_boundary.close()
            Importer.close(self)
            raise ImportError('Runtime journal needs operator recovery.') from None

    def _load_runtime(self):
        try:
            fd = os.open('runtime.json', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                         dir_fd=self.control_fd)
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
            pairs = json.loads(raw, object_pairs_hook=list)
            if len(pairs) != 1 or pairs[0][0] != 'state':
                raise ValueError()
            record = dict(pairs)
        if (set(record) != {'state'} or record['state'] not in
                ('STOPPED', 'STARTING', 'RUNNING', 'FAULT', 'RECOVERY_REQUIRED')):
            raise ValueError()
        self._last_runtime_bytes = raw
        return record

    def _persist_runtime(self):
        pending = '.runtime-' + uuid.uuid4().hex
        fd = os.open(pending, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=self.control_fd)
        try:
            with os.fdopen(fd, 'w') as output:
                json.dump(self.runtime, output)
                output.flush()
                os.fsync(output.fileno())
            os.replace(pending, 'runtime.json', src_dir_fd=self.control_fd,
                       dst_dir_fd=self.control_fd)
            os.fsync(self.control_fd)
        finally:
            try:
                os.unlink(pending, dir_fd=self.control_fd)
            except FileNotFoundError:
                pass

    def _safe_ship(self):
        ship_fd = None
        try:
            # Check the names still identify our locked inodes, not replacement roots.
            for path, held in ((self.pier, self.pier_fd), (self.control, self.control_fd)):
                current = private_root(path)
                try:
                    first, second = os.fstat(current), os.fstat(held)
                    if (first.st_dev, first.st_ino) != (second.st_dev, second.st_ino):
                        raise ValueError()
                finally:
                    os.close(current)
            if os.listdir(self.pier_fd) != ['ship']:
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

    def _observe_owned_child(self):
        # Observation is not settlement or host-wide cessation proof. Keep the
        # original durable launch intent and child handle for operator recovery.
        if self.runtime['state'] == 'RUNNING':
            try:
                if self.child is None or self.child.poll() is not None:
                    self.runtime = {'state': 'FAULT'}
            except Exception:
                self.runtime = {'state': 'FAULT'}

    @contextmanager
    def _launch_slot(self):
        # A request made during recovery must not queue an automatic restart
        # behind it. The owner must submit a separate Start after settlement.
        if not self.mutex.acquire(blocking=False):
            raise ImportError('Lifecycle operation is busy; submit a separate Start after settlement.')
        try:
            yield
        finally:
            self.mutex.release()

    def start(self, *, confirmed_stopped=False):
        with self._launch_slot():
            self._observe_owned_child()
            if (self._closed or self._closing or confirmed_stopped is not True or not self.job or
                    self.job['state'] != 'READY_LOCKED' or self.runtime['state'] != 'STOPPED' or
                    self._recovery_fault or self.recovery_journal.pending()):
                raise ImportError('Explicit stopped confirmation and an inactive ready import are required.')
            try:
                record = self._load_runtime()
                if record is not None and record != self.runtime:
                    raise ValueError()
            except Exception:
                self.runtime = {'state': 'RECOVERY_REQUIRED'}
                raise ImportError('Runtime journal needs operator recovery.') from None
            # Once this backend attempts any writer launch, startup-only
            # authority is gone, even if launch or acknowledgement later fails.
            if self._boot_boundary is not None:
                self._boot_boundary.close()
                self._boot_boundary = None
            ship_fd = self._safe_ship()
            try:
                self.runtime = {'state': 'STARTING'}
                self._stop_result = 'NOT_REQUESTED'
                self._persist_runtime()
                boundary = LinuxChildBoundary.prepare()
                self.child = self.runtime_adapter.launch(ship_fd)
                self._child_boundary = None
                if boundary is not None and isinstance(self.child, subprocess.Popen):
                    boundary.bind(self.child)
                    self._child_boundary = boundary
                self.runtime = {'state': 'RUNNING'}
                self._persist_runtime()
            except Exception:
                self.runtime = {'state': 'FAULT'}
                try:
                    self._persist_runtime()
                except Exception:
                    pass  # The durable STARTING intent, if committed, also blocks retry.
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
            self._observe_owned_child()
            if self.runtime['state'] == 'STOPPED':
                return self.status()
            if self.runtime['state'] != 'RUNNING' or self.child is None:
                raise ImportError('Runtime ownership is uncertain; operator recovery is required.')
            try:
                self._stop_result = 'UNKNOWN'
                if self.child.poll() is not None:
                    raise ValueError()
                if self._child_boundary is not None:
                    code = self._child_boundary.settle()['exit_code']
                else:
                    self.child.terminate()
                    code = self.child.wait(timeout=120)
                if type(code) is not int or code != 0:
                    self._stop_result = 'FORCED' if code == -9 else 'FAILED'
                    raise ValueError()
                self.runtime = {'state': 'STOPPED'}
                self._persist_runtime()
                self.child = None
                self._stop_result = 'GRACEFUL'
            except Exception:
                self.runtime = {'state': 'FAULT'}
                # Keep durable launch/stop evidence unchanged on uncertainty;
                # an active journal also fences a fresh coordinator. Never
                # rewrite or retry an ambiguously acknowledged journal write.
                raise ImportError('Runtime stop is uncertain; storage remains locked.') from None
            return self.status()

    def close(self):
        # Joining the import worker while holding its mutex would deadlock.
        with self.mutex:
            if self._closed:
                return
            self._observe_owned_child()
            if self.runtime['state'] in ('FAULT', 'RECOVERY_REQUIRED', 'STARTING') and self.child is None:
                raise ImportError('Runtime ownership is uncertain; storage remains locked.')
            self._closing = True
            try:
                if self.child is not None:
                    self.stop()
            except Exception:
                self._closing = False
                raise
        Importer.close(self)
        with self.mutex:
            if self.recovery_journal is not None:
                self.recovery_journal.close()
            if self._boot_boundary is not None:
                self._boot_boundary.close()
                self._boot_boundary = None
            self._closed = True

    def status(self):
        with self.mutex:
            self._observe_owned_child()
            result = super().status()
            result['security_gate'] = 'OWNER_SELECTED_OFFICIAL_RISK'
            result['runtime'] = dict(self.runtime)
            # Ephemeral outcome only; runtime.json retains its original schema.
            result['runtime_stop_result'] = self._stop_result
            latest = self.recovery_journal.latest()
            result['local_recovery'] = self._recovery_summary(latest)
            result['local_recovery_available'] = bool(
                not self._closed and not self._closing and not self._recovery_fault and
                not self.recovery_journal.pending() and self.job and self.job['state'] == 'READY_LOCKED' and (
                    (self._child_boundary is not None and self.child is self._child_boundary.child and
                     self.runtime['state'] in ('RUNNING', 'FAULT')) or
                    (self._boot_boundary is not None and not self._boot_boundary.used and self.child is None and
                     self.runtime['state'] == 'RECOVERY_REQUIRED')))
            result['local_recovery_guidance'] = (
                'Restart the package into management mode first; never clear lifecycle journals manually.'
                if self.runtime['state'] == 'RECOVERY_REQUIRED' and not result['local_recovery_available'] else None)
            result['start_available'] = bool(not self._closed and not self._closing and
                                             self.job and self.job['state'] == 'READY_LOCKED'
                                             and self.runtime['state'] == 'STOPPED'
                                             and not self._recovery_fault and not self.recovery_journal.pending())
            return result

    @staticmethod
    def _recovery_summary(record):
        if record is None:
            return None
        return {key: record[key] for key in ('operation_id', 'sequence', 'outcome')}

    def recover(self, *, operation_id):
        """Recover this backend's Linux-owned lifecycle, never Urbit data or native receipts."""
        if not isinstance(operation_id, str) or not re.fullmatch('[a-f0-9]{32}', operation_id):
            raise ImportError('Invalid local recovery operation identifier.')
        with self.mutex:
            journal = self.recovery_journal
            if operation_id in journal.records:
                # Acknowledgement loss never repeats mutation, including PENDING.
                retained = journal.read(operation_id)
                return {'runtime': dict(self.runtime), 'local_recovery': self._recovery_summary(retained)}
            boot_recovery = (self._boot_boundary is not None and not self._boot_boundary.used and
                             self.child is None and self.runtime['state'] == 'RECOVERY_REQUIRED')
            owned_recovery = (self._child_boundary is not None and
                              self.child is self._child_boundary.child and self.runtime['state'] in ('RUNNING', 'FAULT'))
            if (self._closed or self._closing or self._recovery_fault or journal.pending() or
                    not self.job or self.job['state'] != 'READY_LOCKED' or
                    not (boot_recovery or owned_recovery)):
                raise ImportError('Recovery requires an owned child or verified PID1 management boot. Restart the package into management mode first; unknown ownership stays fenced.')
            ship_fd = self._safe_ship()
            os.close(ship_fd)
            try:
                prior = self._load_runtime()
                if prior is None or prior['state'] not in ('RUNNING', 'STARTING', 'FAULT', 'RECOVERY_REQUIRED'):
                    raise ValueError()
                journal.validate()
            except Exception:
                self._recovery_fault = True
                raise ImportError('Lifecycle or evidence storage changed; no recovery signal was sent.') from None
            record = {'operation_id': operation_id, 'sequence': len(journal.records) + 1,
                      'outcome': 'PENDING', 'evidence': {'prior_runtime': prior}}
            if boot_recovery:
                record['evidence']['original_runtime'] = {
                    'utf8': self._last_runtime_bytes.decode('utf-8'),
                    'sha256': hashlib.sha256(self._last_runtime_bytes).hexdigest()}
            try:
                journal.save(record)
            except Exception:
                self._recovery_fault = True
                raise ImportError('Recovery intent is uncertain; no recovery signal was sent.') from None
            try:
                evidence = self._boot_boundary.settle() if boot_recovery else self._child_boundary.settle()
            except Exception:
                record = {**record, 'outcome': 'REFUSED',
                          'evidence': {**record['evidence'], 'error': 'CESSATION_NOT_ESTABLISHED'}}
                try:
                    journal.save(record)
                except Exception:
                    self._recovery_fault = True
                self.runtime = {'state': 'FAULT'}
                raise ImportError('Recovery refused or stop uncertain; descendant/concurrent ownership must be resolved. No force-kill was sent.') from None
            try:
                self.runtime = {'state': 'STOPPED'}
                self._persist_runtime()
                record = {**record, 'outcome': 'COMPLETE',
                          'evidence': {**record['evidence'], **evidence, 'result_runtime': 'STOPPED'}}
                journal.save(record)
                self.child = None
                self._child_boundary = None
                if self._boot_boundary is not None:
                    self._boot_boundary.close()
                    self._boot_boundary = None
                self._stop_result = ('NOT_REQUESTED' if boot_recovery else
                                     'GRACEFUL' if evidence['signal'] == 'SIGTERM' and evidence['exit_code'] == 0 else 'EXITED')
            except Exception:
                self._recovery_fault = True
                self.runtime = {'state': 'FAULT'}
                raise ImportError('Recovery persistence is uncertain; Start remains fenced.') from None
            return {'runtime': dict(self.runtime), 'local_recovery': self._recovery_summary(record)}
