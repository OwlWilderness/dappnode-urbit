"""Explicit importer/runtime lifecycle; import completion never starts a runtime.

API: ManagedImporter(pier, uploads, control, *, runtime_adapter=None, **limits),
start(*, confirmed_stopped=False), stop(), status(), close(). The adapter seam is
launch(ship_fd) -> a Popen-compatible child (poll/terminate/kill/wait(timeout)).
The fd is borrowed for launch only; an adapter must preserve its own child handle.
Any launch exception is uncertain, even if it probably failed before execution.

RUNNING means a launch returned a child, not boot, identity, or health acceptance.
Production launch requires Linux procfs and the pinned official AMD64 binary;
there is no executable-path/hash override, adoption, or automatic recovery API.
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

from importer import Importer, ImportError, private_root


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

    def launch(self, ship_fd):
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
                                    executable=f'/proc/self/fd/{fd}', pass_fds=(fd, ship_fd),
                                    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL, shell=False, close_fds=True,
                                    cwd='/')
        except Exception:
            raise ImportError('Pinned official runtime verification or launch was refused.') from None
        finally:
            if fd is not None:
                os.close(fd)


class ManagedImporter(Importer):
    def __init__(self, pier, uploads, control, *, runtime_adapter=None, **limits):
        self.runtime_adapter = OfficialRuntimeAdapter() if runtime_adapter is None else runtime_adapter
        self.runtime = {'state': 'STOPPED'}
        self.child = None
        self._closing = False
        self._closed = False
        super().__init__(pier, uploads, control, **limits)
        try:
            record = self._load_runtime()
            if record is not None:
                self.runtime = record
                if record['state'] != 'STOPPED':
                    # Preserve the original durable intent; reopen never rewrites it.
                    self.runtime = {'state': 'RECOVERY_REQUIRED'}
        except Exception:
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

    def start(self, *, confirmed_stopped=False):
        with self.mutex:
            if (self._closed or self._closing or confirmed_stopped is not True or not self.job or
                    self.job['state'] != 'READY_LOCKED' or self.runtime['state'] != 'STOPPED'):
                raise ImportError('Explicit stopped confirmation and an inactive ready import are required.')
            try:
                record = self._load_runtime()
                if record is not None and record != self.runtime:
                    raise ValueError()
            except Exception:
                self.runtime = {'state': 'RECOVERY_REQUIRED'}
                raise ImportError('Runtime journal needs operator recovery.') from None
            ship_fd = self._safe_ship()
            try:
                self.runtime = {'state': 'STARTING'}
                self._persist_runtime()
                self.child = self.runtime_adapter.launch(ship_fd)
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
            if self.runtime['state'] == 'STOPPED':
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
                self.runtime = {'state': 'STOPPED'}
                self._persist_runtime()
                self.child = None
            except Exception:
                self.runtime = {'state': 'FAULT'}
                try:
                    self._persist_runtime()
                except Exception:
                    pass
                raise ImportError('Runtime stop is uncertain; storage remains locked.') from None
            return self.status()

    def close(self):
        # Joining the import worker while holding its mutex would deadlock.
        with self.mutex:
            if self._closed:
                return
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
