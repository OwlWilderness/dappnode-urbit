# Prepared successor; historical controller is immutable.
import socket
import subprocess
import os
import sys
import stat
import time
import json
import hashlib
import signal
import fcntl
from pathlib import Path

sys.path.insert(0, '/opt/importer')
from runtime import OfficialRuntimeAdapter

GIB = 1024**3
# Exact public files independently verified in the combined AMD64 image.
BINDING_STATE = 'UNBOUND'
EXECUTABLE_SIZE = None
EXECUTABLE_SHA = None
ADAPTER_SIZE = None
ADAPTER_SHA = None


def stop_child(child):
    forced = False
    if child.poll() is None:
        child.terminate()
        try:
            return child.wait(timeout=120), forced
        except subprocess.TimeoutExpired:
            child.kill()
            forced = True
    return child.wait(timeout=5), forced


def probe_http(path='/'):
    # Deliberately never receive response headers/cookies or an application body.
    if path not in ('/', '/~/login'):
        raise ValueError('Unapproved HTTP path')
    with socket.create_connection(('127.0.0.1', 8081), timeout=1) as client:
        client.sendall(('GET '+path+' HTTP/1.0\r\nHost: 127.0.0.1:8081\r\n\r\n').encode('ascii'))
        line = bytearray()
        while len(line) < 128 and not line.endswith(b'\r\n'):
            part = client.recv(1)
            if not part:
                raise ValueError('Incomplete HTTP status')
            line.extend(part)
        pieces = bytes(line).split(b' ')
        if (not line.endswith(b'\r\n') or len(pieces) < 3 or
                pieces[0] not in (b'HTTP/1.0', b'HTTP/1.1') or
                len(pieces[1]) != 3 or not pieces[1].isdigit() or not 100 <= int(pieces[1]) <= 599):
            raise ValueError('Invalid HTTP status')
        return int(pieces[1])

def bootstrap_argv():
    return ['/bin/urbit', '-t', '-F', 'zod', '-B', '/bootstrap.pill',
            '-c', '/urbit/pier/ship', '-p', '34343', '--http-port', '8081',
            '--loom', '31', '--snap-time', '2', '--no-dock', '-x']


def verify_public(path, size, digest):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        first = os.fstat(fd)
        if not stat.S_ISREG(first.st_mode) or first.st_size != size:
            raise ValueError('Public artifact metadata')
        value = hashlib.sha256()
        while chunk := os.read(fd, 1024**2):
            value.update(chunk)
        after = os.fstat(fd)
        named = os.stat(path, follow_symlinks=False)
        fields = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        if fields(first) != fields(after) or fields(after) != fields(named) or value.hexdigest() != digest:
            raise ValueError('Public artifact changed')
    finally:
        os.close(fd)


def require_bound():
    if BINDING_STATE != 'BOUND':
        raise ValueError('UNBOUND: actual combined executable/adapter pending')
    import re
    for size in (EXECUTABLE_SIZE, ADAPTER_SIZE):
        if type(size) is not int or size <= 0:
            raise ValueError('UNBOUND artifact size')
    for digest in (EXECUTABLE_SHA, ADAPTER_SHA):
        if not isinstance(digest, str) or not re.fullmatch('[0-9a-f]{64}', digest):
            raise ValueError('UNBOUND artifact digest')


def verify_inputs(phase):
    require_bound()
    if phase not in ('bootstrap', 'reopen') or sys.platform != 'linux' or os.getuid() != 10000 or os.getgid() != 10000:
        raise ValueError('Approved container only')
    os.umask(0o077)
    for path in ('/urbit', '/urbit/pier', '/urbit/control'):
        info = os.stat(path, follow_symlinks=False)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 10000 or info.st_mode & 0o077:
            raise ValueError('Private state roots')
    verify_public('/bin/urbit', EXECUTABLE_SIZE, EXECUTABLE_SHA)
    verify_public('/opt/importer/runtime.py', ADAPTER_SIZE, ADAPTER_SHA)
    if phase == 'bootstrap':
        if os.path.lexists('/urbit/pier/ship'):
            raise ValueError('Fresh state required')
        verify_public('/bootstrap.pill', None, None)
    elif os.path.lexists('/bootstrap.pill'):
        raise ValueError('No creation input during reopen')


def guest_metrics():
    available = None
    for line in Path('/proc/meminfo').read_text().splitlines():
        if line.startswith('MemAvailable:'):
            available = int(line.split()[1]) * 1024
    state_free, root_free = os.statvfs('/urbit'), os.statvfs('/')
    return {'memory_available_bytes': available,
            'state_free_bytes': state_free.f_bavail * state_free.f_frsize,
            'root_free_bytes': root_free.f_bavail * root_free.f_frsize,
            'cgroup_memory_max_bytes': int(Path('/sys/fs/cgroup/memory.max').read_text().strip()),
            'cgroup_current_bytes': int(Path('/sys/fs/cgroup/memory.current').read_text().strip())}


def admit(guest):
    if (guest['memory_available_bytes'] < 5 * GIB + 512 * 1024**2 or
            guest['cgroup_memory_max_bytes'] != 5 * GIB or
            guest['cgroup_memory_max_bytes'] - guest['cgroup_current_bytes'] < 4 * GIB or
            guest['state_free_bytes'] < 8 * GIB or guest['root_free_bytes'] < 8 * GIB):
        raise ValueError('Guest admission refused')


def guard(initial):
    current = guest_metrics()
    if (current['memory_available_bytes'] < 512 * 1024**2 or
            current['state_free_bytes'] < 6 * GIB or
            initial['state_free_bytes'] - current['state_free_bytes'] > 4 * GIB):
        raise ValueError('Guest sampled growth/headroom refusal')


def wait_child(child, timeout, initial):
    end = time.monotonic() + timeout
    while child.poll() is None:
        guard(initial)
        if time.monotonic() >= end:
            raise TimeoutError('Bootstrap deadline')
        time.sleep(2)
    return child.wait(timeout=5)


def new_diagnostics():
    # Numeric enums: 0 unstarted/no failure; 1 inputs, 2 guest, 3 bootstrap,
    # 4 open ship, 5 adapter launch, 6 readiness, 7 stop, 8 reap, 9 complete.
    return {'stage': 0, 'failure': 0, 'bootstrap_elapsed_ms': None,
            'readiness_elapsed_ms': None, 'http_attempts': 0,
            'last_root_status': None, 'last_login_status': None,
            'connection_failures': 0, 'last_errno': None,
            'resume_poll_exit': None, 'cleanup_exit': None,
            'cleanup_failure': 0, 'login_200_consecutive': 0}


def elapsed_ms(start):
    return min(3600000, max(0, int((time.monotonic() - start) * 1000)))


def wait_ready(child, initial, diagnostics=None):
    diagnostics = new_diagnostics() if diagnostics is None else diagnostics
    start, consecutive = time.monotonic(), 0
    try:
        while time.monotonic() < start + 300 and diagnostics['http_attempts'] < 1000:
            guard(initial)
            diagnostics['resume_poll_exit'] = child.poll()
            if diagnostics['resume_poll_exit'] is not None:
                raise ValueError('Vere exited before readiness')
            for path, field in (('/', 'last_root_status'), ('/~/login', 'last_login_status')):
                diagnostics['http_attempts'] += 1
                status = None
                try:
                    status = probe_http(path)
                    diagnostics[field] = status
                except OSError as exc:
                    diagnostics['connection_failures'] += 1
                    value = exc.errno
                    diagnostics['last_errno'] = value if type(value) is int and 0 <= value <= 4095 else None
                except ValueError:
                    pass
                if path == '/~/login':
                    consecutive = consecutive + 1 if status == 200 else 0
                    diagnostics['login_200_consecutive'] = consecutive
            diagnostics['resume_poll_exit'] = child.poll()
            if diagnostics['resume_poll_exit'] is not None:
                raise ValueError('Vere exited during readiness')
            if consecutive >= 2:
                return 200
            time.sleep(2)
        raise TimeoutError('HTTP readiness deadline')
    finally:
        diagnostics['readiness_elapsed_ms'] = elapsed_ms(start)


def reap_children():
    # PID1 must have no leftover live/orphaned child before another ship process.
    end = time.monotonic() + 5
    while True:
        try:
            while os.waitpid(-1, os.WNOHANG)[0]:
                pass
        except ChildProcessError:
            pass
        raw = Path(f'/proc/self/task/{os.getpid()}/children').read_text().strip()
        if not raw:
            return
        if time.monotonic() >= end:
            raise ValueError('Unsettled descendants; no reopen')
        time.sleep(0.1)


def open_ship():
    fd = os.open('/urbit/pier/ship', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if info.st_uid != 10000 or info.st_mode & 0o077:
            raise ValueError('Unsafe generated ship root')
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return fd
    except BaseException:
        os.close(fd)
        raise


def run_phase(phase):
    diagnostics = new_diagnostics()
    result = {'schema': 2, 'phase': phase, 'success': False, 'checks': [],
              'native_launches': 0, 'bootstrap_exit': None, 'resume_exit': None,
              'http_status': None, 'forced_kill': False, 'guest': {},
              'diagnostics': diagnostics}
    child, ship_fd, role = None, None, None
    try:
        diagnostics['stage'] = 1
        verify_inputs(phase)
        result['checks'].append('exact_inputs_private_fresh_or_reopen_state')
        diagnostics['stage'] = 2
        initial = guest_metrics()
        result['guest'] = initial
        admit(initial)
        result['checks'].append('numeric_guest_admission_before_Vere')
        if phase == 'bootstrap':
            diagnostics['stage'] = 3
            start = time.monotonic()
            try:
                child = subprocess.Popen(bootstrap_argv(), stdin=subprocess.DEVNULL,
                                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                         shell=False, close_fds=True, cwd='/')
                role = 'bootstrap'
                result['native_launches'] += 1
                result['bootstrap_exit'] = wait_child(child, 600, initial)
                if result['bootstrap_exit'] != 0:
                    raise ValueError('Bootstrap failed')
            finally:
                diagnostics['bootstrap_elapsed_ms'] = elapsed_ms(start)
            diagnostics['stage'] = 8
            reap_children()
            child = None
            result['checks'].append('actual_offline_fake_bootstrap_exit0_no_remaining_child')
        diagnostics['stage'] = 4
        ship_fd = open_ship()
        diagnostics['stage'] = 5
        child = OfficialRuntimeAdapter().launch(ship_fd)
        role = 'resume'
        result['native_launches'] += 1
        diagnostics['stage'] = 6
        result['http_status'] = wait_ready(child, initial, diagnostics)
        result['checks'].append('production_adapter_HTTP200_twice_while_alive')
        diagnostics['stage'] = 7
        result['resume_exit'], result['forced_kill'] = stop_child(child)
        diagnostics['cleanup_exit'] = result['resume_exit']
        child = None
        if result['resume_exit'] != 0 or result['forced_kill']:
            raise ValueError('Unclean stop')
        diagnostics['stage'] = 8
        reap_children()
        result['checks'].append('sigterm_exit0_no_forced_kill_or_remaining_child')
        verify_public('/bin/urbit', EXECUTABLE_SIZE, EXECUTABLE_SHA)
        diagnostics['stage'] = 9
        result['success'] = True
    except BaseException:
        # No exception message, stream, key/code, application body or state payload exported.
        diagnostics['failure'] = diagnostics['stage']
    finally:
        if child is not None:
            try:
                code, forced = stop_child(child)
                diagnostics['cleanup_exit'] = code
                result['forced_kill'] = result['forced_kill'] or forced
                result['bootstrap_exit' if role == 'bootstrap' else 'resume_exit'] = code
                reap_children()
            except BaseException:
                diagnostics['cleanup_failure'] = 1
                result['success'] = False
        if ship_fd is not None:
            try:
                os.close(ship_fd)
            except BaseException:
                diagnostics['cleanup_failure'] = 1
                result['success'] = False
                if not diagnostics['failure']:
                    diagnostics['stage'] = diagnostics['failure'] = 7
    return result


def main():
    if len(sys.argv) != 2 or sys.argv[1] not in ('bootstrap', 'reopen'):
        return 64
    phase = sys.argv[1]
    def interrupted(signum, frame):
        raise InterruptedError()
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    result = run_phase(phase)
    # Explicit private test volume persists across container exit; tmpfs would not.
    path = f'/urbit/control/official-lifecycle-result-{phase}.json'
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as output:
        json.dump(result, output, sort_keys=True)
        output.flush()
        os.fsync(output.fileno())
    return 0 if result['success'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
