#!/usr/bin/env python3
"""In-image test code only. Never opens keys, auth records or pier payloads."""
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import threading
import unittest

ROOT = Path('/urbit')


class NotReady(Exception):
    """Only a known initialization condition may be retried."""


def require(condition):
    if not condition:
        raise ValueError('check refused')


def digest(path):
    with open(path, 'rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()


def snapshot():
    # Only known synthetic directories; never recurse into a pier.
    result = []
    names = sorted(os.listdir(ROOT))
    require(set(names) <= {'pier', 'uploads', 'control', 'synthetic-marker', 'synthetic-ship'})
    paths = [ROOT] + [ROOT / name for name in names]
    if 'synthetic-ship' in names:
        paths.append(ROOT / 'synthetic-ship' / '.urb')
    for path in paths:
        info = path.lstat()
        require(stat.S_ISDIR(info.st_mode))
        result.append([str(path.relative_to(ROOT)), info.st_ino, info.st_mode,
                       info.st_uid, info.st_gid, info.st_mtime_ns])
    return {'metadata_sha256': hashlib.sha256(json.dumps(result).encode()).hexdigest()}


def setup(kind):
    require(set(os.listdir(ROOT)) == {'pier', 'uploads', 'control'})
    for name in ('pier', 'uploads', 'control'):
        require(not os.listdir(ROOT / name))
    if kind == 'empty':
        # Docker copies the image's owned skeleton into this fresh named volume.
        # Remove ONLY its three proven-empty directories to exercise empty startup.
        for name in ('pier', 'uploads', 'control'):
            (ROOT / name).rmdir()
    elif kind == 'legacy':
        (ROOT / 'pier').rename(ROOT / 'synthetic-ship')
        (ROOT / 'synthetic-ship' / '.urb').mkdir(mode=0o700)
    elif kind == 'unknown':
        (ROOT / 'synthetic-marker').mkdir(mode=0o700)
    else:
        raise ValueError('unknown setup')
    return snapshot()


def unit():
    # Adapt ONLY the test loader: the module under test remains image-copied.
    spec = importlib.util.spec_from_file_location('guard_tests', '/tests/test_volume_guard.py')
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    def copied_guard(self):
        spec = importlib.util.spec_from_file_location('volume_guard', '/opt/importer/volume_guard.py')
        assert spec is not None and spec.loader is not None
        guard = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(guard)
        return guard

    module.VolumeGuardTests.load_guard = copied_guard
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        result = unittest.TestResult()
        unittest.defaultTestLoader.loadTestsFromTestCase(module.VolumeGuardTests).run(result)
    require(result.wasSuccessful() and result.testsRun == 4)
    return {'tests': result.testsRun, 'guard_sha256': digest('/opt/importer/volume_guard.py'),
            'vere_sha256': digest('/bin/urbit')}


def quiet_processes():
    # No cmdline/environ reads: enumerate process executable metadata only.
    # Unknown or vanished processes are uncertainty, never a passing sample.
    pids = {int(p.name) for p in Path('/proc').iterdir() if p.name.isdigit()}
    require({1, os.getpid()} <= pids)
    busy = False
    for pid in pids:
        executable = os.readlink(f'/proc/{pid}/exe')
        # Desktop may expose the translator instead of the guest executable.
        # Use only bounded public process names, never cmdline or environment.
        name = Path(f'/proc/{pid}/comm').read_text().strip()
        if pid in {1, os.getpid()}:
            require(name == 'python3' and (Path(executable).name.startswith('python3') or
                                          executable == '/rosetta/rosetta'))
        else:
            # Creation/revalidation launches OpenSSL briefly. Never accept that
            # as a quiet sample, and never retry a different/vanished process.
            require(name == 'openssl' and executable in ('/usr/bin/openssl', '/rosetta/rosetta'))
            busy = True
    for name in ('tcp', 'tcp6', 'udp', 'udp6'):
        lines = Path('/proc/net/' + name).read_text().splitlines()
        require(len(lines) == 1)  # Stronger than absence of listening TCP sockets.
    if busy:
        raise NotReady()


def pending():
    quiet_processes()
    require(set(os.listdir(ROOT)) == {'pier', 'uploads', 'control'})
    require(not os.listdir(ROOT / 'pier') and not os.listdir(ROOT / 'uploads'))
    control = ROOT / 'control'
    expected = {'package-service.lock', '.owner-tls.lock', 'owner-tls', 'owner-tls-public'}
    names = set(os.listdir(control))
    require(names <= expected | {'.owner-tls-init'})
    if names != expected:
        raise NotReady()
    public = control / 'owner-tls-public'
    names = set(os.listdir(public))
    require(names <= {'request.pem'})
    if not names:
        raise NotReady()
    path = public / 'request.pem'
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as source:
        info = os.fstat(source.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and
                info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o444 and
                0 < info.st_size <= 65536)
        csr = source.read(65537)
        require(len(csr) == info.st_size)
    env = {'PATH': '/usr/bin:/bin', 'OPENSSL_CONF': '/dev/null', 'LC_ALL': 'C'}
    verified = subprocess.run(['openssl', 'req', '-verify', '-noout'], input=csr,
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                              env=env, timeout=10)
    require(verified.returncode == 0)
    der = subprocess.run(['openssl', 'req', '-outform', 'DER'], input=csr,
                         stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=env, timeout=10)
    require(der.returncode == 0 and 0 < len(der.stdout) <= 65536)
    quiet_processes()
    return {'state': 'pending', 'csr_sha256': hashlib.sha256(der.stdout).hexdigest(),
            'no_listener': True, 'no_ship': True}


def main():
    try:
        action = sys.argv[1]
        if action == 'hold':
            stop = threading.Event()
            signal.signal(signal.SIGTERM, lambda *_: stop.set())
            signal.signal(signal.SIGINT, lambda *_: stop.set())
            stop.wait(600)
            return 0
        if action == 'setup':
            result = setup(sys.argv[2])
        elif action == 'snapshot':
            result = snapshot()
        elif action == 'unit':
            result = unit()
        elif action == 'pending':
            result = pending()
        else:
            raise ValueError('unknown action')
        print(json.dumps(result, sort_keys=True))
        return 0
    except NotReady:
        print('{"state":"not-ready"}')
        return 0
    except Exception:
        # Fatal uncertainty is distinct from a recognized initialization phase.
        print('{"state":"refused"}')
        return 0


if __name__ == '__main__':
    sys.exit(main())
