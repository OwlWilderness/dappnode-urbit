"""One engine-free legacy regression. No live provider or real ship access."""
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import types
import unittest
from unittest import mock
import zipfile

REPO = Path(__file__).resolve().parents[2]
FIX = REPO / 'tools/browser-importer/legacy015_recovery.py'
SCRATCH = Path(os.environ.get('IMPORTER_TEST_SCRATCH', tempfile.gettempdir())).resolve()


def old_module(name):
    raw = subprocess.check_output(['git', 'show', 'c0cd9ae:tools/browser-importer/' + name + '.py'], cwd=REPO)
    if name == 'runtime':
        assert hashlib.sha256(raw).hexdigest() == '01e910b2eab56a2b2d2795b9a6872f70876bfc7f501482cf55daf5b2b60a6e93'
    mod = types.ModuleType(name)
    sys.modules[name] = mod
    exec(compile(raw, 'c0cd9ae/' + name + '.py', 'exec'), mod.__dict__)
    return mod


old_importer = old_module('importer')
old_archive = old_module('archive')
old_runtime = old_module('runtime')
repair = None
if FIX.exists():
    spec = importlib.util.spec_from_file_location('legacy015_recovery', FIX)
    assert spec is not None and spec.loader is not None
    repair = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(repair)


class HarmlessAdapter:
    def __init__(self):
        self.child = None
        self.calls = 0

    def launch(self, ship_fd):
        self.calls += 1
        self.child = subprocess.Popen([sys.executable, '-B', '-c', 'import time; time.sleep(60)'],
                                      stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                      stderr=subprocess.DEVNULL, close_fds=True)
        return self.child


class FixtureAuthority:
    """Trusted TEST seam only: owns this fresh fixture and every child handle.

    Never installed as a production provider. Does not establish Linux cgroup,
    Docker admission, or outside-writer exclusion.
    """
    def __init__(self, root, adapter):
        self.root, self.adapter = root, adapter
        self.held = False
        self.checks = 0

    @contextlib.contextmanager
    def exclude_and_settle(self, target):
        assert all(Path(p).is_relative_to(self.root) for p in target.values())
        assert self.adapter.child is None or self.adapter.child.poll() is not None
        self.held = True
        try:
            yield self
        finally:
            self.held = False

    def revalidate(self, bindings):
        assert self.held
        assert self.adapter.child is None or self.adapter.child.poll() is not None
        for name, (path, dev, ino) in bindings.items():
            st = os.stat(path, follow_symlinks=False)
            assert (st.st_dev, st.st_ino) == (dev, ino), name
        self.checks += 1


class LegacyRecovery(unittest.TestCase):
    def test_committed_legacy_recovery(self):
        with tempfile.TemporaryDirectory(prefix='legacy015-', dir=SCRATCH) as tmp:
            root = Path(tmp)
            os.chmod(root, 0o700)
            paths = {k: root / k for k in ('pier', 'uploads', 'control', 'evidence')}
            for p in paths.values():
                p.mkdir(mode=0o700)
            adapter = HarmlessAdapter()
            manager = old_runtime.ManagedImporter(paths['pier'], paths['uploads'], paths['control'],
                                                   runtime_adapter=adapter, reserve_bytes=0)
            # Commit through the ACTUAL old importer/extractor, not a hand-forged READY job.
            data = io.BytesIO()
            with zipfile.ZipFile(data, 'w') as z:
                z.writestr('ship/.urb/', '')
                z.writestr('ship/.urb/log', b'owned disposable payload')
            raw = data.getvalue()
            job = manager.create(total_bytes=len(raw), expanded_limit=4096, stopped=True)
            manager.append(job['id'], 0, raw)
            manager.validate(job['id'])
            self.assertEqual(manager.status()['state'], 'READY_LOCKED')
            manager.close()
            runtime_path = paths['control'] / 'runtime.json'
            original = b' { "state" : "RUNNING" }\n'
            runtime_path.write_bytes(original)
            runtime_path.chmod(0o600)
            job_path = paths['control'] / 'job.json'
            job_raw = job_path.read_bytes()
            payload = paths['pier'] / 'ship' / '.urb' / 'log'
            payload_raw = payload.read_bytes()
            payload_stat = payload.stat()
            manager = old_runtime.ManagedImporter(paths['pier'], paths['uploads'], paths['control'], runtime_adapter=adapter)
            self.assertEqual(manager.status()['runtime'], {'state': 'RECOVERY_REQUIRED'})
            self.assertEqual(manager.status()['state'], 'READY_LOCKED')
            with self.assertRaises(old_importer.ImportError):
                manager.start(confirmed_stopped=True)
            with self.assertRaises(old_importer.ImportError):
                manager.stop()
            self.assertEqual(adapter.calls, 0)
            # Fixture cleanup only: drop owned manager FDs without claiming process settlement.
            old_importer.Importer.close(manager)
            authority = FixtureAuthority(root, adapter)
            if repair is not None:
                repair.recover(paths['pier'], paths['control'], paths['evidence'], authority=authority)
            manager = old_runtime.ManagedImporter(paths['pier'], paths['uploads'], paths['control'], runtime_adapter=adapter)
            try:
                self.assertEqual(manager.status()['runtime'], {'state': 'STOPPED'},
                                 'old 0.1.5 reopens non-STOPPED intent as RECOVERY_REQUIRED; repair is absent')
                self.assertEqual(adapter.calls, 0, 'repair must not launch anything')
                self.assertEqual(manager.status()['state'], 'READY_LOCKED')
                with self.assertRaises(old_importer.ImportError):
                    manager.start()
                self.assertEqual(manager.start(confirmed_stopped=True)['runtime'], {'state': 'RUNNING'})
                self.assertEqual(adapter.calls, 1)
                assert adapter.child is not None
                self.assertIsNone(adapter.child.poll())
                manager.stop()
                self.assertIsNotNone(adapter.child.poll())
            finally:
                if adapter.child is not None and adapter.child.poll() is None:
                    adapter.child.kill()
                    adapter.child.wait()
                old_importer.Importer.close(manager)
            self.assertEqual(job_path.read_bytes(), job_raw)
            self.assertEqual(payload.read_bytes(), payload_raw)
            self.assertEqual(payload.stat(), payload_stat)
            self.assertEqual(list(paths['pier'].iterdir()), [paths['pier'] / 'ship'])
            self.assertEqual(list(paths['uploads'].iterdir()), [])
            backups = list(paths['evidence'].glob('*/runtime.before'))
            self.assertEqual(len(backups), 1)
            self.assertEqual(backups[0].read_bytes(), original)
            self.assertGreaterEqual(authority.checks, 2)
            # Essential failures: no authority, invalid runtime, uncertain import,
            # before-replace durability failure, and after-replace uncertainty.
            assert repair is not None
            def attempt(**kw):
                evidence = root / ('evidence-' + str(len(list(root.iterdir()))))
                evidence.mkdir(mode=0o700)
                return repair.recover(paths['pier'], paths['control'], evidence, **kw)
            runtime_path.write_bytes(original)
            with self.assertRaises(repair.RecoveryRefused):
                attempt(authority=None)
            self.assertEqual(runtime_path.read_bytes(), original)
            for bad in (b'{"state":"RUNNING","state":"RUNNING"}', b'{"version":3,"state":"RUNNING"}'):
                runtime_path.write_bytes(bad)
                with self.assertRaises(repair.RecoveryRefused):
                    attempt(authority=authority)
                self.assertEqual(runtime_path.read_bytes(), bad)
            runtime_path.write_bytes(original)
            uncertain = json.loads(job_raw)
            uncertain['state'] = 'COMMITTING'
            uncertain_raw = json.dumps(uncertain).encode()
            job_path.write_bytes(uncertain_raw)
            with self.assertRaises(repair.RecoveryRefused):
                attempt(authority=authority)
            self.assertEqual(job_path.read_bytes(), uncertain_raw)
            self.assertEqual(runtime_path.read_bytes(), original)
            job_path.write_bytes(job_raw)
            real_fsync = os.fsync
            def fail_file(fd):
                if not __import__('stat').S_ISDIR(os.fstat(fd).st_mode):
                    raise OSError('injected file durability failure')
                return real_fsync(fd)
            with mock.patch.object(repair.os, 'fsync', fail_file):
                with self.assertRaises(OSError):
                    attempt(authority=authority)
            self.assertEqual(runtime_path.read_bytes(), original)
            real_replace = os.replace
            def replace_then_fail(*a, **kw):
                real_replace(*a, **kw)
                raise OSError('injected lost rename acknowledgement')
            with mock.patch.object(repair.os, 'replace', replace_then_fail):
                with self.assertRaises(repair.RecoveryUncertain):
                    attempt(authority=authority)
            self.assertEqual(json.loads(runtime_path.read_bytes()), {'state': 'STOPPED'})
            self.assertTrue(any(p.read_bytes() == original for p in root.glob('evidence-*/*/runtime.before')))
            self.assertEqual(job_path.read_bytes(), job_raw)
            self.assertEqual(payload.read_bytes(), payload_raw)
            self.assertEqual(list(paths['pier'].iterdir()), [paths['pier'] / 'ship'])
            # Real rename + real fsync followed by failed durability acknowledgement.
            runtime_path.write_bytes(original)
            control_ino = paths['control'].stat().st_ino
            def fail_control_directory(fd):
                real_fsync(fd)
                if os.fstat(fd).st_ino == control_ino:
                    raise OSError('injected directory durability acknowledgement failure')
            with mock.patch.object(repair.os, 'fsync', fail_control_directory):
                with self.assertRaises(repair.RecoveryUncertain):
                    attempt(authority=authority)
            self.assertEqual(json.loads(runtime_path.read_bytes()), {'state': 'STOPPED'})
            self.assertEqual(job_path.read_bytes(), job_raw)
            self.assertEqual(payload.read_bytes(), payload_raw)
            for assertion in (True, {'stopped': True}):
                with self.assertRaises(repair.RecoveryRefused):
                    attempt(authority=assertion)


if __name__ == '__main__':
    unittest.main(verbosity=2)
