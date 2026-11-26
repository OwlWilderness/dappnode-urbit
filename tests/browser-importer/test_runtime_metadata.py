"""Disposable metadata fault injection; Linux setup is not qualified on Darwin."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tools/browser-importer'))
import runtime
from importer import Importer

BOOT = '11111111-1111-4111-8111-111111111111'


class NativeNoDescendantSeam:
    def subreaper(self):
        return True  # Linux feature setup only is simulated; waitpid is real.

    def wait(self):
        return os.waitpid(-1, os.WNOHANG)


class MetadataTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(dir=os.environ['IMPORTER_TEST_SCRATCH'])
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.children = []
        self.boot = mock.patch.object(runtime, '_boot_id', return_value=BOOT)
        self.boot.start()
        self.addCleanup(self.boot.stop)
        self.adapter = runtime.OfficialRuntimeAdapter(scope=runtime.OwnedChildScope(NativeNoDescendantSeam()))
        self.adapter._launch_verified = self.launch
        self.engine = runtime.ManagedImporter(*(self.root / n for n in ('pier', 'uploads', 'control')),
                                               runtime_adapter=self.adapter, reserve_bytes=0)
        self.addCleanup(self.cleanup)
        job = self.engine.create(total_bytes=1, expanded_limit=1, stopped=True)
        self.engine.append(job['id'], 0, b'x')
        def extract(archive, stage, **kwargs):
            (stage / 'ship/.urb').mkdir(parents=True)
            return {'files': 0, 'expanded_bytes': 0}
        self.engine.validate(job['id'], extractor=extract)
        self.paths = [self.root / 'pier/.runtime-owner.json', self.root / 'control/runtime.json']

    def launch(self, ship, lock):
        child = subprocess.Popen([sys.executable, '-B', '-c', 'import time; time.sleep(30)'],
                                 pass_fds=(ship, lock))
        self.children.append(child)
        return child

    def cleanup(self):
        for child in self.children:
            if child.poll() is None:
                child.kill()
            child.wait(timeout=5)
        Importer.close(self.engine)

    def evidence(self):
        return [p.read_bytes() if p.exists() else None for p in self.paths]

    def test_initialized_start_refuses_loss_of_either_or_both_records(self):
        for missing, after_stop in ((missing, stopped) for missing in ((0,), (1,), (0, 1))
                                    for stopped in (False, True)):
            with self.subTest(missing=missing, after_stop=after_stop):
                # Each case owns a fresh, genuinely imported and initialized fixture.
                case = MetadataTests()
                self.addCleanup(case.doCleanups)
                case.setUp()
                if after_stop:
                    case.engine.start(confirmed_stopped=True)
                    case.engine.stop()
                launches = len(case.children)
                for index in missing:
                    case.paths[index].unlink()
                before = case.evidence()
                with self.assertRaises(runtime.ImportError):
                    case.engine.start(confirmed_stopped=True)
                self.assertEqual(case.evidence(), before)
                self.assertFalse(case.engine.status()['start_available'])
                self.assertEqual(len(case.children), launches)
                case.doCleanups()

    def test_launch_fault_preserves_foreign_evidence(self):
        before = []
        def uncertain_launch(ship, lock):
            self.launch(ship, lock)
            owner = json.loads(self.paths[0].read_text())
            owner['generation'] = 'f' * 32
            self.paths[0].write_text(json.dumps(owner))
            before.extend(self.evidence())
            raise OSError('injected uncertain launch with foreign metadata')
        self.adapter._launch_verified = uncertain_launch
        with self.assertRaises(runtime.ImportError):
            self.engine.start(confirmed_stopped=True)
        self.assertEqual(self.evidence(), before)
        self.assertFalse(self.engine.status()['start_available'])
        with self.assertRaises(runtime.ImportError):
            self.engine.start(confirmed_stopped=True)
        self.assertEqual(len(self.children), 1)

    def test_stop_preserves_missing_or_foreign_metadata_even_on_fault_paths(self):
        for index in (0, 1):
            for anomaly in ('missing', 'generation', 'state', 'storage', 'boot_id', 'malformed'):
                for fault in (False, True):
                    with self.subTest(index=index, anomaly=anomaly, fault=fault):
                        case = MetadataTests()
                        self.addCleanup(case.doCleanups)
                        case.setUp()
                        case.engine.start(confirmed_stopped=True)
                        path = case.paths[index]
                        if anomaly == 'missing':
                            path.unlink()  # disposable fixture only
                        elif anomaly == 'malformed':
                            path.write_bytes(b'{bad evidence')
                        else:
                            record = json.loads(path.read_text())
                            if anomaly == 'storage':
                                record['storage']['ship'][1] += 1
                            else:
                                record[anomaly] = {'generation': 'f' * 32, 'state': 'STOPPED',
                                                   'boot_id': '22222222-2222-4222-8222-222222222222'}[anomaly]
                            path.write_text(json.dumps(record))
                        before = case.evidence()
                        settled = case.adapter.scope_settled
                        def settlement(child):
                            self.assertTrue(settled(child))  # actual Popen reap + native ECHILD
                            if fault:
                                raise OSError('injected post-settlement failure')
                            return True
                        with mock.patch.object(case.adapter, 'scope_settled', side_effect=settlement):
                            for _ in range(2):
                                with self.assertRaises(runtime.ImportError):
                                    case.engine.stop()
                                self.assertEqual(case.evidence(), before)
                                self.assertFalse(case.engine.status()['start_available'])
                        with self.assertRaises(runtime.ImportError):
                            case.engine.start(confirmed_stopped=True)
                        self.assertEqual(len(case.children), 1)
                        self.assertEqual(case.evidence(), before)
                        case.doCleanups()

    def test_idempotent_stop_cannot_acknowledge_lost_ownership(self):
        self.engine.start(confirmed_stopped=True)
        self.engine.stop()
        self.paths[0].unlink()
        before = self.evidence()
        with self.assertRaises(runtime.ImportError):
            self.engine.stop()
        self.assertEqual(self.evidence(), before)
        self.assertFalse(self.engine.status()['start_available'])
        with self.assertRaises(runtime.ImportError):
            self.engine.start(confirmed_stopped=True)
        self.assertEqual(len(self.children), 1)

    def test_repeated_official_lifecycle_and_clean_reopen(self):
        for _ in range(3):
            self.engine.start(confirmed_stopped=True)
            self.engine.stop()
            self.engine.stop()
            self.assertTrue(self.engine.status()['start_available'])
            self.assertEqual(self.evidence()[0], self.evidence()[1])
        self.engine.close()
        self.engine = runtime.ManagedImporter(*(self.root / n for n in ('pier', 'uploads', 'control')),
                                               runtime_adapter=self.adapter)
        self.assertEqual(self.engine.runtime['state'], 'STOPPED')
        self.assertTrue(self.engine.status()['start_available'])
        self.assertEqual(len(self.children), 3)

    def test_same_generation_partial_stop_writes_retry_cleanly(self):
        for index in (0, 1):
            for after_write in (False, True):
                with self.subTest(index=index, after_write=after_write):
                    case = MetadataTests()
                    self.addCleanup(case.doCleanups)
                    case.setUp()
                    case.engine.start(confirmed_stopped=True)
                    write = case.engine._write_runtime
                    target = case.paths[index].name
                    def fail(directory, name):
                        if name != target or after_write:
                            write(directory, name)
                        if name == target:
                            raise OSError('injected paired write failure')
                    with mock.patch.object(case.engine, '_write_runtime', side_effect=fail):
                        with self.assertRaises(runtime.ImportError):
                            case.engine.stop()
                    self.assertFalse(case.engine.status()['start_available'])
                    case.engine.stop()
                    self.assertEqual(case.engine.runtime['state'], 'STOPPED')
                    self.assertEqual(case.evidence()[0], case.evidence()[1])
                    case.engine.start(confirmed_stopped=True)
                    case.engine.stop()
                    case.engine.close()
                    case.doCleanups()


if __name__ == '__main__':
    unittest.main()
