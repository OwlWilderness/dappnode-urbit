"""Synthetic storage only; boot changes are injected, not host reboot evidence."""
from contextlib import ExitStack
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import select
import signal
import subprocess
import time
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tools/browser-importer'))
import runtime
from importer import Importer

BOOT_A = '11111111-1111-4111-8111-111111111111'
BOOT_B = '22222222-2222-4222-8222-222222222222'


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=os.environ['IMPORTER_TEST_SCRATCH'])
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.adapter = mock.Mock()
        self.adapter.scope_settled.return_value = True  # trusted synthetic no-descendant adapter
        self.adapter.launch.return_value.poll.return_value = None
        self.engine = runtime.ManagedImporter(*(self.root / p for p in ('pier', 'uploads', 'control')),
                                               runtime_adapter=self.adapter)
        self.addCleanup(lambda: Importer.close(self.engine))
        (self.root / 'pier/ship/.urb').mkdir(parents=True)
        self.engine.job = {'id': 'a' * 32, 'state': 'READY_LOCKED', 'offset': 1,
                           'total_bytes': 1, 'expanded_limit': 1}
        self.engine._persist()

    def start(self):
        with mock.patch.object(runtime, '_boot_id', return_value=BOOT_A, create=True):
            return self.engine.start(confirmed_stopped=True)

    def reopen(self, boot):
        Importer.close(self.engine)  # simulated manager loss, no production process
        with mock.patch.object(runtime, '_boot_id', return_value=boot, create=True):
            self.engine = runtime.ManagedImporter(*(self.root / p for p in ('pier', 'uploads', 'control')),
                                                   runtime_adapter=self.adapter)
        return self.engine.status()

    def test_reopen_with_missing_pier_does_not_create_replacement(self):
        self.start()
        Importer.close(self.engine)
        (self.root / 'pier').rename(self.root / 'old-pier')
        with mock.patch.object(runtime, '_boot_id', return_value=BOOT_B, create=True):
            with self.assertRaises(runtime.ImportError):
                runtime.ManagedImporter(*(self.root / p for p in ('pier', 'uploads', 'control')))
        self.assertFalse((self.root / 'pier').exists())

    def test_stop_with_replaced_path_never_persists_stopped(self):
        self.start()
        (self.root / 'pier').rename(self.root / 'old-pier')
        (self.root / 'pier/ship/.urb').mkdir(parents=True)
        (self.root / 'pier').chmod(0o700)
        with self.assertRaises(runtime.ImportError):
            self.engine.stop()
        self.assertNotEqual(json.loads((self.root / 'control/runtime.json').read_text())['state'], 'STOPPED')

    def test_legacy_stopped_is_not_proof_of_descendant_settlement(self):
        journal = self.root / 'control/runtime.json'
        journal.write_text('{"state":"STOPPED"}')
        journal.chmod(0o600)
        self.assertEqual(self.reopen(BOOT_B)['runtime']['state'], 'RECOVERY_REQUIRED')
        self.assertEqual(journal.read_text(), '{"state":"STOPPED"}')

    def test_close_rejects_new_import_operations_before_draining(self):
        self.engine.begin_close()
        for name, args, kwargs in [('create', (), {'total_bytes': 1, 'expanded_limit': 1, 'stopped': True}),
                                   ('append', ('a' * 32, 0, b'x'), {}),
                                   ('verify', ('a' * 32, 0, b'x'), {}),
                                   ('cancel', ('a' * 32,), {}),
                                   ('begin_validate', ('a' * 32,), {})]:
            with self.subTest(operation=name), mock.patch.object(Importer, name, return_value='admitted') as call:
                with self.assertRaises(runtime.ImportError):
                    getattr(self.engine, name)(*args, **kwargs)
                call.assert_not_called()

    def test_server_exit_latches_admission_before_request_threads_drain(self):
        import server
        flags = []
        engine = self.engine
        class FakeServer:
            def serve_forever(inner):
                raise KeyboardInterrupt()
            def server_close(inner):
                flags.append(engine._closing)
        argv = ['server.py', '--pier-root', str(self.root / 'pier'), '--uploads-root', str(self.root / 'uploads'),
                '--control-root', str(self.root / 'control'), '--password-hash-file', str(self.root / 'synthetic-auth')]
        with mock.patch.object(sys, 'argv', argv), mock.patch.object(server, 'make_server', return_value=FakeServer()), \
                mock.patch.object(server, 'load_credential', return_value={}), mock.patch.object(server.signal, 'signal'):
            self.assertEqual(server.main(engine_class=lambda *a, **kw: self.engine), 0)
        self.assertEqual(flags, [True])

    def test_signal_shutdown_is_idempotent_and_closes_admission_before_server(self):
        import server
        handlers, interruptions, flags = {}, [], []
        stopped = threading.Event()
        class FakeServer:
            calls = 0
            def __init__(inner):
                inner.engine = self.engine
            def shutdown(inner):
                inner.calls += 1
                stopped.set()
            def serve_forever(inner):
                for number in (signal.SIGTERM, signal.SIGTERM, signal.SIGINT):
                    try:
                        handlers.get(number, handlers[signal.SIGTERM])(number, None)
                    except BaseException as error:
                        interruptions.append(type(error))
                    flags.append(self.engine._closing)
                stopped.wait(2)
            def server_close(inner):
                flags.append(self.engine._closing)
        fake = FakeServer()
        argv = ['server.py', '--pier-root', str(self.root / 'pier'), '--uploads-root', str(self.root / 'uploads'),
                '--control-root', str(self.root / 'control'), '--password-hash-file', str(self.root / 'synthetic-auth')]
        with mock.patch.object(sys, 'argv', argv), mock.patch.object(server, 'make_server', return_value=fake), \
                mock.patch.object(server, 'load_credential', return_value={}), \
                mock.patch.object(server.signal, 'signal', side_effect=lambda n, fn: handlers.__setitem__(n, fn)):
            result = server.main(engine_class=lambda *a, **kw: self.engine)
        self.assertEqual(interruptions, [])
        self.assertTrue(all(flags))
        self.assertEqual(fake.calls, 1)
        self.assertIn(signal.SIGINT, handlers)
        self.assertEqual(result, 0)

    def test_leader_exit_without_scope_proof_never_persists_stopped(self):
        self.start()
        self.adapter.scope_settled.return_value = False
        self.adapter.launch.return_value.poll.return_value = 0
        with self.assertRaises(runtime.ImportError):
            self.engine.stop()
        self.assertEqual(self.engine.runtime['state'], 'FAULT')
        saved = json.loads((self.root / 'control/runtime.json').read_text())
        self.assertNotEqual(saved['state'], 'STOPPED')
        with self.assertRaises(runtime.ImportError):
            self.engine.close()
        self.assertTrue(self.engine._closing)
        with self.assertRaises(runtime.ImportError):
            runtime.ManagedImporter(*(self.root / p for p in ('pier', 'uploads', 'control')))

    def test_repeated_close_keeps_admission_shut_after_uncertain_stop(self):
        self.start()
        self.adapter.launch.return_value.wait.side_effect = OSError('synthetic')
        for _ in range(2):
            with self.assertRaises(runtime.ImportError):
                self.engine.close()
            self.assertTrue(self.engine._closing)
            self.assertFalse(self.engine.status()['start_available'])

    def test_inspection_does_not_recreate_missing_root(self):
        (self.root / 'pier').rename(self.root / 'old-pier')
        with self.assertRaises(runtime.ImportError):
            self.engine._safe_ship()
        self.assertFalse((self.root / 'pier').exists())

    def test_real_service_repeated_signals_exit_without_boot_or_interrupted_cleanup(self):
        credential = self.root / 'synthetic-verifier.json'
        credential.write_text(json.dumps({'salt': '00' * 16, 'hash': '00' * 64}))
        credential.chmod(0o600)
        Importer.close(self.engine)
        module_file = runtime.__file__
        assert module_file is not None
        child = subprocess.Popen([sys.executable, '-B', str(Path(module_file).with_name('managed_service.py')),
                                  '--pier-root', str(self.root / 'service-pier'), '--uploads-root', str(self.root / 'service-uploads'),
                                  '--control-root', str(self.root / 'service-control'), '--password-hash-file', str(credential),
                                  '--port', '0'], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                 stderr=subprocess.PIPE,
                                 env={'PATH': os.defpath, 'PYTHONDONTWRITEBYTECODE': '1',
                                      'TMPDIR': os.environ['IMPORTER_TEST_SCRATCH']})
        try:
            assert child.stderr is not None
            readable, _, _ = select.select([child.stderr], [], [], 5)
            self.assertTrue(readable, 'service did not report startup')
            self.assertEqual(child.stderr.readline(), b'Private importer listening; no ship was automatically started.\n')
            for number in (signal.SIGTERM, signal.SIGTERM, signal.SIGINT):
                child.send_signal(number)
            _, error = child.communicate(timeout=5)
            self.assertEqual(child.returncode, 0, error)
            self.assertNotIn(b'Traceback', error)
            self.assertFalse((self.root / 'control/runtime.json').exists())
        finally:
            if child.poll() is None:
                child.kill()
            child.communicate(timeout=5)

    def test_running_service_repeated_signals_drain_official_scope_platform_seam(self):
        assert runtime.__file__ is not None
        tools = Path(runtime.__file__).parent
        fixture = self.root / 'running-service.py'
        fixture.write_text('''import os, pathlib, subprocess, sys
sys.path.insert(0, sys.argv[1])
import runtime, server
class NativeNoDescendantKernelSeam:
    def subreaper(self): return True  # simulated Linux feature on Darwin
    def wait(self): return os.waitpid(-1, os.WNOHANG)
def factory(*args, **kwargs):
    adapter = runtime.OfficialRuntimeAdapter(scope=runtime.OwnedChildScope(NativeNoDescendantKernelSeam()))
    def launch(ship_fd, lock_fd):
        return subprocess.Popen([sys.executable, '-B', '-c', 'import time; time.sleep(30)'],
                                pass_fds=(ship_fd, lock_fd))
    adapter._launch_verified = launch
    engine = runtime.ManagedImporter(*args, runtime_adapter=adapter, **kwargs)
    (engine.pier/'ship/.urb').mkdir(parents=True)
    engine.job = {'id':'a'*32,'state':'READY_LOCKED','offset':1,'total_bytes':1,'expanded_limit':1}
    engine._persist()
    runtime._boot_id = lambda: '11111111-1111-4111-8111-111111111111'
    engine.start(confirmed_stopped=True)
    return engine
sys.argv = sys.argv[2:]
raise SystemExit(server.main(engine_class=factory))
''')
        credential = self.root / 'seam-auth.json'
        credential.write_text(json.dumps({'salt': '00' * 16, 'hash': '00' * 64}))
        credential.chmod(0o600)
        command = [sys.executable, '-B', str(fixture), str(tools), 'service',
                   '--pier-root', str(self.root / 'seam-pier'), '--uploads-root', str(self.root / 'seam-uploads'),
                   '--control-root', str(self.root / 'seam-control'), '--password-hash-file', str(credential),
                   '--port', '0']
        child = subprocess.Popen(command, stderr=subprocess.PIPE, stdout=subprocess.DEVNULL,
                                 start_new_session=True,
                                 env={'PATH': os.defpath, 'PYTHONDONTWRITEBYTECODE': '1',
                                      'TMPDIR': os.environ['IMPORTER_TEST_SCRATCH']})
        try:
            assert child.stderr is not None
            self.assertTrue(select.select([child.stderr], [], [], 5)[0])
            self.assertEqual(child.stderr.readline(), b'Private importer listening; no ship was automatically started.\n')
            for number in (signal.SIGTERM, signal.SIGTERM, signal.SIGINT):
                child.send_signal(number)
            _, error = child.communicate(timeout=8)
            self.assertEqual(child.returncode, 0, error)
            control = json.loads((self.root / 'seam-control/runtime.json').read_text())
            pier = json.loads((self.root / 'seam-pier/.runtime-owner.json').read_text())
            self.assertEqual(control['state'], 'STOPPED')
            self.assertEqual(control, pier)
        finally:
            # Fixture-only cleanup of this isolated session if startup/drain fails.
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            child.communicate(timeout=5)

    def test_boot_reader_is_bounded_linux_only_and_fails_closed(self):
        with mock.patch.object(runtime.sys, 'platform', 'darwin'), mock.patch('builtins.open') as source:
            self.assertIsNone(runtime._boot_id())
            source.assert_not_called()
        for value in (BOOT_A + '\n', '', 'not-a-boot', BOOT_A + 'junk'):
            with self.subTest(value=value), mock.patch.object(runtime.sys, 'platform', 'linux'), \
                    mock.patch('builtins.open', mock.mock_open(read_data=value)) as source:
                self.assertEqual(runtime._boot_id(), BOOT_A if value == BOOT_A + '\n' else None)
                source().read.assert_called_once_with(38)
        with mock.patch.object(runtime.sys, 'platform', 'linux'), mock.patch('builtins.open', side_effect=OSError()):
            self.assertIsNone(runtime._boot_id())

    def test_malformed_version_two_evidence_is_never_reconciled(self):
        self.start()
        Importer.close(self.engine)
        journal = self.root / 'control/runtime.json'
        original = json.loads(journal.read_text())
        mutations = [('version', True), ('version', 4), ('generation', []), ('generation', 'x'),
                     ('boot_id', None), ('boot_id', 'bad'), ('storage', {}),
                     ('storage', dict(original['storage'], ship=[-1, 2])),
                     ('storage', dict(original['storage'], ship=[True, 2])),
                     ('state', 'STOPPING'), ('extra', 'unrecognized')]
        for key, value in mutations:
            raw = json.dumps(dict(original, **{key: value}))
            journal.write_text(raw)
            with self.subTest(field=key, value=value), mock.patch.object(runtime, '_boot_id', return_value=BOOT_B):
                with self.assertRaises(runtime.ImportError):
                    runtime.ManagedImporter(*(self.root / p for p in ('pier', 'uploads', 'control')))
                self.assertEqual(journal.read_text(), raw)

    def test_uncertain_launch_keeps_versioned_intent_and_blocks_same_boot(self):
        self.adapter.launch.side_effect = OSError('synthetic uncertain launch')
        with self.assertRaises(runtime.ImportError):
            self.start()
        self.assertEqual(self.engine.runtime['state'], 'FAULT')
        self.assertEqual(self.engine.runtime['boot_id'], BOOT_A)
        self.assertEqual(self.reopen(BOOT_A)['runtime']['state'], 'RECOVERY_REQUIRED')
        self.assertEqual(self.reopen(BOOT_B)['runtime']['state'], 'RECOVERY_REQUIRED')
        self.assertEqual(self.adapter.launch.call_count, 1)

    def test_same_or_unavailable_boot_never_clears_intent(self):
        self.start()
        journal = self.root / 'control/runtime.json'
        original = journal.read_bytes()
        for boot in (BOOT_A, None):
            with self.subTest(boot=boot):
                status = self.reopen(boot)
                self.assertEqual(status['runtime']['state'], 'RECOVERY_REQUIRED')
                self.assertFalse(status['start_available'])
                self.assertEqual(journal.read_bytes(), original)
                with self.assertRaises(runtime.ImportError):
                    self.engine.start(confirmed_stopped=True)
        self.assertEqual(self.adapter.launch.call_count, 1)

    def test_stopped_restart_is_idempotent_and_start_remains_explicit(self):
        self.start()
        self.engine.stop()
        original = (self.root / 'control/runtime.json').read_bytes()
        for _ in range(2):
            self.assertEqual(self.reopen(BOOT_A)['runtime']['state'], 'STOPPED')
            self.assertEqual((self.root / 'control/runtime.json').read_bytes(), original)
            with self.assertRaises(runtime.ImportError):
                self.engine.start()
        self.assertEqual(self.adapter.launch.call_count, 1)
        with mock.patch.object(runtime, '_boot_id', return_value=BOOT_A):
            self.engine.start(confirmed_stopped=True)
        self.assertEqual(self.adapter.launch.call_count, 2)

    def test_prior_boot_never_clears_import_recovery(self):
        self.start()
        self.engine.job['state'] = 'RECOVERY_REQUIRED'
        self.engine._persist()
        status = self.reopen(BOOT_B)
        self.assertEqual(status['state'], 'RECOVERY_REQUIRED')
        self.assertEqual(status['runtime']['state'], 'RECOVERY_REQUIRED')
        self.assertFalse(status['start_available'])

    def test_replaced_ship_or_storage_identity_is_not_reconciled(self):
        self.start()
        (self.root / 'pier/ship').rename(self.root / 'old-ship')
        (self.root / 'pier/ship/.urb').mkdir(parents=True)
        original = (self.root / 'control/runtime.json').read_bytes()
        self.assertEqual(self.reopen(BOOT_B)['runtime']['state'], 'RECOVERY_REQUIRED')
        self.assertEqual((self.root / 'control/runtime.json').read_bytes(), original)

    def test_legacy_active_intent_and_malformed_journals_are_never_cleared(self):
        journal = self.root / 'control/runtime.json'
        Importer.close(self.engine)
        for raw in ('{"state":"RUNNING"}', '{"state":"STARTING"}', '{"state":"FAULT"}',
                    '{"state":"RECOVERY_REQUIRED"}', '{"state":"STOPPED","state":"RUNNING"}',
                    '{"state":"RUNNING","version":3}', '[]', '{', '{"state":false}'):
            journal.write_text(raw)
            journal.chmod(0o600)
            with self.subTest(raw=raw), mock.patch.object(runtime, '_boot_id', return_value=BOOT_B):
                if raw in ('{"state":"RUNNING"}', '{"state":"STARTING"}', '{"state":"FAULT"}',
                           '{"state":"RECOVERY_REQUIRED"}'):
                    self.engine = runtime.ManagedImporter(*(self.root / p for p in ('pier', 'uploads', 'control')))
                    self.assertEqual(self.engine.runtime['state'], 'RECOVERY_REQUIRED')
                    Importer.close(self.engine)
                else:
                    with self.assertRaises(runtime.ImportError):
                        runtime.ManagedImporter(*(self.root / p for p in ('pier', 'uploads', 'control')))
                self.assertEqual(journal.read_text(), raw)
        self.adapter.launch.assert_not_called()

    def test_boot_unavailable_and_intent_write_or_fsync_failure_prevent_launch(self):
        # Each failure is before the spawn boundary; no guessed retry is admitted.
        for fault in ('boot', 'write', 'file-fsync', 'directory-fsync'):
            with self.subTest(fault=fault):
                self.engine.runtime = {'state': 'STOPPED'}
                journal = self.root / 'control/runtime.json'
                # Synthetic fixture reset only, never an operator recovery procedure.
                if journal.exists():
                    journal.unlink()
                real_fsync = os.fsync
                def sync(fd):
                    if fault == 'file-fsync' or fd == self.engine.control_fd:
                        raise OSError('synthetic fsync refusal')
                    return real_fsync(fd)
                with ExitStack() as stack:
                    stack.enter_context(mock.patch.object(runtime, '_boot_id', return_value=None if fault == 'boot' else BOOT_A))
                    if fault == 'write':
                        stack.enter_context(mock.patch.object(runtime.json, 'dump', side_effect=OSError('synthetic write refusal')))
                    elif 'fsync' in fault:
                        stack.enter_context(mock.patch.object(runtime.os, 'fsync', side_effect=sync))
                    with self.assertRaises(runtime.ImportError):
                        self.engine.start(confirmed_stopped=True)
                self.assertNotEqual(self.engine.runtime['state'], 'STOPPED')
                self.adapter.launch.assert_not_called()

    def test_reopen_never_writes_or_reconciles_prior_boot_intent(self):
        self.start()
        Importer.close(self.engine)
        with mock.patch.object(runtime, '_boot_id', return_value=BOOT_B), \
                mock.patch.object(runtime.os, 'fsync', side_effect=AssertionError('reopen must not write')):
            self.engine = runtime.ManagedImporter(*(self.root / p for p in ('pier', 'uploads', 'control')),
                                                   runtime_adapter=self.adapter)
        self.assertEqual(self.engine.runtime['state'], 'RECOVERY_REQUIRED')
        self.assertEqual(self.adapter.launch.call_count, 1)

    def test_start_persists_generation_boot_and_storage_before_spawn(self):
        def launch(fd):
            saved = json.loads((self.root / 'control/runtime.json').read_text())
            self.assertEqual(saved['state'], 'STARTING')
            self.assertEqual(saved['boot_id'], BOOT_A)
            self.assertEqual(saved['storage'], self.engine._storage_identity())
            self.assertRegex(saved['generation'], '^[a-f0-9]{32}$')
            self.assertEqual(os.listdir(fd), ['.urb'])
            return mock.Mock()
        self.adapter.launch.side_effect = launch
        self.start()

    def test_start_stop_close_concurrency_drains_owned_scope_once(self):
        entered, release = threading.Event(), threading.Event()
        errors = []
        child = self.adapter.launch.return_value
        def launch(_):
            entered.set()
            if not release.wait(5):
                raise TimeoutError()
            return child
        self.adapter.launch.side_effect = launch
        def run(fn):
            try:
                fn()
            except Exception as error:
                errors.append(error)
        with mock.patch.object(runtime, '_boot_id', return_value=BOOT_A):
            starter = threading.Thread(target=run, args=(lambda: self.engine.start(confirmed_stopped=True),))
            starter.start()
            self.assertTrue(entered.wait(5))
            closers = [threading.Thread(target=run, args=(self.engine.close,)) for _ in range(2)]
            for thread in closers:
                thread.start()
            deadline = time.monotonic() + 2
            while not self.engine._closing and time.monotonic() < deadline:
                time.sleep(.005)
            self.assertTrue(self.engine._closing)
            release.set()
            for thread in [starter] + closers:
                thread.join(5)
                self.assertFalse(thread.is_alive())
        self.assertEqual(errors, [])
        self.assertTrue(self.engine._closed)
        self.assertEqual(child.wait.call_count, 1)
        with self.assertRaises(runtime.ImportError):
            self.engine.start(confirmed_stopped=True)

    def _live_descendant(self, mode):
        script = self.root / 'synthetic-writer.py'
        script.write_text('''import os, signal, sys, time
from pathlib import Path
root, mode = Path(sys.argv[1]), sys.argv[2]
if mode == 'leader-ignore':
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
ready, finish, done, heartbeat = [root / p for p in ('ready', 'finish', 'done', 'heartbeat')]
def work():
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    if mode == 'session':
        os.setsid()
    if mode == 'fds':
        os.closerange(3, 1024)
    if mode == 'exec' and len(sys.argv) == 3:
        os.execv(sys.executable, [sys.executable, __file__, str(root), mode, 'worker'])
    pending = ready.with_suffix('.pending')
    pending.write_text(str(os.getpid()))
    pending.replace(ready)
    while not finish.exists():
        with heartbeat.open('ab') as output:
            output.write(b'x')
        time.sleep(.01)
    done.write_text('done')
if len(sys.argv) == 4:
    work()
elif os.fork() == 0:
    work()
else:
    end = time.monotonic() + 5
    while not ready.exists() and time.monotonic() < end:
        time.sleep(.01)
    if mode == 'leader-ignore':
        while not finish.exists():
            time.sleep(.01)
''')
        children = []
        def cleanup():
            (self.root / 'finish').touch()
            end = time.monotonic() + 5
            while not (self.root / 'done').exists() and time.monotonic() < end:
                time.sleep(.01)
            if not (self.root / 'done').exists() and (self.root / 'ready').exists():
                os.kill(int((self.root / 'ready').read_text()), signal.SIGKILL)
            for child in children:
                if child.poll() is None:
                    child.kill()
                child.wait(timeout=5)
        self.addCleanup(cleanup)
        def launch(ship_fd):
            child = subprocess.Popen([sys.executable, str(script), str(self.root), mode],
                                     pass_fds=(ship_fd,), stdin=subprocess.DEVNULL,
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            children.append(child)
            if mode == 'leader-ignore':
                # Test-only short wait budget exercises real TERM->KILL escalation
                # without changing production's 120-second graceful timeout.
                wait = child.wait
                child.wait = lambda timeout=None: wait(timeout=min(timeout or 5, .2))
            return child
        self.adapter.launch.side_effect = launch
        self.adapter.scope_settled.side_effect = runtime.OfficialRuntimeAdapter().scope_settled
        self.start()
        if mode == 'leader-ignore':
            end = time.monotonic() + 5
            while not (self.root / 'ready').exists() and time.monotonic() < end:
                time.sleep(.01)
            self.assertIsNone(children[0].poll())
        else:
            children[0].wait(timeout=5)
            self.assertEqual(children[0].returncode, 0)
        pid = int((self.root / 'ready').read_text())
        os.kill(pid, signal.SIGTERM)  # owned synthetic descendant deliberately ignores TERM
        with self.assertRaises(runtime.ImportError):
            self.engine.stop()
        if mode == 'leader-ignore':
            self.assertEqual(children[0].returncode, -signal.SIGKILL)
        self.assertNotEqual(json.loads((self.root / 'control/runtime.json').read_text())['state'], 'STOPPED')
        # Loss of manager locks is not proof of absence: the descendant still writes.
        self.assertEqual(self.reopen(BOOT_A)['runtime']['state'], 'RECOVERY_REQUIRED')
        with self.assertRaises(runtime.ImportError):
            self.engine.start(confirmed_stopped=True)
        before = (self.root / 'heartbeat').read_text()
        end = time.monotonic() + 2
        while (self.root / 'heartbeat').read_text() == before and time.monotonic() < end:
            time.sleep(.02)
        self.assertNotEqual((self.root / 'heartbeat').read_text(), before)

    def test_killing_term_ignoring_leader_does_not_settle_descendant(self):
        self._live_descendant('leader-ignore')

    def test_live_fork_descendant_refuses_same_boot_recovery(self):
        self._live_descendant('fork')

    def test_live_exec_descendant_refuses_same_boot_recovery(self):
        self._live_descendant('exec')

    def test_live_fd_closing_descendant_refuses_same_boot_recovery(self):
        self._live_descendant('fds')

    def test_live_session_changing_descendant_refuses_same_boot_recovery(self):
        self._live_descendant('session')

    def test_prior_boot_intent_is_not_positive_scope_proof(self):
        self.start()
        journal = self.root / 'control/runtime.json'
        original = journal.read_bytes()
        status = self.reopen(BOOT_B)
        self.assertEqual(status['runtime']['state'], 'RECOVERY_REQUIRED')
        self.assertFalse(status['start_available'])
        with self.assertRaises(runtime.ImportError):
            self.engine.start(confirmed_stopped=True)
        self.assertEqual(self.adapter.launch.call_count, 1)
        self.assertEqual(journal.read_bytes(), original)

    def test_replayed_prior_boot_intent_with_live_current_writer_is_refused(self):
        children = []
        def launch(fd):
            child = subprocess.Popen([sys.executable, '-B', '-c', 'import time; time.sleep(30)'])
            children.append(child)
            return child
        def cleanup():
            for child in children:
                if child.poll() is None:
                    child.kill()
                child.wait(timeout=5)
        self.addCleanup(cleanup)
        self.adapter.launch.side_effect = launch
        self.start()
        old_intent = (self.root / 'control/runtime.json').read_bytes()
        self.engine.stop()
        with mock.patch.object(runtime, '_boot_id', return_value=BOOT_B):
            self.engine.start(confirmed_stopped=True)
        writer = self.engine.child
        Importer.close(self.engine)
        (self.root / 'control/runtime.json').write_bytes(old_intent)  # fixture-only replay
        with mock.patch.object(runtime, '_boot_id', return_value=BOOT_B):
            self.engine = runtime.ManagedImporter(*(self.root / p for p in ('pier', 'uploads', 'control')),
                                                  runtime_adapter=self.adapter)
        self.assertEqual(self.engine.runtime['state'], 'RECOVERY_REQUIRED')
        self.assertFalse(self.engine.status()['start_available'])
        with self.assertRaises(runtime.ImportError):
            self.engine.start(confirmed_stopped=True)
        self.assertIsNone(writer.poll())
        self.assertEqual(len(children), 2)

    def test_official_adapter_happy_stop_start_close_reopen_via_kernel_seam(self):
        kernel = mock.Mock()
        kernel.subreaper.return_value = True
        kernel.wait.side_effect = ChildProcessError
        adapter = runtime.OfficialRuntimeAdapter(scope=runtime.OwnedChildScope(kernel))
        children = []
        def launch(ship_fd, lock_fd):
            self.assertEqual(os.fstat(lock_fd).st_ino, os.fstat(self.engine.pier_fd).st_ino)
            child = subprocess.Popen([sys.executable, '-B', '-c', 'import time; time.sleep(30)'],
                                     pass_fds=(ship_fd, lock_fd))
            children.append(child)
            return child
        def cleanup():
            for child in children:
                if child.poll() is None:
                    child.kill()
                child.wait(timeout=5)
        self.addCleanup(cleanup)
        self.engine.runtime_adapter = adapter
        with mock.patch.object(adapter, '_launch_verified', side_effect=launch):
            self.start()
            self.engine.stop()
            self.assertEqual(self.engine.runtime['state'], 'STOPPED')
            self.assertTrue(self.engine.status()['start_available'])
            self.start()
            self.engine.close()
        self.assertEqual(len(children), 2)
        self.assertTrue(all(child.returncode is not None for child in children))
        self.assertEqual(self.reopen(BOOT_B)['runtime']['state'], 'STOPPED')
        self.assertEqual(adapter.scope.kernel.wait.call_count, 2)

    def test_fresh_import_without_first_start_reopens_cleanly(self):
        roots = [self.root / ('new-' + p) for p in ('pier', 'uploads', 'control')]
        engine = runtime.ManagedImporter(*roots, runtime_adapter=self.adapter, reserve_bytes=0)
        self.addCleanup(lambda: Importer.close(engine))
        job = engine.create(total_bytes=1, expanded_limit=1, stopped=True)
        engine.append(job['id'], 0, b'x')
        def extract(archive, stage, **kwargs):
            (stage / 'ship/.urb').mkdir(parents=True)
            return {'expanded_bytes': 0, 'files': 0}
        engine.validate(job['id'], extractor=extract)
        engine.close()
        engine = runtime.ManagedImporter(*roots, runtime_adapter=self.adapter)
        self.assertEqual(engine.runtime['state'], 'STOPPED')
        self.assertTrue(engine.status()['start_available'])
        self.adapter.launch.assert_not_called()

    def test_ready_legacy_pier_without_runtime_ownership_is_not_fresh(self):
        # Saved imported pier may predate pier-bound intent. Absence of a
        # selected control journal is not proof that no old writer exists.
        Importer.close(self.engine)
        self.engine = runtime.ManagedImporter(*(self.root / p for p in ('pier', 'uploads', 'control')),
                                              runtime_adapter=self.adapter)
        self.assertEqual(self.engine.runtime['state'], 'RECOVERY_REQUIRED')
        self.assertFalse(self.engine.status()['start_available'])

    def test_manager_loss_alternate_control_without_journal_refuses_live_writer(self):
        child = subprocess.Popen([sys.executable, '-B', '-c', 'import time; time.sleep(30)'])
        self.addCleanup(lambda: (child.kill() if child.poll() is None else None, child.wait(timeout=5)))
        self.adapter.launch.return_value = child
        self.start()
        job = dict(self.engine.job)
        Importer.close(self.engine)  # synthetic manager loss; writer has closed all borrowed FDs
        other = self.root / 'other-control'
        other.mkdir(mode=0o700)
        (other / 'job.json').write_text(json.dumps(job))
        (other / 'job.json').chmod(0o600)
        self.engine = runtime.ManagedImporter(self.root / 'pier', self.root / 'uploads', other,
                                              runtime_adapter=self.adapter)
        self.assertFalse(self.engine.status()['start_available'])
        with self.assertRaises(runtime.ImportError):
            self.engine.start(confirmed_stopped=True)
        self.assertIsNone(child.poll())
        self.assertEqual(self.adapter.launch.call_count, 1)


if __name__ == '__main__':
    unittest.main()
