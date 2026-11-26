"""Production settlement algorithm, simulated kernel seam; Linux runs separate."""
import os
import hashlib
import fcntl
import tempfile
from pathlib import Path
import subprocess
import sys
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tools/browser-importer'))
import runtime


class ChildScopeTests(unittest.TestCase):
    def scope(self):
        kernel = mock.Mock()
        kernel.subreaper.return_value = True
        kernel.wait.side_effect = ChildProcessError
        scope = runtime.OwnedChildScope(kernel)
        return scope, kernel

    def test_official_settlement_requires_echild_after_owned_direct_child_reaped(self):
        scope, kernel = self.scope()
        adapter = runtime.OfficialRuntimeAdapter(scope=scope)
        child = mock.Mock(returncode=0)
        with mock.patch.object(adapter, '_launch_verified', return_value=child):
            self.assertIs(adapter.launch(10, lock_fd=11), child)
        self.assertTrue(adapter.scope_settled(child))
        kernel.wait.assert_called_once_with()
        self.assertTrue(adapter.scope_settled(child))  # retry of durable STOPPED write is safe

    def test_live_descendant_and_wrong_owner_never_settle(self):
        scope, kernel = self.scope()
        child = mock.Mock(returncode=0)
        scope.spawn(lambda: child)
        with mock.patch.object(runtime.time, 'monotonic', side_effect=[0, 0, 0, 2]), \
                mock.patch.object(runtime.time, 'sleep'):
            kernel.wait.side_effect = None
            kernel.wait.return_value = (0, 0)
            self.assertFalse(scope.settled(child, timeout=1))
        self.assertFalse(scope.settled(mock.Mock(), timeout=0))

    def test_reaps_adopted_exited_descendants_before_echild(self):
        scope, kernel = self.scope()
        child = mock.Mock(returncode=0)
        scope.spawn(lambda: child)
        kernel.wait.side_effect = [(123, 0), (124, 0), ChildProcessError()]
        self.assertTrue(scope.settled(child))
        self.assertEqual(kernel.wait.call_count, 3)

    def test_missing_subreaper_or_unreaped_leader_never_reaps(self):
        for valid, returncode in ((False, 0), (True, None)):
            scope, kernel = self.scope()
            child = mock.Mock(returncode=returncode)
            scope.spawn(lambda: child)
            kernel.subreaper.return_value = valid
            self.assertFalse(scope.settled(child))
            kernel.wait.assert_not_called()

    def test_spawn_is_exclusive_and_failed_spawn_cannot_be_reused(self):
        scope, kernel = self.scope()
        scope.spawn(lambda: mock.Mock())
        with self.assertRaises(ValueError):
            scope.spawn(lambda: self.fail('second spawn'))
        failed, _ = self.scope()
        with self.assertRaises(OSError):
            failed.spawn(mock.Mock(side_effect=OSError()))
        with self.assertRaises(ValueError):
            failed.spawn(lambda: self.fail('uncertain retry'))

    def test_audit_guard_allows_only_one_owned_popen_event_on_launch_thread(self):
        scope, kernel = self.scope()
        for event in ('subprocess.Popen', 'os.fork', 'os.forkpty', 'os.posix_spawn', 'os.system'):
            with self.subTest(event=event), self.assertRaises(RuntimeError):
                scope._audit(event, ())
        def launch():
            scope._audit('subprocess.Popen', ())
            with self.assertRaises(RuntimeError):
                scope._audit('subprocess.Popen', ())
            with self.assertRaises(RuntimeError):
                scope._audit('os.fork', ())
            return mock.Mock()
        scope.spawn(launch)
        with self.assertRaises(RuntimeError):
            scope._audit('subprocess.Popen', ())

    def test_production_factory_prepares_scope_before_constructing_engine(self):
        import managed_service
        events = []
        with mock.patch.object(managed_service.sys, 'platform', 'linux'), \
                mock.patch.object(managed_service.OwnedChildScope, 'prepare',
                                  side_effect=lambda: events.append('scope') or sentinel) as prepare, \
                mock.patch.object(managed_service, 'ManagedImporter',
                                  side_effect=lambda *a, **kw: events.append(kw['runtime_adapter'].scope)):
            sentinel = object()
            managed_service.production_engine('pier', 'uploads', 'control')
            prepare.assert_called_once_with()
        self.assertEqual(events, ['scope', sentinel])

    def test_verified_launch_inherits_actual_locked_pier_descriptor(self):
        # Exercise the actual verification/Popen wiring without executing Vere.
        with tempfile.TemporaryDirectory(dir=os.environ['IMPORTER_TEST_SCRATCH']) as directory:
            root = Path(directory)
            binary = root / 'synthetic-pin'
            binary.write_bytes(b'not executable runtime data')
            binary.chmod(0o700)
            (root / 'ship').mkdir()
            pier_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            fcntl.flock(pier_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            ship_fd = os.open(root / 'ship', os.O_RDONLY | os.O_DIRECTORY)
            real_open = os.open
            def open_pin(path, flags, **kwargs):
                return real_open(binary if path == '/bin/urbit' else path, flags, **kwargs)
            try:
                with mock.patch.object(runtime.os, 'open', side_effect=open_pin), \
                        mock.patch.object(runtime.sys, 'platform', 'linux'), \
                        mock.patch.object(runtime, 'OFFICIAL_SHA256', hashlib.sha256(binary.read_bytes()).hexdigest()), \
                        mock.patch.object(runtime.subprocess, 'Popen') as popen:
                    runtime.OfficialRuntimeAdapter()._launch_verified(ship_fd, pier_fd)
                    kwargs = popen.call_args.kwargs
                    self.assertIn(pier_fd, kwargs['pass_fds'])
                    self.assertIn(ship_fd, kwargs['pass_fds'])
                    self.assertTrue(kwargs['close_fds'])
                    self.assertFalse(kwargs['shell'])
            finally:
                os.close(ship_fd)
                os.close(pier_fd)

    def test_unprepared_official_adapter_cannot_spawn_or_certify(self):
        adapter = runtime.OfficialRuntimeAdapter()
        with mock.patch.object(adapter, '_launch_verified') as launch:
            with self.assertRaises(Exception):
                adapter.launch(10, lock_fd=11)
            launch.assert_not_called()
        self.assertFalse(adapter.scope_settled(mock.Mock(returncode=0)))


if __name__ == '__main__':
    unittest.main()
