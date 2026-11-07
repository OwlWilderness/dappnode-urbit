"""Owned files and modeled launch only; never root delivery/native cessation proof."""
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parents[2] / 'tools/native-recovery/service'))
import native_file_channel as channel
import permanent_recovery as base
import trusted_admin_journal as journal
from test_resume import Transitions, OwnedFixturePermit


class Boundary(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve())
        self.addCleanup(self.tmp.cleanup)
        self.paths = {k: Path(self.tmp.name) / k for k in ('pier', 'uploads', 'control', 'evidence')}
        for p in self.paths.values():
            p.mkdir(mode=0o700)
        (self.paths['pier'] / 'ship/.urb').mkdir(parents=True, mode=0o700)
        self.payload = self.paths['pier'] / 'ship/.urb/fixture'
        self.payload.write_bytes(b'retained synthetic pier')
        self.before = self.payload.stat()
        self.runtime = b'{"state":"RUNNING"}'
        self.job = json.dumps(dict(id='a'*32, state='READY_LOCKED', offset=9,
                                  total_bytes=9, expanded_limit=4096, expanded_bytes=32, files=1)).encode()
        for name, raw in [('runtime.json', self.runtime), ('job.json', self.job), ('writer.lock', b'')]:
            p = self.paths['control'] / name
            p.write_bytes(raw)
            p.chmod(0o600)

    def test_repair_preserves_job_payload_and_refuses_replay(self):
        engine = Transitions(**self.paths)
        self.addCleanup(engine.close)
        engine._apply(OwnedFixturePermit(engine, 'repair'))
        self.assertIsNone(engine.manager, 'repair must not construct a runtime')
        self.assertEqual(engine.record['native_outcome'], 'COMPLETE')
        saved = self.paths['evidence'] / engine.record['evidence']
        self.assertEqual((saved / 'runtime.before').read_bytes(), self.runtime)
        self.assertEqual((saved / 'job.before').read_bytes(), self.job)
        self.assertEqual((self.paths['control'] / 'job.json').read_bytes(), self.job)
        self.assertEqual(self.payload.read_bytes(), b'retained synthetic pier')
        self.assertEqual(self.payload.stat(), self.before)
        with self.assertRaises(channel.Refused):
            engine._apply(OwnedFixturePermit(engine, 'repair'))

    def test_explicit_start_spends_durably_before_modeled_launch(self):
        engine = Transitions(**self.paths)
        self.addCleanup(engine.close)
        engine._apply(OwnedFixturePermit(engine, 'repair'))
        launches = []
        class ModeledRuntime:
            def __init__(self, *args, **kwargs):
                durable = json.loads((engine.paths['control'] / 'legacy-recovery-state.json').read_bytes())
                self_test.assertEqual(durable['state'], 'WRITER_ADMITTED')
                self_test.assertEqual(durable['native_outcome'], 'PENDING')
                launches.append('constructed')
            def start(self, *, confirmed_stopped):
                self_test.assertIs(confirmed_stopped, True)
                launches.append('started')
            def status(self):
                return {'runtime': {'state': 'RUNNING'}}
            def close(self):
                pass
        self_test = self
        with patch.object(base, 'ManagedImporter', ModeledRuntime):
            engine._apply(OwnedFixturePermit(engine, 'start'))
        self.assertEqual(launches, ['constructed', 'started'])
        self.assertEqual(engine.record['native_outcome'], 'COMPLETE')
        with self.assertRaises(channel.Refused):
            engine._apply(OwnedFixturePermit(engine, 'start'))

    def test_unsafe_command_path_and_symlink_refused(self):
        command = self.paths['control'] / 'native-command.json'
        command.write_bytes(b'{}')
        command.chmod(0o644)
        with self.assertRaises((channel.Refused, OSError)):
            channel.read_command(command)
        link = command.with_name('link.json')
        link.symlink_to(command)
        with self.assertRaises((channel.Refused, OSError)):
            channel.read_command(link)
        with self.assertRaises(channel.Refused):
            channel.read_command(Path('relative.json'))

    def test_root_reader_healthy_control_if_available(self):
        # Actual root-owned file metadata only: no fake stat, chown, sudo or UID override.
        choices = [Path('/usr/share/misc/ascii'), Path('/etc/os-release').resolve()]
        for path in choices:
            try:
                raw, token = channel.read_command(path)
            except (channel.Refused, OSError):
                continue
            self.assertEqual(raw, path.read_bytes())
            self.assertEqual(token[-1], base.digest(raw))
            return
        self.skipTest('No suitable small root-owned regular control file on this host')

    def test_native_admin_post_gap_is_fail_closed(self):
        class Request:
            path = '/api/start'
            def reply(self, code, value):
                self.reply_value = (code, value)
        for path in ['/api/start', '/api/stop', '/api/maintenance/recover']:
            request = Request()
            request.path = path
            channel.NativeOnlyHandler.do_POST(request)
            self.assertEqual(request.reply_value[0], 403)

    def test_malformed_job_and_duplicate_keys_preserve_original_runtime(self):
        class FixturePermit:
            def verify_delegation(self, *args):
                pass
        target = {k: self.paths[k] for k in ('pier', 'control', 'evidence')}
        for raw in [self.job.replace(b'READY_LOCKED', b'UPLOADING'), b'{"id":1,"id":2}']:
            p = self.paths['control'] / 'job.json'
            p.write_bytes(raw)
            with self.assertRaises(journal.RecoveryRefused):
                journal.recover(**target, permit=FixturePermit())
            self.assertEqual((self.paths['control'] / 'runtime.json').read_bytes(), self.runtime)
            self.assertEqual(self.payload.stat(), self.before)


if __name__ == '__main__':
    unittest.main(verbosity=2)
