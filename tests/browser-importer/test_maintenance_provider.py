"""Engine-free real storage tests; Docker calls are an explicit model seam."""
import importlib.util
import json
import os
from pathlib import Path
import sys
import subprocess
import tempfile
import unittest
from unittest import mock

TOOLS = Path(__file__).resolve().parents[2] / 'tools/browser-importer'
sys.path.insert(0, str(TOOLS))


class ProviderTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=os.environ['IMPORTER_TEST_SCRATCH'])
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.storage = self.root / 'storage'
        self.storage.mkdir(mode=0o700)
        for name in ('pier', 'uploads', 'control'):
            (self.storage / name).mkdir(mode=0o700)
        self.authority = self.root / 'authority'
        self.docker = mock.Mock()
        self.cid = 'a' * 64
        self.info = {'id': self.cid, 'status': 'created', 'running': False,
                     'started': '0001-01-01T00:00:00Z', 'user': '10000:10000',
                     'privileged': False, 'pid_mode': '', 'userns': '', 'restart': 'no',
                     'caps_add': [], 'caps_drop': ['ALL'], 'security': ['no-new-privileges'],
                     'devices': [], 'mounts': [{'Type': 'bind', 'Source': str(self.storage),
                                               'Destination': '/urbit', 'RW': True}],
                     'readonly': False}
        self.docker.inspect.return_value = self.info
        self.docker.consumers.return_value = [self.cid]

    def provider(self):
        import maintenance_provider as provider
        instance = provider.Provider(self.authority, self.storage, docker=self.docker,
                                     owner_uid=os.geteuid())
        # Explicit Darwin/unprivileged platform seam; real root Linux Docker
        # namespace behavior belongs to the separate disposable qualification.
        instance._require_host = lambda: None
        return instance

    def test_enroll_requires_virgin_storage_and_never_started_scope(self):
        import maintenance_provider as provider
        (self.storage / 'control/runtime.json').write_text('{"state":"RUNNING"}')
        with self.assertRaisesRegex(provider.Blocked, 'PRIOR_SCOPE_UNPROVABLE'):
            with self.provider() as authority:
                authority.enroll(self.cid)
        self.docker.start.assert_not_called()

    def admitted_import(self, authority):
        import io
        import zipfile
        from importer import Importer
        authority.enroll(self.cid)
        authority.run()
        payload = io.BytesIO()
        with zipfile.ZipFile(payload, 'w') as archive:
            archive.writestr('zod/.urb/checkpoint', b'disposable import identity')
        raw = payload.getvalue()
        with Importer(*(self.storage / x for x in ('pier', 'uploads', 'control')), reserve_bytes=0) as engine:
            job = engine.create(total_bytes=len(raw), expanded_limit=4096, stopped=True)
            engine.append(job['id'], 0, raw)
            engine.validate(job['id'])
        self.info.update(status='exited', started='2026-11-03T00:00:00Z')
        def remove(cid):
            self.docker.inspect.return_value = None
            self.docker.consumers.return_value = []
        self.docker.remove.side_effect = remove
        return (self.storage / 'control/job.json').read_bytes()

    def test_live_provider_recovers_real_committed_legacy_import_without_start(self):
        import maintenance_provider as provider
        with self.provider() as authority:
            job_raw = self.admitted_import(authority)
            original = b'{"state": "RUNNING"}\n'
            journal = self.storage / 'control/runtime.json'
            journal.write_bytes(original)
            journal.chmod(0o600)
            start_count = self.docker.start.call_count
            result = authority.recover()
            self.assertEqual(result['state'], 'STOPPED')
            self.assertEqual(self.docker.start.call_count, start_count)
            self.assertEqual((self.storage / 'control/job.json').read_bytes(), job_raw)
            self.assertEqual(json.loads(journal.read_bytes()),
                             json.loads((self.storage / 'pier/.runtime-owner.json').read_bytes()))
            self.assertEqual(result['storage']['pier'], authority.state['layout']['pier'])
            self.assertEqual(authority.state['phase'], 'RECOVERED')
            evidence = provider.decode(provider.read_raw(authority.directory,
                                       authority.state['transaction'] + '.json', uid=os.geteuid()))
            self.assertEqual(bytes.fromhex(evidence['originals'][1]), original)

    def test_completed_slot_cannot_regress_to_missing_original(self):
        import maintenance_provider as provider
        with self.provider() as authority:
            self.admitted_import(authority)
            authority.recover()
            owner = self.storage / 'pier/.runtime-owner.json'
            owner.unlink()  # fixture-only loss of an established, committed slot
            with self.assertRaisesRegex(provider.Blocked, 'PRIOR_SCOPE_UNPROVABLE'):
                authority.recover()
            self.assertFalse(owner.exists())

    def test_managed_reopen_preflights_before_interrupted_upload_mutation(self):
        from importer import Importer
        import runtime
        engine = Importer(*(self.storage / x for x in ('pier', 'uploads', 'control')), reserve_bytes=0)
        job = engine.create(total_bytes=100, expanded_limit=100, stopped=True)
        engine.append(job['id'], 0, b'ack')
        engine.close()
        archive = self.storage / 'uploads' / (job['id'] + '.zip')
        with archive.open('ab') as target:
            target.write(b'unacknowledged durable original')
        runtime_journal = self.storage / 'control/runtime.json'
        runtime_journal.write_text('{"state":"RUNNING"}')
        runtime_journal.chmod(0o600)
        original = archive.read_bytes()
        try:
            with self.assertRaises(runtime.ImportError):
                instance = runtime.ManagedImporter(*(self.storage / x for x in ('pier', 'uploads', 'control')))
                self.addCleanup(lambda: Importer.close(instance))
        finally:
            self.assertEqual(archive.read_bytes(), original)

    def test_successor_handoff_holds_same_lease_and_never_admits_running_successor(self):
        import maintenance_provider as provider
        with self.provider() as authority:
            self.admitted_import(authority)
            prior_info = dict(self.info)
            successor = 'b' * 64
            successor_info = dict(self.info, id=successor, status='created', running=False,
                                  started='0001-01-01T00:00:00Z')
            scopes = {self.cid: prior_info, successor: successor_info}
            self.docker.inspect.side_effect = lambda cid: scopes.get(cid)
            self.docker.consumers.side_effect = lambda storage: list(scopes)
            self.docker.remove.side_effect = lambda cid: scopes.pop(cid)
            authority.recover(successor=successor)
            self.assertEqual(authority.state['phase'], 'RECOVERED')
            with self.assertRaises((provider.Blocked, BlockingIOError)):
                with self.provider():
                    self.fail('second authority acquired admission during handoff')
            authority.enroll(successor)
            authority.run()
            self.assertEqual(authority.state['container'], successor)
            self.assertEqual(self.docker.start.call_args.args, (successor,))

    def test_owner_file_fsync_fault_is_retryable_without_deleting_evidence(self):
        import maintenance
        import maintenance_provider as provider
        real_atomic = maintenance.atomic
        with self.provider() as authority:
            self.admitted_import(authority)
            def fail_owner(directory, name, raw, **kwargs):
                if name == '.runtime-owner.json':
                    with mock.patch.object(provider.os, 'fsync', side_effect=OSError('injected durability fault')):
                        return real_atomic(directory, name, raw, **kwargs)
                return real_atomic(directory, name, raw, **kwargs)
            with mock.patch.object(maintenance, 'atomic', side_effect=fail_owner):
                with self.assertRaisesRegex(provider.Blocked, 'RECOVERY_WRITE_UNCERTAIN'):
                    authority.recover()
            self.assertEqual(authority.recover()['state'], 'STOPPED')

    def test_provider_requires_root_linux_host_even_for_imported_api(self):
        import maintenance_provider as provider
        with mock.patch.object(provider.sys, 'platform', 'darwin'):
            with self.assertRaisesRegex(provider.Blocked, 'PRIOR_SCOPE_UNPROVABLE'):
                with provider.Provider(self.authority, self.storage, docker=self.docker,
                                       owner_uid=os.geteuid()):
                    self.fail('unprivileged provider admission escaped CLI guard')
        self.assertFalse(self.authority.exists())

    def test_recovery_rejects_unregistered_history_without_constructor_or_writes(self):
        import maintenance_provider as provider
        from importer import Importer
        (self.storage / 'control/job.json').write_text('{"state":"COMMITTING"}')
        before = (self.storage / 'control/job.json').read_bytes()
        with self.provider() as authority, mock.patch.object(Importer, '__init__', side_effect=AssertionError('constructor')):
            with self.assertRaisesRegex(provider.Blocked, 'PRIOR_SCOPE_UNPROVABLE'):
                authority.recover()
        self.assertEqual((self.storage / 'control/job.json').read_bytes(), before)
        self.docker.stop.assert_not_called()

    def test_active_or_foreign_consumers_refuse_before_metadata_write(self):
        import maintenance_provider as provider
        with self.provider() as authority:
            self.admitted_import(authority)
            self.docker.consumers.return_value = [self.cid, 'b' * 64]
            with self.assertRaisesRegex(provider.Blocked, 'PRIOR_SCOPE_UNPROVABLE'):
                authority.recover()
            self.docker.stop.assert_not_called()
            self.assertFalse((self.storage / 'pier/.runtime-owner.json').exists())

    def test_stop_ack_without_namespace_exit_never_grants_admission(self):
        import maintenance_provider as provider
        with self.provider() as authority:
            self.admitted_import(authority)
            self.info.update(status='running', running=True)
            with self.assertRaisesRegex(provider.Blocked, 'PRIOR_SCOPE_UNPROVABLE'):
                authority.recover()
            self.docker.remove.assert_not_called()
            self.assertEqual(authority.state['phase'], 'ACTIVE')

    def test_missing_active_container_is_not_positive_cessation(self):
        import maintenance_provider as provider
        with self.provider() as authority:
            self.admitted_import(authority)
            self.docker.inspect.return_value = None
            self.docker.consumers.return_value = []
            with self.assertRaisesRegex(provider.Blocked, 'PRIOR_SCOPE_UNPROVABLE'):
                authority.recover()
            self.assertEqual(authority.state['phase'], 'ACTIVE')

    def test_caller_receipt_or_expired_live_capability_is_not_authority(self):
        import maintenance
        import maintenance_provider as provider
        with self.assertRaisesRegex(provider.Blocked, 'PRIOR_SCOPE_UNPROVABLE'):
            maintenance.recover_stopped(self.storage, {'confirmed_stopped': True, 'signed': True})
        with self.provider() as authority:
            self.admitted_import(authority)
            admission = authority.contain()
        with self.assertRaisesRegex(provider.Blocked, 'PRIOR_SCOPE_UNPROVABLE'):
            maintenance.recover_stopped(self.storage, admission)
        self.assertFalse((self.storage / 'pier/.runtime-owner.json').exists())

    def test_exact_storage_replacement_and_foreign_capability_are_refused(self):
        import maintenance
        import maintenance_provider as provider
        with self.provider() as authority:
            self.admitted_import(authority)
            admission = authority.contain()
            with self.assertRaisesRegex(provider.Blocked, 'PRIOR_SCOPE_UNPROVABLE'):
                maintenance.recover_stopped(self.root / 'other-storage', admission)
            self.storage.rename(self.root / 'saved-storage')
            self.storage.mkdir(mode=0o700)
            with self.assertRaisesRegex(provider.Blocked, 'PRIOR_SCOPE_UNPROVABLE'):
                admission.check()
            self.assertEqual(os.listdir(self.storage), [])

    def test_foreign_runtime_storage_is_not_repaired(self):
        import maintenance_provider as provider
        with self.provider() as authority:
            self.admitted_import(authority)
            record = {'version': 2, 'state': 'RUNNING', 'generation': 'a' * 32,
                      'boot_id': '11111111-1111-4111-8111-111111111111',
                      'storage': {'pier': [1, 2], 'control': [3, 4], 'ship': [5, 6]}}
            journal = self.storage / 'control/runtime.json'
            journal.write_bytes(provider.encode(record))
            journal.chmod(0o600)
            original = journal.read_bytes()
            with self.assertRaisesRegex(provider.Blocked, 'PRIOR_SCOPE_UNPROVABLE'):
                authority.recover()
            self.assertEqual(journal.read_bytes(), original)
            self.assertFalse((self.storage / 'pier/.runtime-owner.json').exists())

    def test_external_admission_does_not_override_import_uncertainty(self):
        import maintenance_provider as provider
        from importer import Importer
        with self.provider() as authority:
            self.admitted_import(authority)
            journal = self.storage / 'control/job.json'
            original = json.loads(journal.read_bytes())
            for state in ('UPLOADING', 'VALIDATING', 'COMMITTING', 'CANCELLING', 'RECOVERY_REQUIRED', 'FAILED'):
                with self.subTest(state=state):
                    raw = provider.encode(dict(original, state=state))
                    journal.write_bytes(raw)
                    with mock.patch.object(Importer, '__init__', side_effect=AssertionError('must not construct')):
                        with self.assertRaisesRegex(provider.Blocked, 'IMPORT_STATE_UNPROVABLE'):
                            authority.recover()
                    self.assertEqual(journal.read_bytes(), raw)
                    self.assertFalse((self.storage / 'pier/.runtime-owner.json').exists())

    def test_real_cooperative_active_writer_lock_refuses_migration(self):
        import maintenance_provider as provider
        from importer import Importer
        with self.provider() as authority:
            self.admitted_import(authority)
            with Importer(*(self.storage / x for x in ('pier', 'uploads', 'control'))):
                with self.assertRaises(provider.Blocked):
                    authority.recover()
                self.assertFalse((self.storage / 'pier/.runtime-owner.json').exists())

    def test_v2_and_abrupt_v3_migrations_keep_auth_tls_and_import_identity(self):
        import maintenance_provider as provider
        import runtime
        from importer import Importer
        with self.provider() as authority:
            self.admitted_import(authority)
            self.storage.joinpath('control/auth.json').write_bytes(b'synthetic authentication unchanged')
            self.storage.joinpath('control/owner-tls').mkdir(mode=0o700)
            self.storage.joinpath('control/owner-tls/identity').write_bytes(b'synthetic TLS unchanged')
            preserved = {p: p.read_bytes() for p in self.storage.rglob('*')
                         if p.is_file() and p.name != 'writer.lock'}
            ship = self.storage / 'pier/ship'
            expected = {name: [p.stat().st_dev, p.stat().st_ino] for name, p in
                        (('pier', self.storage / 'pier'), ('control', self.storage / 'control'), ('ship', ship))}
            v2 = {'version': 2, 'state': 'RUNNING', 'generation': 'a' * 32,
                  'boot_id': '11111111-1111-4111-8111-111111111111', 'storage': expected}
            journal = self.storage / 'control/runtime.json'
            journal.write_bytes(provider.encode(v2))
            journal.chmod(0o600)
            target = authority.recover()
            self.assertEqual(target['storage'], expected)
            # New managed successor would write v3 STARTING/RUNNING. Model this
            # persisted abrupt state only; no Linux namespace claim in this test.
            for name in ('runtime.json',):
                journal.write_bytes(provider.encode(dict(target, state='RUNNING', generation='b' * 32)))
            (self.storage / 'pier/.runtime-owner.json').write_bytes(journal.read_bytes())
            authority.save(transaction=None, progress=[0, 0])
            recovered = authority.recover()
            self.assertNotEqual(recovered['generation'], target['generation'])
            for path, raw in preserved.items():
                self.assertEqual(path.read_bytes(), raw)
            engine = runtime.ManagedImporter(*(self.storage / x for x in ('pier', 'uploads', 'control')))
            try:
                self.assertEqual(engine.runtime['state'], 'STOPPED')
                self.assertTrue(engine.status()['start_available'])
            finally:
                Importer.close(engine)

    def test_every_migration_fsync_and_rename_fault_is_fail_closed_and_retryable(self):
        import maintenance_provider as provider
        real_fsync, real_replace = provider.os.fsync, provider.os.replace
        def fresh():
            fixture = ProviderTests()
            self.addCleanup(fixture.doCleanups)
            fixture.setUp()
            return fixture
        baseline = fresh()
        operations = []
        with baseline.provider() as authority:
            baseline.admitted_import(authority)
            authority.contain()
            def record_sync(fd):
                operations.append('fsync')
                return real_fsync(fd)
            def record_replace(*args, **kwargs):
                operations.append('rename')
                return real_replace(*args, **kwargs)
            with mock.patch.object(provider.os, 'fsync', side_effect=record_sync), \
                    mock.patch.object(provider.os, 'replace', side_effect=record_replace):
                authority.recover()
        self.assertGreaterEqual(len(operations), 20)
        for failure_step in range(len(operations)):
            with self.subTest(step=failure_step, operation=operations[failure_step]):
                fixture = fresh()
                with fixture.provider() as authority:
                    job_raw = fixture.admitted_import(authority)
                    authority.contain()
                    counter = [0]
                    def inject(operation, function, *args, **kwargs):
                        position = counter[0]
                        counter[0] += 1
                        if position == failure_step:
                            raise OSError('injected durability refusal')
                        return function(*args, **kwargs)
                    with mock.patch.object(provider.os, 'fsync', side_effect=lambda *a, **kw: inject('fsync', real_fsync, *a, **kw)), \
                            mock.patch.object(provider.os, 'replace', side_effect=lambda *a, **kw: inject('rename', real_replace, *a, **kw)):
                        with self.assertRaises((provider.Blocked, OSError)):
                            authority.recover()
                    self.assertGreater(counter[0], failure_step)
                    self.assertEqual((fixture.storage / 'control/job.json').read_bytes(), job_raw)
                    fixture.docker.start.assert_called_once_with(fixture.cid)
                # Reload durable state, not possibly stale in-memory state after
                # rename succeeded but directory fsync/acknowledgement failed.
                with fixture.provider() as successor_authority:
                    recovered = successor_authority.recover()
                    self.assertEqual(recovered['state'], 'STOPPED')
                    self.assertEqual(successor_authority.state['progress'], [2, 2])
                    self.assertEqual(json.loads((fixture.storage / 'control/runtime.json').read_bytes()),
                                     json.loads((fixture.storage / 'pier/.runtime-owner.json').read_bytes()))
                fixture.doCleanups()
        self.durability_operation_count = len(operations)

    def test_failed_enrollment_directory_fsync_cannot_be_ignored_to_run(self):
        import maintenance_provider as provider
        real_fsync = provider.os.fsync
        with self.provider() as authority:
            def fail_directory(fd):
                if fd == authority.directory:
                    raise OSError('enrollment commit uncertain')
                return real_fsync(fd)
            with mock.patch.object(provider.os, 'fsync', side_effect=fail_directory):
                with self.assertRaises(OSError):
                    authority.enroll(self.cid)
            with self.assertRaisesRegex(provider.Blocked, 'PRIOR_SCOPE_UNPROVABLE'):
                authority.run()
            self.docker.start.assert_not_called()

    def cli_environment(self):
        seam = self.root / 'cli-seam'
        seam.mkdir()
        (seam / 'sitecustomize.py').write_bytes(
            Path(__file__).with_name('provider_cli_fixture.py').read_bytes())
        info = self.root / 'model-container.json'
        info.write_text(json.dumps(self.info))
        return dict(os.environ, PYTHONPATH=str(seam), PYTHONDONTWRITEBYTECODE='1',
                    PROVIDER_CLI_TOOLS=str(TOOLS), PROVIDER_CLI_INFO=str(info),
                    PROVIDER_CLI_EVENTS=str(self.root / 'model-events.jsonl'))

    def test_real_cli_subprocess_recovers_with_canonical_capability(self):
        import maintenance_provider as provider
        entrypoints = ([str(TOOLS / 'maintenance_provider.py')],
                       ['-m', 'maintenance_provider'],
                       ['-c', 'import maintenance; from maintenance_provider import main; raise SystemExit(main())'])
        for entrypoint in entrypoints:
            with self.subTest(entrypoint=entrypoint):
                fixture = ProviderTests()
                self.addCleanup(fixture.doCleanups)
                fixture.setUp()
                with fixture.provider() as authority:
                    job_raw = fixture.admitted_import(authority)
                original = b'{"state":"RUNNING"}\n'
                journal = fixture.storage / 'control/runtime.json'
                journal.write_bytes(original)
                journal.chmod(0o600)
                env = fixture.cli_environment()
                result = subprocess.run(
                    [sys.executable, '-B', *entrypoint, '--authority', str(fixture.authority),
                     '--storage', str(fixture.storage), 'recover'],
                    cwd=fixture.root, env=env, stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
                events_path = Path(env['PROVIDER_CLI_EVENTS'])
                observed = events_path.read_text() if events_path.exists() else 'no boundary reached'
                self.assertEqual(result.returncode, 0, result.stderr.decode() + observed)
                self.assertEqual(result.stdout, b'RECOVERED_STOPPED\n')
                self.assertEqual(result.stderr, b'')
                target_raw = journal.read_bytes()
                self.assertEqual(target_raw, (fixture.storage / 'pier/.runtime-owner.json').read_bytes())
                self.assertEqual(json.loads(target_raw)['state'], 'STOPPED')
                self.assertEqual((fixture.storage / 'control/job.json').read_bytes(), job_raw)
                events = [json.loads(line) for line in Path(env['PROVIDER_CLI_EVENTS']).read_text().splitlines()]
                self.assertEqual(events, [['stop', fixture.cid], ['remove', fixture.cid], ['capability', True]])
                with fixture.provider() as reopened:
                    self.assertEqual(reopened.state['phase'], 'RECOVERED')
                    self.assertEqual(reopened.state['progress'], [2, 2])
                    evidence = provider.decode(provider.read_raw(reopened.directory,
                        reopened.state['transaction'] + '.json', uid=os.geteuid()))
                    self.assertEqual(bytes.fromhex(evidence['originals'][1]), original)
                fixture.doCleanups()

    def test_unmodified_subprocess_entrypoints_offer_help_and_preserve_host_guard(self):
        env = dict(os.environ, PYTHONPATH=str(TOOLS), PYTHONDONTWRITEBYTECODE='1')
        for entrypoint in ([str(TOOLS / 'maintenance_provider.py')], ['-m', 'maintenance_provider']):
            with self.subTest(entrypoint=entrypoint):
                result = subprocess.run([sys.executable, '-B', *entrypoint, '--help'],
                                        cwd=self.root, env=env, stdin=subprocess.DEVNULL,
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
                self.assertEqual(result.returncode, 0, result.stderr.decode())
                self.assertIn(b'{enroll,run,recover}', result.stdout)
                self.assertEqual(result.stderr, b'')
                if not sys.platform.startswith('linux') or os.geteuid() != 0:
                    result = subprocess.run(
                        [sys.executable, '-B', *entrypoint, '--authority', str(self.authority),
                         '--storage', str(self.storage), 'recover'],
                        cwd=self.root, env=env, stdin=subprocess.DEVNULL,
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
                    self.assertEqual(result.returncode, 78)
                    self.assertEqual(result.stdout, b'')
                    self.assertEqual(result.stderr, b'BLOCKED: PRIOR_SCOPE_UNPROVABLE\n')
                    self.assertFalse(self.authority.exists())
                    self.assertTrue(all(not list((self.storage / name).iterdir())
                                        for name in ('pier', 'uploads', 'control')))

    def test_subprocess_rejects_forged_unissued_and_expired_capabilities_before_roots(self):
        with self.provider() as authority:
            self.admitted_import(authority)
        env = self.cli_environment()
        before = {str(p.relative_to(self.storage)): p.read_bytes()
                  for p in self.storage.rglob('*') if p.is_file()}
        script = '''
import os
from pathlib import Path
from unittest import mock
import maintenance
import maintenance_provider as canonical
from sitecustomize import ModelDocker, new_provider

class Duck:
    def check(self):
        raise AssertionError('duck capability must never be called')
class Subclass(canonical.StorageAdmission):
    pass
storage, authority = map(Path, __import__('sys').argv[1:])
rejected = []
def refuse(name, capability, target=storage):
    with mock.patch.object(maintenance, 'open_root', side_effect=AssertionError('opened roots')):
        try:
            maintenance.recover_stopped(target, capability)
        except canonical.Blocked:
            rejected.append(name)
        else:
            raise AssertionError('accepted ' + name)
with new_provider(canonical.Provider, authority, storage, docker=ModelDocker()) as provider:
    refuse('receipt', {'confirmed_stopped': True, 'signed': True})
    refuse('duck', Duck())
    refuse('subclass', Subclass(provider))
    refuse('unissued-exact', canonical.StorageAdmission(provider))
    admission = provider.contain()
    refuse('foreign-storage', admission, storage.parent / 'foreign')
refuse('expired-issued', admission)
print(','.join(rejected))
'''
        result = subprocess.run([sys.executable, '-B', '-c', script, str(self.storage), str(self.authority)],
                                cwd=self.root, env=env, stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual(result.stdout,
                         b'receipt,duck,subclass,unissued-exact,foreign-storage,expired-issued\n')
        self.assertEqual(result.stderr, b'')
        self.assertEqual({str(p.relative_to(self.storage)): p.read_bytes()
                          for p in self.storage.rglob('*') if p.is_file()}, before)

    def test_recovery_modules_are_selected_in_package_build(self):
        root = TOOLS.parents[1]
        dockerfile = (root / 'build/Dockerfile').read_text()
        ignore = (root / '.dockerignore').read_text().splitlines()
        for name in ('maintenance.py', 'maintenance_provider.py'):
            self.assertIn('tools/browser-importer/' + name, dockerfile)
            self.assertIn('!tools/browser-importer/' + name, ignore)

    def test_provider_is_shipped(self):
        self.assertIsNotNone(importlib.util.find_spec('maintenance_provider'),
                             'outside-writer provider is missing (scaffold RED)')


if __name__ == '__main__':
    unittest.main()
