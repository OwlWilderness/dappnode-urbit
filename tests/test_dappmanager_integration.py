"""Engine-free issue19 integration tests; no Docker/host access."""
import importlib.util
import pathlib
import sys
import unittest

import os
import tempfile
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
TEST_SCRATCH = pathlib.Path(os.environ.get('IMPORTER_TEST_SCRATCH',
                            tempfile.gettempdir())).resolve()
sys.path.insert(0, str(ROOT / 'tools/browser-importer'))
sys.path.insert(0, str(ROOT / 'tools/host-integration'))
SOURCE = ROOT / 'tools/host-integration/dappmanager_lifecycle.py'


spec = importlib.util.spec_from_file_location('dappmanager_lifecycle', SOURCE)
assert spec is not None and spec.loader is not None
api = importlib.util.module_from_spec(spec)
spec.loader.exec_module(api)


class Model:
    def __init__(self, events, phase=None):
        self.events, self.state = events, None if phase is None else {'phase': phase}
        self.fresh = phase is None

    def __enter__(self):
        self.events.append('lock')
        return self

    def __exit__(self, *args):
        self.events.append('unlock')

    def prepare(self, *, existing_only=False):
        self.events.append('prepare')
        return 'storage'

    def create(self):
        self.events.append('create-no-start')
        return 'a' * 64

    def enroll(self, cid):
        self.events.append('enroll')
        self.state = {'phase': 'ENROLLED'}

    def run(self):
        self.events.append('active-before-start')
        self.state = {'phase': 'ACTIVE'}

    def recover(self):
        self.events.append('recover')
        self.state = {'phase': 'RECOVERED'}


class LifecycleTests(unittest.TestCase):
    def certificate_wire(self, request, operation, directory):
        import json
        import subprocess
        import threading
        import dappmanager_broker as broker
        request_file = directory / 'certificate-request.json'
        request_file.write_text(json.dumps(request))
        socket = directory / 's'
        with broker.Server(str(socket), broker.Handler) as server:
            server.timeout = 3
            server.dispatch_request = lambda value: broker.dispatch(value, {}, operation)
            thread = threading.Thread(target=server.handle_request)
            thread.start()
            try:
                child = subprocess.run(['node', str(ROOT / 'tests/dappmanager-broker-client.mjs'),
                    str(pathlib.Path(os.environ['UVM_DAPPMANAGER_CHECKOUT']) / 'packages/dockerApi/src/uvmLifecycle.mjs'),
                    str(socket), str(request_file)], stdin=subprocess.DEVNULL, capture_output=True, timeout=5)
            finally:
                thread.join(timeout=4)
            self.assertFalse(thread.is_alive())
        socket.unlink()  # exact endpoint created by this fixture
        self.assertEqual(child.returncode, 0, child.stderr.decode())
        result = json.loads(child.stdout)
        self.assertIs(result.pop('ok'), True)
        return result

    def test_virgin_storage_create_enroll_run_under_continuous_locks(self):
        events = []
        model = Model(events)
        try:
            result = api.Lifecycle(model, model, lambda storage: model).activate()
        except NotImplementedError:
            result = None
        self.assertEqual(result, {'state': 'ACTIVE', 'container': 'a' * 64})
        self.assertEqual(events, ['lock', 'prepare', 'lock', 'create-no-start',
                                  'enroll', 'active-before-start', 'unlock', 'unlock'])

    def test_existing_unregistered_volume_is_not_adopted(self):
        events = []
        model = Model(events)
        model.fresh = False
        with self.assertRaisesRegex(Exception, 'PRIOR_SCOPE_UNPROVABLE'):
            api.Lifecycle(model, model, lambda storage: model).activate()
        self.assertNotIn('create-no-start', events)

    def test_maintenance_uses_same_integration_and_storage_locks_without_create(self):
        events = []
        model = Model(events, 'ACTIVE')
        operation = api.Lifecycle(model, model, lambda storage: model)
        self.assertTrue(hasattr(operation, 'recover'), 'maintenance interlock missing')
        self.assertEqual(operation.recover(), {'state': 'RECOVERED_STOPPED'})
        self.assertEqual(events, ['lock', 'prepare', 'lock', 'recover', 'unlock', 'unlock'])

    def test_real_preparation_private_empty_children_and_refusal_preserves_data(self):
        self.assertTrue(hasattr(api, 'prepare_empty_storage'), 'storage preparation missing')
        with tempfile.TemporaryDirectory(dir=TEST_SCRATCH) as scratch:
            storage = pathlib.Path(scratch) / 'volume'
            storage.mkdir()
            api.prepare_empty_storage(storage, uid=os.geteuid(), gid=os.getegid())
            self.assertEqual(set(p.name for p in storage.iterdir()), {'pier', 'uploads', 'control'})
            for path in [storage, *storage.iterdir()]:
                self.assertEqual(path.stat().st_mode & 0o777, 0o700)
                self.assertEqual(path.stat().st_uid, os.geteuid())
            sentinel = storage / 'control/sentinel'
            sentinel.write_bytes(b'preserve')
            with self.assertRaises(Exception):
                api.prepare_empty_storage(storage, uid=os.geteuid(), gid=os.getegid())
            self.assertEqual(sentinel.read_bytes(), b'preserve')

    def test_real_global_lock_excludes_contenders_before_backend(self):
        self.assertTrue(hasattr(api, 'Admission'), 'canonical integration lock missing')
        with tempfile.TemporaryDirectory(dir=TEST_SCRATCH) as scratch:
            with mock.patch.object(api, 'CANONICAL_AUTHORITY', pathlib.Path(scratch)):
                with api.Admission():
                    with self.assertRaises((BlockingIOError, api.Blocked)):
                        with api.Admission():
                            self.fail('parallel controller entered')

    def test_backend_prepares_before_nocopy_create_and_uses_no_start_only(self):
        self.assertTrue(hasattr(api, 'ComposeBackend'), 'host Docker backend missing')
        events = []
        class Engine:
            def call(self, *args, **kwargs):
                events.append(args)
                if args[0:2] == ('volume', 'ls'):
                    return b''
                if args[0:2] == ('volume', 'create'):
                    return b'uvm_ship_data'
                if args[-2:] == ('ps', '-aq'):
                    return b'a' * 64
                return b''
            def volume(self, name):
                return {'name': name, 'driver': 'local', 'scope': 'local',
                        'options_empty': True, 'mountpoint': '/owned/volume'}
            def consumers(self, storage):
                return []
        plan = {'volume': 'uvm_ship_data', 'compose_path': '/trusted/host.json'}
        backend = api.ComposeBackend(plan, Engine())
        with mock.patch.object(api, 'prepare_empty_storage') as prepare:
            self.assertEqual(backend.prepare(), pathlib.Path('/owned/volume'))
            prepare.assert_called_once_with(pathlib.Path('/owned/volume'))
        self.assertTrue(backend.fresh)
        self.assertEqual(backend.create(), 'a' * 64)
        create = [call for call in events if 'create' in call and call[0] == 'compose']
        self.assertEqual(create, [('compose', '-f', '/trusted/host.json', 'create', '--no-recreate', 'ship')])
        self.assertFalse(any('up' in call or 'start' in call or 'down' in call for call in events))

    def test_backend_existing_volume_never_preinitializes_or_creates_volume(self):
        self.assertTrue(hasattr(api, 'ComposeBackend'), 'host Docker backend missing')
        engine = mock.Mock()
        engine.call.return_value = b'uvm_ship_data\n'
        engine.volume.return_value = {'name': 'uvm_ship_data', 'driver': 'local', 'scope': 'local',
                                      'options_empty': True, 'mountpoint': '/owned/volume'}
        with mock.patch.object(api, 'prepare_empty_storage') as prepare:
            backend = api.ComposeBackend({'volume': 'uvm_ship_data'}, engine)
            backend.prepare()
            prepare.assert_not_called()
            engine.consumers.assert_not_called()
            self.assertFalse(backend.fresh)
        engine.call.assert_called_once_with('volume', 'ls', '--format', '{{.Name}}')

    def test_request_requires_exact_host_approved_compose_before_mutation(self):
        broker_path = ROOT / 'tools/host-integration/dappmanager_broker.py'
        self.assertTrue(broker_path.exists(), 'host broker missing')
        spec = importlib.util.spec_from_file_location('dappmanager_broker', broker_path)
        assert spec is not None and spec.loader is not None
        broker = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(broker)
        import hashlib
        import json
        compose = {'services': {'ship': {'image': 'image@sha256:' + 'a' * 64}}}
        digest = hashlib.sha256(json.dumps(compose, sort_keys=True, separators=(',', ':'),
                                           ensure_ascii=False).encode()).hexdigest()
        operation = mock.Mock()
        operation.activate.return_value = {'state': 'ACTIVE', 'container': 'a' * 64}
        plan = {'manager_compose_sha256': digest}
        request = {'package': 'uvm.public.dappnode.eth', 'operation': 'activate', 'compose': compose}
        self.assertEqual(broker.dispatch(request, plan, operation)['state'], 'ACTIVE')
        operation.reset_mock()
        request['compose']['services']['ship']['pid'] = 'host'
        with self.assertRaises(api.Blocked):
            broker.dispatch(request, plan, operation)
        operation.activate.assert_not_called()
        request['operation'] = 'reset'
        with self.assertRaises(api.Blocked):
            broker.dispatch(request, plan, operation)

    def test_real_provider_initial_enrollment_active_intent_and_update_migration(self):
        self.exercise_real_provider()

    def test_registered_preimport_update_refuses_before_mutation(self):
        self.exercise_real_provider(preimport_only=True)

    def exercise_real_provider(self, preimport_only=False):
        import io
        import json
        import zipfile
        from importer import Importer
        import maintenance_provider
        with tempfile.TemporaryDirectory(dir=TEST_SCRATCH) as scratch:
            root = pathlib.Path(scratch)
            authority, storage = root / 'authority', root / 'volume'
            class Engine:
                def __init__(self):
                    self.created = False
                    self.scopes = {}
                    self.count = 0
                    self.events = []
                def call(engine, *args, **kwargs):
                    if args[:2] == ('volume', 'ls'):
                        return b'uvm_ship_data' if engine.created else b''
                    if args[:2] == ('volume', 'create'):
                        storage.mkdir(mode=0o700)
                        engine.created = True
                        return b'uvm_ship_data'
                    if 'create' in args:
                        engine.count += 1
                        cid = ('a' if engine.count == 1 else 'b') * 64
                        engine.scopes[cid] = {'id': cid, 'status': 'created', 'running': False,
                            'started': '0001-01-01T00:00:00Z', 'user': '10000:10000',
                            'privileged': False, 'pid_mode': '', 'userns': '', 'restart': 'unless-stopped',
                            'caps_add': [], 'caps_drop': ['ALL'], 'security': ['no-new-privileges:true'],
                            'devices': False, 'mounts': [{'Type': 'volume', 'Name': 'uvm_ship_data',
                                'Source': str(storage), 'Destination': '/urbit', 'RW': True}]}
                        engine.events.append('create:' + cid)
                        return b''
                    if args[-2:] == ('ps', '-aq'):
                        return next(iter(engine.scopes)).encode()
                    raise AssertionError(args)
                def volume(engine, name):
                    return {'name': name, 'driver': 'local', 'scope': 'local',
                            'options_empty': True, 'mountpoint': str(storage)}
                def consumers(engine, path):
                    return list(engine.scopes)
                def inspect(engine, cid):
                    return engine.scopes.get(cid)
                def restart(engine, cid, policy):
                    engine.scopes[cid]['restart'] = policy
                def start(engine, cid):
                    registry = next(authority.glob('*/registry.json'))
                    self.assertEqual(json.loads(registry.read_bytes())['phase'], 'ACTIVE')
                    with self.assertRaises((BlockingIOError, api.Blocked)):
                        with factory(storage):
                            self.fail('provider lock lost before Start')
                    engine.scopes[cid].update(running=True, status='running', started='2026-11-06T00:00:00Z')
                    engine.events.append('start:' + cid)
                def wait(engine, cid):
                    api.StartAcknowledgementDocker.wait(engine, cid)
                def stop(engine, cid):
                    engine.events.append('disable-stop:' + cid)
                    engine.scopes[cid].update(restart='no', running=False, status='exited')
                def remove(engine, cid):
                    engine.events.append('remove:' + cid)
                    engine.scopes.pop(cid)
            engine = Engine()
            def factory(path):
                provider = maintenance_provider.Provider(authority, path, docker=engine, owner_uid=os.geteuid())
                provider._require_host = lambda: None  # engine-free Darwin/UID fixture only
                return provider
            real_prepare = api.prepare_empty_storage
            def prepare(path):
                real_prepare(path, uid=os.geteuid(), gid=os.getegid())
            plan = {'volume': 'uvm_ship_data', 'compose_path': '/trusted/host.json'}
            with mock.patch.object(api, 'CANONICAL_AUTHORITY', authority), \
                    mock.patch.object(api, 'prepare_empty_storage', side_effect=prepare):
                first = api.Lifecycle(api.ComposeBackend(plan, engine), api.Admission(), factory).activate()
                self.assertEqual(first['container'], 'a' * 64)
                if preimport_only:
                    import copy
                    # Real Importer initialization, with no committed import.
                    with Importer(*(storage / x for x in ('pier', 'uploads', 'control')), reserve_bytes=0):
                        pass
                    for stage in ('awaiting-certificate', 'enrolled', 'uploading'):
                        with self.subTest(stage=stage):
                            if stage == 'awaiting-certificate':
                                (storage / 'control/owner-tls').mkdir(mode=0o700)
                                (storage / 'control/owner-tls/private.key').write_bytes(b'fixture TLS identity')
                            if stage == 'enrolled':
                                (storage / 'control/auth.json').write_bytes(b'fixture retained enrollment')
                            if stage == 'uploading':
                                with Importer(*(storage / x for x in ('pier', 'uploads', 'control')), reserve_bytes=0) as importer:
                                    job = importer.create(total_bytes=100, expanded_limit=4096, stopped=True)
                                    importer.append(job['id'], 0, b'retained partial upload')
                            def snapshot():
                                return {str(p.relative_to(root)): (p.read_bytes(), p.stat().st_mode)
                                        for p in root.rglob('*') if p.is_file()}
                            before = snapshot()
                            scopes, events = copy.deepcopy(engine.scopes), list(engine.events)
                            error = None
                            try:
                                api.Lifecycle(api.ComposeBackend(plan, engine), api.Admission(), factory).activate()
                            except Exception as caught:
                                error = caught
                            self.assertEqual(engine.events, events, 'pre-import update mutated predecessor before refusing')
                            self.assertEqual(engine.scopes, scopes, 'predecessor/restart policy must remain intact')
                            self.assertEqual(snapshot(), before, 'TLS/enrollment/upload/registry bytes must remain intact')
                            self.assertIsInstance(error, api.Blocked)
                            self.assertIn('PREIMPORT_UPDATE_REFUSED', str(error))
                    return
                # Compose the real registered Provider with the existing TLS consumer.
                tls_spec = importlib.util.spec_from_file_location('tls_fixture', ROOT / 'tests/browser-importer/test_owner_tls.py')
                tls_fixture = importlib.util.module_from_spec(tls_spec)
                tls_spec.loader.exec_module(tls_fixture)
                fixture = tls_fixture.OwnerTLS()
                self.addCleanup(fixture.doCleanups)
                fixture.setUp()
                fixture.control = storage / 'control'
                fixture.ensure()
                fixture.sign(storage / 'control/owner-tls-public/request.pem')
                public = storage / 'control/owner-tls-public'
                certificates = {name: (public / name).read_bytes() for name in ('root-ca.pem', 'server.pem')}
                for name in certificates:
                    (public / name).unlink()  # this test's generated fixture copies only
                import base64
                import dappmanager_broker as broker
                operation = api.Lifecycle(api.ComposeBackend(plan, engine), api.Admission(), factory)
                for name, content in certificates.items():
                    request = {'package': broker.PACKAGE, 'operation': 'certificate',
                               'container': first['container'], 'filename': name,
                               'content': base64.b64encode(content).decode('ascii')}
                    # Both existing leases and the TLS consumer lock reject peers.
                    with api.Admission():
                        with self.assertRaises((BlockingIOError, api.Blocked)):
                            broker.dispatch(request, {}, operation)
                    with factory(storage):
                        with self.assertRaises((BlockingIOError, api.Blocked)):
                            broker.dispatch(request, {}, operation)
                    import fcntl
                    with (storage / 'control/.owner-tls.lock').open('r+b') as lock:
                        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                        with self.assertRaises((BlockingIOError, api.Blocked)):
                            broker.dispatch(request, {}, operation)
                    for update in ({'filename':'server.key'}, {'filename':'../root-ca.pem'},
                                   {'content':base64.b64encode(b'private or invalid bytes').decode()},
                                   {'content':base64.b64encode(content + content).decode()},
                                   {'content':'A' * 87388}, {'content':'%%%%'},
                                   {'container':'b'*64}):
                        with self.subTest(update=list(update)), self.assertRaises((api.Blocked, ValueError)):
                            broker.dispatch(dict(request, **update), {}, operation)
                    self.assertFalse((public / name).exists())
                    sentinel = fixture.base / 'untouched-public-sentinel'
                    sentinel.write_bytes(b'preserve outside destination')
                    (public / name).symlink_to(sentinel)
                    with self.assertRaises(api.Blocked):
                        broker.dispatch(request, {}, operation)
                    self.assertEqual(sentinel.read_bytes(), b'preserve outside destination')
                    (public / name).unlink()  # owned symlink fixture only
                    if name == 'root-ca.pem':
                        # Publication failure must preserve evidence and poison retry.
                        with mock.patch.object(api, 'rename_without_replace', side_effect=OSError('injected publication loss')):
                            with self.assertRaisesRegex(OSError, 'publication loss'):
                                broker.dispatch(request, {}, operation)
                        pending = list((storage / 'control').glob('.dappmanager-cert-*'))
                        self.assertEqual(len(pending), 1)
                        self.assertEqual(pending[0].read_bytes(), content)
                        try:
                            broker.dispatch(request, {}, operation)
                            retry_refused = False
                        except api.Blocked:
                            retry_refused = True
                        self.assertTrue(retry_refused, 'uncertain transfer was silently replayed')
                        self.assertFalse((public / name).exists())
                        pending[0].unlink()  # exact known injected fixture, not recovery behavior
                    publish = api.rename_without_replace
                    def publish_under_leases(*args):
                        with self.assertRaises((BlockingIOError, api.Blocked)):
                            with api.Admission():
                                self.fail('integration lease lost at publication')
                        with self.assertRaises((BlockingIOError, api.Blocked)):
                            with factory(storage):
                                self.fail('Provider lease lost at publication')
                        with (storage / 'control/.owner-tls.lock').open('r+b') as contender:
                            with self.assertRaises(BlockingIOError):
                                fcntl.flock(contender, fcntl.LOCK_EX | fcntl.LOCK_NB)
                        return publish(*args)
                    try:
                        with mock.patch.object(api, 'rename_without_replace', side_effect=publish_under_leases):
                            receipt = self.certificate_wire(request, operation, fixture.base)
                    except Exception as error:
                        receipt = {'refused': str(error)}
                    self.assertEqual(receipt, {'state': 'CERTIFICATE_STORED', 'container': first['container'],
                                               'filename': name}, 'actual owner public certificate upload is blocked')
                    self.assertEqual((public / name).read_bytes(), content)
                    self.assertEqual((public / name).stat().st_mode & 0o777, 0o444)
                    with self.assertRaises(api.Blocked):
                        broker.dispatch(request, {}, operation)  # no overwrite, even same bytes
                    self.assertEqual((public / name).read_bytes(), content)
                self.assertEqual(fixture.ensure()['state'], 'READY')
                with self.assertRaises(api.Blocked):
                    broker.dispatch(request, {}, operation)
                self.assertEqual(fixture.ensure()['state'], 'READY')
                payload = io.BytesIO()
                with zipfile.ZipFile(payload, 'w') as archive:
                    archive.writestr('zod/.urb/checkpoint', b'disposable engine-free import')
                raw = payload.getvalue()
                with Importer(*(storage / x for x in ('pier', 'uploads', 'control')), reserve_bytes=0) as importer:
                    job = importer.create(total_bytes=len(raw), expanded_limit=4096, stopped=True)
                    importer.append(job['id'], 0, raw)
                    importer.validate(job['id'])
                original_job = (storage / 'control/job.json').read_bytes()
                second = api.Lifecycle(api.ComposeBackend(plan, engine), api.Admission(), factory).activate()
                self.assertEqual(second['container'], 'b' * 64)
                self.assertNotIn('a' * 64, engine.scopes)
                self.assertLess(engine.events.index('remove:' + 'a' * 64), engine.events.index('create:' + 'b' * 64))
                self.assertEqual((storage / 'control/job.json').read_bytes(), original_job)
                owner = json.loads((storage / 'pier/.runtime-owner.json').read_bytes())
                self.assertEqual(owner['state'], 'STOPPED')
                self.assertEqual(owner, json.loads((storage / 'control/runtime.json').read_bytes()))

    def test_host_descriptor_binds_nocopy_scope_identity_and_protected_volume_alias(self):
        import copy
        import hashlib
        import json
        sys.path.insert(0, str(ROOT / 'tools/host-integration'))
        import dappmanager_broker as broker
        compose = {'services': {'ship': {
            'image': 'ship.uvm.public.dappnode.eth@sha256:' + 'a' * 64,
            'container_name': 'DAppNodePackage-ship.uvm.public.dappnode.eth',
            'labels': {'dappnode.dnp.dnpName': 'uvm.public.dappnode.eth'},
            'user': '10000:10000', 'restart': 'unless-stopped', 'cap_drop': ['ALL'],
            'security_opt': ['no-new-privileges:true'],
            'volumes': [{'type': 'volume', 'source': 'ship_data', 'target': '/urbit',
                         'volume': {'nocopy': True}}]}},
            'volumes': {'ship_data': {'external': True, 'name': 'uvmpublicdappnodeeth_ship_data'}}}
        def check(value, volume='uvmpublicdappnodeeth_ship_data'):
            raw = json.dumps(value).encode()
            plan = {'volume': volume, 'compose_path': '/trusted/host.json',
                    'compose_file_sha256': hashlib.sha256(raw).hexdigest(),
                    'manager_compose_sha256': 'b' * 64}
            return broker.validate_plan(plan, raw)
        check(compose)
        alias = copy.deepcopy(compose)
        alias['volumes']['ship_data']['name'] = 'unguarded_alias'
        with self.assertRaises(api.Blocked, msg='unprotected volume alias admitted'):
            check(alias, 'unguarded_alias')
        for key, value in [('pid', 'host'), ('container_name', 'innocent'), ('labels', {}),
                           ('volumes', ['ship_data:/urbit']), ('post_start', [{'command': 'bad'}]),
                           ('image', 'mutable:tag')]:
            bad = copy.deepcopy(compose)
            bad['services']['ship'][key] = value
            with self.subTest(key=key), self.assertRaises(api.Blocked):
                check(bad)
        with self.assertRaises(api.Blocked):
            broker.unique_json(b'{"operation":"activate","operation":"reset"}')

    def test_javascript_producer_to_real_python_unix_broker_consumer(self):
        import json
        import subprocess
        import threading
        sys.path.insert(0, str(ROOT / 'tools/host-integration'))
        import dappmanager_broker as broker
        upstream = os.environ.get('UVM_DAPPMANAGER_CHECKOUT')
        self.assertTrue(upstream, 'set UVM_DAPPMANAGER_CHECKOUT for composed protocol test')
        assert upstream is not None
        helper = pathlib.Path(upstream) / 'packages/dockerApi/src/uvmLifecycle.mjs'
        with tempfile.TemporaryDirectory(dir=TEST_SCRATCH) as scratch:
            socket = pathlib.Path(scratch) / 's'
            request_file = pathlib.Path(scratch) / 'request.json'
            compose = {'services': {'ship': {'image': 'approved:test'}}}
            request = {'package': broker.PACKAGE, 'operation': 'activate', 'compose': compose}
            request_file.write_text(json.dumps(request))
            operation = mock.Mock()
            operation.activate.return_value = {'state': 'ACTIVE', 'container': 'c' * 64}
            plan = {'manager_compose_sha256': broker.digest(compose)}
            with broker.Server(str(socket), broker.Handler) as server:
                server.dispatch_request = lambda value: broker.dispatch(value, plan, operation)
                thread = threading.Thread(target=server.handle_request)
                server.timeout = 3
                thread.start()
                try:
                    child = subprocess.run(['node', str(ROOT / 'tests/dappmanager-broker-client.mjs'),
                                            str(helper), str(socket), str(request_file)],
                                           stdin=subprocess.DEVNULL, capture_output=True, timeout=5)
                finally:
                    thread.join(timeout=4)
                self.assertFalse(thread.is_alive(), 'test broker thread failed to settle')
            self.assertEqual(child.returncode, 0, child.stderr.decode())
            self.assertEqual(json.loads(child.stdout), {'ok': True, 'state': 'ACTIVE', 'container': 'c' * 64})
            operation.activate.assert_called_once_with()

    def test_replacement_recovers_prior_before_compose_can_remove_it(self):
        events = []
        model = Model(events, 'ACTIVE')
        with mock.patch.object(api, 'replacement_preflight') as preflight:
            api.Lifecycle(model, model, lambda storage: model).activate()
        preflight.assert_called_once_with(model)
        self.assertIn('recover', events, 'replacement bypassed provider recovery')
        self.assertLess(events.index('recover'), events.index('create-no-start'))
        self.assertEqual(events.count('lock'), 2)
        self.assertNotIn('unlock', events[:events.index('active-before-start')])

    def test_recovery_refusal_cannot_create_or_start_successor(self):
        events = []
        model = Model(events, 'ACTIVE')
        def refuse():
            events.append('refused-recovery')
            raise ValueError('unprovable')
        model.recover = refuse
        with mock.patch.object(api, 'replacement_preflight'), self.assertRaisesRegex(ValueError, 'unprovable'):
            api.Lifecycle(model, model, lambda storage: model).activate()
        self.assertNotIn('create-no-start', events)
        self.assertNotIn('active-before-start', events)


if __name__ == '__main__':
    unittest.main(verbosity=2)
