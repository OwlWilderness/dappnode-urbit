"""C corrections: real scratch filesystem; explicit engine-free host seam."""
import json
import os
from pathlib import Path
import subprocess
import sys
from unittest import mock
import test_maintenance_provider as fixtures
TOOLS = fixtures.TOOLS
import maintenance_provider as mp
import runtime
from importer import Importer


class Corrections(fixtures.ProviderTests):
    # Reuse fixtures, not the inherited test collection.
    def test_interrupted_runtime_owner_write_recovers_and_preserves_pending(self):
        with self.provider() as p:
            self.admitted_import(p)
            target = p.recover()
            # A new lifetime starts a new recovery transaction.
            p.save(transaction=None, progress=[0, 0])
            code = '''import json,os,sys
sys.path.insert(0,sys.argv[1])
import runtime
obj=object.__new__(runtime.ManagedImporter)
obj.runtime=json.loads(sys.argv[3]);obj.runtime['state']='STARTING';obj.runtime['generation']='c'*32
obj.control_fd=os.open(sys.argv[2]+'/control',os.O_RDONLY|os.O_DIRECTORY)
fd=os.open(sys.argv[2]+'/pier',os.O_RDONLY|os.O_DIRECTORY)
runtime.os.replace=lambda *a,**kw:os._exit(29)
obj._write_runtime(fd,'.runtime-owner.json')
'''
            child = subprocess.run([sys.executable, '-B', '-c', code, str(TOOLS), str(self.storage), json.dumps(target)], timeout=10)
            self.assertEqual(child.returncode, 29)
            pending = list(self.storage.glob('*/.runtime-*'))
            pending = [x for x in pending if x.name != '.runtime-owner.json']
            self.assertEqual(len(pending), 1)
            original = pending[0].read_bytes()
            self.assertEqual(p.recover()['state'], 'STOPPED')
            self.assertEqual(pending[0].read_bytes(), original)
            self.assertEqual(pending[0].parent, self.storage / 'control')

    def test_live_ship_replacement_refused_before_launch_or_journal_write(self):
        with self.provider() as p:
            self.admitted_import(p)
            p.recover()
        adapter = mock.Mock()
        engine = runtime.ManagedImporter(*(self.storage / x for x in ('pier', 'uploads', 'control')), runtime_adapter=adapter)
        self.addCleanup(lambda: Importer.close(engine))
        journals = [self.storage / 'pier/.runtime-owner.json', self.storage / 'control/runtime.json']
        original = [x.read_bytes() for x in journals]
        (self.storage / 'pier/ship').rename(self.root / 'saved-ship')
        (self.storage / 'pier/ship').mkdir(mode=0o700)
        (self.storage / 'pier/ship/.urb').mkdir(mode=0o700)
        with mock.patch.object(runtime, '_boot_id', return_value='11111111-1111-4111-8111-111111111111'):
            with self.assertRaises(runtime.ImportError):
                engine.start(confirmed_stopped=True)
        adapter.launch.assert_not_called()
        self.assertEqual([x.read_bytes() for x in journals], original)

    def test_mount_projection_has_only_consumed_leaves(self):
        self.assertNotIn('{{json .Mounts}}', mp.Docker.FORMAT)
        self.assertIn(':= .Mounts', mp.Docker.FORMAT)
        for leaf in ('Type', 'Source', 'Destination', 'RW', 'Name'):
            self.assertIn('{{json .' + leaf + '}}', mp.Docker.FORMAT)

    def curated_container(self):
        # Match the actual projected schema, not the broader provider model.
        item: dict = dict(self.info, devices=False)
        item.pop('readonly')
        item['mounts'] = [dict(self.info['mounts'][0], Name='')]
        return item

    def test_curated_docker_parser_accepts_exact_projection(self):
        docker = object.__new__(mp.Docker)
        item = self.curated_container()
        with mock.patch.object(docker, 'ids', return_value=[self.cid]), mock.patch.object(docker, 'call') as call:
            call.return_value = json.dumps(item).encode()
            self.assertEqual(docker.inspect(self.cid), item)
            self.assertEqual(call.call_args.args, ('inspect', '--format', mp.Docker.FORMAT, self.cid))
        with mock.patch.object(docker, 'ids', return_value=[]), mock.patch.object(docker, 'call') as call:
            self.assertIsNone(docker.inspect(self.cid))
            call.assert_not_called()

    def test_curated_docker_parser_refuses_broad_metadata(self):
        docker = object.__new__(mp.Docker)
        item = self.curated_container()
        variants = (dict(item, Env=['PASSWORD=synthetic-credential-canary']),
                    dict(item, mounts=[dict(item['mounts'][0], Driver='synthetic-driver')]),
                    dict(item, mounts=[dict(item['mounts'][0], Options={'synthetic': 'canary'})]),
                    dict(item, mounts={}),
                    dict(item, mounts=[None]),
                    {key: value for key, value in item.items() if key != 'devices'})
        with mock.patch.object(docker, 'ids', return_value=[self.cid]), mock.patch.object(docker, 'call') as call:
            for index, broad in enumerate(variants):
                with self.subTest(index=index):
                    call.return_value = json.dumps(broad).encode()
                    with self.assertRaises(mp.Blocked):
                        docker.inspect(self.cid)
            args = call.call_args.args
            self.assertEqual(args[:2], ('inspect', '--format'))
            self.assertEqual(args[2], mp.Docker.FORMAT)
            for token in ('{{json .Mounts}}', '{{json .Config}}', '{{json .HostConfig}}', '.Env', '.Options'):
                self.assertNotIn(token, args[2])

    def test_alternate_authority_cannot_enroll_same_storage(self):
        with self.provider() as first:
            first.enroll(self.cid)
            other = mp.Provider(self.root / 'alternate', self.storage, docker=self.docker, owner_uid=os.geteuid())
            other._require_host = lambda: None
            with self.assertRaises((mp.Blocked, BlockingIOError)):
                with other as second:
                    second.enroll(self.cid)

    def test_unrelated_pier_pending_is_refused_unchanged(self):
        with self.provider() as p:
            self.admitted_import(p)
            (self.storage / 'pier' / ('.runtime-' + 'f'*32)).write_bytes(b'unproven evidence')
            before = {str(x): x.read_bytes() for x in self.storage.rglob('*') if x.is_file()}
            with self.assertRaises(mp.Blocked):
                p.recover()
            self.assertEqual(before, {str(x): x.read_bytes() for x in self.storage.rglob('*') if x.is_file()})

    def test_default_named_volume_restart_contract(self):
        self.info['restart'] = 'unless-stopped'
        self.info['mounts'][0].update(Type='volume', Name='dappnode_ship_data')
        self.docker.volume.return_value = {'name': 'dappnode_ship_data', 'driver': 'local',
                                          'scope': 'local', 'options_empty': True,
                                          'mountpoint': str(self.storage)}
        def stopped(cid):
            self.info.update(restart='no', status='exited', running=False)
        self.docker.stop.side_effect = stopped
        with self.provider() as p:
            self.admitted_import(p)
            self.assertEqual(p.state['phase'], 'ACTIVE')
            self.docker.restart.assert_called_once_with(self.cid, 'unless-stopped')
            p.recover()
            self.assertEqual(p.state['phase'], 'RECOVERED')
            self.docker.remove.assert_called_once_with(self.cid)

    def test_nonlocal_or_configured_named_volume_refused_before_enrollment(self):
        self.info['mounts'][0].update(Type='volume', Name='dappnode_ship_data')
        for changed in ({'driver': 'nfs'}, {'scope': 'global'}, {'options_empty': False},
                        {'mountpoint': str(self.root / 'other')}):
            self.docker.volume.return_value = dict(name='dappnode_ship_data', driver='local',
                scope='local', options_empty=True, mountpoint=str(self.storage), **{}) | changed
            with self.provider() as p:
                with self.assertRaises(mp.Blocked):
                    p.enroll(self.cid)
                self.assertIsNone(p.state)

    def test_restart_disable_not_acknowledged_refuses_before_migration(self):
        with self.provider() as p:
            self.admitted_import(p)
            self.info['restart'] = 'unless-stopped'
            with self.assertRaises(mp.Blocked):
                p.recover()
            self.docker.remove.assert_not_called()
            self.assertFalse((self.storage / 'pier/.runtime-owner.json').exists())

    def test_restart_restore_not_acknowledged_refuses_start(self):
        self.info['restart'] = 'unless-stopped'
        self.docker.restart.side_effect = lambda *_: self.info.update(restart='no')
        with self.provider() as p:
            p.enroll(self.cid)
            with self.assertRaises(mp.Blocked):
                p.run()
            self.assertEqual(p.state['phase'], 'ACTIVE')
            self.docker.start.assert_not_called()

    def test_canonical_authority_guard_precedes_storage_access(self):
        other = mp.Provider(self.root / 'alternate', self.storage, docker=self.docker)
        with mock.patch.object(mp.sys, 'platform', 'linux'), mock.patch.object(mp.os, 'geteuid', return_value=0):
            with mock.patch.object(mp, 'open_root', side_effect=AssertionError('storage opened')):
                with self.assertRaises(mp.Blocked):
                    with other:
                        self.fail('alternate authority accepted')

    def test_host_companion_is_engine_free_and_bound_to_package_inputs(self):
        import hashlib
        output = self.root / 'host-companion'
        result = subprocess.run([sys.executable, '-B', str(TOOLS.parents[1] / 'tools/prepare-maintenance-host.py'),
                                 '--output', str(output)], capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        manifest = json.loads((output / 'manifest.json').read_bytes())
        self.assertFalse(manifest['deployment_qualified'])
        self.assertEqual(manifest['authority'], '/var/lib/uvm-maintenance')
        self.assertEqual(manifest['files']['docker-compose.yml'], hashlib.sha256(
            (TOOLS.parents[1] / 'docker-compose.yml').read_bytes()).hexdigest())
        for name, digest in manifest['files'].items():
            self.assertEqual(hashlib.sha256((output / name).read_bytes()).hexdigest(), digest)
        result = subprocess.run([sys.executable, '-B', str(output / 'tools/browser-importer/maintenance_provider.py'),
                                 '--help'], capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr.decode())

# Do not rediscover the parent suite here.
for _name in list(vars(fixtures.ProviderTests)):
    if _name.startswith('test_'):
        setattr(Corrections, _name, None)
