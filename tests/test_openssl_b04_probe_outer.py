"""Host-only outer lifecycle fixtures. Never connects to an engine."""
import importlib
import unittest
import tempfile
import time
from pathlib import Path
from tools.issue3_crypto_tls_probe import outer


def fixture():
    return dict(base=dict(image_id='sha256:'+'1'*64, os='linux',architecture='amd64',
                         volumes=0,onbuild=0),
                python=dict(path='/usr/local/bin/python3.12',bytes=12,sha256='2'*64),
                loader=dict(path='/lib/ld-musl-x86_64.so.1',bytes=12,sha256='3'*64),
                amd64_execution_binding=dict(kind='exact-emulator',sha256='4'*64),
                transport=dict(path='/Applications/Docker.app/Contents/Resources/bin/docker',
                    sha256='b12e1e7a3cd2cebd2d3b03bbb58368e7c2439a3c09003e175029815b6ccc0e24',
                    endpoint='unix:///var/run/docker.sock',engine_id='engine'),
                controllers={},host_controllers={},host_python={},toolchain={},manifest={},pair='original',
                mounts=dict(inputs='/fixture/inputs',controller='/fixture/controller',
                            toolchain='/fixture/toolchain',request='/fixture/request',observer='/fixture/observer'),
                name='issue3-b04-probe-test-compile',phase='compile',
                experiment=dict(deadline_monotonic=time.monotonic()+510,ceiling_seconds=510),
                settlement_allowance_seconds=60)


class Fake:
    def __init__(self, profile):
        self.profile=profile; self.calls=[]; self.cid='a'*64
        self.row=None
    def identity(self, profile):
        self.calls.append('identity')
    def collision(self, name):
        self.calls.append('collision'); return False
    def create(self, argv):
        self.calls.append('create')
        self.row=outer.expected(self.profile,self.cid)
        return self.cid
    def inspect(self, target, timeout=10):
        self.calls.append('inspect')
        if self.row is None: return None
        return dict(self.row)
    def attach(self, cid, folder, seconds, monitor):
        self.calls.append('start')
        self.row.update(status='running',running=True,pid=42,started_at='2026-start')
        monitor(dict(observed_unix=time.time(),engine_free_bytes=32*1024**3,cgroup='0::/',
                     controls=outer.guest_limits(self.profile['phase'])))
        self.row.update(status='exited',running=False,pid=0)
        return dict(reason='EXIT',returncode=0,reaped=True,export=dict(artifact_validated=True))
    def stop(self,cid,timeout):
        self.calls.append('stop'); self.row.update(status='exited',running=False,pid=0)
    def kill(self,cid,timeout):
        self.calls.append('kill'); self.row.update(status='exited',running=False,pid=0)



class OuterTests(unittest.TestCase):
    def setUp(self):
        from unittest.mock import patch
        from types import SimpleNamespace
        mock=patch('tools.issue3_crypto_tls_probe.outer.shutil.disk_usage',return_value=SimpleNamespace(free=32*1024**3))
        mock.start(); self.addCleanup(mock.stop)

    def test_prepare_is_nonexecuting_and_lists_missing_bindings(self):
        from tools.issue3_crypto_tls_probe import outer
        calls = []
        result = outer.prepare({}, lambda *args: calls.append(args))
        self.assertFalse(result['ready'])
        self.assertIn('base', result['missing'])
        self.assertEqual(calls, [])


    def test_runtime_profile_carries_global_deadline_and_debits_shared_settlement(self):
        import json,hashlib
        from tools.issue3_crypto_tls_probe import wire
        with tempfile.TemporaryDirectory() as d:
            root=Path(d); p=fixture(); p['experiment']=dict(deadline_monotonic=time.monotonic()+510,ceiling_seconds=510)
            p['settlement_allowance_seconds']=60
            binary=dict(bytes=120,sha256='8'*64)
            receipt=dict(status='TRANSPORT_SETTLED',settled=True,settlement_elapsed_seconds=2.0,
                profile_sha256=hashlib.sha256(wire.encoded(p)).hexdigest(),
                process=dict(export=dict(phase='compile',artifact_validated=True,binary=binary)))
            (root/'intent.json').write_bytes(wire.encoded(dict(profile=p)))
            (root/'final-result.json').write_bytes(wire.encoded(receipt))
            run=outer.run_profile(root/'final-result.json',str(root/'program'),str(root/'request'),str(root/'observer'),'issue3-b04-probe-test-run')
            self.assertEqual(run['settlement_allowance_seconds'],58)
            self.assertEqual(run['experiment'],p['experiment'])
            self.assertEqual(run['probe'],binary)
            self.assertEqual(run['phase'],'run')
            self.assertEqual(outer.prior_compile(run)['status'],'TRANSPORT_SETTLED')
            run['experiment']=dict(p['experiment'],deadline_monotonic=time.monotonic()+511)
            with self.assertRaisesRegex(ValueError,'lineage'): outer.prior_compile(run)

    def test_profile_assembly_binds_known_bytes_without_inventing_emulation(self):
        p=fixture()
        snapshot={k:p[k] for k in ('base','python','loader','transport')}
        compiler=dict(archive=dict(sha256='5'*64),compiler=dict(sha256='6'*64),
                      files={'known':{}},sysroot_inventory_sha256='7'*64)
        result=outer.compile_profile(snapshot,compiler,{'fixture':True},p['mounts'],p['name'])
        self.assertIsNone(result['amd64_execution_binding'])
        self.assertIn('amd64_execution_binding',outer.prepare(result)['missing'])
        self.assertEqual(result['toolchain']['inventory_sha256'],'7'*64)
        self.assertIn('phase_worker.py',result['controllers'])
        self.assertEqual(set(result['host_controllers']),{'outer.py','docker_transport.py','watchdog.py'})
        self.assertEqual(result['phase'],'compile')

    def test_every_missing_inspect_field_refuses_before_any_write(self):
        p=fixture(); row=outer.expected(p,'a'*64)
        for key in row:
            with self.subTest(key=key):
                incomplete=dict(row); incomplete.pop(key)
                with self.assertRaisesRegex(ValueError,'complete independent inspect'):
                    outer.controls(p,'a'*64,incomplete)

    def test_stop_response_loss_falls_through_to_exact_kill_readback(self):
        p=fixture(); daemon=Fake(p); daemon.create(outer.command(p))
        daemon.row.update(status='running',running=True,pid=42,started_at='start')
        def stop(cid,timeout):
            self.assertEqual(cid,daemon.cid); daemon.calls.append('stop'); raise OSError('lost response')
        daemon.stop=stop
        result=outer.settle(p,daemon.cid,daemon,time.monotonic()+1)
        self.assertFalse(result['running']); self.assertEqual(result['pid'],0)
        self.assertIn('kill',daemon.calls)

    def test_legacy_tmpfs_readback_is_not_in_bind_mount_slice(self):
        p=fixture(); row=outer.expected(p,'a'*64)
        self.assertEqual({m['type'] for m in row['mounts']},{'bind'})
        self.assertEqual(set(row['tmpfs']),{'/work','/output'})

    def test_single_threaded_phase_supervision_reaps_failed_child(self):
        import os
        from tools.issue3_crypto_tls_probe import phase_worker
        with tempfile.TemporaryDirectory() as d:
            marker=Path(d)/'child'
            def child(): marker.write_text('public'); return 7
            heartbeats=[]
            status=phase_worker.fork_supervise(child,lambda:heartbeats.append(True),1)
            self.assertEqual(os.waitstatus_to_exitcode(status),7)
            self.assertTrue(marker.is_file()); self.assertTrue(heartbeats)
            def bad_heartbeat(): raise ValueError('receipt loss')
            with self.assertRaisesRegex(ValueError,'receipt loss'):
                phase_worker.fork_supervise(lambda:__import__('time').sleep(3),bad_heartbeat,1)

    def test_selective_toolchain_stager_never_runs_compiler(self):
        import io,tarfile,hashlib,os
        from tools.issue3_crypto_tls_probe import toolchain_stage
        with tempfile.TemporaryDirectory() as d:
            root=Path(d); path=root/'archive.tar.xz'; files={}
            with tarfile.open(path,'w:xz') as tar:
                for name,data in [('zig-root/zig',b'not executed'),('zig-root/lib/libc/a.h',b'header'),('zig-root/README',b'excluded')]:
                    row=tarfile.TarInfo(name); row.size=len(data); tar.addfile(row,io.BytesIO(data))
                    if not name.endswith('README'): files[name]=dict(bytes=len(data),sha256=hashlib.sha256(data).hexdigest(),mode=0o755)
            raw=path.read_bytes(); pin=dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
            result=toolchain_stage.stage_inventory(root/'new',path,pin,'zig-root',files)
            self.assertFalse(result['compiler_executed'])
            self.assertEqual(result['files'],2)
            self.assertEqual((root/'new/toolchain/zig').read_bytes(),b'not executed')
            self.assertFalse((root/'new/toolchain/README').exists())
            with self.assertRaises(FileExistsError): toolchain_stage.stage_inventory(root/'new',path,pin,'zig-root',files)
            for p in (root/'new').rglob('*'):
                if p.is_dir(): p.chmod(0o700)
            (root/'new/toolchain').chmod(0o700)

    def test_real_host_child_transports_capped_public_artifact_stream(self):
        import hashlib,struct,sys
        from tools.issue3_crypto_tls_probe import docker_transport as dt, phase_worker, wire
        with tempfile.TemporaryDirectory() as d:
            root=Path(d); outputs=root/'outputs'; outputs.mkdir()
            binary=bytearray(120); binary[:7]=b'\x7fELF\x02\x01\x01'
            struct.pack_into('<HH',binary,16,2,62); struct.pack_into('<Q',binary,32,64)
            struct.pack_into('<HH',binary,54,56,1); struct.pack_into('<I',binary,64,1)
            (outputs/'probe').write_bytes(binary); (outputs/'probe.map').write_bytes(b'fixture map')
            pin=lambda data:dict(bytes=len(data),sha256=hashlib.sha256(data).hexdigest())
            (outputs/'compile-result.json').write_bytes(wire.encoded(dict(binary=pin(binary),map=pin(b'fixture map'))))
            (outputs/'worker.json').write_bytes(wire.encoded(dict(success=True,heartbeat_errors=[])))
            with (root/'wire').open('wb') as stream: phase_worker.emit_export('compile',outputs,stream)
            script=root/'child.py'
            script.write_text('import sys,time,pathlib,json\nprint("ISSUE3_GUEST "+json.dumps({"fixture":True}),flush=True)\ntime.sleep(.2)\nsys.stdout.buffer.write(pathlib.Path('+repr(str(root/'wire'))+').read_bytes())\nsys.stdout.buffer.flush()\n')
            daemon=dt.DockerCLI(fixture(),root/'queries')
            daemon.argv=(sys.executable,str(script)); records=[]; (root/'attempt').mkdir()
            row=daemon.attach('a'*64,root/'attempt',2,lambda guest:records.append(guest))
            self.assertTrue(row['reaped']); self.assertEqual(row['returncode'],0)
            self.assertTrue(row['export']['artifact_validated'])
            self.assertFalse(row['export']['target_crypto_qualified'])
            self.assertTrue(records)
            self.assertEqual((root/'attempt/public/probe').read_bytes(),binary)

    def test_cached_layer_runtime_identity_records_whiteouts(self):
        import io,tarfile,hashlib
        from tools.issue3_crypto_tls_probe import cached_base
        payload=io.BytesIO()
        with tarfile.open(fileobj=payload,mode='w') as tar:
            for name,data in [('usr/bin/python3.12',b'public'),('usr/bin/.wh.python3.12',b'')]:
                row=tarfile.TarInfo(name); row.size=len(data); tar.addfile(row,io.BytesIO(data))
        result=cached_base.layer_inventory(io.BytesIO(payload.getvalue()))
        self.assertIn('usr/bin/python3.12',result['files'])
        self.assertIn('usr/bin/python3.12',result['deleted'])
        self.assertEqual(result['sha256'],hashlib.sha256(payload.getvalue()).hexdigest())

    def test_watchdog_settles_exact_partial_create_after_parent_loss(self):
        from tools.issue3_crypto_tls_probe import watchdog
        with tempfile.TemporaryDirectory() as d:
            root=Path(d); p=fixture(); daemon=Fake(p)
            daemon.create(outer.command(p)); daemon.row.update(status='running',running=True,pid=42,started_at='start')
            from tools.issue3_crypto_tls_probe.stage import save_new
            save_new(root/'create-spent.json',b'{}')
            result=watchdog.guard(p,root,daemon,parent_alive=lambda:False,deadline=__import__('time').monotonic()+1)
            self.assertTrue(result['settled'])
            self.assertIn('stop',daemon.calls)
            self.assertNotIn('start',daemon.calls)
            self.assertEqual(result['container_id'],daemon.cid)

    def test_namespace_receipt_requires_private_cgroup_and_readonly_mount(self):
        from tools.issue3_crypto_tls_probe import phase_worker
        with tempfile.TemporaryDirectory() as d:
            root=Path(d); proc=root/'proc'; cg=root/'cg'; (proc/'self').mkdir(parents=True); cg.mkdir()
            for name,value in outer.guest_limits('compile').items(): (cg/name).write_text(value)
            (proc/'self/cgroup').write_text('0::/\n')
            mount=proc/'self/mountinfo'; mount.write_text('1 2 0:3 / /sys/fs/cgroup ro,nosuid,nodev,noexec - cgroup2 cgroup ro\n')
            row=phase_worker.namespace_controls('compile',proc,cg)
            self.assertEqual(row['controls'],outer.guest_limits('compile'))
            for contents in ('0::/wrong\n','1:memory:/\n'):
                (proc/'self/cgroup').write_text(contents)
                with self.assertRaisesRegex(ValueError,'cgroup identity'): phase_worker.namespace_controls('compile',proc,cg)
            (proc/'self/cgroup').write_text('0::/\n')
            mount.write_text('1 2 0:3 / /sys/fs/cgroup rw - cgroup2 cgroup rw\n')
            with self.assertRaisesRegex(ValueError,'readonly'): phase_worker.namespace_controls('compile',proc,cg)

    def test_command_has_hard_caps_no_network_or_writable_host_mount(self):
        p=fixture(); cmd=outer.command(p)
        for word in ('--network=none','--pull=never','--read-only','--cgroupns=private','--ipc=none',
                     '--memory=1073741824','--memory-swap=1073741824','--pids-limit=64','--log-driver=none'):
            self.assertIn(word,cmd)
        self.assertEqual(cmd[-3:],['-I','-S','/controller/tools/issue3_crypto_tls_probe/phase_worker.py'])
        self.assertTrue(all('readonly' in v for v in cmd if v.startswith('--mount=')))
        self.assertFalse(any(v.startswith(('--volume','--publish','--privileged')) for v in cmd))
        p['phase']='run'; p['mounts']['program']='/fixture/program'; p['probe']={}
        self.assertIn('--memory=268435456',outer.command(p))
        self.assertIn('--pids-limit=16',outer.command(p))

    def test_export_rejects_links_traversal_and_unknown_output(self):
        import io,tarfile
        from tools.issue3_crypto_tls_probe import docker_transport as dt
        for name,kind in (('../escape','file'),('unknown','file'),('compile/stdout','link')):
            with self.subTest(name=name,kind=kind),tempfile.TemporaryDirectory() as d:
                root=Path(d); archive=root/'stream'; payload=io.BytesIO()
                with tarfile.open(fileobj=payload,mode='w') as tar:
                    row=tarfile.TarInfo(name)
                    if kind=='link': row.type=tarfile.SYMTYPE; row.linkname='/etc/passwd'
                    tar.addfile(row,io.BytesIO(b''))
                archive.write_bytes(b'ISSUE3_EXPORT\n'+payload.getvalue())
                with self.assertRaises(ValueError): dt.export_public(archive,root/'public','compile')

    def test_capture_monitor_exception_kills_and_reaps_host_fixture(self):
        import sys
        from tools.issue3_crypto_tls_probe import supervisor
        with tempfile.TemporaryDirectory() as d:
            def monitor(): raise ValueError('observer lost')
            row=supervisor.capture((sys.executable,'-c','import time; time.sleep(5)'),Path(d)/'capture',
                dict(supervisor.BUDGETS['run'],seconds=1),monitor=monitor)
            self.assertTrue(row['reaped'])
            self.assertEqual(row['reason'],'LAUNCH_OR_CAPTURE_FAILURE')

    def test_faults_settle_without_retry(self):
        for fault in ('partial-create','start-loss','timeout','transport-loss','settlement-failure','missing-state','cgroup-drift'):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as d:
                p=fixture(); root=Path(d)
                for key in ('request','observer'):
                    (root/key).mkdir(); p['mounts'][key]=str(root/key)
                daemon=Fake(p)
                if fault=='partial-create':
                    original=daemon.create
                    def create(argv): original(argv); raise OSError('lost create response')
                    daemon.create=create
                elif fault in ('start-loss','timeout','transport-loss','settlement-failure','cgroup-drift'):
                    def attach(cid,folder,seconds,monitor):
                        daemon.calls.append('start'); daemon.row.update(status='running',running=True,pid=42,started_at='start')
                        if fault=='cgroup-drift':
                            monitor(dict(engine_free_bytes=32*1024**3,cgroup='0::/wrong',controls=outer.guest_limits('compile')))
                        raise TimeoutError(fault)
                    daemon.attach=attach
                    if fault=='settlement-failure':
                        daemon.stop=lambda *a,**k: None
                        daemon.kill=lambda *a,**k: None
                    if fault=='transport-loss':
                        original=daemon.inspect
                        def inspect(*a,**k):
                            if 'start' in daemon.calls: raise OSError('daemon lost')
                            return original(*a,**k)
                        daemon.inspect=inspect
                else:
                    original=daemon.inspect
                    def inspect(*a,**k):
                        row=original(*a,**k)
                        if row: row.pop('oom_killed')
                        return row
                    daemon.inspect=inspect
                result=outer.run(p,outer.grant_for(p,time.time()+100),root/'attempt',daemon)
                self.assertEqual(result['status'],'FAILED_NO_RETRY')
                self.assertLessEqual(daemon.calls.count('create'),1)
                self.assertLessEqual(daemon.calls.count('start'),1)
                if fault in ('partial-create','start-loss','timeout','cgroup-drift'):
                    self.assertTrue(result['settled'],result)
                else: self.assertFalse(result['settled'],result)

    def test_grant_expiry_during_identity_never_starts(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d); p=fixture(); daemon=Fake(p)
            for key in ('request','observer'):
                (root/key).mkdir(); p['mounts'][key]=str(root/key)
            grant=outer.grant_for(p,time.time()+100)
            def identity(profile):
                if daemon.row is not None: grant['expires_unix']=time.time()-1
            daemon.identity=identity
            result=outer.run(p,grant,root/'attempt',daemon)
            self.assertTrue(result['settled'])
            self.assertNotIn('start',daemon.calls)
            self.assertIn('approval',result['error'])

    def test_worker_import_has_no_historical_transitive_dependencies(self):
        import shutil,subprocess,os
        with tempfile.TemporaryDirectory() as d:
            root=Path(d); dest=root/'tools/issue3_crypto_tls_probe'; dest.mkdir(parents=True)
            for name in ('execution.py','supervisor.py','stage.py','prepare.py','bind_b04.py','wire.py','output_contract.py'):
                shutil.copyfile(outer.Path(outer.__file__).parent/name,dest/name)
            r=subprocess.run([__import__('sys').executable,'-c','from tools.issue3_crypto_tls_probe import execution'],
                cwd=root,env=dict(os.environ,PYTHONPATH=str(root),PYTHONDONTWRITEBYTECODE='1'),capture_output=True,timeout=5)
            self.assertEqual(r.returncode,0,r.stderr.decode())

    def test_explicit_grant_precedes_create_and_success_settles(self):
        profile=fixture(); daemon=Fake(profile)
        with tempfile.TemporaryDirectory() as d:
            root=Path(d); (root/'observer').mkdir(); (root/'request').mkdir()
            profile['mounts']['observer']=str(root/'observer')
            profile['mounts']['request']=str(root/'request')
            with self.assertRaisesRegex(ValueError,'approval'):
                outer.run(profile,{},root/'refused',daemon)
            self.assertNotIn('create',daemon.calls)
            grant=outer.grant_for(profile,time.time()+100)
            result=outer.run(profile,grant,root/'attempt',daemon)
            self.assertTrue(result['settled'])
            self.assertFalse(result['target_qualified'])
            self.assertEqual(daemon.calls.count('create'),1)
            self.assertEqual(daemon.calls.count('start'),1)
            self.assertTrue((root/'attempt'/'started.json').is_file())


if __name__ == '__main__':
    unittest.main()
