"""Settlement-only host fixtures; all actual launch/engine seams are guarded."""
import importlib
import importlib.util
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch
from tests.test_openssl_b04_probe_outer import fixture
from tools.issue3_crypto_tls_probe import outer

HOST_POPEN=subprocess.Popen  # Captured before test-only launch guards.


class Clock:
    def __init__(self, now=100): self.now=now
    def __call__(self): return self.now


class Transport:
    def __init__(self, profile):
        self.profile=profile; self.cid='a'*64; self.calls=[]
        self.row=outer.expected(profile,self.cid)
        self.row.update(status='exited',exit_code=1,started_at='fixture-start')
        self.inventory=''
    def identity(self, profile, deadline=None): self.calls.append(('identity',deadline))
    def inspect(self, cid, timeout):
        self.calls.append(('inspect',timeout)); return self.row
    def query(self, args, timeout):
        self.calls.append((args[0],timeout))
        if args[0]=='top': raise AssertionError('top on stopped container')
        return self.inventory


class SettlementTests(unittest.TestCase):
    def setUp(self):
        for seam in ('subprocess.Popen','os.system','socket.socket.connect'):
            guard=patch(seam,side_effect=AssertionError('forbidden host-test launch/network seam'))
            guard.start(); self.addCleanup(guard.stop)

    def verifier(self):
        # Explicit scaffold RED, followed by behavioral tests once available.
        spec=importlib.util.find_spec('tools.issue3_crypto_tls_probe.settlement_verifier')
        self.assertIsNotNone(spec,'reusable strict settlement verifier is missing')
        return importlib.import_module(spec.name)

    def test_stopped_nonzero_exit_skips_top_but_checks_inventory_and_owned_processes(self):
        p=fixture(); d=Transport(p); checked=[]
        result=self.verifier().verify(p,d.cid,d,deadline=160,owned_pids=[42],owned_pgids=[43],
            process_absent=lambda kind,pid: checked.append((kind,pid)) or True,clock=Clock())
        self.assertTrue(result['safety_verified'])
        self.assertTrue(result['checked_within_shared_deadline'])
        self.assertTrue(result['release_allowed'])
        self.assertFalse(result['docker_top_invoked'])
        self.assertEqual([c[0] for c in d.calls],['identity','inspect','ps'])
        self.assertEqual(checked,[('pid',42),('pgid',43)])
        self.assertEqual(result['state']['exit_code'],1)  # safety != compiler success

    def test_running_oom_unknown_inconsistent_identity_or_missing_never_release(self):
        for change in ({'running':True,'pid':42,'status':'running'}, {'oom_killed':True},
                       {'status':'dead'}, {'pid':42}, {'id':'b'*64}, {'memory':1},
                       {'running':0}, {'pid':False}, {'exit_code':False}, {'readonly':1},
                       {'memory':1073741824.0}, {'status':'created'},
                       {'started_at':'0001-01-01T00:00:00Z'}):
            with self.subTest(change=change):
                p=fixture(); d=Transport(p); d.row.update(change)
                result=self.verifier().verify(p,d.cid,d,160,[],[],clock=Clock())
                self.assertFalse(result['release_allowed'],result)
                self.assertFalse(result['safety_verified'])
                self.assertNotIn('ps',[c[0] for c in d.calls])
        for missing in ('oom_killed','mount_options','id'):
            p=fixture(); d=Transport(p); d.row.pop(missing)
            self.assertFalse(self.verifier().verify(p,d.cid,d,160,[],[],clock=Clock())['release_allowed'])
        p=fixture(); d=Transport(p); d.row=None
        self.assertFalse(self.verifier().verify(p,d.cid,d,160,[],[],clock=Clock())['release_allowed'])

    def test_unrelated_running_inventory_refuses_exclusive_slot_release(self):
        p=fixture(); d=Transport(p); d.inventory='b'*64
        result=self.verifier().verify(p,d.cid,d,160,[],[],clock=Clock())
        self.assertFalse(result['release_allowed'])
        self.assertFalse(result['safety_verified'])

    def test_expired_identity_query_never_runs(self):
        p=fixture(); d=Transport(p)
        result=self.verifier().verify(p,d.cid,d,99,[],[],clock=Clock())
        self.assertFalse(result['release_allowed'])
        self.assertEqual(d.calls,[])

    def test_shared_endpoint_does_not_renew_on_second_acquisition(self):
        p=fixture(); p['experiment']['deadline_monotonic']=500
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            with patch.object(outer.time,'monotonic',return_value=100):
                first=outer.settlement_deadline(p,root)
            with patch.object(outer.time,'monotonic',return_value=139):
                second=outer.settlement_deadline(p,root)
            self.assertEqual(first,160)
            self.assertEqual(second,first)
            self.assertEqual(p['settlement_allowance_seconds'],60)

    def test_owner_integrates_guard_and_verifier_under_same_endpoint(self):
        from tests.test_openssl_b04_probe_outer import Fake
        from types import SimpleNamespace
        p=fixture(); p['experiment']['deadline_monotonic']=610; clock=Clock()
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            for key in ('request','observer'):
                (root/key).mkdir(); p['mounts'][key]=str(root/key)
            daemon=Fake(p); observed=[]
            def finish(folder,deadline):
                observed.append(('guard',deadline)); clock.now=140
                return dict(settled=True)
            def verify(folder,deadline):
                observed.append(('verifier',deadline)); clock.now=145
                return dict(safety_verified=True,checked_within_shared_deadline=True,release_allowed=True)
            daemon.finish_guard=finish; daemon.verify_settlement=verify
            with patch.object(outer.time,'monotonic',clock), patch.object(outer.shutil,'disk_usage',
                    return_value=SimpleNamespace(free=32*1024**3)):
                result=outer.run(p,outer.grant_for(p,time.time()+100),root/'attempt',daemon)
            self.assertEqual(observed,[('guard',160),('verifier',160)])
            self.assertEqual(result['slot_status'],'RELEASED',result)
            self.assertTrue(result['settlement_timing_certified'])
            self.assertTrue((root/'attempt/independent-verification-readback.json').is_file())

    def test_watchdog_parent_loss_consumes_existing_endpoint_remainder(self):
        from tools.issue3_crypto_tls_probe import watchdog
        from tests.test_openssl_b04_probe_outer import Fake
        p=fixture(); p['experiment']['deadline_monotonic']=610; clock=Clock()
        with tempfile.TemporaryDirectory() as d:
            root=Path(d); (root/'create-spent.json').write_text('{}')
            daemon=Fake(p); daemon.create([]); daemon.row.update(status='running',running=True,pid=42)
            timeouts=[]; original=daemon.inspect
            def inspect(cid,timeout=5):
                timeouts.append(timeout); return original(cid,timeout)
            daemon.inspect=inspect
            with patch.object(outer.time,'monotonic',clock):
                self.assertEqual(outer.settlement_deadline(p,root),160)
                clock.now=158
                result=watchdog.guard(p,root,daemon,parent_alive=lambda:False,deadline=220)
                self.assertEqual(outer.settlement_deadline(p,root),160)
            self.assertTrue(result['settled'],result)
            self.assertTrue(all(0<t<=2 for t in timeouts),timeouts)
            self.assertNotIn('start',daemon.calls)

    def test_finish_guard_wait_uses_only_shared_remainder(self):
        from tools.issue3_crypto_tls_probe import docker_transport as dt, settlement
        from unittest.mock import Mock
        p=fixture(); p['experiment']['deadline_monotonic']=610
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            with patch.object(outer.time,'monotonic',return_value=100): settlement.acquire(p,root)
            (root/'watchdog-result.json').write_text('{"settled":true}')
            daemon=dt.DockerCLI(p,root/'transport'); daemon.guard=Mock()
            with patch.object(outer.time,'monotonic',return_value=158):
                result=daemon.finish_guard(root,deadline=160)
            daemon.guard.wait.assert_called_once_with(timeout=2)
            self.assertTrue(result['settled'])

    def test_production_verifier_launch_and_wait_are_integrated_and_bounded(self):
        import json
        from unittest.mock import Mock
        from tools.issue3_crypto_tls_probe import docker_transport as dt, settlement, wire
        p=fixture(); p['experiment']['deadline_monotonic']=610; clock=Clock()
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            with patch.object(outer.time,'monotonic',clock): endpoint=settlement.acquire(p,root)
            (root/'owned.json').write_text(json.dumps(dict(container_id='a'*64)))
            daemon=dt.DockerCLI(p,root/'transport')
            self.assertTrue(hasattr(daemon,'verify_settlement'),'integrated verifier launch is missing')
            child=Mock(pid=4321,returncode=0)
            def launch(argv,**kwargs):
                self.assertIn('settlement_verifier',argv[4])
                self.assertTrue(kwargs['start_new_session'])
                clock.now=157
                (root/'independent-verification.json').write_bytes(wire.encoded(dict(
                    verifier_pid=4321,container_id='a'*64,profile_sha256=endpoint['profile_sha256'],
                    deadline_monotonic=160,safety_verified=True,checked_within_shared_deadline=True,
                    release_allowed=True,docker_top_invoked=False)))
                return child
            with patch.object(outer.time,'monotonic',clock),patch('subprocess.Popen',side_effect=launch):
                result=daemon.verify_settlement(root,deadline=160)
            child.wait.assert_called_once_with(timeout=3)
            self.assertTrue(result['release_allowed'],result)
            self.assertTrue(result['verifier_process']['reaped'])

    def test_verifier_entrypoint_reads_immutable_endpoint_and_checks_owned_id_receipts(self):
        import json
        from tools.issue3_crypto_tls_probe import settlement_verifier as sv, docker_transport as dt, settlement
        p=fixture(); p['experiment']['deadline_monotonic']=610; checked=[]
        with tempfile.TemporaryDirectory() as d:
            root=Path(d); daemon=Transport(p)
            (root/'intent.json').write_text(json.dumps(dict(profile=p)))
            (root/'owned.json').write_text(json.dumps(dict(container_id=daemon.cid)))
            (root/'watchdog-pid.json').write_text('{"pid":77}')
            (root/'attach').mkdir(); (root/'attach/pid.json').write_text('{"pid":78,"pgid":78}')
            with patch.object(outer.time,'monotonic',return_value=100): settlement.acquire(p,root)
            self.assertTrue(hasattr(sv,'main'),'separate-process verifier entrypoint missing')
            with patch.object(outer.time,'monotonic',return_value=158),patch.object(dt,'DockerCLI',return_value=daemon),\
                 patch.object(sv,'process_absent',side_effect=lambda kind,pid:checked.append((kind,pid)) or True):
                status=sv.main(['--folder',str(root)])
            self.assertEqual(status,0)
            receipt=json.loads((root/'independent-verification.json').read_text())
            self.assertTrue(receipt['release_allowed'])
            self.assertEqual(receipt['deadline_monotonic'],160)
            self.assertEqual(checked,[('pid',77),('pid',78),('pgid',78)])
            self.assertTrue(all(t<=2 for _,t in daemon.calls[1:]))

    def test_owner_expiry_after_readback_never_calls_stop_or_kill(self):
        p=fixture(); d=Transport(p); d.row.update(status='running',running=True,pid=42)
        clock=Clock(159)
        original=d.inspect
        def inspect(cid,timeout):
            result=original(cid,timeout); clock.now=161; return result
        d.inspect=inspect; mutations=[]
        d.stop=lambda *a,**k:mutations.append('stop')
        d.kill=lambda *a,**k:mutations.append('kill')
        with patch.object(outer.time,'monotonic',clock):
            with self.assertRaisesRegex(ValueError,'deadline'): outer.settle(p,d.cid,d,160)
        self.assertEqual(mutations,[])

    def test_parent_loss_watchdog_verifies_without_later_owner_handoff(self):
        import json
        from tools.issue3_crypto_tls_probe import watchdog, settlement_verifier as sv
        p=fixture(); p['experiment']['deadline_monotonic']=610
        with tempfile.TemporaryDirectory() as d:
            root=Path(d); daemon=Transport(p)
            (root/'create-spent.json').write_text('{}')
            (root/'owned.json').write_text(json.dumps(dict(container_id=daemon.cid)))
            (root/'intent.json').write_text(json.dumps(dict(profile=p,controller_pid=99)))
            with patch.object(outer.time,'monotonic',return_value=100),patch.object(sv,'process_absent',return_value=True):
                result=watchdog.guard(p,root,daemon,parent_alive=lambda:False,deadline=220)
            self.assertTrue(result['release_allowed'],result)
            self.assertTrue(result['independent_verification']['safety_verified'])
            self.assertIn('ps',[c[0] for c in daemon.calls])

    def test_delay_preserves_safe_observation_but_never_certifies_timing(self):
        p=fixture(); d=Transport(p); clock=Clock(159)
        def absent(kind,pid): clock.now=161; return True
        result=self.verifier().verify(p,d.cid,d,160,[42],[],process_absent=absent,clock=clock)
        self.assertTrue(result['safety_verified'])
        self.assertFalse(result['checked_within_shared_deadline'])
        self.assertFalse(result['release_allowed'])

    def test_identity_delay_exhausts_remainder_without_new_inspect(self):
        p=fixture(); d=Transport(p); clock=Clock(159)
        def identity(profile,deadline): d.calls.append(('identity',deadline)); clock.now=161
        d.identity=identity
        result=self.verifier().verify(p,d.cid,d,160,[],[],clock=clock)
        self.assertFalse(result['safety_verified'])
        self.assertEqual([c[0] for c in d.calls],['identity'])

    def test_owned_watchdog_or_group_presence_and_permission_error_refuse_release(self):
        p=fixture(); d=Transport(p)
        for kind in ('pid','pgid','permission'):
            def absent(k,pid):
                if kind=='permission': raise PermissionError('unresolved')
                return k!=kind
            result=self.verifier().verify(p,d.cid,d,160,[42],[43],process_absent=absent,clock=Clock())
            self.assertFalse(result['release_allowed'],result)
            self.assertFalse(result['safety_verified'])

    def test_verifier_transport_failure_is_not_absence_or_safety(self):
        p=fixture(); d=Transport(p)
        for operation in ('identity','inspect','query'):
            with self.subTest(operation=operation),patch.object(d,operation,side_effect=OSError('transport lost')):
                result=self.verifier().verify(p,d.cid,d,160,[],[],clock=Clock())
                self.assertFalse(result['release_allowed'])
                self.assertFalse(result['safety_verified'])

    def test_concurrent_endpoint_acquisition_publishes_one_complete_nonrenewable_receipt(self):
        import threading
        from concurrent.futures import ThreadPoolExecutor
        from tools.issue3_crypto_tls_probe import settlement
        p=fixture(); p['experiment']['deadline_monotonic']=610
        with tempfile.TemporaryDirectory() as d:
            root=Path(d); barrier=threading.Barrier(4); rename=settlement.os.rename
            def simultaneous(source,target): barrier.wait(timeout=5); return rename(source,target)
            with patch.object(outer.time,'monotonic',return_value=100),patch.object(settlement.os,'rename',side_effect=simultaneous):
                with ThreadPoolExecutor(max_workers=4) as pool:
                    rows=list(pool.map(lambda _:settlement.acquire(p,root),range(4)))
            self.assertTrue(all(row==rows[0] for row in rows))
            self.assertEqual(rows[0]['deadline_monotonic'],160)
            self.assertEqual(len(list(root.glob('settlement-endpoint-candidate-*'))),3)
            original=(root/settlement.NAME/'endpoint.json').read_bytes()
            with patch.object(outer.time,'monotonic',return_value=161):
                self.assertEqual(settlement.acquire(p,root),rows[0])
                with self.assertRaisesRegex(ValueError,'expired'): settlement.remaining(rows[0]['deadline_monotonic'])
            self.assertEqual((root/settlement.NAME/'endpoint.json').read_bytes(),original)

    def test_endpoint_experiment_clip_profile_drift_and_malformed_file_refuse_renewal(self):
        from tools.issue3_crypto_tls_probe import settlement
        p=fixture(); p['experiment']['deadline_monotonic']=130
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            with patch.object(outer.time,'monotonic',return_value=100):
                row=settlement.acquire(p,root)
                self.assertEqual(row['deadline_monotonic'],130)
                changed=dict(p,name=p['name']+'-other')
                with self.assertRaisesRegex(ValueError,'drift'): settlement.acquire(changed,root)
                path=root/settlement.NAME/'endpoint.json'; path.chmod(0o600); path.write_text('{}')
                with self.assertRaisesRegex(ValueError,'complete'): settlement.acquire(p,root)
                self.assertEqual(path.read_text(),'{}')

    def test_expired_verifier_never_launches_or_renews(self):
        from tools.issue3_crypto_tls_probe import docker_transport as dt, settlement
        p=fixture(); p['experiment']['deadline_monotonic']=610
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            with patch.object(outer.time,'monotonic',return_value=100): settlement.acquire(p,root)
            daemon=dt.DockerCLI(p,root/'transport')
            with patch.object(outer.time,'monotonic',return_value=160),patch('subprocess.Popen') as launch:
                with self.assertRaisesRegex(ValueError,'expired'): daemon.verify_settlement(root,deadline=160)
            launch.assert_not_called()
            self.assertFalse((root/'independent-verifier-spent.json').exists())

    def test_verifier_timeout_kills_only_observer_without_new_wait_budget(self):
        import subprocess
        from unittest.mock import Mock
        from tools.issue3_crypto_tls_probe import docker_transport as dt, settlement
        p=fixture(); p['experiment']['deadline_monotonic']=610; clock=Clock()
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            with patch.object(outer.time,'monotonic',clock): settlement.acquire(p,root)
            child=Mock(pid=4321); child.poll.return_value=None
            def wait(timeout):
                self.assertEqual(timeout,2); clock.now=160
                raise subprocess.TimeoutExpired('synthetic verifier',timeout)
            child.wait.side_effect=wait
            daemon=dt.DockerCLI(p,root/'transport'); clock.now=158
            with patch.object(outer.time,'monotonic',clock),patch('subprocess.Popen',return_value=child) as launch:
                result=daemon.verify_settlement(root,deadline=160)
            launch.assert_called_once(); child.kill.assert_called_once(); child.wait.assert_called_once()
            self.assertFalse(result['release_allowed']); self.assertFalse(result['verifier_process']['reaped'])

    def test_owner_retains_slot_for_failed_missing_delayed_or_unstarted_verifier(self):
        from tests.test_openssl_b04_probe_outer import Fake
        from types import SimpleNamespace
        for fault in ('failure','exception','missing','delay','guard-expiry'):
            with self.subTest(fault=fault),tempfile.TemporaryDirectory() as d:
                root=Path(d); p=fixture(); p['experiment']['deadline_monotonic']=610; clock=Clock()
                for key in ('request','observer'):
                    (root/key).mkdir(); p['mounts'][key]=str(root/key)
                daemon=Fake(p); called=[]
                def finish(folder,deadline):
                    if fault=='guard-expiry': clock.now=160
                    return dict(settled=True)
                def verify(folder,deadline):
                    called.append(deadline)
                    if fault=='exception': raise OSError('verifier lost')
                    if fault=='missing': return None
                    if fault=='delay': clock.now=161
                    return dict(safety_verified=fault!='failure',checked_within_shared_deadline=True,release_allowed=True)
                daemon.finish_guard=finish; daemon.verify_settlement=verify
                with patch.object(outer.time,'monotonic',clock),patch.object(outer.shutil,'disk_usage',
                        return_value=SimpleNamespace(free=32*1024**3)):
                    result=outer.run(p,outer.grant_for(p,time.time()+100),root/'attempt',daemon)
                self.assertEqual(result['slot_status'],'HELD_UNRESOLVED',result)
                self.assertEqual(result['status'],'FAILED_NO_RETRY')
                self.assertEqual(called,[] if fault=='guard-expiry' else [160])
                self.assertTrue(result['settled'])  # owner safety readback is not independent completion
                self.assertTrue((root/'attempt/final-result.json').is_file())


    def test_real_host_verifier_child_composes_transport_and_entrypoint_without_engine(self):
        import json
        from tools.issue3_crypto_tls_probe import docker_transport as dt, settlement
        p=fixture(); daemon_row=Transport(p).row
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            (root/'intent.json').write_text(json.dumps(dict(profile=p)))
            (root/'owned.json').write_text(json.dumps(dict(container_id='a'*64)))
            (root/'watchdog-pid.json').write_text('{"pid":77}')
            endpoint=settlement.acquire(p,root)
            daemon=dt.DockerCLI(p,root/'transport'); launches=[]
            def launch(argv,**kwargs):
                self.assertEqual(Path(argv[0]).resolve(),Path(sys.executable).resolve())
                self.assertEqual(argv[1:4],['-I','-S','-c'])
                self.assertIn('settlement_verifier import main',argv[4])
                launches.append(True)
                code='''import sys,subprocess,socket,os
sys.path.insert(0,REPO)
from tools.issue3_crypto_tls_probe import docker_transport as dt, settlement_verifier as sv
def forbidden(*a,**k): raise AssertionError('real launch/network forbidden in verifier child')
subprocess.Popen=forbidden
socket.socket.connect=forbidden
os.system=forbidden
class ReadonlyFixture:
    def __init__(self,*a): pass
    def identity(self,profile,deadline): pass
    def inspect(self,cid,timeout): return ROW
    def query(self,args,timeout):
        assert args==['ps','-q','--no-trunc'],args
        return ''
dt.DockerCLI=ReadonlyFixture
sv.process_absent=lambda kind,pid: kind=='pid' and pid==77
raise SystemExit(sv.main())
'''.replace('REPO',repr(str(Path(outer.__file__).resolve().parents[2]))).replace('ROW',repr(daemon_row))
                argv=list(argv); argv[4]=code
                return HOST_POPEN(argv,**kwargs)
            with patch('subprocess.Popen',side_effect=launch):
                result=daemon.verify_settlement(root,deadline=endpoint['deadline_monotonic'])
            self.assertEqual(launches,[True])
            self.assertTrue(result['release_allowed'],result)
            self.assertTrue(result['verifier_process']['reaped'])
            self.assertNotEqual(result['verifier_pid'],__import__('os').getpid())
            self.assertFalse(result['docker_top_invoked'])

    def test_generic_docker_query_still_rejects_expected_not_running_exit_one(self):
        from tools.issue3_crypto_tls_probe import docker_transport as dt
        p=fixture()
        with tempfile.TemporaryDirectory() as d:
            root=Path(d); daemon=dt.DockerCLI(p,root/'transport'); daemon.argv=(sys.executable,'unused-fixture')
            def capture(argv,folder,budget):
                folder.mkdir(parents=True)
                (folder/'stderr').write_text('container is not running')
                (folder/'stdout').write_text('')
                return dict(reason='EXIT',returncode=1,reaped=True)
            with patch.object(dt.supervisor,'capture',side_effect=capture):
                with self.assertRaisesRegex(ValueError,'bounded Docker request failed'):
                    daemon.query(['top','a'*64])

    def test_compile_profile_seals_new_host_settlement_import_closure(self):
        p=fixture(); snap={k:p[k] for k in ('base','python','loader','transport')}
        compiler=dict(archive=dict(sha256='5'*64),compiler=dict(sha256='6'*64),
                      files={'known':{}},sysroot_inventory_sha256='7'*64)
        result=outer.compile_profile(snap,compiler,{},p['mounts'],p['name'])
        self.assertEqual(set(result['host_settlement_controllers']),{'settlement.py','settlement_verifier.py'})
        self.assertEqual(result['settlement_allowance_seconds'],60)
        self.assertEqual(result['experiment']['ceiling_seconds'],510)

    def test_production_refuses_unsealed_new_settlement_modules_before_input_reads(self):
        from tools.issue3_crypto_tls_probe import docker_transport as dt
        p=fixture(); p['host_controllers']={name:{} for name in ('outer.py','docker_transport.py','watchdog.py')}
        with tempfile.TemporaryDirectory() as d:
            daemon=dt.DockerCLI(p,Path(d)/'transport')
            with patch.object(dt.execution,'verify_public_file') as read:
                with self.assertRaisesRegex(ValueError,'settlement controller binding'): daemon.verify_inputs(p)
            read.assert_not_called()

    def test_settlement_query_propagates_absolute_endpoint_through_capture(self):
        from tools.issue3_crypto_tls_probe import docker_transport as dt, settlement
        p=fixture(); p['experiment']['deadline_monotonic']=610; clock=Clock()
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            with patch.object(outer.time,'monotonic',clock): settlement.acquire(p,root)
            daemon=dt.DockerCLI(p,root/'transport'); daemon.argv=(sys.executable,'fixture-only')
            self.assertTrue(hasattr(daemon,'bind_settlement'),'absolute query endpoint binding missing')
            daemon.bind_settlement(root,deadline=160); clock.now=159
            calls=[]
            def capture(argv,folder,budget,deadline=None):
                calls.append((budget['seconds'],deadline)); clock.now=161
                folder.mkdir(parents=True); (folder/'stdout').write_text(''); (folder/'stderr').write_text('')
                return dict(reason='EXIT',returncode=0,reaped=True)
            with patch.object(outer.time,'monotonic',clock),patch.object(dt.supervisor,'capture',side_effect=capture):
                with self.assertRaisesRegex(ValueError,'expired'): daemon.query(['ps','-q','--no-trunc'],timeout=5)
            self.assertEqual(calls,[(1,160)])

    def test_capture_settlement_teardown_waits_do_not_reset_after_endpoint(self):
        from unittest.mock import Mock
        from tools.issue3_crypto_tls_probe import supervisor
        clock=Clock(); child=Mock(pid=4321,returncode=0); waits=[]
        def wait(timeout):
            waits.append(timeout)
            clock.now=159.9 if len(waits)==1 else 160
            return 0
        child.wait.side_effect=wait
        selector=Mock(); selector.__enter__=Mock(return_value=selector); selector.__exit__=Mock(return_value=False)
        selector.get_map.return_value={}
        with tempfile.TemporaryDirectory() as d,patch.object(outer.time,'monotonic',clock),\
             patch.object(supervisor.subprocess,'Popen',return_value=child),\
             patch.object(supervisor.selectors,'DefaultSelector',return_value=selector),\
             patch.object(supervisor.os,'killpg') as kill:
            result=supervisor.capture((sys.executable,'fixture-only'),Path(d)/'capture',
                                      supervisor.BUDGETS['compile'],deadline=160)
        self.assertAlmostEqual(waits[1],.1)
        self.assertEqual(waits[2],0)
        self.assertTrue(result['reaped'])

    def test_watchdog_expiry_refuses_recovery_queries_and_cannot_renew(self):
        import json
        from tools.issue3_crypto_tls_probe import watchdog, settlement
        p=fixture(); p['experiment']['deadline_monotonic']=610
        with tempfile.TemporaryDirectory() as d:
            root=Path(d); daemon=Transport(p)
            (root/'create-spent.json').write_text('{}')
            with patch.object(outer.time,'monotonic',return_value=100): endpoint=settlement.acquire(p,root)
            with patch.object(outer.time,'monotonic',return_value=160):
                result=watchdog.guard(p,root,daemon,parent_alive=lambda:False,deadline=220)
                self.assertEqual(settlement.read(p,root),endpoint)
            self.assertFalse(result['settled'])
            self.assertFalse(result['release_allowed'])
            self.assertEqual(daemon.calls,[])

    def test_verifier_missing_watchdog_identity_refuses_before_any_engine_read(self):
        import json
        from tools.issue3_crypto_tls_probe import settlement_verifier as sv, docker_transport as dt, settlement
        p=fixture(); p['experiment']['deadline_monotonic']=610
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            (root/'intent.json').write_text(json.dumps(dict(profile=p)))
            (root/'owned.json').write_text(json.dumps(dict(container_id='a'*64)))
            with patch.object(outer.time,'monotonic',return_value=100): settlement.acquire(p,root)
            with patch.object(outer.time,'monotonic',return_value=101),patch.object(dt,'DockerCLI') as engine:
                status=sv.main(['--folder',str(root)])
            engine.assert_not_called()
            self.assertEqual(status,1)
            result=json.loads((root/'independent-verification.json').read_text())
            self.assertFalse(result['release_allowed'])
            self.assertFalse(result['safety_verified'])

    def test_failed_compile_can_be_safely_released_without_claiming_workload_success(self):
        from tests.test_openssl_b04_probe_outer import Fake
        from types import SimpleNamespace
        p=fixture()
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            for key in ('request','observer'):
                (root/key).mkdir(); p['mounts'][key]=str(root/key)
            daemon=Fake(p); original=daemon.attach
            def attach(*args,**kwargs):
                row=original(*args,**kwargs); row['export']['artifact_validated']=False
                daemon.row['exit_code']=1; return row
            daemon.attach=attach
            daemon.finish_guard=lambda folder,deadline:dict(settled=True)
            daemon.verify_settlement=lambda folder,deadline:dict(safety_verified=True,
                checked_within_shared_deadline=True,release_allowed=True)
            with patch.object(outer.shutil,'disk_usage',return_value=SimpleNamespace(free=32*1024**3)):
                result=outer.run(p,outer.grant_for(p,time.time()+100),root/'attempt',daemon)
            self.assertEqual(result['status'],'FAILED_NO_RETRY')
            self.assertEqual(result['slot_status'],'RELEASED')
            self.assertFalse(result['target_qualified'])
            self.assertFalse(result['automatic_retry'])
            self.assertFalse(result['process']['export']['artifact_validated'])


if __name__=='__main__': unittest.main()
