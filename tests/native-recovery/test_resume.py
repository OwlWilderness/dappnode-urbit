"""Transition-only owned filesystem evidence: NOT root/UID10000 delivery."""
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import types
import unittest
sys.path.insert(0,str(Path(__file__).parents[2]/'tools/native-recovery/service'))
import native_file_channel as channel
import permanent_recovery as base
import trusted_admin_journal as journal

class OwnedFixturePermit:
    # Only the transition layer is exercised. No root-reader/stat/UID substitute.
    def __init__(self,engine,op):
        self.command={'operation':op,'sequence':engine.record.get('native_sequence',0)+1,
            'old_container_id':'a'*64,'container_id':'b'*64,
            'runtime_sha256':base.digest(engine._raw('runtime.json')),
            'job_sha256':base.digest(engine._raw('job.json')),
            'prior_state_sha256':base.digest(engine._raw('legacy-recovery-state.json')) if op=='reconcile' else None,
            'generation':engine.generation,'transaction':os.urandom(16).hex()}
        self.raw=json.dumps(self.command).encode();self.receipt_raw=b'OWNED FIXTURE ONLY'
    def verify_delegation(self,target,bindings=None): pass

class Transitions(channel.FileEngine):
    # Do not invoke packaged constructor or polling on an unprivileged host.
    # Exercise inherited real lock/load/save plus actual new transition methods.
    def __init__(self,**paths): base.RecoveryEngine.__init__(self,**paths)

class Resume(unittest.TestCase):
    def test_replay_expiry_and_generation_refuse_before_root_delivery(self):
        engine=types.SimpleNamespace(generation='c'*64,record={'native_sequence':7})
        c=dict(policy=channel.POLICY,generation=engine.generation,sequence=8,transaction='a'*32,
            operation='reconcile',expires=int(time.time())+120,old_container_id='a'*64,container_id='b'*64,
            sources=channel.source_hashes(),native_receipt_sha256='d'*64,runtime_sha256='e'*64,
            job_sha256='f'*64,confirmation=None,prior_state_sha256='1'*64)
        for change,diagnostic in [({'sequence':7},'sequence/expiry'),({'expires':int(time.time())-1},'sequence/expiry'),
                ({'generation':'d'*64},'Stale worker generation'),({'prior_state_sha256':None},'prior durable state')]:
            with self.subTest(change=change),self.assertRaisesRegex(channel.Refused,diagnostic):
                channel.Delegation(engine,json.dumps({**c,**change}).encode(),None)

    def test_known_writer_outcome_survives_load_without_reauthorization(self):
        with tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve(),prefix='b1-load-') as tmp:
            paths={k:Path(tmp)/k for k in ('pier','uploads','control','evidence')}
            for p in paths.values(): p.mkdir(mode=0o700)
            engine=Transitions(**paths)
            engine.save('WRITER_ADMITTED',native_sequence=3,native_outcome='COMPLETE')
            old_generation=engine.generation;engine.close()
            engine=Transitions(**paths)
            try:
                self.assertEqual(engine.record['state'],'WRITER_ADMITTED',
                    'B1: load discarded known prior outcome instead of preserving it for explicit reconciliation')
                self.assertNotEqual(engine.generation,old_generation)
                self.assertEqual(engine.record['generation'],old_generation)
            finally: engine.close()

    def test_reopen_reconcile_and_interrupted_writer(self):
        with tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve(),prefix='b1-') as tmp:
            paths={k:Path(tmp)/k for k in ('pier','uploads','control','evidence')}
            for p in paths.values(): p.mkdir(mode=0o700)
            (paths['pier']/'ship/.urb').mkdir(parents=True,mode=0o700)
            payload=paths['pier']/'ship/.urb/fixture';payload.write_bytes(b'retained fixture')
            before=payload.stat()
            job=json.dumps(dict(id='a'*32,state='READY_LOCKED',offset=9,total_bytes=9,
                expanded_limit=4096,expanded_bytes=32,files=1)).encode()
            for name,raw in [('runtime.json',b'{"state":"RUNNING"}'),('job.json',job),('writer.lock',b'')]:
                p=paths['control']/name;p.write_bytes(raw);p.chmod(0o600)
            engine=Transitions(**paths)
            try:
                # Baseline can perform repair but has no reusable transition path.
                self.assertTrue(callable(getattr(engine,'_apply',None)),
                    'B1: actual delegated transition path lacks explicit reconcile')
                engine._apply(OwnedFixturePermit(engine,'repair'))
                self.assertEqual(engine.record['state'],'REPAIRED')
                original_evidence=engine.record['evidence']; original_generation=engine.generation
                record_bytes=engine._raw('legacy-recovery-state.json')
            finally: engine.close()
            engine=Transitions(**paths)
            try:
                self.assertNotEqual(engine.generation,original_generation)
                self.assertEqual(engine._raw('legacy-recovery-state.json'),record_bytes,'boot must not rewrite evidence')
                with self.assertRaises(channel.Refused): engine._apply(OwnedFixturePermit(engine,'start'))
                bad=OwnedFixturePermit(engine,'reconcile');bad.command['prior_state_sha256']='0'*64
                with self.assertRaisesRegex(channel.Refused,'Prior durable outcome changed'):engine._apply(bad)
                self.assertEqual(engine._raw('legacy-recovery-state.json'),record_bytes)
                engine._apply(OwnedFixturePermit(engine,'reconcile'))
                self.assertEqual(engine.record['state'],'REPAIRED')
                self.assertEqual(engine.record['generation'],engine.generation)
                self.assertEqual(engine.record['native_sequence'],2)
                self.assertEqual(engine.record['evidence'],original_evidence)
                # A runtime change with no admitted Start is NOT an interrupted writer.
                runtime=paths['control']/'runtime.json';stopped=runtime.read_bytes()
                runtime.write_bytes(b'{"state":"RUNNING"}')
                retained_state=engine._raw('legacy-recovery-state.json')
                with self.assertRaises(channel.Refused): engine._apply(OwnedFixturePermit(engine,'reconcile'))
                self.assertEqual(engine._raw('legacy-recovery-state.json'),retained_state)
                runtime.write_bytes(stopped)
                # Known interrupted Start: actual durable intent, no fake child launch.
                p=OwnedFixturePermit(engine,'start')
                engine.save('WRITER_ADMITTED',native_sequence=p.command['sequence'],
                    native_command_raw=p.raw.decode(),native_command_sha256=base.digest(p.raw),
                    native_pending=p.command,native_outcome='PENDING')
                runtime=paths['control']/'runtime.json';runtime.write_bytes(b'{"state":"RUNNING"}');runtime.chmod(0o600)
            finally: engine.close()
            engine=Transitions(**paths)
            try:
                engine._apply(OwnedFixturePermit(engine,'reconcile'))
                self.assertEqual(engine.record['state'],'REPAIRED')
                self.assertEqual(journal._object(engine._raw('runtime.json')),{'state':'STOPPED'})
                self.assertEqual(engine.record['evidence'],original_evidence)
                self.assertTrue(engine.record['native_reconciliations'])
                self.assertEqual(engine._raw('job.json'),job)
                self.assertEqual(payload.read_bytes(),b'retained fixture');self.assertEqual(payload.stat(),before)
                # Partial/unaccounted repair must stay fenced, not manufacture success.
                engine.save('REPAIRING',native_pending={**engine.record['native_pending'],'operation':'repair'},native_outcome='PENDING')
                state=engine._raw('legacy-recovery-state.json')
                with self.assertRaises(channel.Refused): engine._apply(OwnedFixturePermit(engine,'reconcile'))
                self.assertEqual(engine._raw('legacy-recovery-state.json'),state)
            finally: engine.close()

if __name__=='__main__': unittest.main(verbosity=2)
