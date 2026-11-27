"""Synthetic host-only staging/supervision. Never invokes a target toolchain."""
import hashlib
import importlib
import io
import json
import os
from pathlib import Path
import sys
import tarfile
import tempfile
import time
import unittest

AUTHORIZED_SCRATCH = Path(tempfile.gettempdir()).resolve()
SCRATCH = os.environ.get('ISSUE3_PROBE_TEST_SCRATCH', str(AUTHORIZED_SCRATCH))
if not Path(SCRATCH).resolve().is_relative_to(AUTHORIZED_SCRATCH):
    raise ValueError('host fixtures must remain inside authorized scratch')


class StageTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=SCRATCH)
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def module(self):
        self.assertTrue(Path('tools/issue3_crypto_tls_probe/stage.py').is_file(),
                        'bounded stager missing')
        return importlib.import_module('tools.issue3_crypto_tls_probe.stage')

    def fixture(self, members=None):
        rows = members or [('headers/a.h', b'header', None)]
        archive = self.root/'input.tar.gz'
        with tarfile.open(archive, 'w:gz') as t:
            for name, data, link in rows:
                i = tarfile.TarInfo(name)
                if link:
                    i.type = tarfile.SYMTYPE
                    i.linkname = link
                else:
                    i.size = len(data)
                t.addfile(i, io.BytesIO(data))
        data = archive.read_bytes()
        return archive, dict(bytes=len(data), sha256=hashlib.sha256(data).hexdigest())

    def test_exact_small_stage_is_inert_and_readonly(self):
        m = self.module()
        archive, pin = self.fixture()
        f = dict(path='include/a.h', bytes=6, sha256=hashlib.sha256(b'header').hexdigest())
        result = m.stage_selection(self.root/'attempt', archive, pin, [f],
                    {'include/a.h': {'kind':'archive-member', 'path':'headers/a.h'}}, self.root, {})
        self.assertEqual((self.root/'attempt/inputs/include/a.h').read_bytes(), b'header')
        self.assertEqual(result['status'], 'STAGED_UNAUTHENTICATED_NOT_EXECUTED')
        self.assertFalse(result['target_executed'])
        self.assertEqual((self.root/'attempt/inputs/include/a.h').stat().st_mode & 0o777, 0o444)
        self.assertFalse((self.root/'attempt/compiled').exists())
        with self.assertRaises(FileExistsError):
            m.stage_selection(self.root/'attempt', archive, pin, [f],
                {'include/a.h': {'kind':'archive-member', 'path':'headers/a.h'}}, self.root, {})

    def test_hardlinked_public_input_refuses(self):
        m = self.module()
        source = self.root/'source'
        source.write_bytes(b'public')
        os.link(source, self.root/'alias')
        with self.assertRaisesRegex(ValueError, 'single-link'):
            with m.open_regular(source):
                pass

    def test_archive_failures_preserve_partial_attempt_no_ready_receipt(self):
        m = self.module()
        f = dict(path='include/a.h', bytes=6, sha256=hashlib.sha256(b'header').hexdigest())
        for index, rows in enumerate([
            [('headers/a.h',b'header',None),('headers/a.h',b'header',None)],
            [('headers/a.h',b'header',None),('HEADERS/A.H',b'header',None)],
            [('headers/a.h',b'header',None),('../escape',b'x',None)],
            [('headers/a.h',b'header','elsewhere')],
            [('headers/other.h',b'header',None)],
            [('headers/a.h',b'broken',None)],
        ]):
            with self.subTest(index=index):
                archive, pin = self.fixture(rows)
                dest = self.root/f'bad{index}'
                with self.assertRaises(ValueError):
                    m.stage_selection(dest, archive, pin, [f],
                        {'include/a.h':dict(kind='archive-member',path='headers/a.h')}, self.root, {})
                self.assertTrue((dest/'intent.json').exists())
                self.assertTrue((dest/'stage-failed.json').exists())
                self.assertFalse((dest/'stage.json').exists())
                self.assertFalse((self.root/'escape').exists())

    def test_source_symlink_and_parent_symlink_refuse(self):
        m = self.module()
        (self.root/'source').write_bytes(b'public')
        (self.root/'alias').symlink_to(self.root/'source')
        (self.root/'parent').symlink_to(self.root, target_is_directory=True)
        for p in [self.root/'alias', self.root/'parent/source']:
            with self.assertRaises(OSError):
                with m.open_regular(p):
                    pass

    def test_unselected_public_punctuation_does_not_block_exact_selection(self):
        m = self.module()
        archive,pin = self.fixture([('headers/a.h',b'header',None),
            ('unselected/lt~obsolete.m4',b'not staged',None),
            ('unselected/wasm3 Release.xcscheme',b'not staged',None)])
        f = dict(path='include/a.h',bytes=6,sha256=hashlib.sha256(b'header').hexdigest())
        m.stage_selection(self.root/'safe',archive,pin,[f],
            {'include/a.h':dict(kind='archive-member',path='headers/a.h')},self.root,{})
        self.assertEqual([p.relative_to(self.root/'safe/inputs').as_posix()
            for p in (self.root/'safe/inputs').rglob('*') if p.is_file()],['include/a.h'])

    def test_complete_352_synthetic_mixed_origin_selection_prepares_inertly(self):
        m = self.module()
        prep = importlib.import_module('tools.issue3_crypto_tls_probe.prepare')
        roles = [('libssl','lib/libssl.a'),('libcrypto','lib/libcrypto.a'),
            ('libaes_siv','lib/libaes_siv.a'),('build_config','config/configdata.pm'),
            ('siv_header','include/aes_siv.h'),('arena_c','arena/openssl_owned_arena.c'),
            ('arena_h','arena/openssl_owned_arena.h'),('arena_engine','arena/palloc_engine.inc'),
            ('dependency_contract','contract.json')]
        roles += [('header','include/openssl/'+n) for n in ('ssl.h','evp.h','opensslv.h')]
        roles += [('config','include/openssl/'+n) for n in ('configuration.h','opensslconf.h')]
        roles += [('header',f'include/internal/fixture{i}.h') for i in range(338)]
        payload = b'public synthetic only'
        pin = dict(bytes=len(payload),sha256=hashlib.sha256(payload).hexdigest())
        files,origins,members = [],{},[]
        for index,(role,name) in enumerate(roles):
            files.append(dict(role=role,path=name,**pin))
            if index < 4:
                (self.root/f'retained{index}').write_bytes(payload)
                origins[name] = dict(kind='retained-file',path=f'retained{index}')
            elif role == 'dependency_contract':
                origins[name] = dict(kind='canonical-generated-json')
            else:
                origin = 'source/'+name
                origins[name] = dict(kind='archive-member',path=origin)
                members.append((origin,payload,None))
        self.assertEqual(len(files),352)
        archive,archive_pin = self.fixture(members)
        row = m.stage_selection(self.root/'full',archive,archive_pin,files,origins,self.root,
                              {'contract.json':payload})
        self.assertEqual(row['files'],352)
        manifest = dict(schema='issue3-b04-probe-input-v1',evidence_scope='retained-library-only',
                        candidate_sha256=prep.B04_SHA,candidate_bytes=prep.B04_BYTES,
                        final_link_authenticated=False,files=files)
        plan = prep.prepare(self.root/'full/inputs',manifest)
        self.assertFalse(plan['target_executed'])
        self.assertFalse(plan['dependency_contract_semantics_verified'])


class SupervisorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=SCRATCH)
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def module(self):
        self.assertTrue(Path('tools/issue3_crypto_tls_probe/supervisor.py').is_file(),
                        'bounded process supervisor missing')
        return importlib.import_module('tools.issue3_crypto_tls_probe.supervisor')

    def test_host_fixture_process_capture_and_one_shot(self):
        m = self.module()
        result = m.host_fixture((sys.executable,'-c','print("fixture")'), self.root/'one')
        self.assertEqual(result['returncode'], 0)
        self.assertTrue(result['reaped'])
        self.assertFalse(result['target_evidence'])
        self.assertEqual((self.root/'one/stdout').read_bytes(), b'fixture\n')
        with self.assertRaises(FileExistsError):
            m.host_fixture((sys.executable,'-c','print("replay")'), self.root/'one')

    def test_timeout_kills_and_reaps_preserving_captures(self):
        m = self.module()
        row = m.host_fixture((sys.executable,'-c',
            'import time; print("entered",flush=True); time.sleep(10)'),self.root/'slow', seconds=.15)
        self.assertEqual(row['reason'], 'TIMEOUT')
        self.assertTrue(row['reaped'])
        self.assertEqual((self.root/'slow/stdout').read_bytes(),b'entered\n')

    def test_output_overflow_is_stopped_not_truncated_pass(self):
        m = self.module()
        row = m.host_fixture((sys.executable,'-c','print("x"*100000)'),self.root/'loud',cap=100)
        self.assertEqual(row['reason'],'OUTPUT_LIMIT')
        self.assertEqual((self.root/'loud/stdout').stat().st_size,100)
        self.assertTrue(row['reaped'])

    def test_combined_capture_never_persists_over_cap(self):
        m = self.module()
        budget = dict(m.BUDGETS['run'],combined_capture=100)
        row = m.capture((sys.executable,'-c',
            'import os; os.write(1,b"x"*80); os.write(2,b"y"*80)'),self.root/'combined',budget)
        self.assertEqual(row['reason'],'OUTPUT_LIMIT')
        self.assertLessEqual(sum((self.root/'combined'/n).stat().st_size for n in ('stdout','stderr')),100)

    def test_nonzero_and_launch_failure_preserved(self):
        m = self.module()
        failed = m.host_fixture((sys.executable,'-c','raise SystemExit(7)'),self.root/'failed')
        self.assertEqual(failed['returncode'],7)
        missing = m.host_fixture(('/does-not-exist-fixture',),self.root/'absent')
        self.assertEqual(missing['reason'],'LAUNCH_OR_CAPTURE_FAILURE')
        self.assertFalse(missing['reaped'])
        self.assertTrue((self.root/'absent/process.json').exists())

    def test_matrix_stops_after_first_failed_baseline(self):
        m = self.module()
        calls = []
        def invoke(argv, directory, budget, deadline):
            calls.append(argv)
            directory.mkdir()
            (directory/'stdout').write_bytes(b'not a valid success')
            return dict(returncode=1,reaped=True,reason='EXIT',settled=True,controls_verified=True)
        with self.assertRaises(ValueError):
            m.execute_matrix('/synthetic/probe',self.root/'matrix',invoke)
        self.assertEqual(calls,[('/synthetic/probe','crypto','none')])
        self.assertTrue((self.root/'matrix/matrix-failed.json').exists())

    def test_full_synthetic_matrix_is_sequential_and_never_authenticates_transport(self):
        m = self.module()
        calls = []
        def invoke(argv,directory,budget,deadline):
            calls.append(argv[1:])
            directory.mkdir()
            mode,fault = argv[1:]
            result = dict(schema='issue3-b04-probe-result-v1',mode=mode,fault=fault,
                status='CASE_PASS' if fault == 'none' else 'FAULT_OBSERVED',
                case_ok=1,injected=int(fault != 'none'),live_blocks=0,destroyed=1,
                allocations=1,peak_charged_bytes=4096,failed_line=0)
            (directory/'stdout').write_text(json.dumps(result))
            return dict(returncode=0,reaped=True,reason='EXIT',settled=True,controls_verified=True)
        row = m.execute_matrix('/synthetic/probe',self.root/'all',invoke)
        self.assertEqual(calls,m.CASES)
        self.assertEqual(len(calls),15)
        self.assertEqual([f for _,f in calls[:7]],['none']*7)
        self.assertFalse(row['execution_provenance_verified'])
        self.assertFalse(row['target_evidence'])
        self.assertFalse(row['final_elf_acceptance'])

    def test_compile_recipe_uses_only_explicit_archives_in_reviewed_order(self):
        argv = self.module().compile_argv()
        self.assertEqual([p for p in argv if p.endswith('.a')],
                         ['/inputs/lib/libssl.a','/inputs/lib/libaes_siv.a','/inputs/lib/libcrypto.a'])
        self.assertIn('-static',argv)
        self.assertNotIn('-lssl',argv)
        self.assertNotIn('-lcrypto',argv)
        self.assertNotIn('urbit',argv)

    def test_matrix_refuses_symlinked_capture_before_parsing(self):
        m = self.module()
        calls=[]
        outside = self.root/'outside-result'
        outside.write_text(json.dumps(dict(schema='issue3-b04-probe-result-v1',mode='crypto',
            fault='none',status='CASE_PASS',case_ok=1,injected=0,live_blocks=0,destroyed=1,
            allocations=1,peak_charged_bytes=4096,failed_line=0)))
        def invoke(argv,directory,budget,deadline):
            calls.append(argv)
            directory.mkdir()
            (directory/'stdout').symlink_to(outside)
            return dict(returncode=0,reaped=True,reason='EXIT',settled=True,controls_verified=True)
        with self.assertRaises(OSError):
            m.execute_matrix('/synthetic/probe',self.root/'symlink',invoke)
        self.assertEqual(len(calls),1)

    def test_matrix_does_not_reset_external_phase_deadline(self):
        m = self.module()
        calls=[]
        with self.assertRaisesRegex(ValueError,'whole runtime deadline'):
            m.execute_matrix('/synthetic/probe',self.root/'expired',lambda *a:calls.append(a),
                             deadline=time.monotonic()-1)
        self.assertEqual(calls,[])
        self.assertTrue((self.root/'expired/matrix-failed.json').exists())


class CachedBindingTests(unittest.TestCase):
    def test_binder_exists_and_never_launches_for_metadata(self):
        self.assertTrue(Path('tools/issue3_crypto_tls_probe/cached_inputs.py').is_file(),
                        'read-only cached toolchain binding missing')

    def test_explicit_execution_refuses_missing_base_before_transport(self):
        self.assertTrue(Path('tools/issue3_crypto_tls_probe/execution.py').is_file(),
                        'execution gate missing')
        m = importlib.import_module('tools.issue3_crypto_tls_probe.execution')
        calls = []
        with self.assertRaisesRegex(ValueError,'cached execution base'):
            m.execute(None,None,None,lambda *args: calls.append(args))
        self.assertEqual(calls,[])

    def test_image_identity_alone_cannot_bypass_transport_binding(self):
        m = importlib.import_module('tools.issue3_crypto_tls_probe.execution')
        calls=[]
        profile = dict(base=dict(image_id='sha256:'+'a'*64,os='linux',architecture='amd64',
                                volumes=0,onbuild=0))
        with self.assertRaisesRegex(ValueError,'exact cached client'):
            m.execute(profile,{},'compile',lambda:calls.append('called'))
        self.assertEqual(calls,[])

    def test_effective_controls_refuse_missing_and_unbounded_cgroup(self):
        m = importlib.import_module('tools.issue3_crypto_tls_probe.execution')
        with tempfile.TemporaryDirectory(dir=SCRATCH) as d:
            root = Path(d)
            with self.assertRaises(FileNotFoundError):
                m.effective_controls('run',root)
            for n,v in {'memory.max':'268435456','memory.swap.max':'0',
                        'pids.max':'16','cpu.max':'100000 100000'}.items():
                (root/n).write_text(v)
            self.assertEqual(m.effective_controls('run',root)['memory.max'],'268435456')
            (root/'memory.max').write_text('max')
            with self.assertRaisesRegex(ValueError,'cgroup controls'):
                m.effective_controls('run',root)

    def test_grant_wrong_phase_hash_expiry_refuse(self):
        m = importlib.import_module('tools.issue3_crypto_tls_probe.execution')
        from tools.issue3_crypto_tls_probe.bind_b04 import encoded
        profile = {'synthetic':True}
        grant = dict(approved=True,phase='compile',expires_unix=time.time()+60,
            binding_sha256=hashlib.sha256(encoded(profile)).hexdigest(),
            owner_scope='one-original-retained-library-experiment')
        m.check_grant(profile,grant,'compile')
        for change in [dict(phase='run'),dict(expires_unix=time.time()-1),
                       dict(approved=False),dict(binding_sha256='0'*64)]:
            with self.subTest(change=change),self.assertRaises(ValueError):
                m.check_grant(profile,dict(grant,**change),'compile')

    def test_admission_refuses_stale_missing_or_either_low_domain(self):
        m = importlib.import_module('tools.issue3_crypto_tls_probe.execution')
        good = dict(host_free_bytes=16*1024**3,engine_free_bytes=16*1024**3,
                    observed_unix=time.time(),fixture=True)
        self.assertEqual(m.admission(good),dict(fixture=True))
        for change in [dict(host_free_bytes=1),dict(engine_free_bytes=1),
                       dict(observed_unix=time.time()-3),dict(host_free_bytes=True)]:
            with self.subTest(change=change),self.assertRaises(ValueError):
                m.admission(dict(good,**change))

    def test_compiler_archive_fixture_binds_binary_and_whole_sysroot_no_extract(self):
        m = importlib.import_module('tools.issue3_crypto_tls_probe.cached_inputs')
        with tempfile.TemporaryDirectory(dir=SCRATCH) as d:
            root = Path(d)
            archive = root/'compiler.tar.xz'
            with tarfile.open(archive,'w:xz') as t:
                for name in ['zig-x86_64-linux-0.15.2/zig',
                             'zig-x86_64-linux-0.15.2/lib/libc/include/header.h',
                             'zig-x86_64-linux-0.15.2/lib/std/start.zig']:
                    member = tarfile.TarInfo(name)
                    member.size = 7
                    t.addfile(member,io.BytesIO(b'fixture'))
            data = archive.read_bytes()
            pin = dict(bytes=len(data),sha256=hashlib.sha256(data).hexdigest())
            receipt = m.compiler_inventory(archive,pin)
            self.assertEqual(len(receipt['files']),3)
            self.assertFalse(receipt['extracted'])
            self.assertEqual(list(root.iterdir()),[archive])
            with self.assertRaisesRegex(ValueError,'hash/size drift'):
                m.compiler_inventory(archive,dict(pin,sha256='0'*64))
