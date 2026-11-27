"""Host preparation tests only: never link/run a target or real TLS."""
import importlib.util
import hashlib
import json
import copy
import ast
import os
import subprocess
import shutil
import sys
import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
PREP = ROOT / 'tools/issue3_crypto_tls_probe/prepare.py'
AUTHORIZED_SCRATCH = Path(tempfile.gettempdir()).resolve()
TEST_SCRATCH = Path(os.environ.get('ISSUE3_PROBE_TEST_SCRATCH', str(AUTHORIZED_SCRATCH))).resolve()
if not TEST_SCRATCH.is_relative_to(AUTHORIZED_SCRATCH):
    raise ValueError('test scratch must stay inside authorized scratch')

class PreparationTests(unittest.TestCase):
    def load(self):
        spec = importlib.util.spec_from_file_location('probe_prepare', PREP)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_preparation_is_present(self):
        self.assertTrue(PREP.is_file(), 'nonexecuting preparation controller missing')

    def test_real_probe_source_exists(self):
        self.assertTrue((PREP.parent / 'probe.c').is_file(), 'real probe source missing')

    def test_host_cleanup_oracle_fixture_exists(self):
        self.assertTrue((PREP.parent / 'host_cleanup_fixture.c').is_file(),
            'extracted-main host-only cleanup oracle missing')

    def fixture(self, root):
        m = self.load()
        files = []
        for role, path in [('libssl','lib/libssl.a'), ('libcrypto','lib/libcrypto.a'),
                ('libaes_siv','lib/libaes_siv.a'), ('siv_header','include/aes_siv.h'),
                ('build_config','config/configdata.pm'),
                ('arena_c','arena/openssl_owned_arena.c'),
                ('arena_h','arena/openssl_owned_arena.h'), ('arena_engine','arena/palloc_engine.inc'),
                ('header','include/openssl/ssl.h'), ('header','include/openssl/evp.h'),
                ('header','include/openssl/opensslv.h'), ('config','include/openssl/configuration.h'),
                ('config','include/openssl/opensslconf.h'), ('dependency_contract','contract.json')]:
            p = root / path
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(b'PUBLIC SYNTHETIC FIXTURE, NOT A LIBRARY\n')
            files.append(dict(role=role,path=path,bytes=p.stat().st_size,
                sha256=hashlib.sha256(p.read_bytes()).hexdigest()))
        return dict(schema='issue3-b04-probe-input-v1', evidence_scope='retained-library-only',
                candidate_sha256=m.B04_SHA, candidate_bytes=m.B04_BYTES,
                final_link_authenticated=False, files=files)

    def test_fixture_manifest_prepares_without_executing_or_writing(self):
        m = self.load()
        with tempfile.TemporaryDirectory(dir=TEST_SCRATCH) as d:
            root = Path(d)
            manifest = self.fixture(root)
            before = sorted(str(p.relative_to(root)) for p in root.rglob('*'))
            plan = m.prepare(root, manifest)
            self.assertEqual(plan['status'], 'PREPARED_NOT_AUTHORIZED')
            self.assertFalse(plan['target_executed'])
            self.assertEqual(before, sorted(str(p.relative_to(root)) for p in root.rglob('*')))
            self.assertTrue(root.exists())

    def test_missing_siv_binding_refused(self):
        m = self.load()
        with tempfile.TemporaryDirectory(dir=TEST_SCRATCH) as d:
            root = Path(d)
            manifest = self.fixture(root)
            manifest['files'] = [f for f in manifest['files'] if f['role'] != 'libaes_siv']
            (root / 'lib/libaes_siv.a').unlink() # own synthetic fixture only
            with self.assertRaisesRegex(ValueError, 'libaes_siv'):
                m.prepare(root, manifest)

    def test_undeclared_directory_refused(self):
        m = self.load()
        with tempfile.TemporaryDirectory(dir=TEST_SCRATCH) as d:
            root = Path(d)
            manifest = self.fixture(root)
            (root / 'hidden').mkdir()
            with self.assertRaisesRegex(ValueError, 'undeclared staged directory'):
                m.prepare(root, manifest)

    def test_result_parser_exists(self):
        self.assertTrue(callable(getattr(self.load(), 'validate_result', None)), 'cleanup receipt parser missing')

    def result(self, **updates):
        row = dict(schema='issue3-b04-probe-result-v1', mode='tls13', fault='none',
            status='CASE_PASS', case_ok=1, injected=0, live_blocks=0, destroyed=1,
            allocations=50, peak_charged_bytes=65536, failed_line=0)
        row.update(updates)
        return json.dumps(row)

    def test_inapplicable_fault_pair_refused(self):
        m = self.load()
        with self.assertRaisesRegex(ValueError, 'fault/mode pair'):
            m.validate_result(self.result(fault='siv',status='FAULT_OBSERVED',injected=1),
                0, 'tls13', 'siv')

    def test_manifest_scope_and_identity_refusals(self):
        m = self.load()
        with tempfile.TemporaryDirectory(dir=TEST_SCRATCH) as d:
            root = Path(d)
            good = self.fixture(root)
            changes = [dict(final_link_authenticated=True), dict(candidate_sha256='0'*64),
                dict(candidate_bytes=True), dict(evidence_scope='final-ELF'), dict(schema='old'),
                dict(extra='unexpected')]
            for change in changes:
                with self.subTest(change=change):
                    manifest = copy.deepcopy(good); manifest.update(change)
                    with self.assertRaises(ValueError): m.prepare(root,manifest)

    def test_manifest_path_and_role_refusals(self):
        m = self.load()
        with tempfile.TemporaryDirectory(dir=TEST_SCRATCH) as d:
            root = Path(d); good = self.fixture(root)
            for path in ('../libssl.a','/libssl.a','lib//libssl.a','lib/./libssl.a',
                         'lib/../../escape','lib/libssl.a\n'):
                with self.subTest(path=path):
                    manifest = copy.deepcopy(good); manifest['files'][0]['path'] = path
                    with self.assertRaises(ValueError): m.prepare(root,manifest)
            manifest = copy.deepcopy(good); manifest['files'].append(manifest['files'][0])
            with self.assertRaisesRegex(ValueError,'unique relative'): m.prepare(root,manifest)
            manifest = copy.deepcopy(good); manifest['files'][0]['role'] = 'toolchain'
            with self.assertRaisesRegex(ValueError,'role'): m.prepare(root,manifest)

    def test_manifest_size_and_hash_drift_refusals(self):
        m = self.load()
        with tempfile.TemporaryDirectory(dir=TEST_SCRATCH) as d:
            root = Path(d); good = self.fixture(root)
            for size in (True,0,-1,m.MAX_FILE+1):
                manifest = copy.deepcopy(good); manifest['files'][0]['bytes'] = size
                with self.subTest(size=size), self.assertRaisesRegex(ValueError,'size/hash'):
                    m.prepare(root,manifest)
            (root/'lib/libssl.a').write_bytes(b'x'*good['files'][0]['bytes'])
            with self.assertRaisesRegex(ValueError,'hash drift'): m.prepare(root,good)
            (root/'lib/libssl.a').write_bytes(b'x')
            with self.assertRaisesRegex(ValueError,'size drift'): m.prepare(root,good)

    def test_input_growth_during_read_is_bounded(self):
        m=self.load()
        with tempfile.TemporaryDirectory(dir=TEST_SCRATCH) as d:
            root=Path(d); manifest=self.fixture(root)
            original=Path.open
            class GrowingInput:
                reads=0
                def __enter__(self): return self
                def __exit__(self,*args): return False
                def read(self,n):
                    self.reads += 1
                    if self.reads > 1: raise ValueError('fixture repeated read instead of bound refusal')
                    return b'x'*(manifest['files'][0]['bytes']+1)
            def opened(path,*args,**kwargs):
                return GrowingInput() if path == root/'lib/libssl.a' else original(path,*args,**kwargs)
            with patch.object(Path,'open',opened):
                # One-shot oversized read must refuse, rather than request EOF
                # forever from a concurrently growing public fixture.
                with self.assertRaisesRegex(ValueError,'input grew'):
                    m.prepare(root,manifest)

    def test_file_and_manifest_limits(self):
        m = self.load()
        with tempfile.TemporaryDirectory(dir=TEST_SCRATCH) as d:
            root = Path(d); good = self.fixture(root)
            manifest = copy.deepcopy(good); manifest['files'] = [{}]*(m.MAX_FILES+1)
            with self.assertRaisesRegex(ValueError,'file count'): m.prepare(root,manifest)
            manifest = copy.deepcopy(good); manifest['padding'] = 'x'*m.MAX_MANIFEST
            with self.assertRaisesRegex(ValueError,'manifest byte'): m.prepare(root,manifest)
            m.MAX_TOTAL = sum(f['bytes'] for f in good['files'])-1
            with self.assertRaisesRegex(ValueError,'total byte'): m.prepare(root,good)

    def test_missing_generated_config_refused(self):
        m = self.load()
        with tempfile.TemporaryDirectory(dir=TEST_SCRATCH) as d:
            root = Path(d); manifest = self.fixture(root)
            path = 'include/openssl/configuration.h'
            manifest['files'] = [f for f in manifest['files'] if f['path'] != path]
            (root/path).unlink()
            with self.assertRaisesRegex(ValueError,'generated configuration'): m.prepare(root,manifest)

    def test_missing_build_configuration_data_refused(self):
        m = self.load()
        with tempfile.TemporaryDirectory(dir=TEST_SCRATCH) as d:
            root=Path(d); manifest=self.fixture(root)
            manifest['files']=[f for f in manifest['files'] if f['role'] != 'build_config']
            p=root/'config/configdata.pm'
            if p.exists(): p.unlink(); p.parent.rmdir()
            with self.assertRaisesRegex(ValueError,'build_config'): m.prepare(root,manifest)

    def test_symlink_and_undeclared_file_refused(self):
        m = self.load()
        with tempfile.TemporaryDirectory(dir=TEST_SCRATCH) as d:
            root = Path(d); manifest = self.fixture(root)
            p = root/'lib/libssl.a'; data=p.read_bytes(); p.unlink(); p.symlink_to('libcrypto.a')
            with self.assertRaisesRegex(ValueError,'nonsymlink'): m.prepare(root,manifest)
            p.unlink(); p.write_bytes(data)
            (root/'undeclared').write_text('not admitted')
            with self.assertRaisesRegex(ValueError,'undeclared staged files'): m.prepare(root,manifest)

    def test_result_baseline_and_fault_are_distinct(self):
        m = self.load()
        baseline = m.validate_result(self.result(),0,'tls13')
        self.assertTrue(baseline['baseline_case'])
        self.assertFalse(baseline['execution_provenance_verified'])
        self.assertFalse(baseline['final_elf_acceptance'])
        row = self.result(fault='bio',status='FAULT_OBSERVED',injected=1,case_ok=0,failed_line=9)
        fault = m.validate_result(row,0,'tls13','bio')
        self.assertFalse(fault['baseline_case'])
        with self.assertRaises(ValueError): m.validate_result(row,0,'tls13')

    def test_cleanup_failure_refusals(self):
        m = self.load()
        for fields in (dict(live_blocks=1),dict(destroyed=0),dict(peak_charged_bytes=0),
                       dict(peak_charged_bytes=134217729),dict(allocations=0)):
            with self.subTest(fields=fields), self.assertRaisesRegex(ValueError,'cleanup/arena'):
                m.validate_result(self.result(**fields),0,'tls13')

    def test_result_false_success_and_fault_not_reached_refusals(self):
        m = self.load()
        for fields in (dict(case_ok=0),dict(status='CASE_FAIL'),dict(injected=1),
            dict(failed_line=1),dict(case_ok=True),dict(mode='tls12'),dict(fault='ca')):
            with self.subTest(fields=fields), self.assertRaises(ValueError):
                m.validate_result(self.result(**fields),0,'tls13')
        with self.assertRaisesRegex(ValueError,'fault must actually'):
            m.validate_result(self.result(fault='bio',status='FAULT_NOT_REACHED'),0,'tls13','bio')
        for exitcode in (1,-9,True):
            with self.subTest(exitcode=exitcode), self.assertRaisesRegex(ValueError,'process exit'):
                m.validate_result(self.result(),exitcode,'tls13')

    def test_json_duplicate_output_limit_and_extra_record_refusals(self):
        m = self.load()
        for text in ('{"x":1,"x":2}', '{"x":NaN}', '{}\n{}', 'x'*16385):
            with self.subTest(text=text[:30]), self.assertRaises(ValueError):
                m.validate_result(text,0,'tls13')

    def test_cli_only_prepares_synthetic_inputs(self):
        with tempfile.TemporaryDirectory(dir=TEST_SCRATCH) as d:
            parent = Path(d); root=parent/'inputs'; root.mkdir()
            manifest=self.fixture(root)
            path=parent/'manifest.json'; path.write_text(json.dumps(manifest))
            before = {str(p.relative_to(parent)): hashlib.sha256(p.read_bytes()).hexdigest()
                for p in parent.rglob('*') if p.is_file()}
            r=subprocess.run([sys.executable,'-B',str(PREP),'--root',str(root),'--manifest',str(path)],
                capture_output=True,text=True,timeout=10,env={**os.environ,'PYTHONDONTWRITEBYTECODE':'1'})
            self.assertEqual(r.returncode,0,r.stderr)
            plan=json.loads(r.stdout)
            self.assertEqual(plan['status'],'PREPARED_NOT_AUTHORIZED')
            self.assertFalse(plan['dependency_contract_semantics_verified'])
            self.assertEqual(before,{str(p.relative_to(parent)):hashlib.sha256(p.read_bytes()).hexdigest()
                for p in parent.rglob('*') if p.is_file()})

    def test_synthetic_fixture_lifetime_preserves_unrelated_sentinel(self):
        with tempfile.TemporaryDirectory(dir=TEST_SCRATCH) as outer:
            sentinel=Path(outer)/'retained'; sentinel.write_text('unchanged')
            inner=tempfile.TemporaryDirectory(dir=outer)
            class FailingFixture(unittest.TestCase):
                def runTest(case):
                    case.addCleanup(inner.cleanup)
                    (Path(inner.name)/'owned').write_text('fixture')
                    case.fail('deliberate fixture failure')
            result=unittest.TestResult(); FailingFixture().run(result)
            self.assertEqual(len(result.failures),1)
            self.assertFalse(Path(inner.name).exists())
            self.assertEqual(sentinel.read_text(),'unchanged')

    def test_controller_has_no_execution_or_cleanup_dependencies(self):
        tree=ast.parse(PREP.read_text())
        imports={node.names[0].name for node in ast.walk(tree) if isinstance(node,ast.Import)}
        self.assertTrue(imports.isdisjoint({'subprocess','socket','shutil','ctypes'}))
        # This is static corroboration, not a security sandbox or real TLS result.
        for node in ast.walk(tree):
            if isinstance(node,ast.Attribute):
                self.assertNotIn(node.attr,('unlink','rmdir','system','execv','spawn','write_bytes','write_text'))


class ExtractedMainHostOracle(unittest.TestCase):
    """Actual main compiled for host against explicit synthetic externals."""
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='b04-host-main-',
            dir=TEST_SCRATCH)
        cls.addClassCleanup(cls.temp.cleanup)
        cls.root = Path(cls.temp.name)
        source = (PREP.parent/'probe.c').read_text()
        main = source[source.index('int main(int argc, char **argv) {'):]
        template=(PREP.parent/'host_cleanup_fixture.c').read_text()
        assert template.count('/* MAIN_INSERT */') == 1
        path=cls.root/'fixture.c'; path.write_text(template.replace('/* MAIN_INSERT */',main))
        cls.binary=cls.root/'fixture'
        compiler=shutil.which('clang')
        if compiler is None: raise RuntimeError('host clang required; no skipped oracle')
        r=subprocess.run([compiler,'-std=c11','-Wall','-Wextra','-Werror',str(path),'-o',str(cls.binary)],
            capture_output=True,text=True,timeout=30)
        if r.returncode: raise RuntimeError(r.stderr)

    def run_fixture(self, scenario=0, args=('crypto',)):
        return subprocess.run([str(self.binary),*args],capture_output=True,text=True,timeout=5,
            env={**os.environ,'MOCK_SCENARIO':str(scenario)})

    def test_success_unwinds_before_library_cleanup_count_and_destroy(self):
        r=self.run_fixture(); self.assertEqual(r.returncode,0)
        self.assertEqual(r.stderr,'ARICTOLSD')
        self.assertEqual(json.loads(r.stdout)['status'],'CASE_PASS')

    def test_live_blocks_refuse_destruction(self):
        r=self.run_fixture(2); self.assertEqual(r.returncode,1)
        self.assertEqual(r.stderr,'ARICTOLS')
        self.assertEqual(json.loads(r.stdout)['destroyed'],0)

    def test_registration_failure_does_not_touch_openssl_cleanup(self):
        r=self.run_fixture(3); self.assertEqual(r.returncode,1)
        self.assertEqual(r.stderr,'ARLSD')
        self.assertEqual(json.loads(r.stdout)['status'],'CLEANUP_FAIL')

    def test_initialization_failure_still_cleans_registered_library(self):
        r=self.run_fixture(4); self.assertEqual(r.returncode,1)
        self.assertEqual(r.stderr,'ARITOLSD')
        self.assertEqual(json.loads(r.stdout)['status'],'CASE_FAIL')

    def test_failed_arena_initialization_returns_without_registration(self):
        r=self.run_fixture(1); self.assertEqual(r.returncode,70)
        self.assertEqual((r.stderr,r.stdout),('A',''))

    def test_snapshot_or_destroy_failure_never_reports_pass(self):
        for scenario in (5,6):
            with self.subTest(scenario=scenario):
                r=self.run_fixture(scenario); self.assertEqual(r.returncode,1)
                self.assertEqual(json.loads(r.stdout)['status'],'CLEANUP_FAIL')

    def test_case_failure_still_cleans(self):
        r=self.run_fixture(7); self.assertEqual(r.returncode,1)
        self.assertEqual(r.stderr,'ARICTOLSD')
        self.assertEqual(json.loads(r.stdout)['status'],'CASE_FAIL')

    def test_fault_observation_is_not_baseline_success(self):
        r=self.run_fixture(args=('crypto','siv')); self.assertEqual(r.returncode,0)
        self.assertEqual(json.loads(r.stdout)['status'],'FAULT_OBSERVED')
        self.assertEqual(r.stderr,'ARICTOLSD')

    def test_bad_cli_refused_before_arena_or_library(self):
        for args in ((),('unknown',),('crypto','bio'),('tls13','siv'),('crypto','sha','extra')):
            with self.subTest(args=args):
                r=self.run_fixture(args=args)
                self.assertEqual((r.returncode,r.stdout,r.stderr),(64,'',''))


if __name__ == '__main__':
    unittest.main()
