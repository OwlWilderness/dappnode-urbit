"""AMD64 allocator adoption gates; no compiler, Docker or ship execution."""
import importlib.util
import json
from pathlib import Path
import unittest
from contextlib import redirect_stdout
import io
import subprocess
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
RECIPE = ROOT / 'build/vere-openssl3'


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class AmdAllocatorTests(unittest.TestCase):
    def test_explicit_local_cache_matches_capacity_allowlist(self):
        fixtures = load(ROOT / 'tests/test_openssl_candidate.py', 'amd_cache_fixture')
        case = fixtures.CandidateTests()
        self.addCleanup(case.doCleanups)
        case.setUp()
        with case.synthetic_build() as (attempt, trees, _, _), redirect_stdout(io.StringIO()):
            case.api.compile_candidate(attempt, case.lock, trees)
            for call in attempt.run.call_args_list:
                self.assertEqual(call.args[3].get('ZIG_LOCAL_CACHE_DIR'),
                                 str(attempt.output / 'zig-local-cache'))

    def test_unrecognized_disk_scan_failure_preserves_bounded_detail(self):
        api = load(RECIPE / 'candidate.py', 'amd_scan_detail')
        message = b'du: /work/attempt/unknown: Permission denied\n' + b'x' * 4096
        error = subprocess.CalledProcessError(1, ['du'], stderr=message)
        output = io.StringIO()
        with mock.patch.object(api.subprocess, 'check_output', side_effect=error) as call, redirect_stdout(output):
            with self.assertRaises(subprocess.CalledProcessError):
                api.CapacityGuard(Path('/work/attempt')).check(force=True)
        self.assertEqual(call.call_count, 1)
        self.assertIn('Permission denied', output.getvalue())
        self.assertLess(len(output.getvalue()), 2400)

    def test_allocator_correction_and_preimage_pin(self):
        api = load(RECIPE / 'candidate.py', 'amd_allocator')
        self.assertTrue(hasattr(api, 'patch_allocator'), 'allocator integration missing')
        checks = load(ROOT / 'tests/test_openssl_arm64_candidate.py', 'allocator_checks')
        setattr(checks, 'RECIPE', RECIPE)
        checks.ArmRecipeTests('test_allocator_patch_preserves_gmp_and_rejects_drift').debug()
        lock = json.loads((RECIPE / 'inputs.json').read_text())
        arm_lock = json.loads((ROOT / 'build/vere-openssl3-arm64/inputs.json').read_text())
        self.assertEqual(lock['source_preimages']['pkg/noun/manage.c'],
                         arm_lock['source_preimages']['pkg/noun/manage.c'])

    def test_capacity_race_regressions(self):
        checks = load(ROOT / 'diagnostics/issue3-termination-run/test_heap_capacity.py', 'amd_capacity_checks')
        setattr(checks, 'candidate', load(RECIPE / 'candidate.py', 'amd_capacity'))
        result = unittest.TestResult()
        unittest.defaultTestLoader.loadTestsFromTestCase(checks.CapacityRace).run(result)
        self.assertTrue(result.wasSuccessful(), str(result.failures + result.errors))

    def test_amd64_target_is_not_changed(self):
        api = load(RECIPE / 'candidate.py', 'amd_target')
        self.assertIn('-Dtarget=x86_64-linux-musl', api.vere_build_command('/pinned/zig'))
        self.assertIn('--platform=linux/amd64', api.image_build_command(Path('/recipe'), Path('/fresh'), 'fresh-amd64'))
        self.assertEqual(json.loads((RECIPE / 'inputs.json').read_text())['target'], 'x86_64-linux-musl')
        source = (RECIPE / 'candidate.py').read_text()
        self.assertNotIn('uvm_i3_', source)
        self.assertNotIn('_Exit(0)', source)


if __name__ == '__main__':
    unittest.main()
