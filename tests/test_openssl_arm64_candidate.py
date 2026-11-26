"""Focused ARM recipe checks only; never launch Docker, a compiler or Vere."""
import importlib.util
import json
from pathlib import Path
import unittest
from unittest import mock
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
RECIPE = ROOT / 'build/vere-openssl3-arm64'


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ArmRecipeTests(unittest.TestCase):
    def test_production_capacity_monitor_regressions(self):
        checks = load(ROOT / 'diagnostics/issue3-termination-run/test_heap_capacity.py', 'capacity_checks')
        setattr(checks, 'candidate', load(RECIPE / 'candidate.py', 'arm_capacity'))
        result = unittest.TestResult()
        unittest.defaultTestLoader.loadTestsFromTestCase(checks.CapacityRace).run(result)
        self.assertTrue(result.wasSuccessful(), str(result.failures + result.errors))

    def test_allocator_patch_preserves_gmp_and_rejects_drift(self):
        api = load(RECIPE / 'candidate.py', 'arm_allocator')
        before = ('  /* Initialize OpenSSL with loom allocation functions. */\n'
                  '#ifndef U3_URTH_MASS\n'
                  '  CRYPTO_set_mem_functions(malloc_fn, realloc_fn, free_fn);\n'
                  '#endif\n'
                  '  mp_set_memory_functions(u3a_malloc, realloc2, free2);\n')
        after = api.patch_allocator(before)
        self.assertIn('#if !defined(U3_URTH_MASS) && OPENSSL_VERSION_NUMBER < 0x30000000L', after)
        self.assertTrue(after.endswith(before[before.index('  CRYPTO_set_mem_functions'):]))
        with self.assertRaisesRegex(ValueError, 'preimage mismatch'):
            api.patch_allocator(after)
        with self.assertRaisesRegex(ValueError, 'preimage mismatch'):
            api.patch_allocator(before + before)

    def test_delivery_accepts_arm_elf_and_rejects_amd_elf(self):
        # Reuse the existing inert delivery fixture; no additional harness.
        fixtures = load(ROOT / 'tests/test_openssl_candidate.py', 'candidate_fixtures')
        fixtures.RECIPE = RECIPE
        case = fixtures.CandidateTests()
        self.addCleanup(case.doCleanups)
        case.api = load(RECIPE / 'candidate.py', 'arm_delivery')
        case.lock = json.loads((RECIPE / 'inputs.json').read_text())
        for machine in (183, 62):
            with self.subTest(elf_machine=machine), case.synthetic_build() as (attempt, trees, _, _):
                manage = trees['vere'] / 'pkg/noun/manage.c'
                manage.parent.mkdir(parents=True, exist_ok=True)
                manage.write_text('/* synthetic allocator source receipt */\n')
                binary = trees['vere'] / 'zig-out/aarch64-linux-musl/urbit'
                binary.parent.mkdir(parents=True)
                binary.write_bytes(b'\x7fELF\x02\x01' + bytes(12) + machine.to_bytes(2, 'little') + b'OpenSSL 3.5.9')
                with mock.patch.object(case.api.os, 'uname', return_value=SimpleNamespace(sysname='Linux', machine='aarch64')):
                    if machine == 62:
                        with self.assertRaisesRegex(ValueError, 'not Linux ARM64 ELF'):
                            case.api.compile_candidate(attempt, case.lock, trees)
                        self.assertFalse((attempt.output / 'candidate.json').exists())
                    else:
                        case.api.compile_candidate(attempt, case.lock, trees)
                        receipt = json.loads((attempt.output / 'delivery/candidate.json').read_text())
                        self.assertEqual(receipt['architecture'], 'linux/arm64')
                        self.assertEqual((attempt.output / 'delivery/urbit').read_bytes(), binary.read_bytes())
                        configure = next(c for c in attempt.run.call_args_list if c.args[0] == 'openssl-configure')
                        self.assertIn('linux-aarch64', configure.args[1])
                        self.assertIn('-target aarch64-linux-musl', configure.args[3]['CC'])

    def test_native_arm_recipe_and_pinned_inputs_agree(self):
        self.assertTrue((RECIPE / 'candidate.py').is_file(), 'ARM recipe absent: scaffold RED')
        api = load(RECIPE / 'candidate.py', 'arm_candidate')
        lock = json.loads((RECIPE / 'inputs.json').read_text())
        tools = json.loads((RECIPE / 'builder-apks.json').read_text())
        self.assertEqual(lock['target'], 'aarch64-linux-musl')
        self.assertEqual(tools['architecture'], 'aarch64')
        self.assertIn('zig-aarch64-linux-0.15.2', lock['inputs']['zig']['root'])
        self.assertIn('-Dtarget=aarch64-linux-musl', api.vere_build_command('/pinned/zig'))
        self.assertIn('--platform=linux/arm64', api.image_build_command(Path('/recipe'), Path('/fresh'), 'arm-01'))
        adapter = api.object_adapter({'crypto': ['a.o'], 'ssl': ['b.o']})
        self.assertIn('target.result.cpu.arch != .aarch64', adapter)
        self.assertNotIn('.x86_64', adapter)
        dockerfile = (RECIPE / 'Dockerfile').read_text()
        self.assertIn('FROM --platform=linux/arm64 alpine@sha256:', dockerfile)
        for package in tools['packages']:
            self.assertIn(package['P'] + '=' + package['V'], dockerfile)
        self.assertNotIn('x86_64', (RECIPE / 'candidate.py').read_text())
        self.assertNotIn('amd64', (RECIPE / 'candidate.py').read_text())


if __name__ == '__main__':
    unittest.main()
