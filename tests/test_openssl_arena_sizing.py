"""Host-only arithmetic for a measured (not inferred) arena-sizing envelope."""
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
PATH = ROOT / 'tools/issue3_arena_sizing/admission.py'


def module():
    spec = importlib.util.spec_from_file_location('issue3_arena_admission', PATH)
    obj = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(obj)
    return obj


# Test fixtures are synthetic arithmetic examples, never runtime observations.
def evidence():
    return dict(schema_version=1, binary_sha256='a' * 64,
                workload='synthetic-unit-test-not-runtime',
                measurement_method='instrumented exact-binary allocator high-water and concurrent RSS',
                peak_arena_in_use_bytes=300000, successful_arena_capacity_bytes=524288,
                peak_other_resident_bytes=1000000, memory_limit_bytes=3000000)


class SizingTests(unittest.TestCase):
    def test_measured_use_is_not_capacity_estimate(self):
        result = module().assess(evidence(), arena_headroom_bytes=200000,
                                 system_headroom_bytes=100000)
        self.assertEqual(result['measured_peak_arena_in_use_bytes'], 300000)
        self.assertEqual(result['measured_successful_arena_capacity_bytes'], 524288)
        self.assertEqual(result['estimated_arena_capacity_bytes'], 524288)
        self.assertEqual(result['worst_case_resident_envelope_bytes'], 1624288)
        self.assertEqual(result['arithmetic_admission'], 'within-input-bound-only')
        self.assertFalse(result['production_authorized'])

    def test_rounding_and_observed_successful_floor(self):
        data = evidence()
        data['successful_arena_capacity_bytes'] = 131072
        data['peak_arena_in_use_bytes'] = 100000
        result = module().assess(data, arena_headroom_bytes=200000, system_headroom_bytes=0)
        self.assertEqual(result['estimated_arena_capacity_bytes'], 311296)

    def test_no_measurements_no_admission(self):
        for key in ('peak_arena_in_use_bytes', 'successful_arena_capacity_bytes',
                    'peak_other_resident_bytes', 'memory_limit_bytes', 'binary_sha256',
                    'workload', 'measurement_method'):
            with self.subTest(key=key):
                data = evidence()
                del data[key]
                with self.assertRaises(ValueError):
                    module().assess(data, arena_headroom_bytes=0, system_headroom_bytes=0)

    def test_bounds_and_mismatched_observation_refused(self):
        for changes in ({'successful_arena_capacity_bytes': 2097152,
                         'peak_arena_in_use_bytes': 2097153},
                        {'successful_arena_capacity_bytes': 131073},
                        {'peak_arena_in_use_bytes': True},
                        {'memory_limit_bytes': -1},
                        {'extra': 1}):
            with self.subTest(changes=changes):
                with self.assertRaises(ValueError):
                    module().assess({**evidence(), **changes}, arena_headroom_bytes=0,
                                    system_headroom_bytes=0)

    def test_budget_excess_refuses_and_does_not_rebrand_as_production(self):
        data = evidence()
        data['memory_limit_bytes'] = 1100000
        result = module().assess(data, arena_headroom_bytes=200000,
                                 system_headroom_bytes=100000)
        self.assertEqual(result['arithmetic_admission'], 'refused-input-bound-exceeded')
        self.assertFalse(result['production_authorized'])

    def test_unbounded_or_unaccounted_margin_refused(self):
        for kwargs in ({'arena_headroom_bytes': None, 'system_headroom_bytes': 0},
                       {'arena_headroom_bytes': 0, 'system_headroom_bytes': -1},
                       {'arena_headroom_bytes': True, 'system_headroom_bytes': 0}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                module().assess(evidence(), **kwargs)
        with self.assertRaises(ValueError):
            module().assess(evidence(), arena_headroom_bytes=4294950912,
                            system_headroom_bytes=0)

    def test_cli_refuses_missing_measurement_file(self):
        import subprocess
        import sys
        completed = subprocess.run([sys.executable, str(PATH), '--measurements',
                                    '/definitely-not-an-arena-measurement.json',
                                    '--arena-headroom-bytes', '0',
                                    '--system-headroom-bytes', '0'],
                                   capture_output=True, text=True)
        self.assertNotEqual(completed.returncode, 0)
        self.assertNotIn('within-input-bound-only', completed.stdout)

    def test_cli_synthetic_input_is_conditional_not_an_authorization(self):
        import subprocess
        import sys
        import tempfile
        with tempfile.TemporaryDirectory(prefix='arena-sizing-test-') as folder:
            path = Path(folder) / 'synthetic.json'
            path.write_text(json.dumps(evidence()))
            command = [sys.executable, str(PATH), '--measurements', str(path),
                       '--arena-headroom-bytes', '200000',
                       '--system-headroom-bytes', '100000']
            completed = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            output = json.loads(completed.stdout)
            self.assertFalse(output['production_authorized'])
            self.assertFalse(output['evidence_verified'])
            data = evidence()
            data['memory_limit_bytes'] = 1100000
            path.write_text(json.dumps(data))
            denied = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(denied.returncode, 2)
            self.assertEqual(json.loads(denied.stdout)['arithmetic_admission'],
                             'refused-input-bound-exceeded')


if __name__ == '__main__':
    unittest.main()
