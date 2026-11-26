"""Focused regression for du racing with compiler temporary-file deletion."""
import importlib.util
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
RECIPE = ROOT / 'build/vere-openssl3-arm64-heap'
sys.path.insert(0, str(RECIPE))
spec = importlib.util.spec_from_file_location('heap_candidate', RECIPE / 'candidate.py')
assert spec is not None and spec.loader is not None
candidate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(candidate)


class CapacityRace(unittest.TestCase):
    def error(self, message=b'du: /work/attempt/zig-local-cache/tmp/a.o: No such file or directory\n'):
        return subprocess.CalledProcessError(1, ['du'], stderr=message)

    def test_transient_deletion_retries(self):
        with patch.object(candidate.subprocess, 'check_output', side_effect=[self.error(), b'1024 /work/attempt\n']) as call, patch.object(candidate.shutil, 'disk_usage', return_value=type('Usage', (), {'free': 12 * 1024**3})()), patch.object(candidate.time, 'sleep'):
            candidate.CapacityGuard(Path('/work/attempt')).check(force=True)
            self.assertEqual(call.call_count, 2)

    def test_persistent_deletion_fails_closed(self):
        with patch.object(candidate.subprocess, 'check_output', side_effect=self.error()) as call, patch.object(candidate.time, 'sleep'):
            with self.assertRaises(subprocess.CalledProcessError):
                candidate.CapacityGuard(Path('/work/attempt')).check(force=True)
            self.assertEqual(call.call_count, 3)

    def test_permission_error_is_not_retried(self):
        with patch.object(candidate.subprocess, 'check_output', side_effect=self.error(b'du: /work/attempt/secret: Permission denied\n')) as call:
            with self.assertRaises(subprocess.CalledProcessError):
                candidate.CapacityGuard(Path('/work/attempt')).check(force=True)
            self.assertEqual(call.call_count, 1)

    def test_capacity_limit_remains_fatal(self):
        with patch.object(candidate.subprocess, 'check_output', return_value=b'99999999 /work/attempt\n'):
            with self.assertRaisesRegex(RuntimeError, 'capacity limit'):
                candidate.CapacityGuard(Path('/work/attempt')).check(force=True)


if __name__ == '__main__':
    unittest.main()
