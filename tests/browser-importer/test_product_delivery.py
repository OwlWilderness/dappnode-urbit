"""Engine-free integrated delivery checks; not image or installed-host acceptance."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class ProductDeliveryTests(unittest.TestCase):
    def test_host_export_binds_the_matched_runtime_entrypoint_and_supervisor(self):
        spec = importlib.util.spec_from_file_location('host_export', ROOT / 'tools/prepare-maintenance-host.py')
        assert spec is not None and spec.loader is not None
        exporter = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(exporter)
        with tempfile.TemporaryDirectory(dir=os.environ['IMPORTER_TEST_SCRATCH']) as scratch:
            output = Path(scratch) / 'companion'
            manifest = exporter.export(output)
            required = {'host-maintenance.compose.yml', 'build/docker-entrypoint.sh', 'tools/prepare-maintenance-host.py',
                        'tools/browser-importer/managed_service.py',
                        'tools/browser-importer/package_service.py',
                        'tools/browser-importer/server.py', 'tools/browser-importer/enrollment.py',
                        'tools/browser-importer/owner_tls.py', 'tools/browser-importer/backend_tls.py',
                        'tools/browser-importer/public_ingress.py',
                        'tools/host-integration/dappmanager_lifecycle.py',
                        'tools/host-integration/dappmanager_broker.py',
                        'tools/host-integration/upstream-dappmanager.patch'}
            self.assertTrue(required <= set(manifest['files']),
                            'host manifest omits matched package lifecycle source')
            self.assertFalse(manifest['deployment_qualified'])
            self.assertEqual(json.loads((output / 'manifest.json').read_bytes()), manifest)
            for name, digest in manifest['files'].items():
                self.assertEqual((output / name).read_bytes(), (ROOT / name).read_bytes())
                self.assertEqual(hashlib.sha256((output / name).read_bytes()).hexdigest(), digest)
            self.assertFalse(any('guest_' in name or 'boundary_trace' in name
                                 for name in manifest['files']))
            env = os.environ.copy()
            env.pop('PYTHONPATH', None)
            broker = output / 'tools/host-integration/dappmanager_broker.py'
            help_result = subprocess.run(
                [sys.executable, '-I', '-B', str(broker), '--help'],
                cwd=output, env=env, stdin=subprocess.DEVNULL,
                capture_output=True, timeout=10)
            self.assertEqual(help_result.returncode, 0, help_result.stderr)
            self.assertIn(b'--plan', help_result.stdout)
            with self.assertRaises(FileExistsError):
                exporter.export(output)

    def test_product_provider_has_no_guest_runner_or_trace_switch(self):
        tools = ROOT / 'tools/browser-importer'
        provider = (tools / 'maintenance_provider.py').read_text()
        for token in ('guest_docker_process', 'boundary_trace', 'PipeWitness', '--trace-'):
            self.assertNotIn(token, provider)
        result = subprocess.run([sys.executable, '-B', str(tools / 'maintenance_provider.py'), '--help'],
                                stdin=subprocess.DEVNULL, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(b'{enroll,run,recover}', result.stdout)
        self.assertNotIn(b'--trace-', result.stdout)
        self.assertFalse((tools / 'affected_cli.py').exists(), 'affected_cli is a test harness, not production')


if __name__ == '__main__':
    unittest.main()
