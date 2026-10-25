"""Check test scratch selection without creating fixtures or running TLS."""
import importlib.util
import os
from pathlib import Path
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent / 'browser-importer'


class ScratchConfigurationTests(unittest.TestCase):
    def load(self, filename):
        spec = importlib.util.spec_from_file_location('scratch_fixture', ROOT / filename)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def check_selection(self, environment, expected):
        default = str(Path('/synthetic/platform-scratch').resolve())
        with patch.dict(os.environ, environment, clear=True), \
                patch('tempfile.gettempdir', return_value=default):
            owner = self.load('test_owner_tls.py')
            self.assertEqual(owner.SCRATCH, expected)
            service = self.load('test_package_service.py')
            with patch('tempfile.TemporaryDirectory') as create:
                service.PackageServiceTests().scratch()
                create.assert_called_once()
                self.assertEqual(create.call_args.kwargs['prefix'], 'package-service-test-')
                self.assertEqual(Path(create.call_args.kwargs['dir']), expected)

    def test_platform_default_without_personal_path(self):
        self.check_selection({}, Path('/synthetic/platform-scratch').resolve())

    def test_explicit_scratch_override(self):
        self.check_selection({'IMPORTER_TEST_SCRATCH': '/synthetic/owner-scratch'},
                             Path('/synthetic/owner-scratch').resolve())


if __name__ == '__main__':
    unittest.main()
