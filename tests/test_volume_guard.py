import importlib.util
import contextlib
import io
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


class VolumeGuardTests(unittest.TestCase):
    def load_guard(self):
        path = ROOT / 'build' / 'volume_guard.py'
        self.assertTrue(path.is_file(), 'package volume guard is missing')
        spec = importlib.util.spec_from_file_location('volume_guard', path)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_empty_volume_dispatches_to_supervisor(self):
        guard = self.load_guard()
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(guard.os, 'execv') as execute:
                guard.main(['--bind', '0.0.0.0'], root=directory)
            execute.assert_called_once_with(sys.executable, [
                sys.executable, '/opt/importer/package_service.py',
                '--bind', '0.0.0.0',
            ])
            self.assertEqual({p.name for p in Path(directory).iterdir()}, {'pier', 'uploads', 'control'})
            for path in Path(directory).iterdir():
                self.assertEqual(path.stat().st_mode & 0o777, 0o700)

    def test_legacy_volume_refuses_before_any_dispatch_or_mutation(self):
        guard = self.load_guard()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'synthetic-ship').mkdir()
            (root / 'synthetic-ship' / '.urb').mkdir()
            before = sorted(str(p.relative_to(root)) for p in root.rglob('*'))
            with patch.object(guard.os, 'execv') as execute:
                self.assertEqual(guard.main([], root=directory), 78)
            execute.assert_not_called()
            self.assertEqual(sorted(str(p.relative_to(root)) for p in root.rglob('*')), before)

    def test_current_layout_dispatches_without_reading_payloads(self):
        guard = self.load_guard()
        with tempfile.TemporaryDirectory() as directory:
            for name in ('pier', 'uploads', 'control'):
                (Path(directory) / name).mkdir()
            with patch.object(guard.os, 'execv') as execute:
                guard.main([], root=directory)
            execute.assert_called_once()

    def test_unknown_partial_and_symlink_layouts_refuse(self):
        guard = self.load_guard()
        for kind in ('partial', 'unknown', 'child_symlink', 'root_symlink', 'missing'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                root = Path(directory) / 'volume'
                root.mkdir()
                if kind == 'partial':
                    (root / 'pier').mkdir()
                elif kind == 'unknown':
                    (root / 'synthetic-boot.key').touch()
                elif kind == 'child_symlink':
                    (root / 'pier').symlink_to(directory, target_is_directory=True)
                    (root / 'uploads').mkdir()
                    (root / 'control').mkdir()
                elif kind == 'root_symlink':
                    link = Path(directory) / 'link'
                    link.symlink_to(root, target_is_directory=True)
                    root = link
                else:
                    root = Path(directory) / 'missing'
                errors = io.StringIO()
                with patch.object(guard.os, 'execv') as execute, contextlib.redirect_stderr(errors):
                    self.assertEqual(guard.main([], root=root), 78)
                execute.assert_not_called()
                self.assertIn('VOLUME_LAYOUT_REFUSED', errors.getvalue())
                self.assertNotIn('synthetic-boot', errors.getvalue())


if __name__ == '__main__':
    unittest.main()
