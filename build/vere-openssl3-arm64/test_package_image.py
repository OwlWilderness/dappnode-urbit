"""Narrow host-only ARM package checks; no Docker or Vere execution."""
import importlib.util
import json
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / 'build/vere-openssl3-arm64/package_image.py'


def load():
    assert SCRIPT.is_file(), 'scaffold RED: ARM package preparer missing'
    spec = importlib.util.spec_from_file_location('arm_package', SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ArmPackageTests(unittest.TestCase):
    def test_arm_overlay_and_real_elf_parser_without_execution(self):
        m = load()
        originals = {p: m.read_public(ROOT / p) for p in m.PREIMAGES}
        with patch('subprocess.Popen', side_effect=AssertionError('no execution')):
            files = m.overlay(ROOT)
            self.assertEqual(json.loads(files['build/vere-release.json'])['architecture'], 'linux/arm64')
            self.assertEqual(files['build/Dockerfile'].count(('FROM --platform=linux/arm64 ' + m.BASE).encode()), 2)
            self.assertIn(b'python3=3.14.10-r1', files['build/Dockerfile'])
            adapter = files['tools/browser-importer/runtime.py']
            self.assertIn(m.CANDIDATE_SHA256.encode(), adapter)
            self.assertIn(b"int.from_bytes(header[18:20], 'little') != 183", adapter)
            self.assertIn(b"os.uname().machine != 'aarch64'", adapter)
            self.assertEqual(originals, {p: m.read_public(ROOT / p) for p in m.PREIMAGES})
            fixture = m.load(ROOT, 'tests/test_candidate_image_verifier.py')
            fixture.ELF = m.read_public(ROOT / m.BINARY)
            apk_lock = json.loads(m.read_public(ROOT / m.APK_LOCK))
            fixture.DB = ('\n\n'.join('\n'.join(k + ':' + p[k] for k in ('P', 'V', 'A', 'C', 'L', 'o'))
                                       for p in apk_lock['packages'].values()) + '\n\n').encode()
            m.validate_binary(fixture.ELF)
            stream, metadata, contract = fixture.fixture()
            metadata['architecture'] = 'arm64'
            verifier = m.image_verifier()
            result = verifier.verify_stream(stream, metadata, contract)
            self.assertEqual(result['selected_files']['bin/urbit']['sha256'], m.CANDIDATE_SHA256)
            self.assertFalse(result['container_executed'])
            self.assertNotIn('PRIVATE-CONFIG-CANARY', repr(result))
            for architecture in ('amd64', 'x86_64'):
                stream.seek(0)
                with self.assertRaises(ValueError):
                    verifier.verify_stream(stream, dict(metadata, architecture=architecture), contract)
            fixture.ELF = fixture.ELF[:18] + b'\x3e\0' + fixture.ELF[20:]
            stream, metadata, contract = fixture.fixture()
            metadata['architecture'] = 'arm64'
            with self.assertRaisesRegex(ValueError, 'ELF architecture'):
                verifier.verify_stream(stream, metadata, contract)
        self.assertEqual(m.load(ROOT, 'tools/local-candidate/verify_image.py').MAX_ELF, 24 * 1024**2)

    def test_pinned_apk_identities(self):
        m = load()
        verifier = m.image_verifier()
        self.assertTrue(hasattr(verifier, 'verify_runtime_apks'), 'scaffold RED: APK identity verifier missing')
        lock = json.loads(m.read_public(ROOT / m.APK_LOCK))
        packages = [{'name': name, 'version': p['V'], 'architecture': p['A'], 'checksum': p['C']}
                    for name, p in lock['packages'].items()]
        verifier.verify_runtime_apks(packages)
        for field, wrong in [('version', '0-r0'), ('architecture', 'x86_64'), ('checksum', 'wrong')]:
            altered = [dict(p) for p in packages]
            altered[0][field] = wrong
            with self.assertRaisesRegex(ValueError, 'APK identity'):
                verifier.verify_runtime_apks(altered)

    def test_existing_preimage_and_nofollow_boundaries(self):
        m = load()
        prior = m.load(ROOT, 'tests/test_openssl_package_image.py')
        prior.load = lambda: m
        for name in ('test_dockerfile_preimage_refuses_before_derived_source_reads',
                     'test_public_reader_holds_ancestor_during_swap',
                     'test_public_reader_refuses_links_special_files_and_oversize'):
            with self.subTest(name=name):
                getattr(prior.PackageImageTests(name), name)()

    def test_staged_adapter_checks_real_elf_and_machine_before_launch(self):
        import ast
        from types import SimpleNamespace
        from unittest.mock import Mock
        import hashlib
        m = load()
        code = m.overlay(ROOT)['tools/browser-importer/runtime.py']
        tree = ast.parse(code)
        selected = ast.Module(body=[node for node in tree.body
                                   if isinstance(node, ast.ClassDef) and node.name == 'OfficialRuntimeAdapter'],
                              type_ignores=[])
        host_os = SimpleNamespace(**{name: getattr(os, name) for name in
            ('O_RDONLY', 'O_NOFOLLOW', 'O_NONBLOCK', 'fstat', 'read', 'close', 'pread')})
        def open_candidate(path, flags):
            self.assertEqual(path, '/bin/urbit')
            return os.open(ROOT / m.BINARY, flags)
        host_os.open = open_candidate
        host_os.uname = lambda: SimpleNamespace(machine='aarch64')
        popen = Mock(return_value=object())
        import stat
        namespace = {'os': host_os, 'sys': SimpleNamespace(platform='linux'), 'stat': stat,
                     'hashlib': hashlib, 'OFFICIAL_SHA256': m.CANDIDATE_SHA256,
                     'subprocess': SimpleNamespace(Popen=popen, DEVNULL=-3), 'ImportError': RuntimeError}
        exec(compile(selected, '<staged adapter class only>', 'exec'), namespace)
        adapter = namespace['OfficialRuntimeAdapter']()
        adapter.launch(123)
        popen.assert_called_once()
        popen.reset_mock()
        host_os.uname = lambda: SimpleNamespace(machine='x86_64')
        with self.assertRaises(RuntimeError):
            adapter.launch(123)
        popen.assert_not_called()
        host_os.uname = lambda: SimpleNamespace(machine='aarch64')
        host_os.pread = lambda fd, size, offset: os.pread(fd, size, offset)[:18] + b'\x3e\0' + os.pread(fd, size, offset)[20:]
        with self.assertRaises(RuntimeError):
            adapter.launch(123)
        popen.assert_not_called()


if __name__ == '__main__':
    unittest.main()
