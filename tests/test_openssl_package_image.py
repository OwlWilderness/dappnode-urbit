"""Host-only package staging; no Docker, compiler or Vere execution."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import subprocess
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'build/vere-openssl3/package_image.py'
# Historical helper remains pinned to its historical source controls. Do not
# rewrite PREIMAGES, official evidence or production b04 selectors to fit it.
HISTORICAL_REF = '1e64ae302011990fe10af30a940c64a3b0a24024'
HISTORICAL_VERIFIER_SHA256 = '43ce75c21e7702cad88319c553d0c1bb2077a76457624eada62cd638947cebfe'


def load():
    if not SCRIPT.is_file():
        raise AssertionError('scaffold RED: isolated package preparer missing')
    spec = importlib.util.spec_from_file_location('openssl_package_image', SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    snapshots = {}
    for name, digest in {**module.PREIMAGES,
                         'tools/local-candidate/verify_image.py': HISTORICAL_VERIFIER_SHA256}.items():
        result = subprocess.run(['git', 'show', HISTORICAL_REF + ':' + name], cwd=ROOT,
                                check=True, capture_output=True, timeout=10)
        if hashlib.sha256(result.stdout).hexdigest() != digest:
            raise AssertionError('historical test source fixture digest drift')
        snapshots[name] = result.stdout
    original_read, original_load = module.read_public, module.load
    def historical_read(path, *args):
        relative = Path(path).relative_to(ROOT).as_posix() if Path(path).is_relative_to(ROOT) else None
        return snapshots[relative] if relative in snapshots else original_read(path, *args)
    def historical_load(root, name):
        if name != 'tools/local-candidate/verify_image.py':
            return original_load(root, name)
        verifier = types.ModuleType('historical_public_candidate_verifier')
        verifier.__file__ = str(ROOT / name)
        # The later historical helper supplies an immutable-reader seam absent
        # from this commit. Adapt only this in-memory TEST fixture, retaining
        # every old contract/hash/mapping/budget check and raw snapshot digest.
        source = snapshots[name].decode()
        signature = 'def build_contract(source_root):'
        reader_site = '    spec.loader.exec_module(notices)\n'
        assert source.count(signature) == source.count(reader_site) == 1
        source = source.replace(signature, 'def build_contract(source_root, *, read_regular=None):')
        source = source.replace(reader_site, reader_site +
                                '    if read_regular is not None:\n        notices.read_regular = read_regular\n')
        exec(compile(source, verifier.__file__, 'exec'), verifier.__dict__)
        return verifier
    setattr(module, 'read_public', historical_read)
    setattr(module, 'load', historical_load)
    return module


class PackageImageTests(unittest.TestCase):
    def test_overlay_binds_candidate_without_changing_production(self):
        m = load()
        paths = ('build/Dockerfile', 'build/vere-release.json',
                 'tools/browser-importer/runtime.py', '.dockerignore')
        before = {p: (ROOT / p).read_bytes() for p in paths}
        historical = {p: m.read_public(ROOT / p) for p in paths}
        files = m.overlay(ROOT)
        recipe = files['build/Dockerfile'].decode()
        self.assertIn('COPY --chown=0:0 candidate/urbit /out/urbit', recipe)
        self.assertIn(m.CANDIDATE_SHA256 + '  /out/urbit', recipe)
        self.assertNotIn('install_vere.py', recipe)
        self.assertNotIn('--download', recipe)
        self.assertIn('distribution-cleared="false"', recipe)
        self.assertIn('python3=3.14.10-r1', recipe)
        self.assertNotIn('python3=3.14.8-r0', recipe)
        self.assertEqual(files['tools/browser-importer/runtime.py'],
                         historical['tools/browser-importer/runtime.py'].replace(
                             m.OFFICIAL_SHA256.encode(), m.CANDIDATE_SHA256.encode()))
        self.assertEqual(before, {p: (ROOT / p).read_bytes() for p in paths})
        self.assertNotIn('build/install_vere.py', files)
        self.assertTrue(files['.dockerignore'].startswith(b'**\n'))
        self.assertIn(b'!candidate/urbit\n', files['.dockerignore'])

    def test_prepare_and_verify_real_candidate_without_execution(self):
        m = load()
        self.assertTrue(hasattr(m, 'prepare'), 'scaffold RED: staging missing')
        scratch = tempfile.TemporaryDirectory(prefix='issue3-package-test-', dir=os.environ['TMPDIR'])
        self.addCleanup(scratch.cleanup)
        parent = Path(scratch.name)
        output = parent / 'prepared'
        with patch('subprocess.Popen', side_effect=AssertionError('no subprocess permitted')):
            result = m.prepare(ROOT, output)
        self.assertEqual(result['status'], 'PREPARED_NOT_BUILT')
        self.assertEqual(result['image_id'], None)
        self.assertFalse(result['build_authorized'])
        self.assertFalse(result['ship_execution_authorized'])
        binary = output / 'context/candidate/urbit'
        self.assertEqual(hashlib.sha256(binary.read_bytes()).hexdigest(), m.CANDIDATE_SHA256)
        self.assertEqual(binary.stat().st_mode & 0o777, 0o555)
        digest = hashlib.sha256((output / 'binding.json').read_bytes()).hexdigest()
        self.assertEqual(m.verify(output, digest)['status'], 'PREPARED_NOT_BUILT')
        with self.assertRaises(FileExistsError):
            m.prepare(ROOT, output)
        # Metadata-only rejection: never acquire an unexpected/private payload.
        unexpected = output / 'context/candidate/private-canary'
        unexpected.write_text('SYNTHETIC-DO-NOT-READ\n')
        real_read = m.read_public
        def checked_read(path, *args):
            self.assertNotEqual(Path(path), unexpected)
            return real_read(path, *args)
        with patch.object(m, 'read_public', side_effect=checked_read):
            with self.assertRaisesRegex(ValueError, 'unexpected'):
                m.verify(output, digest)

    def test_exact_binary_refuses_corruption_and_substitution(self):
        m = load()
        data = (ROOT / 'build_issue3_amd64_curl_build_02/artifact/urbit').read_bytes()
        m.validate_binary(data)
        for changed in (data[:-1], data[:-1] + bytes([data[-1] ^ 1]), b'not the candidate'):
            with self.assertRaisesRegex(ValueError, 'exact allocator-corrected'):
                m.validate_binary(changed)

    def test_dockerfile_preimage_refuses_before_derived_source_reads(self):
        m = load()
        changed = (ROOT / 'build/Dockerfile').read_bytes() + b'COPY tools/browser-importer/private-canary /tmp/\n'
        real_read = m.read_public
        def altered(path, *args):
            if Path(path) == ROOT / 'build/Dockerfile':
                return changed
            return real_read(path, *args)
        with patch.object(m, 'read_public', side_effect=altered), \
                patch.object(m, 'load', side_effect=AssertionError('derived reader reached before preimage check')):
            with self.assertRaisesRegex(ValueError, 'preimage'):
                m.overlay(ROOT)

    def test_public_reader_holds_ancestor_during_swap(self):
        m = load()
        scratch = tempfile.TemporaryDirectory(prefix='issue3-ancestor-race-', dir=os.environ['TMPDIR'])
        self.addCleanup(scratch.cleanup)
        root = Path(scratch.name)
        (root / 'public').mkdir()
        (root / 'other').mkdir()
        (root / 'public/item').write_bytes(b'public fixture')
        (root / 'other/item').write_bytes(b'SYNTHETIC-PRIVATE-CANARY')
        original_open = os.open
        swapped = []
        def swap(path, flags, *args, **kwargs):
            if Path(path).name == 'item' and not swapped:
                (root / 'public').rename(root / 'held')
                (root / 'public').symlink_to(root / 'other', target_is_directory=True)
                swapped.append(True)
            return original_open(path, flags, *args, **kwargs)
        with patch.object(m.os, 'open', side_effect=swap):
            self.assertEqual(m.read_public(root / 'public/item'), b'public fixture')
        self.assertEqual(swapped, [True])

    def test_public_reader_refuses_links_special_files_and_oversize(self):
        m = load()
        scratch = tempfile.TemporaryDirectory(prefix='issue3-public-reader-', dir=os.environ['TMPDIR'])
        self.addCleanup(scratch.cleanup)
        root = Path(scratch.name)
        ordinary = root / 'ordinary'
        ordinary.write_bytes(b'public fixture')
        self.assertEqual(m.read_public(ordinary), b'public fixture')
        with self.assertRaises(ValueError):
            m.read_public(ordinary, 2)
        (root / 'symlink').symlink_to(ordinary)
        with self.assertRaises(OSError):
            m.read_public(root / 'symlink')
        os.link(ordinary, root / 'hardlink')
        with self.assertRaises(ValueError):
            m.read_public(ordinary)
        os.mkfifo(root / 'fifo')
        with self.assertRaises(ValueError):
            m.read_public(root / 'fifo')

    def test_task_local_verifier_accepts_candidate_size_only_in_its_instance(self):
        m = load()
        fixture = m.load(ROOT, 'tests/test_candidate_image_verifier.py')
        # Real saved-image parser, synthetic layer with the actual candidate ELF.
        # No Docker or executable invocation; Config/private canaries stay unread.
        fixture.ELF = (ROOT / 'build_issue3_amd64_curl_build_02/artifact/urbit').read_bytes()
        stream, metadata, contract = fixture.fixture()
        with self.assertRaises(ValueError):
            m.load(ROOT, 'tools/local-candidate/verify_image.py').verify_stream(stream, metadata, contract)
        stream.seek(0)
        result = m.image_verifier().verify_stream(stream, metadata, contract)
        self.assertEqual(result['selected_files']['bin/urbit']['sha256'], m.CANDIDATE_SHA256)
        self.assertFalse(result['container_executed'])
        self.assertFalse(result['config_parsed'])
        self.assertNotIn('NEVER-RETAIN', repr(result))
        self.assertNotIn('PRIVATE-CONFIG-CANARY', repr(result))
        self.assertEqual(m.load(ROOT, 'tools/local-candidate/verify_image.py').MAX_ELF, 24 * 1024**2)


if __name__ == '__main__':
    unittest.main()
