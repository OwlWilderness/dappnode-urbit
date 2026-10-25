"""Source-only notice packaging checks; no Docker or identity execution."""
import hashlib
import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def verifier():
    path = ROOT / 'scripts/verify-notice-packaging.py'
    if not path.is_file():
        raise AssertionError('scaffold RED: notice verifier is not implemented')
    spec = importlib.util.spec_from_file_location('notice_verifier', path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class NoticePackagingTests(unittest.TestCase):
    def test_runtime_image_copies_notices_and_contribution_terms(self):
        dockerfile = (ROOT / 'build/Dockerfile').read_text()
        runtime = dockerfile.split('\nFROM ', 1)[1]
        required = [
            'COPY --chown=0:0 THIRD_PARTY/ /usr/share/doc/uvm/THIRD_PARTY/',
            'COPY --chown=0:0 LICENSE.md /usr/share/doc/uvm/LICENSE.md',
            'COPY --chown=0:0 LICENSES/GPL-3.0-only.txt /usr/share/doc/uvm/LICENSES/GPL-3.0-only.txt',
        ]
        for instruction in required:
            self.assertIn(instruction, runtime)
        self.assertLess(runtime.index(required[0]), runtime.index('USER 10000:10000'))
        self.assertNotIn('chmod -R 777', runtime)

    def test_notice_tree_is_readable_and_not_writable_by_service(self):
        dockerfile = (ROOT / 'build/Dockerfile').read_text()
        permission = 'RUN chmod -R a=rX /usr/share/doc/uvm'
        self.assertIn(permission, dockerfile)
        self.assertLess(dockerfile.index(permission), dockerfile.index('USER 10000:10000'))

    def test_manifest_binds_source_and_optional_image_copy(self):
        module = verifier()
        scratch = os.environ['IMPORTER_TEST_SCRATCH']
        root = Path(tempfile.mkdtemp(prefix='notice-fixture-', dir=scratch))
        (root / 'build').mkdir()
        (root / 'THIRD_PARTY').mkdir()
        data = b'Public synthetic terms\n'
        (root / 'THIRD_PARTY/LICENSE').write_bytes(data)
        manifest = {'schema_version': 1, 'destination': '/usr/share/doc/uvm',
                    'files': {'THIRD_PARTY/LICENSE': hashlib.sha256(data).hexdigest()}}
        encoded = (json.dumps(manifest, indent=2) + '\n').encode()
        (root / 'build/notice-files.json').write_bytes(encoded)
        (root / '.dockerignore').write_text('**\n' + module.context_block(manifest['files']))
        self.assertEqual(module.verify(root)['files_verified'], 1)
        image = root / 'image'
        target = image / 'usr/share/doc/uvm'
        (target / 'THIRD_PARTY').mkdir(parents=True)
        (target / 'THIRD_PARTY/LICENSE').write_bytes(data)
        (target / 'notice-files.json').write_bytes(encoded)
        self.assertEqual(module.verify(root, image)['image_files_verified'], 1)
        ignore = (root / '.dockerignore').read_text()
        (root / '.dockerignore').write_text(ignore + '!THIRD_PARTY/private.key\n')
        with self.assertRaisesRegex(ValueError, 'context'):
            module.verify(root)
        (root / '.dockerignore').write_text(ignore)
        (target / 'THIRD_PARTY/LICENSE').write_bytes(b'altered notice')
        with self.assertRaisesRegex(ValueError, 'Copied notice digest mismatch'):
            module.verify(root, image)
        (root / 'THIRD_PARTY/LICENSE').write_bytes(b'altered source')
        with self.assertRaisesRegex(ValueError, 'Notice digest mismatch'):
            module.verify(root)

    def test_context_block_does_not_reset_existing_build_allowlist(self):
        module = verifier()
        block = module.context_block({'THIRD_PARTY/LICENSE': '0' * 64})
        self.assertNotIn('\nbuild/**\n', block)
        self.assertIn('!build/notice-files.json\n', block)
        self.assertIn('!THIRD_PARTY/\nTHIRD_PARTY/**\n', block)

    def test_rejects_symlink_root_before_reading_notice(self):
        module = verifier()
        root = Path(tempfile.mkdtemp(prefix='notice-link-', dir=os.environ['IMPORTER_TEST_SCRATCH']))
        actual = root / 'actual'
        actual.mkdir()
        (actual / 'public.txt').write_text('synthetic public text')
        (root / 'alias').symlink_to(actual, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, 'symlink'):
            module.read_regular(root / 'alias', 'public.txt')

    def test_accepts_bounded_prepared_public_source_archive(self):
        module = verifier()
        root = Path(tempfile.mkdtemp(prefix='notice-archive-', dir=os.environ['IMPORTER_TEST_SCRATCH']))
        data = b'public synthetic archive bytes\n' * 180000
        (root / 'public-source.tar.gz').write_bytes(data)
        self.assertEqual(module.read_regular(root, 'public-source.tar.gz'), data)

    def test_preserves_literal_public_distro_key_source_filename(self):
        module = verifier()
        name = 'THIRD_PARTY/platform/followup/aports/sources/alpine-keys/alpine-devel@lists.alpinelinux.org-4a6a0840.rsa.pub'
        self.assertEqual(module.public_path(name), name)


if __name__ == '__main__':
    unittest.main()
