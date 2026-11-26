"""Engine-free local-source candidate preparation checks (no SDK or engine)."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / 'tools/host-integration/prepare_manager_candidate.py'
_SOURCE_ENV = os.environ.get('UVM_MANAGER_PRISTINE_SOURCE')
SOURCE = Path(_SOURCE_ENV).resolve() if _SOURCE_ENV else ROOT / '.missing-upstream-source'
PATCH = ROOT / 'tools/host-integration/upstream-dappmanager.patch'
PIN = 'a21bab295d4c68c3b6115498b18a8efaf89d52a0'
PATCH_HASH = 'c7149f6b0923b013c354e89e43e02378c15e0bf7fe52c7671eeb693090ecbd50'
SCRATCH = Path(os.environ.get('IMPORTER_TEST_SCRATCH', tempfile.gettempdir())).resolve()


def run_cli(source, patch, output):
    return subprocess.run([sys.executable, '-B', str(CLI), '--source', str(source),
                           '--patch', str(patch), '--output', str(output)],
                          capture_output=True, text=True, timeout=90)


@unittest.skipUnless(_SOURCE_ENV and SOURCE.is_dir(),
                     'set UVM_MANAGER_PRISTINE_SOURCE to the pinned upstream checkout')
class CandidateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='manager-prep-test-', dir=SCRATCH)
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.output = self.base / 'candidate'

    def clone_source(self, name='input'):
        path = self.base / name
        child = subprocess.run(['git', 'clone', '--quiet', '--local', '--no-hardlinks',
                                str(SOURCE), str(path)], capture_output=True, text=True, timeout=90)
        self.assertEqual(child.returncode, 0, child.stderr)
        return path

    def test_nonpristine_or_wrong_pinned_source_is_refused_before_output_creation(self):
        for kind in ('tracked', 'untracked', 'ignored', 'wrong-head', 'wrong-tag', 'assume-unchanged', 'cid', 'content-hash'):
            with self.subTest(kind=kind):
                source = self.clone_source(kind)
                if kind in ('tracked', 'assume-unchanged'):
                    if kind == 'assume-unchanged':
                        subprocess.run(['git', '-C', str(source), 'update-index', '--assume-unchanged', 'README.md'], check=True)
                    with (source / 'README.md').open('a') as target:
                        target.write('\nDRIFT\n')
                elif kind == 'untracked':
                    (source / 'foreign.txt').write_text('not pinned')
                elif kind == 'ignored':
                    (source / 'node_modules').mkdir()
                    (source / 'node_modules/foreign').write_text('ignored drift')
                elif kind in ('wrong-head', 'wrong-tag'):
                    commit = subprocess.run(['git', '-C', str(source), '-c', 'user.name=Fixture',
                        '-c', 'user.email=fixture@example.invalid', 'commit-tree', 'HEAD^{tree}', '-p', 'HEAD'],
                        input='fixture-only wrong pin\n', text=True, capture_output=True, check=True).stdout.strip()
                    if kind == 'wrong-head':
                        subprocess.run(['git', '-C', str(source), 'update-ref', 'HEAD', commit], check=True)
                    else:
                        subprocess.run(['git', '-C', str(source), 'tag', '-f', 'v0.2.129', commit], check=True, capture_output=True)
                else:
                    path = source / 'dappnode_package.json'
                    manifest = json.loads(path.read_text())
                    manifest['cid' if kind == 'cid' else 'contentHash'] = 'official-release-identity'
                    path.write_text(json.dumps(manifest))
                output = self.base / ('candidate-' + kind)
                result = run_cli(source, PATCH, output)
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertIn('source', result.stderr)
                self.assertFalse(output.exists())

    def test_postpatch_identity_or_compose_drift_cannot_emit_completion(self):
        from unittest import mock
        spec = importlib.util.spec_from_file_location('manager_candidate', CLI)
        assert spec is not None and spec.loader is not None
        api = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(api)
        real_git = api.git
        for kind in ('cid', 'contentHash', 'compose-mount'):
            with self.subTest(kind=kind):
                output = self.base / ('tampered-' + kind)
                def altered_git(directory, *args, **kwargs):
                    result = real_git(directory, *args, **kwargs)
                    if args == ('apply', '-'):
                        if kind == 'compose-mount':
                            path = Path(directory) / 'docker-compose.yml'
                            path.write_bytes(path.read_bytes().replace(b'/var/run/docker.sock', b'/foreign/docker.sock'))
                        else:
                            path = Path(directory) / 'dappnode_package.json'
                            value = json.loads(path.read_text())
                            value[kind] = 'official-release-identity'
                            path.write_text(json.dumps(value))
                    return result
                with mock.patch.object(api, 'git', side_effect=altered_git):
                    with self.assertRaisesRegex(ValueError, 'candidate'):
                        api.prepare(SOURCE, PATCH, output)
                self.assertFalse((output / 'candidate.json').exists())
                self.assertTrue((output / 'source').exists())

    def test_existing_output_is_never_overwritten(self):
        for kind in ('directory', 'file', 'symlink', 'dangling-symlink'):
            with self.subTest(kind=kind):
                output = self.base / kind
                sentinel = self.base / (kind + '-sentinel')
                sentinel.write_bytes(b'owned evidence')
                if kind == 'directory':
                    output.mkdir()
                    (output / 'evidence').write_bytes(b'owned evidence')
                elif kind == 'file':
                    output.write_bytes(b'owned evidence')
                else:
                    output.symlink_to(sentinel if kind == 'symlink' else self.base / 'absent')
                result = run_cli(SOURCE, PATCH, output)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('File exists', result.stderr)
                self.assertEqual(sentinel.read_bytes(), b'owned evidence')
                if kind == 'directory':
                    self.assertEqual(list(p.name for p in output.iterdir()), ['evidence'])
                    self.assertEqual((output / 'evidence').read_bytes(), b'owned evidence')
                elif kind == 'file':
                    self.assertEqual(output.read_bytes(), b'owned evidence')
                else:
                    self.assertTrue(output.is_symlink())

    def test_output_within_input_is_refused_without_dirtying_source(self):
        source = self.clone_source()
        output = source / 'nested-output'
        result = run_cli(source, PATCH, output)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn('output must be outside source', result.stderr)
        self.assertFalse(output.exists())
        status = subprocess.run(['git', '-C', str(source), 'status', '--porcelain=v1',
                                 '--untracked-files=all', '--ignored'], capture_output=True, check=True)
        self.assertEqual(status.stdout, b'')

    def test_wrong_patch_hash_is_refused_before_output_creation(self):
        changed_patch = self.base / 'wrong.patch'
        changed_patch.write_bytes(PATCH.read_bytes() + b'\n')
        result = run_cli(SOURCE, changed_patch, self.output)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn('patch SHA256 mismatch', result.stderr)
        self.assertFalse(self.output.exists())

    def test_real_pinned_source_becomes_version_consistent_source_only(self):
        result = run_cli(SOURCE, PATCH, self.output)
        self.assertEqual(result.returncode, 0, result.stderr)
        receipt = json.loads((self.output / 'candidate.json').read_text())
        self.assertEqual(json.loads(result.stdout), receipt)
        self.assertEqual(receipt['state'], 'source-prepared')
        self.assertEqual(receipt['image_state'], 'image-pending')
        self.assertFalse(receipt['installable'])
        self.assertIsNone(receipt['image_id'])
        self.assertIsNone(receipt['archive'])
        self.assertIsNone(receipt['cid'])
        self.assertIsNone(receipt['content_hash'])
        self.assertEqual(receipt['source_commit'], PIN)
        self.assertEqual(receipt['source_tag'], 'v0.2.129')
        self.assertEqual(receipt['patch_sha256'], PATCH_HASH)
        self.assertEqual((self.output / 'provenance/upstream-dappmanager.patch').read_bytes(), PATCH.read_bytes())
        prepared = self.output / 'source'
        manifest = json.loads((prepared / 'dappnode_package.json').read_text())
        original = json.loads((SOURCE / 'dappnode_package.json').read_text())
        self.assertEqual(manifest.pop('version'), '0.2.129')
        original.pop('version')
        self.assertEqual(manifest, original)
        old_compose = (SOURCE / 'docker-compose.yml').read_bytes()
        self.assertEqual((prepared / 'docker-compose.yml').read_bytes(), old_compose.replace(
            b'image: "dappmanager.dnp.dappnode.eth:0.2.71"',
            b'image: "dappmanager.dnp.dappnode.eth:0.2.129"'))
        self.assertIn('assertUnmanaged', (prepared / 'packages/dappmanager/src/calls/backupRestore.ts').read_text())
        self.assertFalse((prepared / '.git').exists())
        self.assertEqual(receipt['manifest_sha256'], hashlib.sha256((prepared / 'dappnode_package.json').read_bytes()).hexdigest())
        self.assertEqual(receipt['compose_sha256'], hashlib.sha256((prepared / 'docker-compose.yml').read_bytes()).hexdigest())
        self.assertEqual(len(receipt['source_tree_sha256']), 64)
        self.assertEqual(json.loads((SOURCE / 'dappnode_package.json').read_text())['version'], '0.2.71')


if __name__ == '__main__':
    unittest.main()
