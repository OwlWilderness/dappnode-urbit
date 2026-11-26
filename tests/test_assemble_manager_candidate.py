#!/usr/bin/env python3
"""Engine-free assembler controls using tiny synthetic Docker-save archives."""
import contextlib
import hashlib
import importlib.util
import io
import json
import os
import shutil
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / 'tools/host-integration/assemble_manager_candidate.py'
IMAGE = 'dappmanager.dnp.dappnode.eth:0.2.129'
PIN = 'a21bab295d4c68c3b6115498b18a8efaf89d52a0'
PATCH = ROOT / 'tools/host-integration/upstream-dappmanager.patch'


def digest(data):
    return hashlib.sha256(data).hexdigest()


def tree_digest(directory):
    records = [[p.relative_to(directory).as_posix(), oct(p.stat().st_mode & 0o777),
                digest(p.read_bytes())] for p in sorted(directory.rglob('*')) if p.is_file()]
    return digest(json.dumps(records, separators=(',', ':')).encode())


def put_json(path, value):
    path.write_text(json.dumps(value, sort_keys=True) + '\n')


class AssemblerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='assembler-', dir=os.environ.get('TMPDIR'))
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.prepared = self.base / 'prepared'
        source = self.prepared / 'source'
        source.mkdir(parents=True)
        provenance = self.prepared / 'provenance'
        provenance.mkdir()
        (provenance / PATCH.name).write_bytes(PATCH.read_bytes())
        put_json(source / 'dappnode_package.json', {'name': 'dappmanager.dnp.dappnode.eth',
                 'version': '0.2.129', 'architectures': ['linux/amd64', 'linux/arm64'],
                 'type': 'dncore', 'cid': 'OFFICIAL-DO-NOT-COPY'})
        (source / 'docker-compose.yml').write_text('''version: "3.5"
networks:
  dncore_network:
    name: dncore_network
    external: true
volumes:
  dappmanagerdnpdappnodeeth_data: {}
services:
  dappmanager.dnp.dappnode.eth:
    build: .
    image: "dappmanager.dnp.dappnode.eth:0.2.129"
    container_name: DAppNodeCore-dappmanager.dnp.dappnode.eth
    restart: always
    volumes:
      - "/run/dbus/system_bus_socket:/run/dbus/system_bus_socket"
      - "dappmanagerdnpdappnodeeth_data:/usr/src/app/dnp_repo/"
      - "/usr/src/dappnode/DNCORE/:/usr/src/app/DNCORE/"
      - "/var/run/docker.sock:/var/run/docker.sock"
      - "/etc/hostname:/etc/dappnodename:ro"
    environment:
      - LOG_LEVEL=info
      - ETH_MAINNET_RPC_URL_REMOTE=
      - IPFS_HOST=
      - DISABLE_UPNP=
      - ALWAYS_DAPPGETBASIC=
      - SKIP_COMPOSE_VALIDATION=
      - TEST=
    networks:
      dncore_network:
        aliases:
          - dappmanager.dappnode
          - my.dappnode
          - dappnode.local
''')
        (source / 'source.txt').write_text('patched synthetic source\n')
        self.candidate = {'schema': 1, 'state': 'source-prepared', 'image_state': 'image-pending',
            'installable': False, 'version': '0.2.129', 'compose_image': IMAGE,
            'image_id': None, 'archive': None, 'cid': None, 'content_hash': None,
            'historical_releases_are_candidate_identity': False,
            'source_tag': 'v0.2.129', 'source_commit': PIN,
            'source_archive_sha256': 'c958726dee40246aa67d3ac736fb20305befc4f238511346c0b5724419eb759d',
            'patch_sha256': digest(PATCH.read_bytes()), 'source_tree_sha256': tree_digest(source),
            'manifest_sha256': digest((source / 'dappnode_package.json').read_bytes()),
            'compose_sha256': digest((source / 'docker-compose.yml').read_bytes())}
        self.save_candidate()
        self.host = self.base / 'host'
        self.host.mkdir()
        (self.host / 'host.py').write_text('# source-only host companion\n')
        self.host_manifest = {'version': 1, 'deployment_qualified': False,
            'files': {'host.py': digest((self.host / 'host.py').read_bytes())}}
        self.save_host()
        self.archive = self.base / 'manager.txz'
        self.labels = {'org.uvm.issue19.source': PIN,
            'org.uvm.issue19.patch-sha256': self.candidate['patch_sha256'],
            'org.uvm.issue19.source-tree-sha256': self.candidate['source_tree_sha256']}
        self.image_id = self.make_archive()
        self.output = self.base / 'output'

    def save_candidate(self):
        put_json(self.prepared / 'candidate.json', self.candidate)

    def save_host(self):
        put_json(self.host / 'manifest.json', self.host_manifest)

    def make_archive(self, tags=None, architecture='arm64', labels=None, layer=b'synthetic layer',
                     recorded_layer=None, extra=None):
        config = json.dumps({'architecture': architecture, 'os': 'linux',
            'config': {'Labels': self.labels if labels is None else labels},
            'rootfs': {'type': 'layers', 'diff_ids': ['sha256:' + digest(
                layer if recorded_layer is None else recorded_layer)]}}, sort_keys=True).encode()
        config_name = digest(config) + '.json'
        members = [('manifest.json', json.dumps([{'Config': config_name,
            'RepoTags': [IMAGE] if tags is None else tags, 'Layers': ['layer/layer.tar']}]).encode()),
            (config_name, config), ('layer/layer.tar', layer)]
        members.extend(extra or [])
        with tarfile.open(self.archive, 'w:xz') as tar:
            for name, data in members:
                entry = tarfile.TarInfo(name)
                entry.size = len(data)
                tar.addfile(entry, io.BytesIO(data))
        return 'sha256:' + digest(config)

    def api(self):
        self.assertTrue(MODULE.is_file(), 'assembler implementation is missing (scaffold RED)')
        spec = importlib.util.spec_from_file_location('assemble_manager_candidate', MODULE)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def assemble(self):
        return self.api().assemble(self.prepared, self.host, self.archive, self.image_id, self.output)

    def assert_refused(self, pattern):
        try:
            with self.assertRaisesRegex(ValueError, pattern):
                self.assemble()
            self.assertFalse(self.output.exists(), 'refusal must precede output creation')
        finally:
            if self.output.exists():
                shutil.rmtree(self.output)

    def test_source_candidate_refusals(self):
        changes = {'schema': 2, 'state': 'installed', 'version': '0.2.71',
            'image_state': 'built', 'installable': True, 'image_id': 'sha256:' + 'a' * 64,
            'archive': 'official.txz', 'cid': 'official', 'content_hash': 'official',
            'historical_releases_are_candidate_identity': True,
            'compose_image': IMAGE + '-wrong', 'source_tag': 'v0.2.71',
            'source_commit': '0' * 40, 'source_archive_sha256': '0' * 64,
            'patch_sha256': '0' * 64, 'source_tree_sha256': '0' * 64,
            'manifest_sha256': '0' * 64, 'compose_sha256': '0' * 64}
        baseline = dict(self.candidate)
        for key, value in changes.items():
            with self.subTest(field=key):
                self.candidate = dict(baseline, **{key: value})
                self.save_candidate()
                self.assert_refused('candidate|source|patch|manifest|Compose')
        self.candidate = baseline
        self.save_candidate()

    def test_source_bytes_modes_and_patch_refusals(self):
        source = self.prepared / 'source'
        for relative in ('source/source.txt', 'source/dappnode_package.json',
                         'source/docker-compose.yml', 'provenance/upstream-dappmanager.patch'):
            path = self.prepared / relative
            original = path.read_bytes()
            with self.subTest(path=relative):
                path.write_bytes(original + b' ')
                self.assert_refused('source|patch|manifest|Compose')
                path.write_bytes(original)
        original_mode = (source / 'source.txt').stat().st_mode & 0o777
        (source / 'source.txt').chmod(0o755)
        self.assert_refused('source')
        (source / 'source.txt').chmod(original_mode)
        (source / 'extra').write_text('untracked')
        self.assert_refused('source')
        (source / 'extra').unlink()
        (source / 'link').symlink_to(source / 'source.txt')
        self.candidate['source_tree_sha256'] = tree_digest(source)
        self.save_candidate()
        self.assert_refused('symlink|regular')

    def test_host_byte_inventory_refusals(self):
        path = self.host / 'host.py'
        baseline = path.read_bytes()
        with self.subTest(case='changed'):
            path.write_bytes(baseline + b'changed')
            self.assert_refused('host')
        path.write_bytes(baseline)
        with self.subTest(case='extra'):
            (self.host / 'extra').write_text('unlisted')
            self.assert_refused('host')
        (self.host / 'extra').unlink()
        with self.subTest(case='missing'):
            path.unlink()
            self.assert_refused('host')
        path.write_bytes(baseline)
        with self.subTest(case='symlink'):
            path.unlink()
            path.symlink_to(self.prepared / 'source/source.txt')
            self.assert_refused('symlink|regular|host')
        path.unlink()
        path.write_bytes(baseline)

    def test_host_manifest_refusals(self):
        baseline = dict(self.host_manifest)
        variants = [{'version': 2}, {'deployment_qualified': True},
                    {'files': {'../outside': '0' * 64}}, {'files': {}},
                    {'files': {'host.py': 'wrong'}},
                    {'files': {'host.py': self.host_manifest['files']['host.py'],
                               'manifest.json': '0' * 64}}]
        for variant in variants:
            with self.subTest(variant=variant):
                self.host_manifest = dict(baseline, **variant)
                self.save_host()
                self.assert_refused('host')
        self.host_manifest = baseline
        self.save_host()

    def test_archive_identity_refusals(self):
        variants = [('tag', {'tags': ['wrong:0.2.129']}),
                    ('extra-tag', {'tags': [IMAGE, 'extra:latest']}),
                    ('duplicate-tag', {'tags': [IMAGE, IMAGE]}),
                    ('no-tag', {'tags': []}),
                    ('arch', {'architecture': 'amd64'}),
                    ('layer', {'recorded_layer': b'not the actual layer'})]
        for name, options in variants:
            with self.subTest(case=name):
                self.image_id = self.make_archive(**options)
                self.assert_refused('archive|image|ARM64|tag|layer')
        for key in self.labels:
            for mode in ('wrong', 'missing'):
                with self.subTest(label=key, mode=mode):
                    labels = dict(self.labels)
                    if mode == 'wrong':
                        labels[key] = 'wrong'
                    else:
                        labels.pop(key)
                    self.image_id = self.make_archive(labels=labels)
                    self.assert_refused('label')

    def test_expected_image_id_refusals(self):
        for value in ('sha256:' + '0' * 64, 'a' * 64, 'sha256:' + 'A' * 64, 'sha256:bad'):
            with self.subTest(image_id=value):
                self.image_id = value
                self.assert_refused('image ID|config|archive')

    def test_archive_members_refusals(self):
        for name, data in [('manifest.json', b'[]'), ('../escape', b'escape'),
                           ('/absolute', b'escape'), ('layer/layer.tar', b'duplicate')]:
            with self.subTest(member=name):
                self.image_id = self.make_archive(extra=[(name, data)])
                self.assert_refused('archive|member|duplicate')
        self.archive.write_bytes(b'not xz Docker-save data')
        self.assert_refused('archive|xz')

    def test_output_is_fresh_and_outside_inputs(self):
        sentinel = self.output
        sentinel.mkdir()
        (sentinel / 'sentinel').write_text('untouched')
        try:
            self.assemble()
        except (ValueError, OSError) as error:
            self.assertIsInstance(error, ValueError, 'fresh output refusal must be explicit')
        else:
            self.fail('existing output accepted')
        self.assertEqual((sentinel / 'sentinel').read_text(), 'untouched')
        self.assertEqual(sorted(p.name for p in sentinel.iterdir()), ['sentinel'])
        for directory in (self.prepared, self.host):
            with self.subTest(input=directory):
                self.output = directory / 'nested-output'
                with self.assertRaisesRegex(ValueError, 'outside|overlap'):
                    self.assemble()
                self.assertFalse(self.output.exists())

    def reseal_source_and_image(self):
        source = self.prepared / 'source'
        self.candidate['manifest_sha256'] = digest((source / 'dappnode_package.json').read_bytes())
        self.candidate['compose_sha256'] = digest((source / 'docker-compose.yml').read_bytes())
        self.candidate['source_tree_sha256'] = tree_digest(source)
        self.save_candidate()
        self.labels['org.uvm.issue19.source-tree-sha256'] = self.candidate['source_tree_sha256']
        self.image_id = self.make_archive()

    def test_resealed_source_version_refused(self):
        path = self.prepared / 'source/dappnode_package.json'
        manifest = json.loads(path.read_text())
        manifest['version'] = '0.2.71'
        put_json(path, manifest)
        self.reseal_source_and_image()
        self.assert_refused('manifest|version')

    def test_resealed_compose_drift_refused(self):
        path = self.prepared / 'source/docker-compose.yml'
        original = path.read_text()
        variants = [original.replace(IMAGE, 'wrong:0.2.71'),
                    original.replace('    build: .\n', ''),
                    original.replace('    volumes:\n', '    volumes:\n    volumes:\n'),
                    original + '    build: another\n',
                    original.replace('    volumes:\n',
                        '    volumes:\n      - "/run/uvm-maintenance:/run/uvm-maintenance:rw"\n')]
        for text in variants:
            with self.subTest(compose=text):
                path.write_text(text)
                self.reseal_source_and_image()
                self.assert_refused('Compose|mount|build')

    def test_resealed_quoted_build_and_flow_compose_refused(self):
        path = self.prepared / 'source/docker-compose.yml'
        original = path.read_text()
        for extra in ('    "build": another\n', "    'build': another\n",
                      '  injected: {image: "wrong:latest", build: another}\n'):
            with self.subTest(extra=extra):
                path.write_text(original + extra)
                self.reseal_source_and_image()
                self.assert_refused('Compose')

    def test_copy_corruption_cannot_complete(self):
        api = self.api()
        real_copyfile = api.shutil.copyfile
        for target in (api.ARCHIVE_NAME, 'source-candidate.json', 'upstream-dappmanager.patch'):
            with self.subTest(target=target):
                def corrupt(source, destination, **kwargs):
                    result = real_copyfile(source, destination, **kwargs)
                    if Path(destination).name == target:
                        with Path(destination).open('ab') as stream:
                            stream.write(b'corruption')
                    return result
                try:
                    with mock.patch.object(api.shutil, 'copyfile', side_effect=corrupt):
                        with self.assertRaisesRegex(ValueError, 'copied|copy|changed'):
                            api.assemble(self.prepared, self.host, self.archive, self.image_id, self.output)
                    self.assertFalse((self.output / 'local-provenance.json').exists())
                    self.assertFalse((self.output / 'sha256-manifest.json').exists())
                finally:
                    if self.output.exists():
                        shutil.rmtree(self.output)

    def test_host_copy_corruption_cannot_complete(self):
        api = self.api()
        real_copytree = api.shutil.copytree
        def corrupt(source, destination, **kwargs):
            result = real_copytree(source, destination, **kwargs)
            (Path(destination) / 'host.py').write_text('corrupted copy')
            return result
        with mock.patch.object(api.shutil, 'copytree', side_effect=corrupt):
            with self.assertRaisesRegex(ValueError, 'host|copied|copy'):
                api.assemble(self.prepared, self.host, self.archive, self.image_id, self.output)
        self.assertFalse((self.output / 'local-provenance.json').exists())
        self.assertFalse((self.output / 'sha256-manifest.json').exists())

    def rewrite_archive(self, transform):
        members = []
        with tarfile.open(self.archive, 'r:xz') as tar:
            for member in tar:
                stream = tar.extractfile(member)
                assert stream is not None
                members.append((member.name, stream.read()))
        with tarfile.open(self.archive, 'w:xz') as tar:
            for name, data in transform(members):
                member = tarfile.TarInfo(name)
                member.size = len(data)
                tar.addfile(member, io.BytesIO(data))

    def test_archive_config_bytes_and_metadata_regressions(self):
        # Regression controls for the existing ID/config and metadata validator.
        def corrupt_config(members):
            return [(name, data + b' ' if name.endswith('.json') and name != 'manifest.json' else data)
                    for name, data in members]
        def extra_image(members):
            return [(name, json.dumps(json.loads(data) * 2).encode() if name == 'manifest.json' else data)
                    for name, data in members]
        def missing_layer(members):
            return [(name, data) for name, data in members if not name.endswith('layer.tar')]
        for transform in (corrupt_config, extra_image, missing_layer):
            with self.subTest(transform=transform.__name__):
                self.image_id = self.make_archive()
                self.rewrite_archive(transform)
                self.assert_refused('archive|config|image|metadata')
        self.image_id = self.make_archive()
        self.archive.write_bytes(self.archive.read_bytes()[:-8])
        self.assert_refused('archive|xz')

    def test_cli_refusal_has_no_output_or_completion(self):
        api = self.api()
        argv = [str(MODULE), '--prepared', str(self.prepared), '--host-companion', str(self.host),
                '--image-archive', str(self.archive), '--expected-image-id', 'sha256:' + '0' * 64,
                '--output', str(self.output)]
        stdout, stderr = io.StringIO(), io.StringIO()
        with mock.patch.object(api.sys, 'argv', argv):
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                status = api.main()
        self.assertEqual(status, 2)
        self.assertEqual(stdout.getvalue(), '')
        self.assertIn('candidate assembly refused:', stderr.getvalue())
        self.assertFalse(self.output.exists())

    def test_local_arm64_success(self):
        result = self.assemble()
        self.assertEqual(result['state'], 'local-arm64-candidate')
        self.assertIs(result['installable'], False)
        self.assertIs(result['host_plan_approved'], False)
        self.assertEqual(result['image_id'], self.image_id)
        self.assertEqual(result['image_archive_sha256'], digest(self.archive.read_bytes()))
        self.assertEqual(result['host_manifest_sha256'], digest((self.host / 'manifest.json').read_bytes()))
        manifest = json.loads((self.output / 'dappnode_package.json').read_text())
        self.assertEqual(manifest['architectures'], ['linux/arm64'])
        self.assertEqual(manifest['version'], '0.2.129')
        self.assertNotIn('cid', manifest)
        compose = (self.output / 'docker-compose.yml').read_text()
        self.assertIn(IMAGE, compose)
        self.assertNotIn('build:', compose)
        self.assertEqual(compose.count('/run/uvm-maintenance:/run/uvm-maintenance:ro'), 1)
        self.assertEqual((self.output / 'host-companion/host.py').read_bytes(),
                         (self.host / 'host.py').read_bytes())
        self.assertEqual((self.output / 'dappmanager.dnp.dappnode.eth_0.2.129_linux-arm64.txz').read_bytes(),
                         self.archive.read_bytes())
        inventory = json.loads((self.output / 'sha256-manifest.json').read_text())['files']
        actual = {p.relative_to(self.output).as_posix(): digest(p.read_bytes())
                  for p in self.output.rglob('*') if p.is_file() and p.name != 'sha256-manifest.json'}
        self.assertEqual(inventory, actual)
        self.assertNotIn('OFFICIAL-DO-NOT-COPY', (self.output / 'dappnode_package.json').read_text())


if __name__ == '__main__':
    unittest.main(verbosity=2)
