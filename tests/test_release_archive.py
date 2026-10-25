"""Synthetic public Docker-save archives only; retain every fixture."""
import hashlib
import importlib.util
import io
import json
import lzma
import os
from pathlib import Path
import tarfile
import tempfile
import tracemalloc
import unittest
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
CANARY = 'SYNTHETIC_CONFIG_SECRET_DO_NOT_DISCLOSE'
TAG = 'ship.uvm.public.dappnode.eth:0.1.3'


def digest(data):
    return 'sha256:' + hashlib.sha256(data).hexdigest()


def tar_bytes(entries):
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode='w', format=tarfile.USTAR_FORMAT) as archive:
        for name, data, kind in entries:
            member = tarfile.TarInfo(name)
            member.type = kind
            member.size = len(data)
            if kind in (tarfile.SYMTYPE, tarfile.LNKTYPE):
                member.linkname = 'manifest.json'
            archive.addfile(member, io.BytesIO(data))
    return out.getvalue()


class ArchiveTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        base = Path(os.environ['ARCHIVE_TEST_SCRATCH'])
        base.mkdir(mode=0o700, parents=True, exist_ok=True)
        cls.directory = Path(tempfile.mkdtemp(prefix='case-', dir=base))

    def setUp(self):
        module_path = ROOT / 'scripts/verify_release_archive.py'
        self.assertTrue(module_path.is_file(), 'archive verifier API is missing (scaffold RED)')
        spec = importlib.util.spec_from_file_location('verify_release_archive', module_path)
        assert spec is not None and spec.loader is not None
        self.api = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.api)
        self.raw_layers = [tar_bytes([('public.txt', b'first', tarfile.REGTYPE)]),
                           tar_bytes([('other.txt', b'second', tarfile.REGTYPE)])]
        self.layers = [digest(data) for data in self.raw_layers]
        self.layer_ids = ['a' * 64, 'b' * 64]
        self.layer_names = [name + '/layer.tar' for name in self.layer_ids]
        self.config: Any = {'os': 'linux', 'architecture': 'amd64',
                       'rootfs': {'type': 'layers', 'diff_ids': self.layers},
                       'config': {'Env': [CANARY]}, 'history': [{'created_by': CANARY}]}
        self.bind_config()

    def bind_config(self):
        self.config_bytes = json.dumps(self.config).encode()
        self.image_id = digest(self.config_bytes)
        self.config_name = self.image_id[7:] + '.json'
        self.manifest = [{'Config': self.config_name, 'RepoTags': [TAG],
                          'Layers': list(self.layer_names)}]

    def entries(self):
        entries = [(self.config_name, self.config_bytes, tarfile.REGTYPE)]
        for name, data in zip(self.layer_ids, self.raw_layers):
            entries.extend([(name + '/', b'', tarfile.DIRTYPE),
                            (name + '/VERSION', b'1.0', tarfile.REGTYPE),
                            (name + '/json', json.dumps({'id': name}).encode(), tarfile.REGTYPE),
                            (name + '/layer.tar', data, tarfile.REGTYPE)])
        entries.extend([('manifest.json', json.dumps(self.manifest).encode(), tarfile.REGTYPE),
                        ('repositories', json.dumps({TAG.rsplit(':', 1)[0]: {
                            TAG.rsplit(':', 1)[1]: self.layer_ids[-1]}}).encode(), tarfile.REGTYPE)])
        return entries

    def fixture(self, entries=None, raw=None, compressed=None):
        if compressed is None:
            compressed = lzma.compress(raw if raw is not None else tar_bytes(
                self.entries() if entries is None else entries), format=lzma.FORMAT_XZ)
        fd, path = tempfile.mkstemp(prefix='archive-', suffix='.txz', dir=self.directory)
        with os.fdopen(fd, 'wb') as out:
            out.write(compressed)
        return Path(path)

    def verify(self, path, **overrides):
        kwargs = dict(image_id=self.image_id, repo_tag=TAG, layers=self.layers)
        kwargs.update(overrides)
        return self.api.verify_archive(path, **kwargs)

    def refuse(self, path, **overrides):
        with self.assertRaises(self.api.ArchiveError) as caught:
            self.verify(path, **overrides)
        self.assertNotIn(CANARY, str(caught.exception))
        self.assertIsNone(caught.exception.__cause__)

    def test_identity_must_be_bound_to_actual_archive_bytes(self):
        path = self.fixture()
        self.refuse(path, image_id='sha256:' + '0' * 64)

    def test_binding_rejects_wrong_tag_platform_and_layer_order(self):
        self.refuse(self.fixture(), repo_tag='other:tag')
        self.config['architecture'] = 'arm64'
        self.bind_config()
        self.refuse(self.fixture())

    def test_layer_bytes_must_match_ordered_diff_ids(self):
        self.raw_layers.reverse()
        self.refuse(self.fixture())

    def test_raw_config_hash_not_filename_is_identity(self):
        self.config_bytes += b' '
        self.refuse(self.fixture())

    def test_xz_must_finish_exactly_one_complete_stream(self):
        compressed = lzma.compress(tar_bytes(self.entries()))
        for bad in (compressed[:-1], compressed[:-12], compressed + b'junk',
                    compressed + b'\0' * 4, compressed + lzma.compress(b''),
                    compressed[:-8] + b'BROKEN!!'):
            with self.subTest(length=len(bad)):
                self.refuse(self.fixture(compressed=bad))

    def test_tar_requires_two_terminal_blocks_and_zero_padding(self):
        raw = tar_bytes(self.entries())
        end = 0
        for _, data, _ in self.entries():
            end += 512 + ((len(data) + 511) // 512) * 512
        for bad in (raw[:end], raw[:end + 512], raw[:end + 1023],
                    raw[:-1], raw + b'x' * 512, raw[:end + 512] + raw[:512]):
            with self.subTest(length=len(bad)):
                self.refuse(self.fixture(raw=bad))

    def test_size_budget_bounds_compressed_and_decompressed_bytes(self):
        path = self.fixture()
        self.refuse(path, max_bytes=100)
        self.refuse(path, max_bytes=path.stat().st_size + 1)

    def test_duplicate_unsafe_unknown_and_special_members_refused(self):
        entries = self.entries()
        additions = [entries[0], entries[-2], entries[1],
                     ('../escape', b'', tarfile.REGTYPE),
                     ('/absolute', b'', tarfile.REGTYPE),
                     ('./manifest.json', b'[]', tarfile.REGTYPE),
                     ('unknown', b'', tarfile.REGTYPE),
                     ('blobs/sha256/' + 'c' * 64, b'', tarfile.REGTYPE),
                     ('c' * 64 + '/json', b'{}', tarfile.REGTYPE)]
        for entry in additions:
            with self.subTest(name=entry[0]):
                self.refuse(self.fixture(entries=entries + [entry]))
        for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.FIFOTYPE,
                     tarfile.CHRTYPE, tarfile.GNUTYPE_SPARSE, tarfile.XHDTYPE):
            with self.subTest(kind=kind):
                self.refuse(self.fixture(entries=entries + [('c' * 64 + '/json', b'', kind)]))

    def test_oversized_config_refused_before_parsing(self):
        self.config['history'] = ['x' * (1024 * 1024)]
        self.bind_config()
        self.refuse(self.fixture())

    def test_duplicate_json_keys_refused_without_payload_disclosure(self):
        self.config_bytes = self.config_bytes[:-1] + b', "architecture": "amd64"}'
        self.image_id = digest(self.config_bytes)
        self.config_name = self.image_id[7:] + '.json'
        self.manifest[0]['Config'] = self.config_name
        self.refuse(self.fixture())

    def test_unreferenced_layer_refused(self):
        extra = ('c' * 64 + '/layer.tar', self.raw_layers[0], tarfile.REGTYPE)
        self.refuse(self.fixture(entries=self.entries() + [extra]))

    def test_malformed_schemas_are_sanitized_refusals(self):
        for malformed in ({}, [None], [dict(self.manifest[0], Layers=[{}])],
                          [dict(self.manifest[0], Layers=None)],
                          [dict(self.manifest[0], Unexpected='value')]):
            with self.subTest(schema=type(malformed).__name__):
                entries = [(n, json.dumps(malformed).encode() if n == 'manifest.json' else d, k)
                           for n, d, k in self.entries()]
                self.refuse(self.fixture(entries=entries))
        self.config = []
        self.bind_config()
        self.refuse(self.fixture())

    def test_invalid_expected_contract_is_refused(self):
        path = self.fixture()
        for override in ({'image_id': None}, {'image_id': 'SHA256:' + 'a' * 64},
                         {'layers': None}, {'layers': []}, {'layers': self.layers * 33},
                         {'repo_tag': None}, {'repo_tag': ''}, {'max_bytes': True},
                         {'max_bytes': -1}, {'max_bytes': 0}, {'max_bytes': 1.5}):
            with self.subTest(field=next(iter(override))):
                self.refuse(path, **override)

    def test_conflicting_legacy_repository_metadata_is_refused(self):
        entries = [(n, b'{"other":{"tag":"bad"}}' if n == 'repositories' else d, k)
                   for n, d, k in self.entries()]
        self.refuse(self.fixture(entries=entries))

    def test_path_must_be_regular_nonsymlink_file(self):
        path = self.fixture()
        link = self.directory / ('link-' + path.name)
        link.symlink_to(path)
        self.refuse(link)
        self.refuse(self.directory)
        self.refuse(self.directory / 'missing')

    def test_manifest_selection_is_exact(self):
        variants = [[], self.manifest * 2,
                    [dict(self.manifest[0], RepoTags=[TAG, 'other:tag'])],
                    [dict(self.manifest[0], Layers=list(reversed(self.layer_names)))],
                    [dict(self.manifest[0], Layers=self.layer_names[:1])],
                    [dict(self.manifest[0], Layers=[self.layer_names[0]] * 2)]]
        for manifest in variants:
            with self.subTest(manifest_count=len(manifest)):
                entries = [(n, json.dumps(manifest).encode() if n == 'manifest.json' else d, k)
                           for n, d, k in self.entries()]
                self.refuse(self.fixture(entries=entries))

    def test_rootfs_and_os_are_independently_checked(self):
        for field, value in (('os', 'windows'), ('rootfs', {'type': 'layers', 'diff_ids': []}),
                             ('rootfs', {'type': 'layers', 'diff_ids': self.layers[::-1]}),
                             ('rootfs', None)):
            with self.subTest(field=field):
                original = self.config[field]
                self.config[field] = value
                self.bind_config()
                self.refuse(self.fixture())
                self.config[field] = original

    def test_truncated_member_corrupt_header_and_member_padding_refused(self):
        raw = tar_bytes(self.entries())
        damaged_header = bytes([raw[0] ^ 1]) + raw[1:]
        padding_at = 512 + len(self.config_bytes)
        damaged_padding = raw[:padding_at] + b'x' + raw[padding_at + 1:]
        for bad in (raw[:600], damaged_header, damaged_padding):
            self.refuse(self.fixture(raw=bad))

    def test_manifest_and_legacy_metadata_sizes_are_bounded(self):
        for name, size in (('manifest.json', 65537), (self.layer_ids[0] + '/json', 1048577),
                           ('repositories', 1048577)):
            with self.subTest(name=name):
                entries = [(n, b' ' * size if n == name else d, k) for n, d, k in self.entries()]
                self.refuse(self.fixture(entries=entries))
        header = tarfile.TarInfo(self.layer_names[0])
        header.size = 8589934593
        self.refuse(self.fixture(raw=header.tobuf(format=tarfile.GNU_FORMAT) + bytes(1024)))

    def test_legacy_metadata_is_optional_and_tar_order_not_layer_order(self):
        entries = [entry for entry in self.entries() if entry[0] in
                   {self.config_name, 'manifest.json', *self.layer_names}]
        result = self.verify(self.fixture(entries=list(reversed(entries))))
        self.assertEqual(result['layers'], self.layers)

    def test_large_layer_is_streamed_with_bounded_python_memory(self):
        self.raw_layers[0] = tar_bytes([('large', b'0' * (4 * 1024 * 1024), tarfile.REGTYPE)])
        self.layers = [digest(data) for data in self.raw_layers]
        self.config['rootfs']['diff_ids'] = self.layers
        self.bind_config()
        path = self.fixture()
        tracemalloc.start()
        try:
            result = self.verify(path)
            _, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        self.assertEqual(result['layers'], self.layers)
        # Includes the LZMA allocation as exposed by this Python build.
        self.assertLess(peak, 12 * 1024 * 1024)

    def test_malformed_config_error_and_stdout_never_disclose_canary(self):
        import contextlib
        self.config_bytes = ('{"config":"' + CANARY).encode()
        self.image_id = digest(self.config_bytes)
        self.config_name = self.image_id[7:] + '.json'
        self.manifest[0]['Config'] = self.config_name
        output = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            self.refuse(self.fixture())
        self.assertEqual(output.getvalue(), '')

    def test_unknown_tar_header_format_refused(self):
        raw = tar_bytes(self.entries())
        header = bytearray(raw[:512])
        header[257:265] = b'unknown!'
        header[148:156] = b' ' * 8
        header[148:156] = ('%06o\0 ' % sum(header)).encode()
        self.refuse(self.fixture(raw=bytes(header) + raw[512:]))

    def test_legacy_exporter_grammar_returns_exact_public_binding(self):
        path = self.fixture()
        result = self.verify(path)
        self.assertEqual(result, dict(image_id=self.image_id, repo_tag=TAG,
                                     platform='linux/amd64', layers=self.layers,
                                     archive_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                                     archive_bytes=path.stat().st_size))
        self.assertNotIn(CANARY, json.dumps(result))


if __name__ == '__main__':
    unittest.main()
