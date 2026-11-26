"""Synthetic static-verifier regression tests, not build/runtime evidence."""
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

RECIPE = Path(__file__).resolve().parents[1] / 'build/vere-openssl3'
spec = importlib.util.spec_from_file_location('openssl_binary_verifier', RECIPE / 'verify_binary.py')
assert spec is not None and spec.loader is not None
verifier = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verifier)
TARGETS = ('ext/curl/build.zig', 'ext/curl/build.zig.zon')


class BinaryVerifierTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='synthetic-binary-verifier-')
        self.addCleanup(self.temp.cleanup)
        self.attempt = Path(self.temp.name)
        self.artifact = self.attempt / 'artifact'
        self.frozen = self.attempt / 'frozen-recipe'
        self.artifact.mkdir()
        self.frozen.mkdir()
        self.lock = json.loads((RECIPE / 'inputs.json').read_text())
        # These existing fixtures model the preserved pre-hardening delivery.
        self.lock.pop('allocation_hardening', None)
        self.lock.pop('sha_overlay', None)
        self.lock.pop('h2o_overlay', None)
        self.lock.pop('ca_hardening', None)
        self.lock.pop('ca_preimages', None)
        self.lock.pop('curl_buffer_sha256', None)
        self.changes = {'pkg/noun/manage.c': b'synthetic allocator source'}
        self.receipt = dict(executable_sha256=verifier.sha(b'synthetic binary'),
                            executable_bytes=len(b'synthetic binary'), architecture='linux/amd64')
        self.write_json(self.attempt / 'result.json', dict(status='PASS', exit_code=0,
                                                        preserved=True, active_after=False))
        (self.artifact / 'urbit').write_bytes(b'synthetic binary')
        (self.artifact / 'urbit').chmod(0o555)
        for name, key in [('candidate.py', 'recipe_sha256'), ('Dockerfile', 'dockerfile_sha256'),
                          ('builder-apks.json', 'builder_apks_sha256')]:
            data = ('synthetic ' + name).encode()
            for directory in (self.artifact, self.frozen):
                (directory / name).write_bytes(data)
            self.receipt[key] = verifier.sha(data)
        (self.artifact / 'builder-apk-db.txt').write_bytes(b'synthetic database')
        self.receipt['builder_apk_db_sha256'] = verifier.sha(b'synthetic database')
        for target, item in self.lock['curl_overlays'].items():
            data = (RECIPE / item['file']).read_bytes()
            self.changes[target] = data
            for directory in (self.artifact, self.frozen):
                (directory / item['file']).write_bytes(data)
        self.receipt['source_changes'] = {name: verifier.sha(data) for name, data in self.changes.items()}
        self.overlay = dict(source_preimages={t: self.lock['source_preimages'][t] for t in TARGETS},
                            source_changes={t: self.receipt['source_changes'][t] for t in TARGETS},
                            overlays=self.lock['curl_overlays'])
        self.write_json(self.artifact / 'curl-overlay.json', self.overlay)
        self.sync_lock()
        self.sync_receipt()
        self.sync_archive()
        # Isolate unrelated native-tool linkage and reviewed allocator preimage.
        # All curl hashing, frozen-file, receipt and tar checks run for real.
        self.linkage = patch.object(verifier, 'linkage', return_value={
            k: self.receipt[k] for k in ('executable_sha256', 'executable_bytes', 'architecture')})
        self.linkage.start()
        self.addCleanup(self.linkage.stop)
        allocator = patch.object(verifier, 'ALLOCATOR_SHA256', verifier.sha(self.changes['pkg/noun/manage.c']))
        allocator.start()
        self.addCleanup(allocator.stop)

    @staticmethod
    def write_json(path, value):
        path.write_text(json.dumps(value))

    def sync_lock(self):
        for directory in (self.artifact, self.frozen):
            self.write_json(directory / 'inputs.json', self.lock)
        self.receipt['inputs_sha256'] = verifier.sha((self.artifact / 'inputs.json').read_bytes())

    def sync_receipt(self):
        self.write_json(self.artifact / 'candidate.json', self.receipt)

    def sync_archive(self):
        with tarfile.open(self.artifact / 'source-materials.tar.gz', 'w:gz') as archive:
            for name, data in self.changes.items():
                member = tarfile.TarInfo(self.lock['inputs']['vere']['root'] + '/' + name)
                member.size = len(data)
                archive.addfile(member, io.BytesIO(data))

    def test_hardening_source_receipt_cannot_be_omitted(self):
        expected = {}
        for name in ('pkg/vere/io/cttp.c', 'pkg/vere/io/http.c'):
            self.changes[name] = ('synthetic hardened ' + name).encode()
            expected[name] = verifier.sha(self.changes[name])
        self.lock['allocation_hardening'] = expected
        self.receipt['source_changes'].update(expected)
        overlay = dict(source_changes=expected,
                       source_preimages={name: self.lock['source_preimages'][name] for name in expected})
        path = self.artifact / 'allocation-overlay.json'
        self.write_json(path, overlay)
        self.sync_lock()
        self.sync_receipt()
        self.sync_archive()
        self.assertEqual(verifier.verify(self.attempt)['status'], 'PASS')
        for name in expected:
            digest = self.receipt['source_changes'].pop(name)
            self.sync_receipt()
            with self.subTest(omitted=name), self.assertRaisesRegex(ValueError, 'allocation'):
                verifier.verify(self.attempt)
            self.receipt['source_changes'][name] = digest
        self.sync_receipt()
        for invalid in ({}, dict(overlay, source_changes={}), dict(overlay, extra=True)):
            self.write_json(path, invalid)
            with self.subTest(overlay=invalid), self.assertRaisesRegex(ValueError, 'allocation'):
                verifier.verify(self.attempt)
        path.unlink()
        with self.assertRaisesRegex(ValueError, 'allocation'):
            verifier.verify(self.attempt)

    def test_ca_delivery_requires_all_source_and_receipt_bindings(self):
        targets = ('pkg/vere/main.c', 'pkg/vere/vere.h', 'pkg/vere/io/cttp.c')
        expected = {}
        for name in targets:
            self.changes[name] = ('synthetic CA hardening ' + name).encode()
            expected[name] = verifier.sha(self.changes[name])
        self.lock['ca_hardening'] = expected
        self.lock['ca_preimages'] = {name: 'a' * 64 for name in targets[:2]}
        self.receipt['source_changes'].update(expected)
        overlay = dict(source_changes=expected, source_preimages=self.lock['ca_preimages'])
        path = self.artifact / 'ca-overlay.json'
        self.write_json(path, overlay)
        self.sync_lock(); self.sync_receipt(); self.sync_archive()
        self.assertEqual(verifier.verify(self.attempt)['status'], 'PASS')
        for name in expected:
            digest = self.receipt['source_changes'].pop(name)
            self.sync_receipt()
            with self.subTest(omitted=name), self.assertRaisesRegex(ValueError, 'CA'):
                verifier.verify(self.attempt)
            self.receipt['source_changes'][name] = digest
        self.sync_receipt()
        for invalid in ({}, dict(overlay, source_changes={}), dict(overlay, extra=True)):
            self.write_json(path, invalid)
            with self.subTest(overlay=invalid), self.assertRaisesRegex(ValueError, 'CA'):
                verifier.verify(self.attempt)
        path.unlink()
        with self.assertRaisesRegex(ValueError, 'CA'):
            verifier.verify(self.attempt)
        self.write_json(path, overlay)
        for name in targets:
            data = self.changes[name]
            self.changes[name] = b'tampered CA source'
            self.sync_archive()
            with self.subTest(tampered=name), self.assertRaisesRegex(ValueError, 'archived changed-source'):
                verifier.verify(self.attempt)
            self.changes[name] = data
        self.sync_archive()
        # Duplicate members must not allow getmember's last-entry-wins lookup.
        with tarfile.open(self.artifact/'source-materials.tar.gz', 'w:gz') as archive:
            for name,data in self.changes.items():
                for content in ([b'drift',data] if name==targets[0] else [data]):
                    member = tarfile.TarInfo(self.lock['inputs']['vere']['root']+'/'+name)
                    member.size=len(content)
                    archive.addfile(member,io.BytesIO(content))
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            verifier.verify(self.attempt)

    def test_sha_source_delivery_requires_complete_bindings(self):
        item = json.loads((RECIPE / 'inputs.json').read_text())['sha_overlay']
        data = (RECIPE / item['file']).read_bytes()
        self.changes['ext/urcrypt/sha.c'] = data
        self.changes['ext/urcrypt/build.zig'] = b'synthetic SHA build'
        item['build_sha256'] = verifier.sha(self.changes['ext/urcrypt/build.zig'])
        expected = {name: verifier.sha(self.changes[name]) for name in ('ext/urcrypt/sha.c', 'ext/urcrypt/build.zig')}
        # The prior verifier ignored a dependency manifest present in the archive.
        manifest = 'ext/urcrypt/build.zig.zon'
        self.changes[manifest] = b'synthetic pinned SHA dependency'
        self.lock['source_preimages'][manifest] = verifier.sha(self.changes[manifest])
        expected[manifest] = self.lock['source_preimages'][manifest]
        self.lock['sha_overlay'] = item
        self.receipt['source_changes'].update(expected)
        for directory in (self.frozen, self.artifact):
            (directory / item['file']).write_bytes(data)
        overlay = dict(overlay=item, source_changes=expected,
                       source_preimages={name: self.lock['source_preimages'][name] for name in
                                         ('ext/urcrypt/build.zig', 'ext/urcrypt/build.zig.zon')})
        path = self.artifact / 'sha-overlay.json'
        self.write_json(path, overlay)
        self.sync_lock(); self.sync_receipt(); self.sync_archive()
        self.assertEqual(verifier.verify(self.attempt)['status'], 'PASS')
        original_manifest = self.changes[manifest]
        self.changes[manifest] = b'tampered dependency manifest'
        self.sync_archive()
        with self.assertRaisesRegex(ValueError, 'archived changed-source'):
            verifier.verify(self.attempt)
        self.changes[manifest] = original_manifest
        self.sync_archive()
        for name in expected:
            digest = self.receipt['source_changes'].pop(name)
            self.sync_receipt()
            with self.subTest(omitted=name), self.assertRaisesRegex(ValueError, 'SHA'):
                verifier.verify(self.attempt)
            self.receipt['source_changes'][name] = digest
        self.sync_receipt()
        for directory in (self.frozen, self.artifact):
            (directory / item['file']).write_bytes(b'changed')
            with self.subTest(directory=str(directory)), self.assertRaisesRegex(ValueError, 'SHA'):
                verifier.verify(self.attempt)
            (directory / item['file']).write_bytes(data)
        self.write_json(path, dict(overlay, extra=True))
        with self.assertRaisesRegex(ValueError, 'SHA'):
            verifier.verify(self.attempt)

    def test_curl_buffer_delivery_binding(self):
        name = 'pkg/vere/king.c'
        self.changes[name] = b'synthetic hardened curl caller'
        digest = verifier.sha(self.changes[name])
        self.lock['curl_buffer_sha256'] = digest
        self.receipt['source_changes'][name] = digest
        self.sync_lock(); self.sync_receipt(); self.sync_archive()
        self.assertEqual(verifier.verify(self.attempt)['status'], 'PASS')
        del self.receipt['source_changes'][name]
        self.sync_receipt()
        with self.assertRaisesRegex(ValueError, 'curl buffer'):
            verifier.verify(self.attempt)
        self.receipt['source_changes'][name] = digest
        self.sync_receipt()
        self.changes[name] = b'tampered curl caller'
        self.sync_archive()
        with self.assertRaisesRegex(ValueError, 'archived changed-source'):
            verifier.verify(self.attempt)

    def test_valid_combined_candidate(self):
        self.assertEqual(verifier.verify(self.attempt)['status'], 'PASS')

    def test_legacy_without_curl_version(self):
        del self.lock['curl_version']
        del self.lock['curl_overlays']
        for target in TARGETS:
            del self.receipt['source_changes'][target]
            del self.changes[target]
        for directory in (self.artifact, self.frozen):
            for name in ('curl-build.zig', 'curl-build.zig.zon'):
                (directory / name).unlink()
        (self.artifact / 'curl-overlay.json').unlink()
        self.sync_lock()
        self.sync_receipt()
        self.sync_archive()
        self.assertEqual(verifier.verify(self.attempt)['status'], 'PASS')

    def test_wrong_or_empty_curl_version_refused(self):
        for version in ('8.22.0', '', None):
            with self.subTest(version=version):
                self.lock['curl_version'] = version
                self.sync_lock()
                self.sync_receipt()
                with self.assertRaisesRegex(ValueError, 'curl'):
                    verifier.verify(self.attempt)

    def test_omitted_curl_source_changes_refused(self):
        for missing in ((TARGETS[0],), (TARGETS[1],), TARGETS):
            with self.subTest(missing=missing):
                self.receipt['source_changes'] = {n: verifier.sha(d) for n, d in self.changes.items()
                                                  if n not in missing}
                self.sync_receipt()
                with self.assertRaisesRegex(ValueError, 'curl'):
                    verifier.verify(self.attempt)

    def test_lock_requires_exact_pinned_overlay_mapping(self):
        original = json.loads(json.dumps(self.lock['curl_overlays']))
        variants = [{}, {TARGETS[0]: original[TARGETS[0]]},
                    dict(original, **{'ext/curl/extra': original[TARGETS[0]]})]
        for field, value in [('file', '../curl-build.zig'), ('sha256', '0' * 64)]:
            changed = json.loads(json.dumps(original))
            changed[TARGETS[0]][field] = value
            variants.append(changed)
        for overlays in variants:
            with self.subTest(overlays=overlays):
                self.lock['curl_overlays'] = overlays
                self.sync_lock()
                self.sync_receipt()
                with self.assertRaisesRegex(ValueError, 'curl'):
                    verifier.verify(self.attempt)

    def test_changed_or_extra_curl_source_changes_refused(self):
        original = dict(self.receipt['source_changes'])
        variants = [dict(original, **{target: '0' * 64}) for target in TARGETS]
        variants.append(dict(original, **{'ext/curl/extra': verifier.sha(b'extra')}))
        for changes in variants:
            with self.subTest(changes=changes):
                self.receipt['source_changes'] = changes
                self.sync_receipt()
                with self.assertRaisesRegex(ValueError, 'curl'):
                    verifier.verify(self.attempt)

    def test_archived_curl_bytes_must_match_pins(self):
        for target in TARGETS:
            with self.subTest(target=target):
                original = self.changes[target]
                self.changes[target] = b'tampered archived source'
                self.sync_archive()
                with self.assertRaisesRegex(ValueError, 'archived changed-source mismatch'):
                    verifier.verify(self.attempt)
                self.changes[target] = original

    def test_missing_archived_curl_member_refused(self):
        for target in TARGETS:
            with self.subTest(target=target):
                original = self.changes.pop(target)
                self.sync_archive()
                with self.assertRaises(KeyError):
                    verifier.verify(self.attempt)
                self.changes[target] = original

    def test_overlay_files_required_and_pinned_in_both_locations(self):
        for directory in (self.artifact, self.frozen):
            for name in ('curl-build.zig', 'curl-build.zig.zon'):
                path = directory / name
                original = path.read_bytes()
                for mutation in ('missing', 'changed'):
                    with self.subTest(directory=directory.name, name=name, mutation=mutation):
                        if mutation == 'missing':
                            path.unlink()
                        else:
                            path.write_bytes(b'tampered overlay')
                        try:
                            with self.assertRaisesRegex(ValueError, 'curl'):
                                verifier.verify(self.attempt)
                        finally:
                            path.write_bytes(original)

    def test_overlay_receipt_required_and_exact(self):
        path = self.artifact / 'curl-overlay.json'
        variants = [None, {}, dict(self.overlay, extra=True)]
        for section in ('source_preimages', 'source_changes', 'overlays'):
            for target in TARGETS:
                changed = json.loads(json.dumps(self.overlay))
                del changed[section][target]
                variants.append(changed)
                changed = json.loads(json.dumps(self.overlay))
                changed[section][target] = '0' * 64
                variants.append(changed)
        for value in variants:
            with self.subTest(receipt=value):
                if value is None:
                    path.unlink()
                else:
                    self.write_json(path, value)
                with self.assertRaisesRegex(ValueError, 'curl'):
                    verifier.verify(self.attempt)


if __name__ == '__main__':
    unittest.main()
