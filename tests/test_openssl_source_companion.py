"""Source assembly tests use synthetic archives, never binaries/builds."""
import importlib.util
import io
import json
import os
from pathlib import Path
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT/'build/vere-openssl3/source_companion.py'

class CompanionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=os.environ['TMPDIR'])
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.assertTrue(HELPER.exists(), 'missing helper (scaffold RED)')
        spec = importlib.util.spec_from_file_location('companion', HELPER)
        assert spec and spec.loader
        self.m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.m)
        self.archive = self.root/'source-materials.tar.gz'
        with tarfile.open(self.archive, 'w:gz') as t:
            for n in range(24):
                data = b'public fixture source'
                member = tarfile.TarInfo(f'p/tree{n}/COPYING')
                member.size = len(data)
                t.addfile(member, io.BytesIO(data))
        (self.root/'candidate.py').write_text('# frozen fixture recipe\n')
        self.plan = {'source_archive_sha256': self.m.digest(self.archive),
                     'files': {'candidate.py': self.m.digest(self.root/'candidate.py')}}

    def test_roundtrip_preserves_archive_and_24_trees(self):
        out = self.root/'companion'
        receipt = self.m.assemble(self.root, self.plan, out)
        self.assertEqual(receipt['package_tree_count'], 24)
        self.assertEqual((out/'source-materials.tar.gz').read_bytes(), self.archive.read_bytes())
        self.assertFalse(receipt['distribution_cleared'])
        self.assertEqual(self.m.validate(out), receipt)

    def test_validator_recomputes_tree_inventory(self):
        out = self.root/'out'
        receipt = self.m.assemble(self.root, self.plan, out)
        receipt['package_trees'] = ['invented']
        (out/'companion.json').write_text(json.dumps(receipt))
        with self.assertRaises(ValueError): self.m.validate(out)

    def test_internal_source_symlink_preserved_without_extraction(self):
        # A real retained dependency uses README.md -> README.
        with tarfile.open(self.archive, 'r:gz') as t:
            members = [(m, t.extractfile(m).read()) for m in t if m.isfile()]
        with tarfile.open(self.archive, 'w:gz') as t:
            for m, data in members: t.addfile(m, io.BytesIO(data))
            m = tarfile.TarInfo('p/tree0/README.md')
            m.type = tarfile.SYMTYPE
            m.linkname = 'COPYING'
            t.addfile(m)
        self.plan['source_archive_sha256'] = self.m.digest(self.archive)
        self.assertEqual(self.m.assemble(self.root, self.plan, self.root/'out')['package_tree_count'], 24)

    def test_wrong_source_hash_refused_before_output(self):
        self.plan['source_archive_sha256'] = '0'*64
        with self.assertRaises(ValueError):
            self.m.assemble(self.root, self.plan, self.root/'bad')
        self.assertFalse((self.root/'bad').exists())

    def test_unsafe_archive_refused_before_output(self):
        with tarfile.open(self.archive, 'w:gz') as t:
            member = tarfile.TarInfo('../escape')
            member.size = 1
            t.addfile(member, io.BytesIO(b'x'))
        self.plan['source_archive_sha256'] = self.m.digest(self.archive)
        with self.assertRaises(ValueError):
            self.m.assemble(self.root, self.plan, self.root/'bad')
        self.assertFalse((self.root/'bad').exists())

    def test_missing_tree_refused(self):
        with tarfile.open(self.archive, 'w:gz'):
            pass
        self.plan['source_archive_sha256'] = self.m.digest(self.archive)
        with self.assertRaises(ValueError):
            self.m.assemble(self.root, self.plan, self.root/'bad')

    def test_nonallowlisted_file_refused(self):
        (self.root/'private-key').write_text('synthetic forbidden fixture')
        self.plan['files']['private-key'] = self.m.digest(self.root/'private-key')
        with self.assertRaises(ValueError):
            self.m.assemble(self.root, self.plan, self.root/'bad')
        self.assertFalse((self.root/'bad').exists())

    def test_h2o_overlay_and_receipt_preserved_when_explicitly_planned(self):
        for name in ('h2o-socket.c', 'h2o-overlay.json'):
            (self.root/name).write_text('public synthetic overlay evidence: ' + name)
            self.plan['files'][name] = self.m.digest(self.root/name)
        out = self.root/'h2o-companion'
        receipt = self.m.assemble(self.root, self.plan, out)
        self.assertEqual(self.m.validate(out), receipt)
        for name in ('h2o-socket.c', 'h2o-overlay.json'):
            self.assertEqual((out/name).read_bytes(), (self.root/name).read_bytes())

    def test_validator_requires_archive_hash_even_with_same_tree_names(self):
        for changed in (False, True):
            with self.subTest(changed=changed):
                out = self.root/f'omitted-{changed}'
                receipt = self.m.assemble(self.root, self.plan, out)
                del receipt['files']['source-materials.tar.gz']
                (out/'companion.json').write_text(json.dumps(receipt))
                if changed:
                    with tarfile.open(out/'source-materials.tar.gz', 'w:gz') as t:
                        for n in range(24):
                            data = b'changed source'
                            member = tarfile.TarInfo(f'p/tree{n}/COPYING')
                            member.size = len(data)
                            t.addfile(member, io.BytesIO(data))
                with self.assertRaises(ValueError):
                    self.m.validate(out)

    def test_validator_checks_receipt_schema_and_status(self):
        for index, (key, value) in enumerate((('schema_version', 2),
                                             ('schema_version', True),
                                             ('status', 'RELEASE_COMPLETE'))):
            out = self.root/f'schema-{index}'
            receipt = self.m.assemble(self.root, self.plan, out)
            receipt[key] = value
            (out/'companion.json').write_text(json.dumps(receipt))
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                self.m.validate(out)

if __name__ == '__main__':
    unittest.main()
