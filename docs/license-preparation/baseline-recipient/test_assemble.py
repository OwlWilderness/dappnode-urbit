"""Finite file-only companion tests. No compiler/engine/network/process fixture."""
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tarfile
import tempfile
import unittest
from typing import Any

spec = importlib.util.spec_from_file_location('assemble', Path(__file__).with_name('assemble.py'))
assert spec is not None and spec.loader is not None
assemble = importlib.util.module_from_spec(spec)
spec.loader.exec_module(assemble)


def ident(data):
    return dict(bytes=len(data), sha256=hashlib.sha256(data).hexdigest())


class CompanionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='baseline-companion-', dir=Path(os.environ['TMPDIR']).resolve())
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.archive = self.root/'source.tar.gz'
        with tarfile.open(self.archive,'w:gz') as t:
            info=tarfile.TarInfo('source/LICENSE'); data=b'literal upstream grant\n';info.size=len(data)
            t.addfile(info, io.BytesIO(data))
        (self.root/'BUILD.md').write_bytes(b'instructions\n')
        aid=assemble.digest_file(self.archive)
        self.m: dict[str, Any] = dict(schema_version=1,status='SEALED_RETAINED_BASELINE_COMPANION_WITH_EXPLICIT_GAPS',
          selected_baseline=dict(source_archive=dict(path='source.tar.gz',**aid)),
          entries=[dict(recipient_path='sources/source.tar.gz',source=dict(kind='repository_file',path='source.tar.gz'),role='source',**aid),
          dict(recipient_path='BUILD.md',source=dict(kind='repository_file',path='BUILD.md'),role='instructions',**ident(b'instructions\n')),
          dict(recipient_path='notices/LICENSE',source=dict(kind='archive_member',path='source.tar.gz',member='source/LICENSE'),role='notice',**ident(b'literal upstream grant\n'))])

    def test_valid_verify_and_assemble(self):
        self.assertEqual(assemble.verify(self.root,self.m)['entries_verified'],3)
        out=self.root/'recipient';assemble.assemble(self.root,self.m,out)
        self.assertEqual(assemble.verify_recipient(out,self.m)['recipient_files_verified'],3)
        self.assertEqual(json.loads((out/'companion-manifest.json').read_text()),self.m)
        for e in self.m['entries']:
            self.assertEqual(assemble.digest_file(out/e['recipient_path']),{k:e[k] for k in ('bytes','sha256')})

    def test_changed_source_refuses(self):
        (self.root/'BUILD.md').write_bytes(b'changed source')
        with self.assertRaises(ValueError):assemble.verify(self.root,self.m)

    def test_archive_omission_refuses(self):
        self.m['entries']=self.m['entries'][1:]
        with self.assertRaises(ValueError):assemble.verify(self.root,self.m)

    def test_altered_same_member_archive_refuses(self):
        with tarfile.open(self.archive,'w:gz') as t:
            m=tarfile.TarInfo('source/LICENSE');m.size=8;t.addfile(m,io.BytesIO(b'changed!'))
        with self.assertRaises(ValueError):assemble.verify(self.root,self.m)

    def test_duplicate_archive_member_refuses(self):
        with tarfile.open(self.archive,'w:gz') as t:
            for _ in range(2):
                m=tarfile.TarInfo('source/LICENSE');d=b'literal upstream grant\n';m.size=len(d);t.addfile(m,io.BytesIO(d))
        aid=assemble.digest_file(self.archive); self.m['selected_baseline']['source_archive'].update(aid);self.m['entries'][0].update(aid)
        with self.assertRaises(ValueError):assemble.verify(self.root,self.m)

    def test_unsafe_and_noncanonical_paths_refuse(self):
        for path in ['../secret','/absolute','a/../b','a//b','./file','a\\b','a/']:
            with self.subTest(path=path),self.assertRaises(ValueError):assemble.safe_relative(path)

    def test_portable_recipient_collision_refuses(self):
        for path in ['build.md','BUILD.md/subfile']:
            m=copy.deepcopy(self.m);e=copy.deepcopy(m['entries'][1]);e['recipient_path']=path;m['entries'].append(e)
            with self.subTest(path=path),self.assertRaises(ValueError):assemble.validate_manifest(m)

    def test_symlink_source_refuses(self):
        (self.root/'actual').write_bytes(b'instructions\n');(self.root/'BUILD.md').unlink();(self.root/'BUILD.md').symlink_to('actual')
        with self.assertRaises(ValueError):assemble.verify(self.root,self.m)

    def test_existing_destination_refuses(self):
        out=self.root/'existing';out.mkdir()
        with self.assertRaises(ValueError):assemble.assemble(self.root,self.m,out)

    def test_boolean_schema_and_size_refuse(self):
        for field in ['schema','bytes']:
            m=copy.deepcopy(self.m)
            if field=='schema':m['schema_version']=True
            else:m['entries'][0]['bytes']=True
            with self.subTest(field=field),self.assertRaises(ValueError):assemble.validate_manifest(m)

    def test_member_hash_refuses(self):
        self.m['entries'][2]['sha256']='0'*64
        with self.assertRaises(ValueError):assemble.verify(self.root,self.m)

    def test_entry_count_refuses(self):
        self.m['entry_count']=2
        with self.assertRaises(ValueError):assemble.validate_manifest(self.m)

    def test_duplicate_member_reference_refuses(self):
        e=copy.deepcopy(self.m['entries'][2]);e['recipient_path']='another/LICENSE';self.m['entries'].append(e)
        with self.assertRaises(ValueError):assemble.validate_manifest(self.m)

    def test_reserved_manifest_name_refuses(self):
        self.m['entries'][1]['recipient_path']='companion-manifest.json'
        with self.assertRaises(ValueError):assemble.validate_manifest(self.m)

    def test_missing_member_refuses(self):
        self.m['entries'][2]['source']['member']='source/MISSING'
        with self.assertRaises(ValueError):assemble.verify(self.root,self.m)


if __name__=='__main__':unittest.main()
