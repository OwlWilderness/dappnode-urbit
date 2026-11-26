"""File-only fixtures; never compile or execute Vere."""
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / 'build/vere-openssl3/retain_link_inputs.py'

class RetentionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=os.environ['TMPDIR'])
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.assertTrue(HELPER.exists(), 'retention helper missing (scaffold RED)')
        spec = importlib.util.spec_from_file_location('retention', HELPER)
        assert spec and spec.loader
        self.m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.m)
        for name in ('libssl.a', 'libcrypto.a', 'libcurl.a', 'urbit', 'openssl.h', 'curl.h'):
            (self.root / name).write_bytes(('fixture:' + name).encode())
        self.argv = ['ld.lld', '-o', 'urbit', 'libssl.a', 'libcrypto.a', 'libcurl.a']

    def retain(self):
        return self.m.retain(self.root, self.argv, self.root/'urbit',
                             {'openssl/openssl.h': self.root/'openssl.h', 'curl/curl.h': self.root/'curl.h'},
                             self.root/'retained')

    def test_copies_exact_link_bytes_and_binds_output(self):
        result = self.retain()
        self.assertEqual(result['status'], 'RETAINED_NOT_TLS_TESTED')
        self.assertEqual(result['argv'], self.argv)
        for name in ('libssl.a', 'libcrypto.a', 'libcurl.a'):
            self.assertEqual((self.root/'retained/libraries'/name).read_bytes(), (self.root/name).read_bytes())
        self.assertEqual(result['binary_sha256'], self.m.digest(self.root/'urbit'))

    def test_missing_curl_headers_refused_before_writes(self):
        with self.assertRaises(ValueError):
            self.m.retain(self.root, self.argv, self.root/'urbit',
                          {'openssl/openssl.h': self.root/'openssl.h'}, self.root/'bad')
        self.assertFalse((self.root/'bad').exists())

    def test_copy_mutation_never_emits_success_manifest(self):
        class MutatingGuard:
            def copy_file(inner, source, target):
                target.write_bytes(b'not the linked bytes')
        with self.assertRaises(ValueError):
            self.m.retain(self.root, self.argv, self.root/'urbit',
                          {'openssl/openssl.h': self.root/'openssl.h', 'curl/curl.h': self.root/'curl.h'},
                          self.root/'retained', MutatingGuard())
        self.assertFalse((self.root/'retained/link-inputs.json').exists())

    def test_rejects_unproven_or_unsafe_inputs_before_writes(self):
        cases = ('duplicate', 'response', 'output', 'symlink', 'traversal', 'header-label')
        for case in cases:
            with self.subTest(case=case):
                original = self.argv[:]
                headers = {'openssl/openssl.h': self.root/'openssl.h', 'curl/curl.h': self.root/'curl.h'}
                if case == 'duplicate': self.argv.append('other/libcurl.a')
                if case == 'response': self.argv.append('@args.rsp')
                if case == 'output': self.argv[2] = 'curl.h'
                if case == 'symlink':
                    (self.root/'alias').symlink_to(self.root, target_is_directory=True)
                    self.argv[-1] = 'alias/libcurl.a'
                if case == 'traversal': self.argv[-1] = '../libcurl.a'
                if case == 'header-label': headers['../../escape'] = self.root/'curl.h'
                destination = self.root / ('reject-' + case)
                with self.assertRaises(ValueError):
                    self.m.retain(self.root, self.argv, self.root/'urbit', headers, destination)
                self.assertFalse(destination.exists())
                self.argv = original

    def test_header_aliases_and_incomplete_labels_refused_before_writes(self):
        for index, label in enumerate(('openssl//a.h', 'openssl/./a.h',
                                       'openssl/a.h/', 'openssl', 'openssl/',
                                       'openssl/A.h')):
            with self.subTest(label=label):
                headers = {'openssl/a.h': self.root/'openssl.h',
                           'curl/curl.h': self.root/'curl.h', label: self.root/'curl.h'}
                out = self.root/f'aliases-{index}'
                with self.assertRaises(ValueError):
                    self.m.retain(self.root, self.argv, self.root/'urbit', headers, out)
                self.assertFalse(out.exists())

    def test_later_copy_mutating_earlier_destination_refused(self):
        import shutil
        class MutatingGuard:
            def copy_file(inner, source, target):
                shutil.copyfile(source, target)
                if target.name == 'curl.h':
                    (self.root/'retained/libraries/libssl.a').write_bytes(b'changed')
            def check(inner, **kwargs):
                pass
        with self.assertRaises(ValueError):
            self.m.retain(self.root, self.argv, self.root/'urbit',
                          {'openssl/openssl.h': self.root/'openssl.h', 'curl/curl.h': self.root/'curl.h'},
                          self.root/'retained', MutatingGuard())
        self.assertFalse((self.root/'retained/link-inputs.json').exists())

if __name__ == '__main__':
    unittest.main()
