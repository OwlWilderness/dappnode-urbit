"""SHA wrapper boundary probes, not a rebuilt/linked OpenSSL qualification.

Compile exact archived urcrypt wrappers or the proposed local replacement.
The low-level digest boundary is mocked with a Python hashlib reference
callback. This validates byte ordering, salted composition and failure policy,
NOT the accepted OpenSSL implementation's known-answer/runtime behavior.
"""
import ctypes
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
RECIPE = ROOT / 'build/vere-openssl3'
MEMBER = 'p/N-V-__8AAEPPSQAFB28-gqWMJB7_zp5ZIS8wIN4boyLzAWRb/urcrypt/sha.c'
SHA_PREIMAGE = 'f94d7003ea8b2f9994a57ab920a695fcf31c20bf3155e05603c7668f2f184fd5'


def archived_public(member_name, expected):
    with tarfile.open(ROOT / 'build_issue3_amd64_curl_build_02/artifact/source-materials.tar.gz') as archive:
        member = archive.getmember(member_name)
        assert member.isfile() and member.size < 32768
        stream = archive.extractfile(member)
        assert stream is not None
        data = stream.read()
    assert hashlib.sha256(data).hexdigest() == expected
    return data.decode()


def archived_sha():
    return archived_public(MEMBER, SHA_PREIMAGE)


PREFIX = r'''
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <setjmp.h>
typedef struct { int bits; const void *data; size_t len; } Digest;
typedef Digest SHA_CTX;
typedef Digest SHA256_CTX;
typedef Digest SHA512_CTX;
static int fail_at, step, oneshot, wipes, status;
static jmp_buf fatal;
static int (*digest_callback)(int,const void*,size_t,void*);
static void mock_exit(int value) { status=value; longjmp(fatal,1); }
#define exit mock_exit
static int init(Digest *p,int bits) { if (++step==fail_at) return 0; p->bits=bits; return 1; }
static int update(Digest *p,const void *data,size_t len) { if (++step==fail_at) return 0; p->data=data;p->len=len;return 1; }
static int final(unsigned char *out,Digest *p) { if (++step==fail_at) return 0; return digest_callback(p->bits,p->data,p->len,out); }
#define SHA1_Init(p) init(p,160)
#define SHA256_Init(p) init(p,256)
#define SHA512_Init(p) init(p,512)
#define SHA1_Update update
#define SHA256_Update update
#define SHA512_Update update
#define SHA1_Final final
#define SHA256_Final final
#define SHA512_Final final
static void cleanse(void *p,size_t n) { memset(p,0,n); wipes++; }
#define OPENSSL_cleanse cleanse
static unsigned char *allocating_oneshot(const void *p,size_t n,unsigned char *out) {
  (void)p;(void)n;(void)out; oneshot++; return NULL;
}
#define SHA1 allocating_oneshot
#define SHA256 allocating_oneshot
#define SHA512 allocating_oneshot
static void urcrypt__reverse(size_t n,uint8_t *p) {
  for(size_t i=0;i<n/2;i++) { uint8_t x=p[i];p[i]=p[n-1-i];p[n-1-i]=x; }
}
'''
SUFFIX = r'''
int probe(int kind,int fail,uint8_t *message,size_t length,
          uint8_t *salt,size_t salt_length,uint8_t *out,
          int (*callback)(int,const void*,size_t,void*)) {
  (void)init;(void)update;(void)final;(void)cleanse;(void)allocating_oneshot;(void)mock_exit;
  digest_callback=callback; fail_at=fail; step=oneshot=wipes=status=0;
  if (setjmp(fatal)) return status;
  switch(kind) {
    case 1: urcrypt_sha1(message,length,out);break;
    case 2: urcrypt_shay(message,length,out);break;
    case 3: urcrypt_shal(message,length,out);break;
    case 4: urcrypt_shas(salt,salt_length,message,length,out);break;
    default: return 99;
  }
  return 0;
}
int oneshot_calls(void) { return oneshot; }
int cleanse_calls(void) { return wipes; }
'''


class ShaAllocationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        baseline = archived_sha()
        overlay = RECIPE / 'sha-stack.c'
        text = baseline if os.environ.get('ISSUE3_SHA_BASELINE') else overlay.read_text()
        # Includes are the mocked boundary; the actual wrapper body is intact.
        body = '\n'.join(line for line in text.splitlines() if not line.startswith('#include'))
        scratch = tempfile.TemporaryDirectory(prefix='issue3-sha-probe-', dir=os.environ['TMPDIR'])
        cls.addClassCleanup(scratch.cleanup)
        out = Path(scratch.name)
        code = PREFIX + body + SUFFIX
        (out / 'probe.c').write_text(code)
        subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror', '-dynamiclib',
                        str(out / 'probe.c'), '-o', str(out / 'probe.dylib')],
                       check=True, capture_output=True, text=True, timeout=30)
        print(json.dumps({'sha_probe': str(out), 'wrapper_sha256': hashlib.sha256(text.encode()).hexdigest()}))
        cls.lib = ctypes.CDLL(str(out / 'probe.dylib'))
        cls.callback_type = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_int, ctypes.c_void_p,
                                             ctypes.c_size_t, ctypes.c_void_p)
        def digest(bits, ptr, length, output):
            value = {160: hashlib.sha1, 256: hashlib.sha256, 512: hashlib.sha512}[bits](ctypes.string_at(ptr, length)).digest()
            ctypes.memmove(output, value, len(value))
            return 1
        cls.callback = cls.callback_type(digest)
        cls.lib.probe.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_void_p, ctypes.c_size_t,
                                  ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, cls.callback_type]
        cls.lib.probe.restype = ctypes.c_int

    def call(self, kind, message, salt=b'', fail=0):
        msg = ctypes.create_string_buffer(message)
        sal = ctypes.create_string_buffer(salt)
        length = {1:20,2:32,3:64,4:32}[kind]
        out = ctypes.create_string_buffer(b'\xa5' * length)
        status = self.lib.probe(kind, fail, msg, len(message), sal, len(salt), out, self.callback)
        return status, out.raw[:length], msg.raw[:len(message)], sal.raw[:len(salt)]

    def test_sha_overlay_syntax_against_accepted_headers(self):
        # Syntax only: no dependency object or replacement library is built.
        import re
        archive_path = ROOT / 'build_issue3_amd64_curl_build_02/artifact/source-materials.tar.gz'
        digest = hashlib.sha256()
        with archive_path.open('rb') as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b''):
                digest.update(chunk)
        self.assertEqual(digest.hexdigest(), '8ed4fc8a6b4c1acba3e4e89860a4059e490feb3efaf2a818805770f24f65654f')
        scratch = tempfile.TemporaryDirectory(prefix='issue3-sha-headers-', dir=os.environ['TMPDIR'])
        self.addCleanup(scratch.cleanup)
        out = Path(scratch.name)
        prefix = 'vere-8ddc4b786979574dbfcb655e3db1b634f658d0de/ext/openssl/prebuilt/include/'
        urcrypt = MEMBER.rsplit('/', 1)[0] + '/'
        pending = {'openssl/sha.h', 'openssl/crypto.h', 'urcrypt.h', 'util.h'}
        seen = set()
        with tarfile.open(archive_path) as archive:
            metadata = {m.name: m for m in archive.getmembers()}
            while pending:
                name = pending.pop()
                if name in seen:
                    continue
                self.assertRegex(name, r'^(openssl/)?[A-Za-z0-9_]+\.h$')
                member = metadata[(prefix if name.startswith('openssl/') else urcrypt) + name]
                self.assertTrue(member.isfile())
                self.assertLess(member.size, 256 * 1024)
                header_stream = archive.extractfile(member)
                assert header_stream is not None
                data = header_stream.read()
                target = out / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(data)
                seen.add(name)
                pending.update(re.findall(r'#\s*include\s*[<"](openssl/[A-Za-z0-9_]+\.h)[>"]', data.decode()))
        subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror', '-fsyntax-only',
                        '-I', str(out), str(RECIPE / 'sha-stack.c')],
                       check=True, capture_output=True, text=True, timeout=30)
        print(json.dumps({'accepted_header_syntax': str(out), 'headers': len(seen), 'linked': False}))

    def test_sha_graph_and_overlay_integrity(self):
        import importlib.util
        from unittest import mock
        spec = importlib.util.spec_from_file_location('sha_candidate', RECIPE / 'candidate.py')
        assert spec is not None and spec.loader is not None
        api = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(api)
        lock = json.loads((RECIPE / 'inputs.json').read_text())
        name = 'ext/urcrypt/build.zig'
        original = archived_public('vere-8ddc4b786979574dbfcb655e3db1b634f658d0de/' + name,
                                   'e56c7b287026d6843f3b4c2bb865194c41d6247595e292d4900a7f3a3c18fd9d')
        scratch = tempfile.TemporaryDirectory(prefix='issue3-sha-overlay-', dir=os.environ['TMPDIR'])
        self.addCleanup(scratch.cleanup)
        source = Path(scratch.name)
        (source / name).parent.mkdir(parents=True)
        (source / name).write_text(original)
        manifest = 'ext/urcrypt/build.zig.zon'
        manifest_text = archived_public(lock['inputs']['vere']['root'] + '/' + manifest,
                                        lock['source_preimages'][manifest])
        (source / manifest).write_text(manifest_text)
        changed = api.apply_sha_overlay(source, lock)
        after = (source / name).read_text()
        self.assertNotIn('            "sha.c",', after)
        self.assertEqual(after.count('.file = b.path("sha.c")'), 1)
        self.assertEqual((source / 'ext/urcrypt/sha.c').read_bytes(), (RECIPE / 'sha-stack.c').read_bytes())
        self.assertEqual(changed, {name: lock['sha_overlay']['build_sha256'],
                                  manifest: lock['source_preimages'][manifest],
                                  'ext/urcrypt/sha.c': lock['sha_overlay']['sha256']})
        with self.assertRaisesRegex(ValueError, 'preimage|exists'):
            api.apply_sha_overlay(source, lock)
        for bad in (original + '/* drift */', original * 2, after):
            with self.assertRaisesRegex(ValueError, 'preimage'):
                api.patch_sha_build(bad)
        other = source / 'recipe'
        other.mkdir()
        (other / 'sha-stack.c').write_text('changed')
        fresh = source / 'fresh'
        (fresh / name).parent.mkdir(parents=True)
        (fresh / name).write_text(original)
        (fresh / manifest).write_text('tampered dependency')
        with self.assertRaisesRegex(ValueError, 'manifest preimage'):
            api.apply_sha_overlay(fresh, lock)
        self.assertEqual((fresh / name).read_text(), original)
        self.assertFalse((fresh / 'ext/urcrypt/sha.c').exists())
        (fresh / manifest).write_text(manifest_text)
        with mock.patch.object(api, 'HERE', other), self.assertRaisesRegex(ValueError, 'SHA overlay hash'):
            api.apply_sha_overlay(fresh, lock)
        self.assertEqual((fresh / name).read_text(), original)
        self.assertFalse((fresh / 'ext/urcrypt/sha.c').exists())

    def test_wrapper_bytes_and_no_allocating_oneshot(self):
        for message in (b'', b'abc', b'\x00\xff\x01', b'a' * (1024 * 1024)):
            for kind in (1,2,3):
                with self.subTest(size=len(message), kind=kind):
                    status, output, changed, _ = self.call(kind, message)
                    expected = (hashlib.sha1(message[::-1]).digest()[::-1] if kind == 1 else
                                (hashlib.sha256 if kind == 2 else hashlib.sha512)(message).digest())
                    self.assertEqual(status, 0)
                    self.assertEqual(output, expected)
                    self.assertEqual(changed, message[::-1] if kind == 1 else message)
                    self.assertEqual(self.lib.oneshot_calls(), 0)
                    self.assertGreaterEqual(self.lib.cleanse_calls(), 1)

    def test_salted_branches_preserve_output_and_salt_mutation(self):
        for size in (0,4,32,33,64):
            salt = bytes(range(size))
            mid = bytearray(hashlib.sha256(b'synthetic').digest())
            changed = bytearray(salt)
            if size > 32:
                for i in range(32): changed[i] ^= mid[i]
                expected = hashlib.sha256(changed).digest()
            else:
                for i in range(size): mid[i] ^= salt[i]
                expected = hashlib.sha256(mid).digest()
            with self.subTest(salt_size=size):
                status, output, _, actual_salt = self.call(4, b'synthetic', salt)
                self.assertEqual((status, output, actual_salt), (0, expected, bytes(changed)))
                self.assertEqual(self.lib.oneshot_calls(), 0)
                self.assertGreaterEqual(self.lib.cleanse_calls(), 2)

    def test_digest_output_may_overlap_message(self):
        message = b'overlapping synthetic bytes'
        for kind in (1,2,3,4):
            with self.subTest(kind=kind):
                expected = self.call(kind, message, b'ab')[1]
                buf = ctypes.create_string_buffer(message, 128)
                salt = ctypes.create_string_buffer(b'ab')
                status = self.lib.probe(kind, 0, buf, len(message), salt, 2, buf, self.callback)
                self.assertEqual(status, 0)
                self.assertEqual(buf.raw[:len(expected)], expected)
                self.assertEqual(self.lib.oneshot_calls(), 0)

    def test_low_level_failure_never_returns_digest_success(self):
        for kind, salt, limit in ((1,b'',3),(2,b'',3),(3,b'',3),(4,b'ab',6),(4,b'x'*40,6)):
            for fault in range(1,limit+1):
                with self.subTest(kind=kind,salt_size=len(salt),fault=fault):
                    status, output, _, _ = self.call(kind, b'synthetic', salt, fault)
                    self.assertEqual(status, 1)
                    self.assertEqual(output, b'\xa5' * len(output))
                    self.assertEqual(self.lib.oneshot_calls(), 0)
                    self.assertGreaterEqual(self.lib.cleanse_calls(), 1)


if __name__ == '__main__':
    unittest.main(verbosity=2)
