"""Source-only curl overlay gates; never compile or execute Vere."""
from contextlib import contextmanager
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import subprocess
import io
import tarfile
from unittest import mock
import unittest

ROOT = Path(__file__).resolve().parents[1]
RECIPE = ROOT / 'build/vere-openssl3'
FILES = {'ext/curl/build.zig': ('curl-build.zig', '2e422b3cd0669ef3d3d028b9b104f842dbbd4061bd78593b39775fefa805c092'),
         'ext/curl/build.zig.zon': ('curl-build.zig.zon', '5a2e9e951b89a95794550cdf5d12cb6a8a7e349f1ce76092dea4fbdd2e1a8b78')}


class CurlTests(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location('curl_candidate', RECIPE / 'candidate.py')
        assert spec is not None and spec.loader is not None
        self.api = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.api)
        self.lock = json.loads((RECIPE / 'inputs.json').read_text())

    def archived_king(self):
        # Exact retained public input, not the accepted (timeout-patched) tree.
        with tarfile.open(ROOT / 'build_issue3_amd64_curl_build_02/artifact/source-materials.tar.gz') as archive:
            member = archive.getmember('materials/vere-8ddc4b7.tar.gz')
            self.assertTrue(member.isfile())
            self.assertEqual(member.size, self.lock['inputs']['vere']['bytes'])
            stream = archive.extractfile(member)
            assert stream is not None
            data = stream.read()
        self.api.verify_input(data, self.lock['inputs']['vere'])
        with tarfile.open(fileobj=io.BytesIO(data)) as archive:
            stream = archive.extractfile(self.lock['inputs']['vere']['root'] + '/pkg/vere/king.c')
            assert stream is not None
            text = stream.read().decode()
        self.assertEqual(self.api.sha(text.encode()), self.lock['source_preimages']['pkg/vere/king.c'])
        return text

    def test_actual_curl_retry_and_failure_ownership(self):
        text = self.archived_king()
        text = self.api.patch_curl_buffer(text)
        functions = text[text.index('size_t\nking_curl_alloc('):text.index('/* _king_get_atom():')]
        prefix = r'''
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <stdarg.h>
typedef uint64_t c3_d;
typedef char c3_c;
typedef int c3_i;
typedef uint32_t c3_w;
typedef unsigned char c3_y;
typedef int c3_t;
typedef struct { c3_y *buf_y; c3_d len_d,cap_d; } u3_array;
typedef int CURL;
typedef int CURLcode;
enum { CURLOPT_URL, CURLOPT_HEADERFUNCTION, CURLOPT_HEADERDATA,
       CURLOPT_WRITEFUNCTION, CURLOPT_WRITEDATA, CURLOPT_SERVER_RESPONSE_TIMEOUT,
       CURLINFO_RESPONSE_CODE, CURLE_OK=0 };
static int live, attempt, scenario, cleaned;
static u3_array *body;
static void *tracked_malloc(size_t n) { live++; void *p=malloc(n+4096); memset(p,0xcc,n+4096); return p; }
static void *tracked_realloc(void *p,size_t n) { if(!p) return tracked_malloc(n); return realloc(p,n+4096); }
static void tracked_free(void *p) { if(p) live--; free(p); }
#define c3_malloc tracked_malloc
#define c3_realloc tracked_realloc
#define c3_free tracked_free
#define free tracked_free
#define sleep(n) ((void)(n))
static CURL handle;
static CURL *curl_easy_init(void) {return &handle;}
static void trust(CURL *p) {(void)p;}
static struct { void (*ssl_curl_f)(CURL*); } u3K={trust};
static void u3l_log(const char *s,...) {(void)s;}
static void u3_king_bail(void) {}
static int curl_easy_setopt(CURL *p,int option,...) {
  (void)p; va_list ap; va_start(ap,option);
  if(option==CURLOPT_WRITEDATA) body=va_arg(ap,void*);
  va_end(ap); return 0;
}
static int curl_easy_getinfo(CURL *p,int option,long *code) {(void)p;(void)option;*code=scenario==3?404:200;return 0;}
static void curl_easy_cleanup(CURL *p) {(void)p;cleaned++;}
static const char *curl_easy_strerror(int code) {(void)code;return "mock failure";}
size_t king_curl_header(char*,size_t,size_t,void*);
size_t king_curl_alloc(void*,size_t,size_t,void*);
static int curl_easy_perform(CURL *p) {
  (void)p; attempt++;
  if(scenario==1 || scenario==4) {
    char h[]="Content-Length: 4\r\n";
    if(king_curl_header(h,1,strlen(h),body)!=strlen(h)) abort();
  }
  if(scenario==4) {
    king_curl_alloc("go",1,2,body);
    char h[]="Content-Length: 4\r\n";
    king_curl_header(h,1,strlen(h),body);
    king_curl_alloc("od",1,2,body);
    return 0;
  }
  char *s=attempt==1?"bad":"good";
  king_curl_alloc(s,1,strlen(s),body);
  return (scenario==2 || attempt==1)?1:0;
}
'''
        suffix = r'''
int main(int argc,char **argv) {
  (void)argc; scenario=atoi(argv[1]); c3_w len=123; c3_y *out=NULL;
  int result=king_curl_bytes("synthetic",&len,&out,0,scenario==5?0:2);
  int expected=scenario==2||scenario==5?-1:scenario==3?-2:0;
  if(result!=expected) {fprintf(stderr,"result %d expected %d\n",result,expected);return 10;}
  if(!result && (len!=4 || !out || memcmp(out,"good",4) || out[4])) {
    fprintf(stderr,"wrong response length/content: %u\n",len); return 11;
  }
  if(!result) free(out);
  if(live) {fprintf(stderr,"leaked buffers: %d\n",live);return 12;}
  if(cleaned!=1) return 13;
  return 0;
}
'''
        with tempfile.TemporaryDirectory(prefix='issue3-curl-buffer-', dir=os.environ['TMPDIR']) as directory:
            path = Path(directory)
            (path/'probe.c').write_text(prefix + functions + suffix)
            compiled = subprocess.run(['cc','-std=c99','-Wall','-Wextra','-Werror',str(path/'probe.c'),'-o',str(path/'probe')], capture_output=True, text=True)
            self.assertEqual(compiled.returncode, 0, compiled.stderr)
            for scenario in range(6):
                with self.subTest(scenario=scenario):
                    result = subprocess.run([str(path/'probe'),str(scenario)], capture_output=True, text=True)
                    self.assertEqual(result.returncode, 0, result.stderr)

    @contextmanager
    def prepared_fixture(self, king_text=None, king_digest=None):
        scratch = tempfile.TemporaryDirectory(prefix='issue3-curl-prepare-', dir=os.environ['TMPDIR'])
        self.addCleanup(scratch.cleanup)
        parent = Path(scratch.name)
        inputs = parent / 'inputs'
        inputs.mkdir()
        lock = json.loads(json.dumps(self.lock))
        files = {
            'build.zig': 'const VERSION = "4.6";\n    // Parse short git rev\nold\n    // Binary version\n',
            'pkg/vere/main.c': '  printf("openssl: %s\\n", SSLeay_version(SSLEAY_VERSION));\n' + self.curl_report(),
            'pkg/vere/king.c': self.archived_king(),
            'pkg/noun/manage.c': '  /* Initialize OpenSSL with loom allocation functions. */\n#ifndef U3_URTH_MASS',
            'pkg/vere/vere.h': 'synthetic king callback declaration',
            'pkg/vere/io/cttp.c': 'synthetic client TLS source',
            'pkg/vere/io/http.c': 'synthetic server TLS source',
            'ext/h2o/build.zig': 'synthetic h2o graph',
            'ext/h2o/build.zig.zon': 'synthetic h2o manifest',
            'ext/urcrypt/build.zig': 'synthetic urcrypt build',
            'ext/urcrypt/build.zig.zon': 'synthetic pinned urcrypt manifest',
            'ext/openssl/build.zig': 'old', 'ext/openssl/build.zig.zon': 'old',
            'ext/curl/build.zig': 'old curl', 'ext/curl/build.zig.zon': 'old curl manifest',
            'ext/gmp/build.zig.zon': 'https://ftp.fr.openbsd.org/pub/OpenBSD/distfiles/gmp-6.3.0.tar.xz',
            'ext/sigsegv/build.zig.zon': 'https://ftp.fr.openbsd.org/pub/OpenBSD/distfiles/libsigsegv-2.14.tar.gz',
            'ext/natpmp/build.zig.zon': 'http://deb.debian.org/debian/pool/main/libn/libnatpmp/libnatpmp_20230423.orig.tar.gz',
        }
        if king_text is not None:
            files['pkg/vere/king.c'] = king_text
        lock['source_preimages'] = {name: self.api.sha(text.encode()) for name, text in files.items()}
        if king_digest is not None:
            lock['source_preimages']['pkg/vere/king.c'] = king_digest
        for name, filename in [('vere', 'vere-8ddc4b7.tar.gz'), ('openssl', 'openssl-3.5.9.tar.gz'), ('zig', 'zig-x86_64-linux-0.15.2.tar.xz')]:
            path = inputs / filename
            with tarfile.open(path, 'w:gz') as archive:
                for relative, text in (files if name == 'vere' else {'placeholder': 'fixture'}).items():
                    data = text.encode()
                    member = tarfile.TarInfo(lock['inputs'][name]['root'] + '/' + relative)
                    member.size = len(data)
                    archive.addfile(member, io.BytesIO(data))
            lock['inputs'][name].update(bytes=path.stat().st_size, sha256=self.api.sha(path.read_bytes()))
        attempt = self.api.Attempt(parent / 'attempt')
        # Keep the production main.c preimage guard; substitute its known hash
        # only for this deliberately minimal public synthetic report fixture.
        digest = self.api.sha
        def fixture_digest(data):
            if data == files['pkg/vere/main.c'].encode():
                return '01e9f2de08464b136c46e2c1ec395161c64c7be4ce01f49072344ae62e2f1781'
            return digest(data)
        lock['source_preimages']['pkg/vere/main.c'] = fixture_digest(files['pkg/vere/main.c'].encode())
        lock['allocation_hardening'] = {
            name: digest((files[name] + '\n/* synthetic hardening */').encode())
            for name in ('pkg/vere/io/cttp.c', 'pkg/vere/io/http.c')}
        # The exact-source compiled suite exercises this transformation itself.
        # Here only preparation, batching and receipt delivery use fixtures.
        lock['sha_overlay']['build_sha256'] = digest((files['ext/urcrypt/build.zig'] + '\n/* SHA */').encode())
        ca_sources = {'pkg/vere/main.c': self.api.patch_report(files['pkg/vere/main.c']),
                      'pkg/vere/vere.h': files['pkg/vere/vere.h']}
        lock['ca_preimages'] = {n: digest(t.encode()) for n,t in ca_sources.items()}
        lock['ca_hardening'] = {n: digest((t+'\n/* CA */').encode()) for n,t in ca_sources.items()}
        lock['ca_hardening']['pkg/vere/io/cttp.c'] = lock['allocation_hardening']['pkg/vere/io/cttp.c']
        def fixture_h2o(source, fixture_lock):
            # Only preparation delivery is under test here; H2O graph preimage
            # and fault behavior are exercised against exact source separately.
            (source/'ext/h2o/socket.c').write_bytes((RECIPE/'h2o-socket.c').read_bytes())
            return {n: digest((source/n).read_bytes()) for n in
                    ('ext/h2o/build.zig','ext/h2o/build.zig.zon','ext/h2o/socket.c')}
        with mock.patch.object(self.api, 'apply_h2o_overlay', side_effect=fixture_h2o), \
             mock.patch.object(self.api, 'sha', side_effect=fixture_digest), \
             mock.patch.object(self.api, 'patch_ca_source', side_effect=lambda n,t: t+'\n/* CA */'), \
             mock.patch.object(self.api, 'patch_sha_build', side_effect=lambda text: text + '\n/* SHA */'), \
             mock.patch.object(self.api, 'patch_allocation_source',
                               side_effect=lambda name, text: text + '\n/* synthetic hardening */'):
            yield attempt, lock, inputs, files

    def test_prepare_receipts_and_docker_inputs_include_curl(self):
        with self.prepared_fixture() as (attempt, lock, inputs, files):
            trees = self.api.prepare(attempt, lock, inputs)
        digest = self.api.sha
        self.assertTrue((attempt.output/'ca-overlay.json').is_file(), 'CA preparation receipt missing')
        ca_receipt = json.loads((attempt.output/'ca-overlay.json').read_text())
        self.assertEqual(ca_receipt, dict(source_preimages=lock['ca_preimages'],
                                         source_changes=lock['ca_hardening']))
        for name, expected in lock['ca_hardening'].items():
            self.assertEqual(digest((trees['vere']/name).read_bytes()), expected)
        sha_receipt = json.loads((attempt.output / 'sha-overlay.json').read_text())
        self.assertEqual(sha_receipt, {
            'overlay': lock['sha_overlay'],
            'source_preimages': {name: lock['source_preimages'][name] for name in
                                ('ext/urcrypt/build.zig', 'ext/urcrypt/build.zig.zon')},
            'source_changes': {'ext/urcrypt/build.zig': lock['sha_overlay']['build_sha256'],
                               'ext/urcrypt/build.zig.zon': lock['source_preimages']['ext/urcrypt/build.zig.zon'],
                               'ext/urcrypt/sha.c': lock['sha_overlay']['sha256']}})
        self.assertEqual((attempt.output / 'sha-stack.c').read_bytes(), (RECIPE / 'sha-stack.c').read_bytes())
        self.assertEqual((trees['vere'] / 'ext/urcrypt/sha.c').read_bytes(), (RECIPE / 'sha-stack.c').read_bytes())
        self.assertIn('!sha-stack.c', (RECIPE / '.dockerignore').read_text().splitlines())
        self.assertIn('COPY sha-stack.c ./', (RECIPE / 'Dockerfile').read_text())
        allocation = json.loads((attempt.output / 'allocation-overlay.json').read_text())
        self.assertEqual(allocation, {
            'source_preimages': {name: lock['source_preimages'][name] for name in lock['allocation_hardening']},
            'source_changes': lock['allocation_hardening']})
        for name, expected in lock['allocation_hardening'].items():
            self.assertEqual(digest((trees['vere'] / name).read_bytes()), expected)
        self.assertEqual((trees['vere'] / 'pkg/vere/king.c').read_text(),
                         self.api.patch_curl_buffer(files['pkg/vere/king.c']))
        for target, (overlay, expected) in FILES.items():
            self.assertEqual(digest((trees['vere'] / target).read_bytes()), expected)
            self.assertTrue((attempt.output / overlay).is_file(), 'overlay input must be deliverable')
            self.assertEqual(digest((attempt.output / overlay).read_bytes()), expected)
        receipt = json.loads((attempt.output / 'curl-overlay.json').read_text())
        self.assertEqual(receipt['source_changes'], {target: value[1] for target, value in FILES.items()})
        for overlay, _ in FILES.values():
            self.assertIn('!' + overlay, (RECIPE / '.dockerignore').read_text().splitlines())
            self.assertIn(overlay, (RECIPE / 'Dockerfile').read_text())

    @staticmethod
    def curl_report():
        return ('  printf("curl: %d.%d.%d\\n",\n'
                '         LIBCURL_VERSION_MAJOR,\n'
                '         LIBCURL_VERSION_MINOR,\n'
                '         LIBCURL_VERSION_PATCH);')

    def test_king_preimage_pin_matches_audited_upstream(self):
        self.assertEqual(self.lock['source_preimages'].get('pkg/vere/king.c'),
                         '49d175e108cfd77e531d3346b9449680cab7e3ba4a8885c66d806af5ed969801')

    def test_timeout_patch_is_unique_and_refuses_drift_or_replay(self):
        original = '  curl_easy_setopt(cul_u, CURLOPT_SERVER_RESPONSE_TIMEOUT, 30);\n'
        corrected = original.replace(', 30);', ', 30L);')
        self.assertEqual(self.api.patch_curl_timeout(original), corrected)
        for text in (corrected, original.replace('30', '31'), original + original, ''):
            with self.subTest(text=text), self.assertRaisesRegex(ValueError, 'preimage mismatch'):
                self.api.patch_curl_timeout(text)

    def test_king_hash_drift_refuses_before_source_changes(self):
        original = '  curl_easy_setopt(cul_u, CURLOPT_SERVER_RESPONSE_TIMEOUT, 30);\n'
        for text in (original + '/* drift */\n', original.replace('30);', '30L);')):
            with self.subTest(text=text), self.prepared_fixture(
                    king_text=text, king_digest=self.api.sha(original.encode())) as (attempt, lock, inputs, files):
                with self.assertRaisesRegex(ValueError, 'preimage hash mismatch: pkg/vere/king.c'):
                    self.api.prepare(attempt, lock, inputs)
                source = attempt.output / lock['inputs']['vere']['root']
                for name, before in files.items():
                    self.assertEqual((source / name).read_text(), before)
                self.assertFalse((attempt.output / 'curl-overlay.json').exists())

    def test_report_distinguishes_linked_library_and_headers(self):
        original = '  printf("openssl: %s\\n", SSLeay_version(SSLEAY_VERSION));\n' + self.curl_report()
        patched = self.api.patch_report(original)
        self.assertIn(self.curl_report(), patched)
        self.assertIn('printf("curl-linked: %s\\n", curl_version_info(CURLVERSION_NOW)->version);', patched)
        self.assertIn('printf("curl-headers: %s\\n", LIBCURL_VERSION);', patched)
        self.assertNotIn('uvm_i3_', patched)
        self.assertNotIn('_Exit', patched)

    def test_overlay_drift_refuses_before_either_source_write(self):
        for kind in ('source', 'overlay'):
            for damaged in FILES:
                with self.subTest(kind=kind, damaged=damaged):
                    scratch = tempfile.TemporaryDirectory(prefix='issue3-curl-refusal-', dir=os.environ['TMPDIR'])
                    self.addCleanup(scratch.cleanup)
                    parent = Path(scratch.name)
                    source, recipe = parent / 'source', parent / 'recipe'
                    (source / 'ext/curl').mkdir(parents=True)
                    recipe.mkdir()
                    lock = json.loads(json.dumps(self.lock))
                    for target, (overlay, _) in FILES.items():
                        (source / target).write_bytes(b'upstream')
                        lock['source_preimages'][target] = self.api.sha(b'upstream')
                        (recipe / overlay).write_bytes((RECIPE / overlay).read_bytes())
                    path = source / damaged if kind == 'source' else recipe / FILES[damaged][0]
                    path.write_bytes(b'drift')
                    before = {target: (source / target).read_bytes() for target in FILES}
                    with mock.patch.object(self.api, 'HERE', recipe):
                        with self.assertRaisesRegex(ValueError, 'preimage|overlay hash'):
                            self.api.apply_curl_overlay(source, lock)
                    self.assertEqual({target: (source / target).read_bytes() for target in FILES}, before)

    def test_pinned_overlay_applies_and_refuses_replay(self):
        self.assertIn('curl_overlays', self.lock)
        scratch = tempfile.TemporaryDirectory(prefix='issue3-curl-', dir=os.environ['TMPDIR'])
        self.addCleanup(scratch.cleanup)
        parent = Path(scratch.name)
        source = parent / 'source'
        (source / 'ext/curl').mkdir(parents=True)
        lock = json.loads(json.dumps(self.lock))
        for target, (overlay, digest) in FILES.items():
            self.assertEqual(lock['curl_overlays'][target], {'file': overlay, 'sha256': digest})
            self.assertEqual(hashlib.sha256((RECIPE / overlay).read_bytes()).hexdigest(), digest)
            (source / target).write_bytes(b'synthetic upstream')
            lock['source_preimages'][target] = hashlib.sha256(b'synthetic upstream').hexdigest()
        changes = self.api.apply_curl_overlay(source, lock)
        for target, (overlay, digest) in FILES.items():
            self.assertEqual((source / target).read_bytes(), (RECIPE / overlay).read_bytes())
            self.assertEqual(changes[target], digest)
        with self.assertRaisesRegex(ValueError, 'preimage'):
            self.api.apply_curl_overlay(source, lock)


if __name__ == '__main__':
    unittest.main()
