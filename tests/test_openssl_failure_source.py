"""No-ship characterization of exact accepted source, NOT linked-library testing.

Run with ISSUE3_SOURCE_REVIEW pointing at the public-source-only extraction.
Dependencies are mocked; tests characterize unchecked NULL/return handling.
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = Path(os.environ.get('ISSUE3_SOURCE_REVIEW', '/nonexistent-public-source-review'))


@unittest.skipUnless(os.environ.get('ISSUE3_SOURCE_REVIEW'), 'requires exact accepted public source extraction')
class FailureSourceTests(unittest.TestCase):
    def test_cttp_actual_function_passes_failed_context_to_setters(self):
        text = (SOURCE / 'pkg/vere/io/cttp.c').read_text()
        begin = text.index('static SSL_CTX*\n_cttp_init_tls(void)')
        end = text.index('\n}', begin) + 2
        function = text[begin:end]
        prefix = r'''
#include <stdio.h>
#include <stdlib.h>
typedef int SSL_CTX;
static SSL_CTX ctx;
static int fail_alloc, null_calls, setters;
#define SSL_OP_NO_SSLv2 1
#define SSL_OP_NO_SSLv3 2
#define SSL_OP_NO_COMPRESSION 4
#define SSL_VERIFY_PEER 1
#define SSL_SESS_CACHE_OFF 0
static void *SSLv23_client_method(void) { return NULL; }
static SSL_CTX *SSL_CTX_new(void *p) { (void)p; return fail_alloc ? NULL : &ctx; }
static int check(SSL_CTX *p) { setters++; if(!p) null_calls++; return 0; }
static int SSL_CTX_set_options(SSL_CTX *p, int x) { (void)x; return check(p); }
static void *SSL_CTX_get_cert_store(SSL_CTX *p) { check(p); return NULL; }
static void trust(void *p) { (void)p; }
static struct { void (*ssl_x509_f)(void *); } u3K = {trust};
static void SSL_CTX_set_verify(SSL_CTX *p,int a,void *b) {(void)a;(void)b;check(p);}
static int SSL_CTX_set_session_cache_mode(SSL_CTX *p,int a) {(void)a;return check(p);}
static int SSL_CTX_set_cipher_list(SSL_CTX *p,const char *s) {(void)s;return check(p);}
'''
        suffix = r'''
int main(int argc,char **argv) {
  fail_alloc=argc>1 && argv[1][0]=='1';
  SSL_CTX *result=_cttp_init_tls();
  printf("{\"allocation_failed\":%d,\"null_argument_calls\":%d,\"setter_calls\":%d,\"returned_context\":%d}\n",fail_alloc,null_calls,setters,result!=NULL);
  return 0;
}
'''
        scratch = tempfile.TemporaryDirectory(prefix='issue3-failure-source-', dir=os.environ['TMPDIR'])
        self.addCleanup(scratch.cleanup)
        out = Path(scratch.name)
        c = out / 'probe.c'
        c.write_text(prefix + function + suffix)
        subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror', str(c), '-o', str(out / 'probe')], check=True, timeout=30)
        observations = []
        for mode in ('0', '1'):
            r = subprocess.run([str(out / 'probe'), mode], check=True, capture_output=True, text=True, timeout=5)
            observations.append(json.loads(r.stdout))
        # Characterization: these are defects, not a passing recovery guarantee.
        self.assertEqual(observations[0]['returned_context'], 1)
        self.assertEqual(observations[0]['setter_calls'], 5)
        self.assertEqual(observations[1]['null_argument_calls'], 5)
        self.assertEqual(observations[1]['returned_context'], 0)
        print(json.dumps({'probe_directory': str(out), 'exact_function_sha256': hashlib.sha256(function.encode()).hexdigest(), 'observations': observations}))

    def test_accepted_allocator_patch_has_process_lifetime_gate(self):
        text = (SOURCE / 'pkg/noun/manage.c').read_text()
        receipt = json.loads((ROOT / 'build_issue3_amd64_curl_build_02/artifact/candidate.json').read_text())
        self.assertEqual(hashlib.sha256(text.encode()).hexdigest(), receipt['source_changes']['pkg/noun/manage.c'])
        self.assertIn('#if !defined(U3_URTH_MASS) && OPENSSL_VERSION_NUMBER < 0x30000000L', text)
        self.assertIn('mp_set_memory_functions', text)


if __name__ == '__main__':
    unittest.main(verbosity=2)
