"""A06: exact archived C bodies, host-compiled mocked boundaries only."""
import hashlib
import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from test_openssl_allocation_hardening import function

RECIPE = Path(__file__).resolve().parents[1] / 'build/vere-openssl3'
PINS = {
    'pkg/vere/main.c': '206929fef62b6f7246b7313675b6120ab876bc7ae8c4399342e1f0eceaf48549',
    'pkg/vere/vere.h': '20b6fe3b20f7100ec22ac47e1ecac20df4dc8a66475573cc0290e126e90f5c06',
}

def api():
    spec = importlib.util.spec_from_file_location('ca_candidate', RECIPE / 'candidate.py')
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

def original(name):
    text = (Path(os.environ['ISSUE3_SOURCE_REVIEW']) / name).read_text()
    assert hashlib.sha256(text.encode()).hexdigest() == PINS[name]
    return text

def source(name):
    text = original(name)
    if not os.environ.get('ISSUE3_CA_BASELINE'):
        text = api().patch_ca_source(name, text)
    return text

GLUE = r'''
#include <stdio.h>
#include <stdlib.h>
#include <setjmp.h>
typedef int BIO;
typedef struct { int *x509, *crl; } X509_INFO;
typedef struct { int count; X509_INFO entries[2]; } InfoStack;
#define STACK_OF(t) InfoStack
static InfoStack *_cert_store;
static int fail_at, step, bios, stacks, null_use, exit_status, log_bios;
static jmp_buf fatal;
static int ok(void) { return ++step != fail_at; }
static void mock_exit(int status) { exit_status=status; longjmp(fatal,1); }
#define exit mock_exit
#define include_ca_bundle_crt "synthetic public CA bundle"
#define include_ca_bundle_crt_len 26
static BIO *BIO_new_mem_buf(const void *p,int n) {
  (void)p; (void)n; if(!ok()) return NULL; bios++; return calloc(1,sizeof(BIO));
}
static int BIO_free(BIO *p) { if(p) { bios--; free(p); } return 1; }
static InfoStack *PEM_X509_INFO_read_bio(BIO *p,void *a,void *b,void *c) {
  (void)a;(void)b;(void)c; if(!p) null_use++;
  if(!ok()) return NULL;
  stacks++; InfoStack *s=calloc(1,sizeof(*s)); s->count=2; return s;
}
#define u3l_log(s) ((void)(s),log_bios=bios)
'''

@unittest.skipUnless(os.environ.get('ISSUE3_SOURCE_REVIEW'), 'requires accepted public source')
class CATests(unittest.TestCase):
    def compile_probe(self, code):
        scratch = tempfile.TemporaryDirectory(prefix='issue3-ca-probe-', dir=os.environ['TMPDIR'])
        self.addCleanup(scratch.cleanup)
        out = Path(scratch.name)
        (out / 'probe.c').write_text(code)
        result = subprocess.run(['cc','-std=c11','-Wall','-Wextra','-Werror',
                                 '-Wno-unused-parameter', str(out/'probe.c'),'-o',str(out/'probe')],
                                capture_output=True,text=True,timeout=30)
        self.assertEqual(result.returncode,0,result.stderr)
        print('compiled CA probe:', out, hashlib.sha256(code.encode()).hexdigest())
        return out/'probe'

    def run_probe(self, probe, fault, *args):
        return subprocess.run([str(probe),str(fault),*map(str,args)],check=True,
                              capture_output=True,text=True,timeout=5).stdout.strip()

    def test_insertion_failure_propagates_to_curl_and_cttp(self):
        text = source('pkg/vere/main.c')
        header = source('pkg/vere/vere.h')
        declaration = next(line for line in header.splitlines() if '(*ssl_x509_f)' in line)
        client = (Path(os.environ['ISSUE3_SOURCE_REVIEW']) / 'pkg/vere/io/cttp.c').read_text()
        if not os.environ.get('ISSUE3_CA_BASELINE'):
            client = api().patch_allocation_source('pkg/vere/io/cttp.c', client)
        trust = text[text.index('static ', text.index('/* _setup_ssl_x509()')):text.index('/* _setup_ssl_curl()')]
        glue = r'''
#include <stdio.h>
#include <stdlib.h>
typedef int CURLcode;
typedef int CURL;
#define CURLE_OK 0
#define CURLE_ABORTED_BY_CALLBACK 42
typedef struct { int refs; } Cert;
typedef struct { Cert *x509,*crl; } X509_INFO;
typedef struct { int count; X509_INFO entries[2]; } InfoStack;
typedef struct { Cert *items[8]; int count; } X509_STORE;
typedef struct { X509_STORE store; } SSL_CTX;
static InfoStack *_cert_store;
static int fail_at,step,null_use,contexts,missing;
static int sk_X509_INFO_num(InfoStack *s) { if(!s) {null_use++;return 0;} return s->count; }
static X509_INFO *sk_X509_INFO_value(InfoStack *s,int n) { return &s->entries[n]; }
static int add(X509_STORE *s,Cert *c) {
  step++; if(!s || !c) {null_use++;return 0;}
  if(step==fail_at) return 0;
  /* OpenSSL retains its own reference; never consumes the global one. */
  s->items[s->count++]=c; c->refs++; return 1;
}
#define X509_STORE_add_cert add
#define X509_STORE_add_crl add
static SSL_CTX *SSL_CTX_new(void *method) { (void)method; contexts++; return calloc(1,sizeof(SSL_CTX)); }
static void SSL_CTX_free(SSL_CTX *s) {
  if(!s) return;
  for(int i=0;i<s->store.count;i++) s->store.items[i]->refs--;
  contexts--;free(s);
}
static X509_STORE *SSL_CTX_get_cert_store(SSL_CTX *s) { return missing==1 ? NULL : &s->store; }
#define SSLv23_client_method() NULL
#define SSL_OP_NO_SSLv2 1
#define SSL_OP_NO_SSLv3 2
#define SSL_OP_NO_COMPRESSION 4
#define SSL_VERIFY_PEER 1
#define SSL_SESS_CACHE_OFF 0
#define SSL_CTX_set_options(s,n) ((void)(s),(void)(n))
#define SSL_CTX_set_verify(s,n,p) ((void)(s),(void)(n),(void)(p))
#define SSL_CTX_set_session_cache_mode(s,n) ((void)(s),(void)(n))
static int SSL_CTX_set_cipher_list(SSL_CTX *s,const char *n) { (void)s;(void)n;return 1; }
'''
        probe = self.compile_probe(glue + trust + '\nstatic struct {\n' + declaration +
                                   '\n} u3K = {_setup_ssl_x509};\n' +
                                   function(client, 'static SSL_CTX*\n_cttp_init_tls(void)') + r'''
int main(int argc,char **argv) {
  (void)argc; fail_at=atoi(argv[1]); int mode=atoi(argv[2]); missing=atoi(argv[3]);
  Cert certs[4]={{1},{1},{1},{1}};
  InfoStack stack={2,{{&certs[0],&certs[1]},{&certs[2],&certs[3]}}};
  _cert_store=missing==2 ? NULL : &stack;
  SSL_CTX *ctx;
  int success;
  if(mode==0) {ctx=SSL_CTX_new(NULL); success=_curl_ssl_ctx_cb(NULL,ctx,NULL)==CURLE_OK;}
  else {ctx=_cttp_init_tls();success=ctx!=NULL;}
  SSL_CTX_free(ctx);
  printf("%d %d %d %d %d %d %d %d\n",success,step,null_use,contexts,
         certs[0].refs,certs[1].refs,certs[2].refs,certs[3].refs);
  return 0;
}
''')
        for mode in (0,1):
            for fault in range(5):
                with self.subTest(mode=mode,fault=fault):
                    self.assertEqual(self.run_probe(probe,fault,mode,0),
                                     f'{int(fault==0)} {fault or 4} 0 0 1 1 1 1')
            for missing in (1,2):
                with self.subTest(mode=mode,missing=missing):
                    self.assertEqual(self.run_probe(probe,0,mode,missing),'0 0 0 0 1 1 1 1')

    def test_curl_setup_failure_is_terminal_before_transfer(self):
        text = source('pkg/vere/main.c')
        glue = r'''
#include <stdio.h>
#include <stdlib.h>
#include <setjmp.h>
typedef int CURL;
static int step,fail_at,live,exit_status,log_live;
static jmp_buf fatal;
static void mock_exit(int n) { exit_status=n;longjmp(fatal,1); }
#define exit mock_exit
#define CURLE_OK 0
#define CURLOPT_CAINFO 1
#define CURLOPT_CAPATH 2
#define CURLOPT_SSL_CTX_FUNCTION 3
#define _curl_ssl_ctx_cb NULL
static int curl_easy_setopt(CURL *p,int opt,void *value) {
  (void)p;(void)opt;(void)value;return ++step==fail_at ? 1 : 0;
}
static void curl_easy_cleanup(CURL *p) { (void)p;live--; }
#define u3l_log(s) ((void)(s),log_live=live)
'''
        probe = self.compile_probe(glue + function(text,'static void\n_setup_ssl_curl(void* arg)') + r'''
int main(int argc,char **argv) {
  (void)argc; (void)mock_exit; fail_at=atoi(argv[1]); live=1;CURL curl=0;int continued=0;
  if(!setjmp(fatal)) {_setup_ssl_curl(&curl);continued=1;curl_easy_cleanup(&curl);}
  printf("%d %d %d %d %d\n",exit_status,continued,live,log_live,step);
  return 0;
}
''')
        for fault in range(4):
            with self.subTest(fault=fault):
                self.assertEqual(self.run_probe(probe,fault),
                                 '0 1 0 0 3' if fault==0 else f'1 0 0 0 {fault}')

    def test_ca_overlay_exact_guards_and_atomic_validation(self):
        import json
        from unittest.mock import patch
        recipe = api()
        lock = json.loads((RECIPE/'inputs.json').read_text())
        scratch = tempfile.TemporaryDirectory(prefix='issue3-ca-overlay-',dir=os.environ['TMPDIR'])
        self.addCleanup(scratch.cleanup)
        tree = Path(scratch.name)
        originals = {name: original(name) for name in PINS}
        cttp = 'pkg/vere/io/cttp.c'
        originals[cttp] = recipe.patch_allocation_source(cttp,
            (Path(os.environ['ISSUE3_SOURCE_REVIEW'])/cttp).read_text())
        def reset():
            for name,text in originals.items():
                (tree/name).parent.mkdir(parents=True,exist_ok=True)
                (tree/name).write_text(text)
        reset()
        for name in PINS:
            for text in (originals[name]+'/* drift */', originals[name]*2,
                         recipe.patch_ca_source(name,originals[name])):
                with self.subTest(name=name), self.assertRaisesRegex(ValueError,'preimage'):
                    recipe.patch_ca_source(name,text)
        self.assertTrue(hasattr(recipe,'apply_ca_overlay'), 'CA batch overlay missing')
        for name in originals:
            reset()
            (tree/name).write_text(originals[name]+'/* drift */')
            before = {n:(tree/n).read_bytes() for n in originals}
            with self.subTest(drift=name), self.assertRaisesRegex(ValueError,'CA'):
                recipe.apply_ca_overlay(tree,lock)
            self.assertEqual(before,{n:(tree/n).read_bytes() for n in originals})
        reset()
        with patch.object(recipe,'patch_ca_source',side_effect=lambda n,t:t):
            with self.assertRaisesRegex(ValueError,'postimage'):
                recipe.apply_ca_overlay(tree,lock)
        self.assertEqual(originals,{n:(tree/n).read_text() for n in originals})
        self.assertEqual(recipe.apply_ca_overlay(tree,lock),lock['ca_hardening'])
        with self.assertRaisesRegex(ValueError,'preimage'):
            recipe.apply_ca_overlay(tree,lock)

    def test_startup_decode_failure_frees_bio_before_fatal_log(self):
        text = source('pkg/vere/main.c')
        probe = self.compile_probe(GLUE + function(text,'static void\n_setup_cert_store()') + r'''
int main(int argc,char **argv) {
  (void)argc; fail_at=atoi(argv[1]);
  if(!setjmp(fatal)) _setup_cert_store();
  printf("%d %d %d %d %d\n",exit_status,bios,stacks,null_use,log_bios);
  /* Test teardown only: production retains this stack for process lifetime. */
  free(_cert_store);
  return 0;
}
''')
        for fault in (0,1,2):
            with self.subTest(fault=fault):
                self.assertEqual(self.run_probe(probe,fault),
                                 '0 0 1 0 0' if fault==0 else '1 0 0 0 0')

if __name__ == '__main__':
    unittest.main()
