"""Compiled exact-source probes. Mock boundary only; no linked-library claim.

ISSUE3_SOURCE_REVIEW must name the accepted public-source extraction.
ISSUE3_ALLOCATION_BASELINE=1 exercises the unchanged accepted source (RED).
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
RECIPE = ROOT / 'build/vere-openssl3'
PINS = {
    'pkg/vere/io/cttp.c': '257caa336c71e963be0b029796ef62c9e154806927d95a1f221b7dc5341e34b4',
    'pkg/vere/io/http.c': '7f80902b1ce7ec0adf717d6dd5b58a5b4f4a6b0d9d6bb16719271e7ed3a721cf',
}


def source_text(name):
    path = Path(os.environ['ISSUE3_SOURCE_REVIEW']) / name
    text = path.read_text()
    assert hashlib.sha256(text.encode()).hexdigest() == PINS[name]
    if not os.environ.get('ISSUE3_ALLOCATION_BASELINE'):
        spec = importlib.util.spec_from_file_location('allocation_candidate', RECIPE / 'candidate.py')
        assert spec is not None and spec.loader is not None
        api = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(api)
        text = api.patch_allocation_source(name, text)
    return text


def function(text, declaration):
    start = text.index(declaration)
    return text[start:text.index('\n}', start) + 2]


COMMON = r'''
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
typedef struct Obj { int live; struct Obj *chain[4]; int n; } Obj;
typedef Obj SSL_CTX;
typedef Obj BIO;
typedef Obj EVP_PKEY;
typedef Obj X509;
typedef int c3_i;
typedef struct { char *base; int len; } uv_buf_t;
static Obj objects[32];
static int used, null_use, double_free, fail_at, step;
static int ok(void) { return ++step != fail_at; }
static Obj *make(void) {
  if (!ok()) return NULL;
  Obj *p=&objects[used++]; p->live=1; return p;
}
static void use(Obj *p) { if (!p || !p->live) null_use++; }
static void release(Obj *p) {
  if (!p) return;
  if (!p->live) { double_free++; return; }
  p->live=0;
  for (int i=0;i<p->n;i++) release(p->chain[i]);
}
static int live(void) { int n=0; for(int i=0;i<used;i++) n+=objects[i].live; return n; }
#define SSL_OP_NO_SSLv2 1
#define SSL_OP_NO_SSLv3 2
#define SSL_OP_NO_COMPRESSION 4
#define SSL_VERIFY_PEER 1
#define SSL_SESS_CACHE_OFF 0
#define SSLv23_client_method() NULL
#define SSLv23_server_method() NULL
#define SSL_CTX_new(p) make()
#define SSL_CTX_free(p) release(p)
static int SSL_CTX_set_options(SSL_CTX *p,int x) { use(p); return x; }
static int SSL_CTX_set_session_cache_mode(SSL_CTX *p,int x) { use(p); (void)x; return 0; }
static int SSL_CTX_set_cipher_list(SSL_CTX *p,const char *s) { use(p); (void)s; return ok(); }
'''
CLIENT = r'''
static void *SSL_CTX_get_cert_store(SSL_CTX *p) { use(p); return p; }
static int trust(void *p) { use(p); return ok(); }
static struct { int (*ssl_x509_f)(void *); } u3K = {trust};
static void SSL_CTX_set_verify(SSL_CTX *p,int a,void *b) { use(p); (void)a; (void)b; }
'''


@unittest.skipUnless(os.environ.get('ISSUE3_SOURCE_REVIEW'), 'requires accepted public source')
class AllocationTests(unittest.TestCase):
    def compile_probe(self, code):
        scratch = tempfile.TemporaryDirectory(prefix='issue3-allocation-probe-', dir=os.environ['TMPDIR'])
        self.addCleanup(scratch.cleanup)
        out = Path(scratch.name)
        path = out / 'probe.c'
        path.write_text(code)
        subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror', '-Wno-unused-parameter', str(path), '-o', str(out / 'probe')], check=True, capture_output=True, text=True, timeout=30)
        print(json.dumps({'compiled_probe': str(out / 'probe'),
                          'harness_sha256': hashlib.sha256(code.encode()).hexdigest()}))
        return out / 'probe'

    def test_overlay_pins_replay_and_batch_refusal(self):
        from unittest import mock
        spec = importlib.util.spec_from_file_location('allocation_recipe', RECIPE / 'candidate.py')
        assert spec is not None and spec.loader is not None
        api = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(api)
        lock = json.loads((RECIPE / 'inputs.json').read_text())
        original = {name: (Path(os.environ['ISSUE3_SOURCE_REVIEW']) / name).read_text() for name in PINS}
        scratch = tempfile.TemporaryDirectory(prefix='issue3-allocation-overlay-', dir=os.environ['TMPDIR'])
        self.addCleanup(scratch.cleanup)
        source = Path(scratch.name)
        for name, text in original.items():
            (source / name).parent.mkdir(parents=True, exist_ok=True)
            (source / name).write_text(text)
        for name in PINS:
            for text in (original[name] + '/* drift */', original[name] * 2,
                         api.patch_allocation_source(name, original[name])):
                with self.subTest(name=name), self.assertRaisesRegex(ValueError, 'preimage'):
                    api.patch_allocation_source(name, text)
        # Last member drift must not permit an earlier member write.
        last = list(PINS)[-1]
        (source / last).write_text(original[last] + '/* drift */')
        before = {name: (source / name).read_bytes() for name in PINS}
        with self.assertRaisesRegex(ValueError, 'preimage'):
            api.apply_allocation_overlay(source, lock)
        self.assertEqual(before, {name: (source / name).read_bytes() for name in PINS})
        (source / last).write_text(original[last])
        changes = api.apply_allocation_overlay(source, lock)
        self.assertEqual(changes, lock['allocation_hardening'])
        with self.assertRaisesRegex(ValueError, 'preimage'):
            api.apply_allocation_overlay(source, lock)
        for name, text in original.items():
            (source / name).write_text(text)
        with mock.patch.object(api, 'patch_allocation_source', side_effect=lambda n,t: t):
            with self.assertRaisesRegex(ValueError, 'postimage'):
                api.apply_allocation_overlay(source, lock)
        self.assertEqual(original, {name: (source / name).read_text() for name in PINS})

    def test_client_startup_failure_never_registers_null_tls(self):
        text = source_text('pkg/vere/io/cttp.c')
        glue = r'''
#include <setjmp.h>
#include <sys/time.h>
typedef int u3_pier;
typedef int u3_noun;
typedef struct { int nam_m,liv_o; struct { int talk_f,kick_f,exit_f; } io; } u3_auto;
typedef struct { u3_auto car_u; SSL_CTX *tls_u; struct { void *loop,*io_timeout; SSL_CTX *ssl_ctx; } ctx_u; struct { void *data; } nop_u; int tim_u,sev_l; } u3_cttp;
static void *u3L;
static int allocations,handles,timeouts,exit_status;
static jmp_buf fatal;
static void fail_exit(int status) { exit_status=status; longjmp(fatal,1); }
#define exit fail_exit
static void *c3_calloc(size_t n) { allocations++; return calloc(1,n); }
#define c3__cttp 1
#define c3y 1
#define _cttp_io_talk 1
#define _cttp_io_kick 2
#define _cttp_io_exit 3
#define u3m_time_in_tv(p) ((void)(p),0)
#define u3r_mug(n) (n)
#define u3z(n) ((void)(n))
#define uv_async_init(loop,handle,cb) ((void)(loop),(void)(handle),(void)(cb),handles++)
#define h2o_timeout_init(loop,timer,delay) ((void)(loop),(void)(timer),(void)(delay),timeouts++)
'''
        probe = self.compile_probe(COMMON + CLIENT + glue + function(text, 'static SSL_CTX*\n_cttp_init_tls(void)') + '\n' + function(text, 'u3_auto*\nu3_cttp_io_init(u3_pier* pir_u)') + r'''
int main(int argc,char **argv) {
  (void)argc; (void)fail_exit; fail_at=atoi(argv[1]);
  u3_auto *car=NULL;
  if (!setjmp(fatal)) car=u3_cttp_io_init(NULL);
  if (car) { u3_cttp *p=(u3_cttp*)car; SSL_CTX_free(p->tls_u); free(p); }
  printf("%d %d %d %d %d %d %d\n",exit_status,allocations,handles,timeouts,null_use,double_free,live());
  return 0;
}
''')
        for fault in (0, 1, 2, 3):
            with self.subTest(fault=fault):
                result = subprocess.run([str(probe), str(fault)], check=True, capture_output=True, text=True, timeout=5)
                self.assertEqual(result.stdout.strip(), '0 1 1 1 0 0 0' if fault == 0 else '1 0 0 0 0 0 0')

    def test_server_allocation_and_ownership_failures(self):
        text = source_text('pkg/vere/io/http.c')
        server = r'''
#define H2O_USE_ALPN 1
#define PEM_R_NO_START_LINE 108
#define ERR_LIB_PEM 9
static unsigned long error_code;
static int chain_reads, transferred;
#define ERR_GET_REASON(e) ((e)&255)
#define ERR_GET_LIB(e) ((e)>>8)
#define ERR_peek_last_error() error_code
#define ERR_clear_error() (error_code=0)
#define BIO_eof(p) ((void)(p),1)
#define u3l_log(s) ((void)(s))
#define u3_term_io_loja(a,b) ((void)(a),(void)(b))
#define u3_term_io_hija() stderr
#define ERR_print_errors_fp(p) ((void)(p))
#define SSL_CTX_set_ecdh_auto(p,n) ((void)(n),use(p))
#define h2o_http2_alpn_protocols NULL
#define h2o_ssl_register_alpn_protocols(p,v) ((void)(v),use(p))
#define BIO_free(p) release(p)
#define X509_free(p) release(p)
#define EVP_PKEY_free(p) release(p)
static int SSL_CTX_set_default_verify_paths(SSL_CTX *p) { use(p); return ok(); }
static BIO *BIO_new_mem_buf(const void *p,int len) { (void)p;(void)len; return make(); }
static EVP_PKEY *PEM_read_bio_PrivateKey(BIO *p,void *a,void *b,void *c) { (void)a;(void)b;(void)c; use(p); return make(); }
static X509 *PEM_read_bio_X509_AUX(BIO *p,void *a,void *b,void *c) { (void)a;(void)b;(void)c; use(p); return make(); }
static int SSL_CTX_use_PrivateKey(SSL_CTX *p,EVP_PKEY *k) { use(p);use(k); return ok(); }
static int SSL_CTX_use_certificate(SSL_CTX *p,X509 *k) { use(p);use(k); return ok(); }
static X509 *PEM_read_bio_X509(BIO *p,void *a,void *b,void *c) {
  (void)a;(void)b;(void)c; use(p);
  if (chain_reads++ < 2) { X509 *x=make(); if (!x) error_code=999; return x; }
  error_code=ok() ? ((ERR_LIB_PEM<<8)|PEM_R_NO_START_LINE) : 999; return NULL;
}
static int SSL_CTX_add_extra_chain_cert(SSL_CTX *p,X509 *x) {
  use(p);use(x);
  if (!ok()) return 0;
  if(p) p->chain[p->n++]=x;
  transferred++; return 1;
}
'''
        probe = self.compile_probe(COMMON + server + function(text, 'static SSL_CTX*\n_http_init_tls(uv_buf_t key_u, uv_buf_t cer_u)') + r'''
int main(int argc,char **argv) {
  (void)argc; fail_at=atoi(argv[1]);
  uv_buf_t key={"synthetic",9},cert={"synthetic",9};
  SSL_CTX *p=_http_init_tls(key,cert);
  int returned=p!=NULL;
  SSL_CTX_free(p);
  printf("%d %d %d %d %d\n",returned,null_use,double_free,live(),transferred);
  return 0;
}
''')
        for fault in range(15):
            with self.subTest(fault=fault):
                result = subprocess.run([str(probe), str(fault)], check=True, capture_output=True, text=True, timeout=5)
                values = list(map(int, result.stdout.split()))
                self.assertEqual(values[:4], [int(fault == 0), 0, 0, 0])
                if fault == 0:
                    self.assertEqual(values[4], 2)

    def test_client_context_and_cipher_fail_closed(self):
        text = source_text('pkg/vere/io/cttp.c')
        probe = self.compile_probe(COMMON + CLIENT + function(text, 'static SSL_CTX*\n_cttp_init_tls(void)') + r'''
int main(int argc,char **argv) {
  (void)argc; fail_at=atoi(argv[1]);
  SSL_CTX *p=_cttp_init_tls();
  int returned=p!=NULL;
  SSL_CTX_free(p);
  printf("%d %d %d %d\n",returned,null_use,double_free,live());
  return 0;
}
''')
        for fault in (0, 1, 2, 3):
            with self.subTest(fault=fault):
                result = subprocess.run([str(probe), str(fault)], check=True, capture_output=True, text=True, timeout=5)
                self.assertEqual(result.stdout.strip(), ('1' if fault == 0 else '0') + ' 0 0 0')


if __name__ == '__main__':
    unittest.main(verbosity=2)
