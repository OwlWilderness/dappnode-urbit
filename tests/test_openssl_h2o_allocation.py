"""Pinned H2O constructor bodies, mocked SSL/BIO seams; no library build."""
import hashlib
import os
from pathlib import Path
import subprocess
import unittest
import test_openssl_allocation_hardening as allocation
from test_openssl_allocation_hardening import function, RECIPE
import test_openssl_binary_verifier as binary
import importlib.util
import json
import tempfile
import tarfile
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('h2o_candidate', RECIPE / 'candidate.py')
assert spec is not None and spec.loader is not None
api = importlib.util.module_from_spec(spec)
spec.loader.exec_module(api)

UPSTREAM = 'a301247dbd95f7145aa1cc3c83a720c93bf5d1d3d7a5a961846eea7dbfd8476d'

# Exact reviewed publication delta; retain preimage for historical RED controls.
PRE_PUBLICATION_SETUP = '''static void setup_bio(h2o_socket_t *sock)
{
    static BIO_METHOD *bio_methods = NULL;
    if (bio_methods == NULL) {
        static pthread_mutex_t init_lock = PTHREAD_MUTEX_INITIALIZER;
        pthread_mutex_lock(&init_lock);
        if (bio_methods == NULL) {
            BIO_METHOD *biom = BIO_meth_new(BIO_TYPE_FD, "h2o_socket");
            if (biom == NULL) {
                pthread_mutex_unlock(&init_lock);
                h2o_fatal("no memory");
            }
            BIO_meth_set_write(biom, write_bio);
            BIO_meth_set_read(biom, read_bio);
            BIO_meth_set_puts(biom, puts_bio);
            BIO_meth_set_ctrl(biom, ctrl_bio);
            __sync_synchronize();
            bio_methods = biom;
        }
\tpthread_mutex_unlock(&init_lock);
    }

    BIO *bio = BIO_new(bio_methods);
    if (bio == NULL)
        h2o_fatal("no memory");
    BIO_set_data(bio, sock);
    BIO_set_init(bio, 1);
    SSL_set_bio(sock->ssl->ossl, bio, bio);
}'''
PUBLISHED_SETUP = '''static void setup_bio(h2o_socket_t *sock)
{
    static BIO_METHOD *bio_methods = NULL;
    static pthread_mutex_t init_lock = PTHREAD_MUTEX_INITIALIZER;
    BIO_METHOD *methods;

    /* Every reader acquires the publication lock, including warm callers. */
    pthread_mutex_lock(&init_lock);
    if (bio_methods == NULL) {
        BIO_METHOD *biom = BIO_meth_new(BIO_TYPE_FD, "h2o_socket");
        if (biom == NULL) {
            pthread_mutex_unlock(&init_lock);
            h2o_fatal("no memory");
        }
        BIO_meth_set_write(biom, write_bio);
        BIO_meth_set_read(biom, read_bio);
        BIO_meth_set_puts(biom, puts_bio);
        BIO_meth_set_ctrl(biom, ctrl_bio);
        bio_methods = biom;
    }
    methods = bio_methods;
    pthread_mutex_unlock(&init_lock);

    BIO *bio = BIO_new(methods);
    if (bio == NULL)
        h2o_fatal("no memory");
    BIO_set_data(bio, sock);
    BIO_set_init(bio, 1);
    SSL_set_bio(sock->ssl->ossl, bio, bio);
}'''

GLUE = r'''
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>
#include <string.h>
typedef struct {int live;} SSL;
typedef int SSL_CTX;
typedef int BIO_METHOD;
typedef int BIO;
typedef int h2o_loop_t;
typedef struct {SSL *ossl; SSL_CTX *ssl_ctx; struct {void *encrypted;} input;} ssl_t;
typedef struct {ssl_t *ssl; void *input;} h2o_socket_t;
typedef struct {int fd; ssl_t *ssl; void *input;} h2o_socket_export_t;
static int fail,locked,sets,transfers,old_frees,continued;
static SSL fresh={1},old={1};
static int method,bio,h2o_socket_buffer_prototype;
static h2o_socket_t socket;
static void check(void *p) {if(!p) {fprintf(stderr,"NULL API use\n");exit(71);}}
static int tracked_lock(pthread_mutex_t *p) {int r=pthread_mutex_lock(p);assert(!r);locked++;return r;}
static int tracked_unlock(pthread_mutex_t *p) {locked--;return pthread_mutex_unlock(p);}
#define pthread_mutex_lock tracked_lock
#define pthread_mutex_unlock tracked_unlock
static void h2o_fatal(const char *s) __attribute__((noreturn));
static void h2o_fatal(const char *s) {
 assert(!locked);assert(!continued);assert(!transfers);
 assert(strstr(s,"memory"));exit(70);
}
static SSL *SSL_new(SSL_CTX *p) {(void)p;return fail==1?NULL:&fresh;}
static void SSL_free(SSL *p) {assert(p==&old);assert(old.live);old.live=0;old_frees++;}
#define BIO_TYPE_FD 1
static BIO_METHOD *BIO_meth_new(int t,const char *s) {(void)t;(void)s;return fail==2?NULL:&method;}
static int write_bio,read_bio,puts_bio,ctrl_bio;
static int setter(BIO_METHOD *m,int f) {check(m);(void)f;sets++;return 1;}
#define BIO_meth_set_write setter
#define BIO_meth_set_read setter
#define BIO_meth_set_puts setter
#define BIO_meth_set_ctrl setter
static BIO *BIO_new(BIO_METHOD *m) {check(m);return fail==3?NULL:&bio;}
static void BIO_set_data(BIO *b,void *s) {check(b);check(s);}
static void BIO_set_init(BIO *b,int i) {check(b);assert(i==1);}
static void SSL_set_bio(SSL *s,BIO *a,BIO *b) {check(s);check(a);assert(a==b);assert(s->live);transfers++;}
static h2o_socket_t *do_import(h2o_loop_t *l,h2o_socket_export_t *i) {(void)l;(void)i;return &socket;}
static void h2o_buffer_set_prototype(void *p,void *v) {(void)p;(void)v;}
'''

@unittest.skipUnless(os.environ.get('ISSUE3_SOURCE_REVIEW'), 'requires accepted public source')
class H2OTests(unittest.TestCase):
    compile_probe = allocation.AllocationTests.compile_probe

    def test_missing_h2o_receipt_refused(self):
        fx = binary.BinaryVerifierTests(methodName='test_valid_combined_candidate')
        self.addCleanup(fx.doCleanups)
        fx.setUp()
        # Even an otherwise valid old delivery cannot claim a new H2O overlay.
        fx.lock['h2o_overlay'] = {'file': 'h2o-socket.c'}
        fx.sync_lock(); fx.sync_receipt()
        with self.assertRaisesRegex(ValueError, 'H2O'):
            binary.verifier.verify(fx.attempt)

    def test_graph_preimages_and_overlay(self):
        self.assertTrue(hasattr(api, 'apply_h2o_overlay'), 'H2O graph overlay missing')
        lock = json.loads((RECIPE / 'inputs.json').read_text())
        scratch = tempfile.TemporaryDirectory(prefix='issue3-h2o-source-', dir=os.environ['TMPDIR'])
        self.addCleanup(scratch.cleanup)
        root = Path(scratch.name)
        archive = RECIPE.parents[1] / 'build_issue3_amd64_curl_build_02/artifact/source-materials.tar.gz'
        with tarfile.open(archive) as t:
            members = t.getmembers()
            for name in ('ext/h2o/build.zig', 'ext/h2o/build.zig.zon'):
                matches = [m for m in members if m.name == lock['inputs']['vere']['root']+'/'+name]
                self.assertEqual(len(matches),1)
                self.assertTrue(matches[0].isfile()); self.assertLess(matches[0].size,50000)
                p = root/name; p.parent.mkdir(parents=True,exist_ok=True)
                stream=t.extractfile(matches[0]);assert stream is not None
                p.write_bytes(stream.read())
        original = (root/'ext/h2o/build.zig').read_bytes()
        zon = (root/'ext/h2o/build.zig.zon').read_bytes()
        changes = api.apply_h2o_overlay(root,lock)
        graph = (root/'ext/h2o/build.zig').read_text()
        self.assertNotIn('"common/socket.c",',graph)
        self.assertEqual(graph.count('.file = b.path("socket.c")'),1)
        self.assertIn('h2o.addIncludePath(h2o_c.path("lib/common"))',graph)
        self.assertEqual((root/'ext/h2o/socket.c').read_bytes(),(RECIPE/'h2o-socket.c').read_bytes())
        with self.assertRaises(ValueError): api.apply_h2o_overlay(root,lock)
        # Fresh sibling trees; bad graph, dependency manifest or overlay must not write.
        for bad in ('build.zig','build.zig.zon','overlay'):
            sibling = root/bad; (sibling/'ext/h2o').mkdir(parents=True)
            (sibling/'ext/h2o/build.zig').write_bytes(original+(b' drift' if bad=='build.zig' else b''))
            (sibling/'ext/h2o/build.zig.zon').write_bytes(zon+(b' drift' if bad=='build.zig.zon' else b''))
            before=(sibling/'ext/h2o/build.zig').read_bytes()
            with patch.object(api,'HERE',root if bad=='overlay' else RECIPE):
                if bad=='overlay': (root/'h2o-socket.c').write_bytes(b'drift')
                with self.assertRaises(ValueError): api.apply_h2o_overlay(sibling,lock)
            self.assertEqual((sibling/'ext/h2o/build.zig').read_bytes(),before)
            self.assertFalse((sibling/'ext/h2o/socket.c').exists())
        receipt = dict(overlay=lock['h2o_overlay'], source_changes=changes,
                       source_preimages={n: lock['source_preimages'][n] for n in
                                         ('ext/h2o/build.zig','ext/h2o/build.zig.zon')})
        (root/'h2o-overlay.json').write_text(json.dumps(receipt,indent=2)+'\n')
        fx = binary.BinaryVerifierTests(methodName='test_valid_combined_candidate')
        self.addCleanup(fx.doCleanups)
        fx.setUp()
        fx.lock['h2o_overlay'] = lock['h2o_overlay']
        for name in changes:
            fx.changes[name]=(root/name).read_bytes()
        fx.receipt['source_changes'].update(changes)
        for directory in (fx.frozen,fx.artifact):
            (directory/'h2o-socket.c').write_bytes((RECIPE/'h2o-socket.c').read_bytes())
        fx.write_json(fx.artifact/'h2o-overlay.json',receipt)
        fx.sync_lock();fx.sync_receipt();fx.sync_archive()
        self.assertEqual(binary.verifier.verify(fx.attempt)['status'],'PASS')
        for name in changes:
            data=fx.changes[name]
            fx.changes[name]=b'tampered source';fx.sync_archive()
            with self.subTest(source=name),self.assertRaisesRegex(ValueError,'archived changed-source'):
                binary.verifier.verify(fx.attempt)
            fx.changes[name]=data
            del fx.changes[name];fx.sync_archive()
            with self.subTest(missing_member=name),self.assertRaises((ValueError,KeyError)):
                binary.verifier.verify(fx.attempt)
            fx.changes[name]=data
            digest=fx.receipt['source_changes'].pop(name);fx.sync_receipt()
            with self.subTest(missing_mapping=name),self.assertRaisesRegex(ValueError,'H2O'):
                binary.verifier.verify(fx.attempt)
            fx.receipt['source_changes'][name]=digest;fx.sync_receipt()
        fx.sync_archive()
        for directory in (fx.frozen,fx.artifact):
            p=directory/'h2o-socket.c';data=p.read_bytes()
            for wrong in (None,b'tampered overlay'):
                if wrong is None: p.unlink()
                else: p.write_bytes(wrong)
                with self.subTest(delivery=str(directory),tamper=wrong),self.assertRaisesRegex(ValueError,'H2O'):
                    binary.verifier.verify(fx.attempt)
            p.write_bytes(data)
        p=fx.artifact/'h2o-overlay.json'
        for wrong in (None,{},dict(receipt,source_changes={}),dict(receipt,source_preimages={}),dict(receipt,extra=True)):
            if wrong is None: p.unlink()
            else: fx.write_json(p,wrong)
            with self.subTest(receipt=wrong),self.assertRaisesRegex(ValueError,'H2O'):
                binary.verifier.verify(fx.attempt)
        fx.write_json(p,receipt)
        self.assertEqual(binary.verifier.verify(fx.attempt)['status'],'PASS')
        saved=fx.lock.pop('h2o_overlay');fx.sync_lock();fx.sync_receipt()
        with self.assertRaisesRegex(ValueError,'H2O'):
            binary.verifier.verify(fx.attempt)
        fx.lock['h2o_overlay']=saved;fx.sync_lock();fx.sync_receipt()
        print(json.dumps({'h2o_exact_source':str(root),'source_changes':changes}))


    def test_only_reviewed_guards_and_all_constructor_callers(self):
        original = (Path(os.environ['ISSUE3_SOURCE_REVIEW'])/'h2o/lib/common/socket.c').read_text()
        text = (RECIPE/'h2o-socket.c').read_text()
        method_guard = ('\n            if (biom == NULL) {\n'
                        '                pthread_mutex_unlock(&init_lock);\n'
                        '                h2o_fatal("no memory");\n            }')
        ssl_guard = ('\n    /* Terminal refusal, matching setup_bio; never continue with plaintext. */\n'
                     '    if (sock->ssl->ossl == NULL)\n        h2o_fatal("no memory");')
        self.assertEqual(text.count(PUBLISHED_SETUP), 1)
        guarded = text.replace(PUBLISHED_SETUP, PRE_PUBLICATION_SETUP)
        self.assertEqual(guarded.count(method_guard),1);self.assertEqual(guarded.count(ssl_guard),1)
        self.assertEqual(guarded.replace(method_guard,'').replace(ssl_guard,''),original)
        self.assertEqual(original.count('create_ossl(sock);'),3)
        self.assertEqual(original.count('setup_bio(sock);'),2)
        self.assertIn('/* fallback to openssl if the attempt failed */\n        create_ossl(sock);',text)
        client = function(text,'void h2o_socket_ssl_handshake(')
        self.assertLess(client.index('create_ossl(sock);'),client.index('session_cache_key.base ='))
        self.assertLess(client.index('create_ossl(sock);'),client.index('handshake.client.server_name ='))
        # No new callback dispatch/cleanup; existing callback and resume tails
        # remain byte-identical. Fatal refusal never returns into those tails.

    def test_constructor_syntax_with_exact_openssl_headers(self):
        import re
        archive = RECIPE.parents[1]/'build_issue3_amd64_curl_build_02/artifact/source-materials.tar.gz'
        digest=hashlib.sha256()
        with archive.open('rb') as stream:
            for chunk in iter(lambda:stream.read(1024**2),b''): digest.update(chunk)
        self.assertEqual(digest.hexdigest(),'8ed4fc8a6b4c1acba3e4e89860a4059e490feb3efaf2a818805770f24f65654f')
        scratch = tempfile.TemporaryDirectory(prefix='issue3-h2o-headers-',dir=os.environ['TMPDIR'])
        self.addCleanup(scratch.cleanup)
        root = Path(scratch.name)
        prefix='vere-8ddc4b786979574dbfcb655e3db1b634f658d0de/ext/openssl/prebuilt/include/'
        pending={'openssl/ssl.h'};seen=set()
        with tarfile.open(archive) as t:
            members=t.getmembers()
            while pending-seen:
                name=sorted(pending-seen)[0]
                matches=[m for m in members if m.name==prefix+name]
                self.assertEqual(len(matches),1);m=matches[0]
                self.assertTrue(m.isfile());self.assertLess(m.size,512*1024)
                stream=t.extractfile(m);assert stream is not None
                data=stream.read();p=root/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(data)
                seen.add(name)
                pending.update(re.findall(r'#\s*include\s*[<"](openssl/[A-Za-z0-9_]+\.h)[>"]',data.decode()))
        code = r'''
#include <openssl/ssl.h>
#include <pthread.h>
typedef struct {struct {SSL *ossl;SSL_CTX *ssl_ctx;} *ssl;} h2o_socket_t;
void h2o_fatal(const char *) __attribute__((noreturn));
int write_bio(BIO *,const char *,int);
int read_bio(BIO *,char *,int);
int puts_bio(BIO *,const char *);
long ctrl_bio(BIO *,int,long,void *);
'''
        text=self.source()
        code+='\n'.join(function(text,n) for n in ('static void setup_bio(','static void create_ossl('))
        code+='\nvoid exercise(h2o_socket_t *s) {create_ossl(s);}\n'
        path=root/'constructors.c';path.write_text(code)
        run=subprocess.run(['cc','-std=c11','-Wall','-Wextra','-Werror','-fsyntax-only','-I',str(root),str(path)],capture_output=True,text=True,timeout=30)
        self.assertEqual(run.returncode,0,run.stderr)
        print(json.dumps({'h2o_exact_header_syntax':str(root),'headers':len(seen),'linked':False}))

    def source(self):
        upstream = (Path(os.environ['ISSUE3_SOURCE_REVIEW']) / 'h2o/lib/common/socket.c').read_bytes()
        self.assertEqual(hashlib.sha256(upstream).hexdigest(), UPSTREAM)
        overlay = RECIPE / 'h2o-socket.c'
        return upstream.decode() if os.environ.get('ISSUE3_H2O_UNPATCHED') or not overlay.exists() else overlay.read_text()

    def probe(self):
        text = self.source()
        # Actual recreation seam includes the old SSL release before construction.
        seam = '            SSL_free(sock->ssl->ossl);\n            create_ossl(sock);'
        self.assertEqual(text.count(seam), 1)
        bodies = '\n'.join(function(text, n) for n in (
            'static void setup_bio(', 'static void create_ossl(', 'h2o_socket_t *h2o_socket_import('))
        return self.compile_probe(GLUE + bodies + '\nstatic void recreate(h2o_socket_t *sock) {\n' + seam + r'''
}
int main(int argc,char **argv) {
 (void)argc;fail=atoi(argv[1]);int route=atoi(argv[2]);
 ssl_t state={0};socket.ssl=&state;
 if(atoi(argv[3])) {int saved=fail;fail=0;create_ossl(&socket);fail=saved;transfers=0;}
 if(route==2) {state.ossl=&old;recreate(&socket);assert(old_frees==1);assert(state.ossl!=&old);}
 else if(route==3) {
  state.ossl=&fresh;h2o_socket_export_t info={4,&state,NULL};
  assert(h2o_socket_import(NULL,&info)==&socket);assert(info.fd==-1);
 } else {create_ossl(&socket);}
 continued++;assert(!fail);assert(transfers==1);assert(sets==4);assert(!locked);
 return 0;
}
''')

    def test_terminal_constructors_and_success(self):
        probe = self.probe()
        for warm in (0,1):
            for route in range(4):
                for fail in range(4):
                    if route==3 and fail==1: continue  # import adopts existing SSL
                    if warm and fail==2: continue  # method already published
                    with self.subTest(warm=warm,route=('client','server-fallback','recreation','import')[route], fail=fail):
                        run = subprocess.run([str(probe),str(fail),str(route),str(warm)], capture_output=True,text=True,timeout=5)
                        self.assertEqual(run.returncode,70 if fail else 0,run.stderr)

if __name__ == '__main__':
    unittest.main(verbosity=2)
