"""Exact cttp bodies with a finite callback scheduler, not a real loop/TLS test."""
import os
import hashlib
from pathlib import Path
import subprocess
import unittest
import test_openssl_allocation_hardening as allocation
from test_openssl_allocation_hardening import source_text, function

GLUE = r'''
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <arpa/inet.h>
typedef unsigned c3_w;
typedef unsigned long c3_l;
typedef unsigned short c3_s;
typedef char c3_c;
typedef int c3_o;
typedef int c3_i;
typedef int c3_t;
typedef int u3_noun;
typedef struct {int unused;} u3_auto;
typedef struct {int unused;} u3_hbod;
typedef struct {int unused;} u3_hhed;
typedef struct {char *base; size_t len;} h2o_iovec_t;
typedef struct {void *data;} uv_handle_t;
typedef uv_handle_t uv_async_t;
typedef uv_handle_t uv_getaddrinfo_t;
typedef struct {int linked; } h2o_linklist_t;
typedef struct {h2o_linklist_t _entries; struct {uv_handle_t timer;} _backend;} h2o_timeout_t;
typedef struct {void *loop,*io_timeout,*ssl_ctx;} h2o_http1client_ctx_t;
typedef struct {void *data; struct {char *server_name;} ssl;} h2o_http1client_t;
#define c3y 0
#define c3n 1
#define u3_assert assert
static void *u3L;
static void _cttp_heds_free(void *p) {(void)p;}
static void _cttp_bods_free(void *p) {(void)p;}
static void _cttp_cres_free(void *p) {(void)p;}
static int owner_dead,freed,cancels,ctx_frees,queued,completed,connects,failures;
static uv_handle_t *handles[2];
static void (*callbacks[2])(uv_handle_t*);
static int h2o_linklist_is_empty(h2o_linklist_t *p) {return !p->linked;}
static void uv_close(uv_handle_t *p,void (*cb)(uv_handle_t*)) {
 assert(queued<2);handles[queued]=p;callbacks[queued++]=cb;
}
static void h2o_timeout_dispose(void *loop,h2o_timeout_t *p) {
 (void)loop;assert(h2o_linklist_is_empty(&p->_entries));uv_close(&p->_backend.timer,NULL);
}
static void SSL_CTX_free(void *p) {(void)p;ctx_frees++;}
static const char *uv_strerror(int n) {(void)n;return "DNS failure";}
static void uv_freeaddrinfo(struct addrinfo *p) {(void)p;}
static char *_cttp_creq_ip(c3_w n) {(void)n;return "127.0.0.1";}
'''

AFTER_TYPES = r'''
static u3_cttp owner;
static u3_creq nodes[8];
static int dead[8];
static void c3_free(void *p) {
 if (!p) return;
 if (p==&owner) {assert(!owner_dead);owner_dead=1;return;}
 for(int i=0;i<8;i++) if(p==&nodes[i]) {
  assert(!dead[i]);dead[i]=1;freed++;
  /* Poison list links at release: a post-release next read loses traversal. */
  nodes[i].nex_u=NULL;nodes[i].pre_u=NULL;return;
 }
}
static void h2o_http1client_cancel(h2o_http1client_t *p) {
 (void)p;assert(!owner_dead);cancels++;owner.tim_u._entries.linked--;
}
static void _cttp_creq_connect(u3_creq *p) {(void)p;connects++;}
static void _cttp_creq_fail(u3_creq *p,const char *s) {(void)p;(void)s;failures++;}
static void init(int n,int dns_mask) {
 owner.nop_u.data=&owner;owner.tim_u._backend.timer.data=&owner;
 for(int i=0;i<n;i++) {
  nodes[i].ctp_u=&owner;nodes[i].sat_e=(dns_mask&(1<<i))?u3_csat_addr:u3_csat_ripe;
  nodes[i].pre_u=i?&nodes[i-1]:NULL;nodes[i].nex_u=i+1<n?&nodes[i+1]:NULL;
  if(nodes[i].sat_e==u3_csat_ripe) {nodes[i].cli_u=(void*)1;owner.tim_u._entries.linked++;}
 }
 owner.ceq_u=n?nodes:NULL;
}
static void close_event(int i) {
 assert(!owner_dead);assert(i<queued);completed++;
 if(callbacks[i]) callbacks[i](handles[i]);
}
'''


@unittest.skipUnless(os.environ.get('ISSUE3_SOURCE_REVIEW'), 'requires accepted public source')
class ShutdownTests(unittest.TestCase):
    compile_probe = allocation.AllocationTests.compile_probe

    def harness(self):
        text = source_text('pkg/vere/io/cttp.c')
        types = text[text.index('  typedef enum {'):text.index('// XX deduplicate')]
        bodies = []
        if 'static void\n_cttp_io_maybe_free(' in text:
            bodies.append(function(text, 'static void\n_cttp_io_maybe_free('))
        for name in ('_cttp_creq_unlink', '_cttp_creq_free', '_cttp_creq_quit',
                     '_cttp_creq_resolve_cb', '_cttp_io_exit_cb', '_cttp_io_exit'):
            bodies.append(function(text, 'static void\n' + name + '('))
        timeout_header = (Path(os.environ['ISSUE3_SOURCE_REVIEW']) / 'h2o/include/h2o/timeout.h').read_text()
        backend_header = (Path(os.environ['ISSUE3_SOURCE_REVIEW']) / 'h2o/include/h2o/socket/uv-binding.h').read_text()
        self.assertEqual(hashlib.sha256(timeout_header.encode()).hexdigest(), '52aee5e050c3d581cb379371e650a5c53aec810ac31b00e906100c0f355047c9')
        self.assertEqual(hashlib.sha256(backend_header.encode()).hexdigest(), '7cc74c10fa9e89b3406186c0f94a99478133681d9f98a69e5b9c434a23db282f')
        start = timeout_header.index('typedef struct st_h2o_timeout_t {')
        timeout_type = timeout_header[start:timeout_header.index('} h2o_timeout_t;', start) + len('} h2o_timeout_t;')]
        start = backend_header.index('struct st_h2o_timeout_backend_properties_t {')
        backend_type = backend_header[start:backend_header.index('};', start) + 2]
        glue = GLUE.replace('typedef struct {h2o_linklist_t _entries; struct {uv_handle_t timer;} _backend;} h2o_timeout_t;',
                            '#include <stdint.h>\ntypedef uv_handle_t uv_timer_t;\n' + backend_type + '\n' + timeout_type)
        return glue + types + AFTER_TYPES + '\n'.join(bodies)

    def test_zero_one_three_request_traversal(self):
        probe = self.compile_probe(self.harness() + r'''
int main(int argc,char **argv) {
 (void)argc;(void)close_event;(void)_cttp_creq_resolve_cb;(void)h2o_timeout_dispose;(void)u3L;
 int n=atoi(argv[1]);init(n,0);_cttp_io_exit(&owner.car_u);
 assert(freed==n);assert(cancels==n);assert(owner.ceq_u==NULL);
 /* This slice checks traversal; drain ordering is a separate probe. */
 for(int i=0;i<queued;i++) {if(callbacks[i]) {completed++;callbacks[i](handles[i]);}}
 assert(owner_dead==1);assert(ctx_frees==1);return 0;
}
''')
        for n in (0, 1, 3):
            with self.subTest(requests=n):
                result = subprocess.run([str(probe), str(n)], capture_output=True, text=True, timeout=5)
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_dns_and_both_handle_close_barriers(self):
        import itertools
        probe = self.compile_probe(self.harness() + r'''
int main(int argc,char **argv) {
 (void)argc;(void)h2o_timeout_dispose;(void)u3L;
 int mask=atoi(argv[1]),status=atoi(argv[2]);init(3,mask);
 _cttp_io_exit(&owner.car_u);
 assert(queued==2);assert(!owner_dead);
 int length=(int)strlen(argv[3]);
 for(int j=0;j<length;j++) {
  int event=argv[3][j]-'0';
  assert(!owner_dead);
  if(event<2) close_event(event);
  else {uv_getaddrinfo_t adr={&nodes[event-2]};_cttp_creq_resolve_cb(&adr,status,NULL);}
  if(j+1<length) assert(!owner_dead);
  if(!owner_dead) {
   u3_creq *prev=NULL;
   for(u3_creq *p=owner.ceq_u;p;p=p->nex_u) {assert(p->pre_u==prev);prev=p;}
  }
 }
 assert(owner_dead==1);assert(ctx_frees==1);assert(freed==3);
 assert(completed==2);assert(!connects);assert(!failures);return 0;
}
''')
        for mask, events in ((0, '01'), (1, '012'), (5, '0124')):
            for order in itertools.permutations(events):
                for status in (0, -2, -125):
                    with self.subTest(mask=mask, order=order, status=status):
                        result = subprocess.run([str(probe), str(mask), str(status), ''.join(order)], capture_output=True, text=True, timeout=5)
                        self.assertEqual(result.returncode, 0, result.stderr)

    def test_precanceled_dns_and_late_effects(self):
        text = source_text('pkg/vere/io/cttp.c')
        glue = r'''
static int created,started,noun_frees;
static int u3r_sing_c(const char *s,u3_noun n) {(void)s;(void)n;return c3y;}
static int u3r_cell(u3_noun n,u3_noun *a,u3_noun *b) {(void)n;*a=0;*b=0;return c3y;}
static int u3r_safe_word(u3_noun n,c3_l *a) {(void)n;*a=0;return c3y;}
static void u3z(u3_noun n) {(void)n;noun_frees++;}
static u3_noun u3k(u3_noun n) {return n;}
static void u3l_log(const char *s) {(void)s;}
static u3_creq *_cttp_creq_new(u3_cttp *p,c3_l n,u3_noun a) {(void)p;(void)n;(void)a;created++;return nodes;}
static void _cttp_creq_start(u3_creq *p) {(void)p;started++;}
static u3_creq *_cttp_creq_find(u3_cttp *p,c3_l n) {(void)p;(void)n;return nodes;}
'''
        probe = self.compile_probe(self.harness() + glue + function(text, 'static c3_o\n_cttp_ef_http_client(') + r'''
int main(int argc,char **argv) {
 (void)argc;(void)h2o_timeout_dispose;(void)u3L;
 init(1,1);
 if(atoi(argv[1])==0) {
  _cttp_creq_quit(nodes);_cttp_creq_quit(nodes);
  assert(freed==0);_cttp_io_exit(&owner.car_u);
  assert(freed==0);_cttp_io_exit(&owner.car_u);assert(queued==2);
 } else {
  _cttp_io_exit(&owner.car_u);
  assert(_cttp_ef_http_client(&owner,0,0)==c3n);
  assert(created==0);assert(started==0);assert(noun_frees==2);
 }
 close_event(0);close_event(1);assert(!owner_dead);
 uv_getaddrinfo_t adr={nodes};_cttp_creq_resolve_cb(&adr,0,NULL);
 assert(freed==1);assert(owner_dead);assert(!connects);return 0;
}
''')
        for mode in (0, 1):
            with self.subTest(mode=mode):
                result = subprocess.run([str(probe), str(mode)], capture_output=True, text=True, timeout=5)
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_sync_connect_and_async_handshake_failure_ownership(self):
        text = source_text('pkg/vere/io/cttp.c')
        code = self.harness()
        code = code.replace('static void _cttp_creq_connect(u3_creq *p) {(void)p;connects++;}', 'static void _cttp_creq_connect(u3_creq *p);')
        code = code.replace('static void _cttp_creq_fail(u3_creq *p,const char *s) {(void)p;(void)s;failures++;}', 'static void _cttp_creq_fail(u3_creq *p,const char *s);')
        glue = r'''
typedef void (*h2o_http1client_head_cb)(void);
static int mode,client_live,responses,serialized;
static h2o_http1client_t client;
static void _cttp_creq_on_head(void) {}
static void _cttp_creq_fire(u3_creq *p) {(void)p;serialized++;}
static h2o_iovec_t *_cttp_bods_to_vec(u3_hbod *p,c3_w *n) {(void)p;*n=0;return NULL;}
static void u3l_log(const char *s,...) {(void)s;}
#define u3_nul 0
static void _cttp_http_client_receive(u3_creq *p,c3_w status,u3_noun a,u3_noun b) {
 (void)p;(void)a;(void)b;assert(status==504);responses++;
}
static h2o_iovec_t h2o_iovec_init(char *p,size_t n) {h2o_iovec_t v={p,n};return v;}
static void h2o_http1client_connect(h2o_http1client_t **out,void *data,h2o_http1client_ctx_t *ctx,
 h2o_iovec_t ip,c3_s port,c3_t tls,
 h2o_http1client_head_cb (*cb)(h2o_http1client_t*,const char*,h2o_iovec_t**,size_t*,c3_i*)) {
 (void)ctx;(void)ip;(void)port;(void)tls;client.data=data;*out=&client;client_live=1;
 if(mode==0) {assert(!cb(&client,"socket error",NULL,NULL,NULL));client_live=0;}
}
'''
        code += glue + function(text, 'static void\n_cttp_creq_fail(')
        code += function(text, 'static h2o_http1client_head_cb\n_cttp_creq_on_connect(')
        code += function(text, 'static void\n_cttp_creq_connect(')
        probe = self.compile_probe(code + r'''
int main(int argc,char **argv) {
 (void)argc;(void)h2o_timeout_dispose;(void)u3L;(void)connects;(void)failures;(void)_cttp_creq_resolve_cb;
 mode=atoi(argv[1]);init(1,1);nodes[0].sat_e=u3_csat_conn;nodes[0].ipf_c="127.0.0.1";
 _cttp_creq_connect(nodes);
 if(mode==1) {
  assert(client_live);assert(!freed);assert(nodes[0].sat_e==u3_csat_ripe);
  assert(!_cttp_creq_on_connect(&client,"handshake failed",NULL,NULL,NULL));
  /* H2O on_connect_error closes its own client after the cttp callback. */
  client_live=0;
 }
 assert(freed==1);assert(responses==1);assert(!serialized);assert(!cancels);assert(!client_live);
 _cttp_io_exit(&owner.car_u);close_event(1);close_event(0);
 assert(owner_dead);assert(ctx_frees==1);return 0;
}
''')
        for mode in (0, 1):
            result = subprocess.run([str(probe), str(mode)], capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_exact_h2o_cancel_delayed_tls_and_uv_write_completion(self):
        pins = {
            'lib/common/http1client.c': '700063eb8d47e0f2b215711f539388cd92118b46dafaae1faebbb99a3ab0569d',
            'lib/common/socket.c': 'a301247dbd95f7145aa1cc3c83a720c93bf5d1d3d7a5a961846eea7dbfd8476d',
            'lib/common/socket/uv-binding.c.h': '22a7404fb3e0df5ccf2357be010a2020f4d7d1e790471971b3330baf59af674b',
            'lib/common/timeout.c': '1e776d0b4de75fd02afff2e1bc348481da09abdc3549cda10d6c2c05f78c5114',
        }
        sources = {}
        for name, digest in pins.items():
            data = (Path(os.environ['ISSUE3_SOURCE_REVIEW']) / 'h2o' / name).read_bytes()
            self.assertEqual(hashlib.sha256(data).hexdigest(), digest)
            sources[name] = data.decode()
        glue = r'''
#include <assert.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#define H2O_USE_PICOTLS 0
#define SSL_ERROR_WANT_READ 2
#define H2O_STRUCT_FROM_MEMBER(type,member,p) ((type*)((char*)(p)-offsetof(type,member)))
typedef struct {void *data;} uv_handle_t;
typedef void (*uv_close_cb)(uv_handle_t*);
typedef struct {int unused;} uv_write_t;
typedef int h2o_loop_t;
typedef struct {int linked;} h2o_linklist_t;
typedef struct {h2o_linklist_t _entries;struct {uv_handle_t timer;} _backend;} h2o_timeout_t;
typedef struct {int linked;} h2o_timeout_entry_t;
typedef struct {int size;} h2o_buffer_t;
struct st_h2o_socket_ssl_t {
 void *ossl;
 struct {struct {char *server_name;struct {char *base;} session_cache_key;} client;} handshake;
 struct {h2o_buffer_t *encrypted;} input;
 struct {struct {void *entries;size_t size;} bufs;int pool;} output;
};
typedef struct Sock h2o_socket_t;
typedef void (*h2o_socket_cb)(h2o_socket_t*,const char*);
struct Sock {
 struct st_h2o_socket_ssl_t *ssl;h2o_buffer_t *input;void *_peername;
 struct {h2o_socket_cb read,write;} _cb;
 struct {void (*cb)(void*);void *data;} on_close;
};
struct st_h2o_uv_socket_t {
 h2o_socket_t super;uv_write_t _wreq;
 struct {uv_close_cb close_cb;uv_handle_t *stream;} uv;
};
typedef struct {
 h2o_socket_t *sock;void *ctx;
 struct {char *server_name;} ssl;
 struct {void *pool,*connect_req;} sockpool;
} h2o_http1client_t;
struct st_h2o_http1client_private_t {
 h2o_http1client_t super;void *_getaddr_req;int _can_keepalive;h2o_timeout_entry_t _timeout;
};
static int client_dead,ssl_dead,socket_dead,stream_done,timeout_live=1,timer_entries=1;
static int context_refs=2,shutdown_result,shutdown_calls,flushes,close_notifications;
static void *client_ptr,*ssl_ptr,*socket_ptr;
static void tracked_free(void *p) {
 if(p==client_ptr) {assert(!client_dead);client_dead=1;}
 if(p==ssl_ptr) {assert(!ssl_dead);ssl_dead=1;}
 if(p==socket_ptr) {assert(!socket_dead);socket_dead=1;}
 free(p);
}
#define free tracked_free
static uv_handle_t *close_handles[2];static uv_close_cb close_callbacks[2];static int closes;
static void uv_close(uv_handle_t *h,uv_close_cb cb) {assert(closes<2);close_handles[closes]=h;close_callbacks[closes++]=cb;}
static int h2o_linklist_is_empty(h2o_linklist_t *p) {return !p->linked;}
static int h2o_timeout_is_linked(h2o_timeout_entry_t *p) {assert(timeout_live);return p->linked;}
static void h2o_timeout_unlink(h2o_timeout_entry_t *p) {assert(timeout_live);timer_entries-=p->linked;p->linked=0;}
static void h2o_hostinfo_getaddr_cancel(void *p) {(void)p;abort();}
static void h2o_socketpool_return(void *p,h2o_socket_t *s) {(void)p;(void)s;abort();}
static void h2o_socketpool_cancel_connect(void *p) {(void)p;abort();}
static void h2o_buffer_consume(h2o_buffer_t **p,int size) {(void)p;(void)size;abort();}
static void h2o_buffer_dispose(h2o_buffer_t **p) {(void)p;}
static void h2o_mem_clear_pool(int *p) {(void)p;}
static int SSL_is_server(void *p) {(void)p;return 0;}
static void SSL_free(void *p) {(void)p;assert(context_refs>0);context_refs--;}
static void ERR_clear_error(void) {}
static int SSL_shutdown(void *p) {(void)p;shutdown_calls++;return shutdown_calls==1?shutdown_result:1;}
static int SSL_get_error(void *p,int n) {(void)p;(void)n;return SSL_ERROR_WANT_READ;}
static const char *h2o_socket_error_io="write error";
static void h2o_socket_read_stop(h2o_socket_t *s) {s->_cb.read=NULL;}
static void h2o_socket_read_start(h2o_socket_t *s,h2o_socket_cb cb) {s->_cb.read=cb;}
static void do_write(h2o_socket_t *s,void *buf,size_t n,h2o_socket_cb cb) {(void)buf;(void)n;flushes++;s->_cb.write=cb;}
static void on_write_complete(h2o_socket_t *s,const char *err);
static void closed_stream(uv_handle_t *h) {(void)h;stream_done++;}
static void closed_socket(void *data) {(void)data;close_notifications++;}
'''
        order = [
            ('lib/common/socket/uv-binding.c.h', 'static void free_sock('),
            ('lib/common/socket/uv-binding.c.h', 'void do_dispose_socket('),
            ('lib/common/socket/uv-binding.c.h', 'static void on_do_write_complete('),
            ('lib/common/socket/uv-binding.c.h', 'void h2o_timeout__do_dispose('),
            ('lib/common/timeout.c', 'void h2o_timeout_dispose('),
            ('lib/common/socket.c', 'static void flush_pending_ssl('),
            ('lib/common/socket.c', 'static void clear_output_buffer('),
            ('lib/common/socket.c', 'void on_write_complete(h2o_socket_t *sock, const char *err)\n{'),
            ('lib/common/socket.c', 'static void destroy_ssl('),
            ('lib/common/socket.c', 'static void dispose_socket('),
            ('lib/common/socket.c', 'static void shutdown_ssl('),
            ('lib/common/socket.c', 'void h2o_socket_close('),
            ('lib/common/http1client.c', 'static void close_client('),
            ('lib/common/http1client.c', 'void h2o_http1client_cancel('),
        ]
        probe = self.compile_probe(glue + '\n'.join(function(sources[p], name) for p, name in order) + r'''
int main(int argc,char **argv) {
 (void)argc;shutdown_result=atoi(argv[1]);int pending=atoi(argv[2]),status=atoi(argv[3]);
 struct st_h2o_http1client_private_t *client=calloc(1,sizeof(*client));client_ptr=client;
 struct st_h2o_uv_socket_t *sock=calloc(1,sizeof(*sock));socket_ptr=sock;
 sock->super.ssl=calloc(1,sizeof(*sock->super.ssl));ssl_ptr=sock->super.ssl;
 sock->super.ssl->ossl=(void*)1;sock->super.ssl->output.bufs.size=1;
 uv_handle_t stream={sock};sock->uv.stream=&stream;sock->uv.close_cb=closed_stream;
 sock->super.on_close.cb=closed_socket;
 if(pending) sock->super._cb.write=dispose_socket;
 client->super.sock=&sock->super;client->super.ctx=(void*)1;client->_timeout.linked=1;
 h2o_http1client_cancel(&client->super);
 assert(client_dead);assert(!socket_dead);assert(!timer_entries);
 /* cttp no longer owns a client or timeout entry. Its own context ref may go;
    the delayed SSL still retains a separate reference (mock OpenSSL seam). */
 context_refs--;timeout_live=0;
 h2o_timeout_t timer={0};h2o_timeout_dispose(NULL,&timer);
 if(!pending && shutdown_result>=0) {
  assert(!ssl_dead);assert(context_refs==1);assert(!close_notifications);
  assert(flushes==1);on_do_write_complete(&sock->_wreq,status);
 }
 assert(ssl_dead);assert(!context_refs);assert(close_notifications==1);
 /* libuv may deliver an outstanding write after uv_close; actual binding
    must suppress its former callback before freeing socket storage. */
 int before=close_notifications;on_do_write_complete(&sock->_wreq,status);assert(close_notifications==before);
 assert(closes==2);assert(!socket_dead);assert(!stream_done);
 for(int i=0;i<closes;i++) if(close_callbacks[i]) close_callbacks[i](close_handles[i]);
 assert(socket_dead);assert(stream_done==1);return 0;
}
''')
        for result in (-1, 0, 1):
            for pending in (0, 1):
                for status in (0, -1):
                    with self.subTest(shutdown=result, pending=pending, write_status=status):
                        run = subprocess.run([str(probe), str(result), str(pending), str(status)], capture_output=True, text=True, timeout=5)
                        self.assertEqual(run.returncode, 0, run.stderr)

    def test_exact_source_receipts_and_stale_delivery_refusal(self):
        import importlib.util
        import json
        import tempfile
        import test_openssl_binary_verifier as binary
        recipe = allocation.RECIPE
        spec = importlib.util.spec_from_file_location('cttp_recipe', recipe / 'candidate.py')
        assert spec is not None and spec.loader is not None
        api = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(api)
        lock = json.loads((recipe / 'inputs.json').read_text())
        scratch = tempfile.TemporaryDirectory(prefix='issue3-cttp-exact-source-', dir=os.environ['TMPDIR'])
        self.addCleanup(scratch.cleanup)
        root = Path(scratch.name)
        names = ('pkg/vere/io/cttp.c', 'pkg/vere/io/http.c', 'pkg/vere/main.c', 'pkg/vere/vere.h')
        for name in names:
            target = root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes((Path(os.environ['ISSUE3_SOURCE_REVIEW']) / name).read_bytes())
        allocation_changes = api.apply_allocation_overlay(root, lock)
        ca_changes = api.apply_ca_overlay(root, lock)
        self.assertEqual(allocation_changes['pkg/vere/io/cttp.c'], ca_changes['pkg/vere/io/cttp.c'])
        receipts = {
            'allocation-overlay.json': dict(source_preimages={n: lock['source_preimages'][n] for n in allocation_changes}, source_changes=allocation_changes),
            'ca-overlay.json': dict(source_preimages=lock['ca_preimages'], source_changes=ca_changes),
        }
        for name, receipt in receipts.items():
            (root / name).write_text(json.dumps(receipt, indent=2) + '\n')
        print(json.dumps({'exact_source_receipts': str(root), 'source_changes': dict(allocation_changes, **ca_changes)}))
        # Only the executable/linkage and unrelated fixture source are synthetic.
        # The four source members and CA/allocation receipts below are exact.
        fx = binary.BinaryVerifierTests(methodName='test_valid_combined_candidate')
        self.addCleanup(fx.doCleanups)
        fx.setUp()
        for key in ('allocation_hardening', 'ca_hardening', 'ca_preimages'):
            fx.lock[key] = lock[key]
        for name in names:
            fx.changes[name] = (root / name).read_bytes()
            fx.receipt['source_changes'][name] = api.sha(fx.changes[name])
        for name, receipt in receipts.items():
            fx.write_json(fx.artifact / name, receipt)
        fx.sync_lock(); fx.sync_receipt(); fx.sync_archive()
        self.assertEqual(binary.verifier.verify(fx.attempt)['status'], 'PASS')
        client = 'pkg/vere/io/cttp.c'
        patched = fx.changes[client]
        fx.changes[client] = (Path(os.environ['ISSUE3_SOURCE_REVIEW']) / client).read_bytes()
        fx.sync_archive()
        with self.assertRaisesRegex(ValueError, 'archived changed-source'):
            binary.verifier.verify(fx.attempt)
        fx.changes[client] = patched
        fx.sync_archive()
        for name, receipt in receipts.items():
            path = fx.artifact / name
            path.unlink()
            with self.subTest(missing=name), self.assertRaisesRegex(ValueError, 'overlay receipt'):
                binary.verifier.verify(fx.attempt)
            stale = dict(receipt, source_changes=dict(receipt['source_changes'], **{client: lock['source_preimages'][client]}))
            fx.write_json(path, stale)
            with self.subTest(stale=name), self.assertRaisesRegex(ValueError, 'overlay receipt'):
                binary.verifier.verify(fx.attempt)
            fx.write_json(path, receipt)
        self.assertEqual(binary.verifier.verify(fx.attempt)['status'], 'PASS')


if __name__ == '__main__':
    unittest.main(verbosity=2)
