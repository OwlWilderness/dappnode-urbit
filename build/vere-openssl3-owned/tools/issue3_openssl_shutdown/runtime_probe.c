/* Mocked loop/library seams around the exact runtime include, not libuv/SSL. */
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
typedef char c3_c;
typedef struct {int closing,ref;void *data;} uv_handle_t;
typedef uv_handle_t uv_stream_t;
typedef uv_handle_t uv_shutdown_t;
typedef uv_handle_t uv_timer_t;
typedef struct {int unused;} uv_loop_t;
typedef struct {uv_handle_t pyp_u,tim_u;} u3_moat;
typedef struct {uv_handle_t pyp_u;} u3_mojo;
#include "openssl_owned_arena.h"
#include "openssl_shutdown.h"

static u3_moat inn_u; static u3_mojo out_u;
static uv_loop_t loop;
static struct {uv_loop_t *lup_u;} u3_Host={&loop};
static struct {void (*ssl_curl_f)(void*);int (*ssl_x509_f)(void*);} u3K;
static void *_cert_store;
static int in_callback,queued=1,blocks=3,cleaned,destroyed,backing,retired,curl,ca,method;
static uv_handle_t handle;
#define UV_RUN_DEFAULT 0
#define UV_EBUSY (-16)
static int uv_os_getpid(void) {return 123;}
static int uv_is_closing(uv_handle_t *p) {return p->closing;}
static void uv_ref(uv_handle_t *p) {p->ref=1;}
static int uv_read_stop(uv_stream_t *p) {(void)p;return 0;}
static int uv_timer_stop(uv_timer_t *p) {(void)p;return 0;}
static void uv_stop(uv_loop_t *p) {(void)p;assert(in_callback);}
static void u3_newt_moat_stop(u3_moat *p,void (*cb)(void*,ssize_t,const char*)) {(void)p;(void)cb;}
static void u3_newt_mojo_stop(u3_mojo *p,void (*cb)(void*,ssize_t,const char*)) {(void)p;(void)cb;}
static int uv_shutdown(uv_shutdown_t *p,uv_stream_t *s,void (*cb)(uv_shutdown_t*,int)) {(void)p;(void)s;(void)cb;return 0;}
static void uv_walk(uv_loop_t *p,void (*cb)(uv_handle_t*,void*),void *v) {(void)p;cb(&handle,v);}
static int uv_loop_alive(uv_loop_t *p) {(void)p;return queued;}
static int uv_loop_close(uv_loop_t *p) {(void)p;assert(!in_callback);return queued?UV_EBUSY:0;}
void u3_ssl_shutdown_release(void);
static int uv_run(uv_loop_t *p,int mode) {
 (void)p;(void)mode;assert(!in_callback);assert(queued);in_callback=1;
 /* Modeled TLS close callback does its normal free before releasing lease. */
 blocks--;u3_ssl_shutdown_release();queued=0;in_callback=0;return 0;
}
static void curl_global_cleanup(void) {assert(!queued&&!in_callback);curl++;}
static void X509_INFO_free(void *p) {(void)p;}
static void sk_X509_INFO_pop_free(void *p,void (*f)(void*)) {(void)p;(void)f;ca++;blocks--;}
void u3_h2o_openssl_shutdown(void) {method++;blocks--;}
static void OPENSSL_cleanup(void) {assert(curl==1&&ca==1&&method==1&&retired==1);cleaned++;assert(!blocks);}
size_t u3_openssl_arena_live_blocks(void) {assert(cleaned==1);return (size_t)blocks;}
int u3_openssl_arena_destroy(void) {assert(cleaned==1&&!blocks);destroyed++;return 1;}
static void u3m_stop(void) {assert(cleaned==1&&destroyed==1);backing++;}
#include "runtime.inc"
static void dispose(void *p) {(void)p;assert(!queued);retired++;}
int main(void) {
 _ssl_loom=1;_ssl_curl_ready=1;_cert_store=(void*)1;
 u3_ssl_shutdown_hold();u3_ssl_shutdown_retire((void*)1,dispose);
 u3_ssl_shutdown_request(0);assert(u3_ssl_shutdown_finish()==1);assert(!cleaned);
 u3_ssl_shutdown_run(&loop);assert(!cleaned&&_ssl_loop_closed);
 assert(u3_ssl_shutdown_finish()==0);assert(cleaned==1&&destroyed==1&&backing==1);
 assert(u3_ssl_shutdown_finish()==0);assert(cleaned==1&&destroyed==1&&backing==1);
 puts("outer-loop;consumer-completion;curl-ca-h2o;openssl;arena;backing;once");
}
