/* Included by main.c after _cert_store; globals are process-local and the
 * daemon fork precedes OpenSSL/arena startup. Worker processes enter via exec.
 * All these functions run on the owning event-loop thread. */
#include "completion.h"

static u3_ssl_completion _ssl_completion;
static int _ssl_loop_closed, _ssl_loom, _ssl_curl_ready, _ssl_worker_io;
static u3_mojo* _ssl_output;
static uv_shutdown_t _ssl_output_shutdown;

typedef struct _ssl_retired {
  void* value;
  void (*dispose)(void*);
  struct _ssl_retired* next;
} _ssl_retired;
static _ssl_retired* _ssl_retired_head;

static uintptr_t
_ssl_owner(void)
{
  return (uintptr_t)uv_os_getpid();
}

void
u3_ssl_shutdown_hold(void)
{
  if ( !u3_ssl_completion_hold(&_ssl_completion, _ssl_owner()) ) abort();
}

void
u3_ssl_shutdown_release(void)
{
  if ( !u3_ssl_completion_release(&_ssl_completion, _ssl_owner()) ) abort();
}

void
u3_ssl_shutdown_retire(void* value, void (*dispose)(void*))
{
  _ssl_retired* item;
  if ( _ssl_completion.phase > 1 ) abort();
  item = malloc(sizeof(*item));
  if ( !item ) abort();
  item->value = value;
  item->dispose = dispose;
  item->next = _ssl_retired_head;
  _ssl_retired_head = item;
}

void
u3_ssl_shutdown_loom(void)
{
  _ssl_loom = 1;
}

void
u3_ssl_shutdown_request(int status)
{
  if ( !u3_ssl_completion_request(&_ssl_completion, _ssl_owner(), status) ) {
    abort();
  }
}

int
u3_ssl_shutdown_pending(void)
{
  return _ssl_completion.phase != 0;
}

void
u3_ssl_shutdown_worker(void)
{
  if ( u3_ssl_shutdown_pending() ) return;
  u3_ssl_shutdown_loom();
  u3_ssl_shutdown_request(0);
  /* Stop admission, but do not dispose the currently-dispatched newt message.
   * _newt_meat_poke still owns it until this callback unwinds. */
  uv_read_stop((uv_stream_t*)&inn_u.pyp_u);
  uv_timer_stop(&inn_u.tim_u);
  uv_stop(u3_Host.lup_u);
}

static void
_ssl_io_closed(void* value, ssize_t status, const c3_c* message)
{
  (void)value; (void)status; (void)message;
}

static void
_ssl_output_done(uv_shutdown_t* req, int status)
{
  (void)req;
  if ( status ) _ssl_completion.status = 1;
  u3_mojo* output = _ssl_output;
  _ssl_output = 0;
  if ( output ) u3_newt_mojo_stop(output, _ssl_io_closed);
}

static void
_ssl_ref_handle(uv_handle_t* handle, void* ignored)
{
  (void)ignored;
  if ( !uv_is_closing(handle) ) uv_ref(handle);
}

void
u3_ssl_shutdown_run(uv_loop_t* loop)
{
  int status;
  if ( _ssl_loop_closed ) return;
  if ( !u3_ssl_shutdown_pending() ) uv_run(loop, UV_RUN_DEFAULT);
  if ( !u3_ssl_shutdown_pending() ) return;

  /* The application callback has returned; newt's active message is no longer
   * borrowed. Keep worker/eval stack storage live through all completions. */
  if ( 1 == _ssl_worker_io ) {
    _ssl_worker_io = 2;
    u3_newt_moat_stop(&inn_u, _ssl_io_closed);
    _ssl_output = &out_u;
  }
  if ( _ssl_output ) {
    u3_mojo* output = _ssl_output;
    if ( !uv_is_closing((uv_handle_t*)&output->pyp_u) ) {
      /* uv_shutdown completes only after pending writes. Do not cancel gifts. */
      status = uv_shutdown(&_ssl_output_shutdown,
                           (uv_stream_t*)&output->pyp_u, _ssl_output_done);
      if ( status ) {
        _ssl_completion.status = 1;
        u3_newt_mojo_stop(output, _ssl_io_closed);
        _ssl_output = 0;
      }
    }
  }

  while ( (status = uv_loop_close(loop)) == UV_EBUSY ) {
    /* Unref is not destruction. Preserve every driver's normal close callback,
     * and drive its pending work from here, never recursively from a callback. */
    uv_walk(loop, _ssl_ref_handle, 0);
    if ( !uv_loop_alive(loop) ) return; /* inactive orphan: no false certificate */
    uv_run(loop, UV_RUN_DEFAULT);
  }
  if ( !status ) {
    _ssl_loop_closed = 1;
    _ssl_output = 0;
  }
}

/* The H2O overlay exposes this destructor for its process-wide BIO_METHOD.
 * It is called only after all H2O socket close callbacks and TLS frees. */
extern void u3_h2o_openssl_shutdown(void);

static void
_ssl_consumers_cleanup(void* ignored)
{
  (void)ignored;
  while ( _ssl_retired_head ) {
    _ssl_retired* item = _ssl_retired_head;
    _ssl_retired_head = item->next;
    item->dispose(item->value);
    free(item);
  }
  if ( _ssl_curl_ready ) {
    _ssl_curl_ready = 0;
    curl_global_cleanup();
  }
  u3_h2o_openssl_shutdown();
  if ( _cert_store ) {
    sk_X509_INFO_pop_free(_cert_store, X509_INFO_free);
    _cert_store = 0;
  }
  u3K.ssl_curl_f = 0;
  u3K.ssl_x509_f = 0;
}

static void
_ssl_openssl_cleanup(void* ignored)
{
  (void)ignored;
  OPENSSL_cleanup();
}

static size_t
_ssl_live_blocks(void* ignored)
{
  (void)ignored;
#ifndef U3_URTH_MASS
  if ( _ssl_loom ) return u3_openssl_arena_live_blocks();
#endif
  return 0;
}

static int
_ssl_arena_destroy(void* ignored)
{
  (void)ignored;
#ifndef U3_URTH_MASS
  if ( _ssl_loom ) return u3_openssl_arena_destroy();
#endif
  return 1;
}

static void
_ssl_backing_stop(void* ignored)
{
  (void)ignored;
  if ( _ssl_loom ) {
    _ssl_loom = 0;
    u3m_stop();
  }
}

int
u3_ssl_shutdown_finish(void)
{
  const u3_ssl_completion_ops ops = {
    _ssl_consumers_cleanup, _ssl_openssl_cleanup, _ssl_live_blocks,
    _ssl_arena_destroy, _ssl_backing_stop, 0
  };
  if ( 1 != u3_ssl_completion_finish(&_ssl_completion, _ssl_owner(),
                                    _ssl_loop_closed, &ops) ) {
    /* Do not destroy storage underneath an uncompleted user or leaked block.
     * Caller retains its existing process-fatal failure disposition. */
    return 1;
  }
  return _ssl_completion.status;
}
