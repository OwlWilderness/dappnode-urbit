/* Included at the end of vere.h, after uv_loop_t is declared. */
#ifndef U3_OPENSSL_SHUTDOWN_H
#define U3_OPENSSL_SHUTDOWN_H
void u3_ssl_shutdown_hold(void);
void u3_ssl_shutdown_release(void);
void u3_ssl_shutdown_retire(void* value, void (*dispose)(void*));
void u3_ssl_shutdown_loom(void);
void u3_ssl_shutdown_request(int status);
int u3_ssl_shutdown_pending(void);
void u3_ssl_shutdown_worker(void);
/* This runner is a top-level entry only; never call from a loop callback. */
void u3_ssl_shutdown_run(uv_loop_t* loop);
int u3_ssl_shutdown_finish(void);
#endif
