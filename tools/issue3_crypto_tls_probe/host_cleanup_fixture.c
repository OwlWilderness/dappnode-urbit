/* HOST SYNTHETIC ORACLE ONLY. Tests insert actual probe.c main below.
 * No OpenSSL, TLS, cryptography, real arena, target objects or target archives.
 * Trace assertions characterize this mocked boundary, not library ownership.
 */
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define ARENA_BYTES ((size_t)134217728)
#define OPENSSL_INIT_NO_LOAD_CONFIG 1
#define TLS1_2_VERSION 12
#define TLS1_3_VERSION 13
static int scenario, injected, armed, failed_line;
static size_t allocations = 50;
static const char *fault = "none";
static void trace(char c) { fputc(c,stderr); }
static void *probe_malloc(size_t n, const char *s, int l) { (void)n; (void)s; (void)l; return NULL; }
static void *probe_realloc(void *p, size_t n, const char *s, int l) { (void)p; return probe_malloc(n,s,l); }
static void probe_free(void *p, const char *s, int l) { (void)p; (void)s; (void)l; }
static void at(const char *s) { if (!strcmp(s,fault)) armed = 1; }
static int u3_openssl_arena_init(size_t bytes) { trace('A'); return bytes == ARENA_BYTES && scenario != 1; }
static int CRYPTO_set_mem_functions(void *(*m)(size_t,const char*,int),
    void *(*r)(void*,size_t,const char*,int), void (*f)(void*,const char*,int)) {
  trace('R'); return m && r && f && scenario != 3;
}
static int OPENSSL_init_ssl(int flags, void *unused) { (void)flags; (void)unused; trace('I'); return scenario != 4; }
static int crypto_case(void) { trace('C'); if (strcmp(fault,"none")) injected = 1; return scenario != 7; }
static int tls_case(int version, int host, int root) { (void)version; (void)host; (void)root; return crypto_case(); }
static void OPENSSL_thread_stop(void) { trace('T'); }
static void OPENSSL_cleanup(void) { trace('O'); }
static size_t u3_openssl_arena_live_blocks(void) { trace('L'); return scenario == 2 ? 1 : 0; }
typedef struct { size_t peak_charged_bytes; } u3_openssl_arena_metrics;
static int u3_openssl_arena_snapshot(u3_openssl_arena_metrics *out) { trace('S'); out->peak_charged_bytes=4096; return scenario != 5; }
static int u3_openssl_arena_destroy(void) { trace('D'); return scenario != 6; }
#define main probe_main
int probe_main(int argc, char **argv);
/* MAIN_INSERT */
#undef main
int main(int argc, char **argv) {
  const char *setting = getenv("MOCK_SCENARIO");
  scenario = setting ? atoi(setting) : 0;
  return probe_main(argc,argv);
}
