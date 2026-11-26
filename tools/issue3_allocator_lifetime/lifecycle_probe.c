/* Host-only boundary model. Production bodies arrive via extracted.h.
 * This does not link OpenSSL or run Vere, and does not model actual loom pages.
 */
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifndef OPENSSL_VERSION_NUMBER
#define OPENSSL_VERSION_NUMBER 0x30500090L
#endif
static unsigned _cm_ssl_state;
static int registrations, allocations, resizes, frees, secp_inits, secp_stops;
static int cleanup_count, storage_stops, storage_live = 1, registration_ok = 1;
static int consumers;
static const char* mode;
static void* (*mem_malloc)(size_t, const char*, int);
static void* (*mem_realloc)(void*, size_t, const char*, int);
static void (*mem_free)(void*, const char*, int);
void* u3a_malloc(size_t n) { ++allocations; return malloc(n); }
void* u3a_realloc(void* p, size_t n) { ++resizes; return realloc(p, n); }
void u3a_free(void* p) { ++frees; free(p); }
void u3je_secp_init(void) { ++secp_inits; }
void u3je_secp_stop(void) { ++secp_stops; }
void u3t_sstack_exit(void) {}
void u3l_log(const char* format, ...) { (void)format; }
int CRYPTO_set_mem_functions(void* (*m)(size_t, const char*, int),
                             void* (*r)(void*, size_t, const char*, int),
                             void (*f)(void*, const char*, int)) {
  ++registrations;
  if (!registration_ok) return 0;
  mem_malloc=m; mem_realloc=r; mem_free=f;
  return 1;
}
static _Noreturn void probe_abort(void) {
  if (!registration_ok && secp_inits) exit(76);
  if (strcmp(mode, "restart") == 0 && registrations != 1) exit(77);
  if (strcmp(mode, "repeat-init") == 0 && registrations != 1) exit(78);
  puts("refused-before-reinit");
  exit(71);
}
#define abort probe_abort
void OPENSSL_cleanup(void) {
  /* Detect, do not bless, a global teardown while a modeled user is live. */
  if (consumers) { puts("unsafe-live-consumer"); exit(84); }
  if (!storage_live) exit(62);
  ++cleanup_count;
}
#ifdef PROBE_CALLER_CHECK
void probe_caller_check(void);
#endif
void u3e_stop(void) {
  /* A hypothetical boundary that makes outstanding callbacks unusable.
   * Real u3e_stop is NOT asserted to unmap or discard the entire loom.
   */
  if (cleanup_count != 1) exit(61);
#ifdef PROBE_CALLER_CHECK
  probe_caller_check();
#endif
  ++storage_stops;
  storage_live = 0;
}
#include "extracted.h"

int main(int argc, char** argv) {
  mode = argc > 1 ? argv[1] : "repeat-stop";
  (void)_cm_ssl_state;
  (void)probe_abort;
  (void)_cm_malloc_ssl; (void)_cm_realloc_ssl; (void)_cm_free_ssl;
  if (strcmp(mode, "cold-stop") == 0) {
    u3m_stop();
    if (cleanup_count || storage_stops || secp_stops) return 79;
    puts("cold-stop-noop"); return 0;
  }
  if (strcmp(mode, "registration-failure") == 0) registration_ok = 0;
  _cm_crypto();
  if (strcmp(mode, "registration-failure") == 0) return 80;
  if (strcmp(mode, "repeat-init") == 0) { _cm_crypto(); return 81; }
  if (strcmp(mode, "live-consumer") == 0) consumers = 1;
  u3m_stop();
  if (strcmp(mode, "restart") == 0) { _cm_crypto(); return 82; }
  u3m_stop();
  if (cleanup_count != 1 || storage_stops != 1 || secp_stops != 1) return 83;
  puts("one-shot-cleanup-and-storage-stop");
  return 0;
}
