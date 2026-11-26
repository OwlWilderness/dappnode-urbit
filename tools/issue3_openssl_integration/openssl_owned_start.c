/* Early, one-time registration for the process-owned palloc adaptation.
 * Capacity is supplied explicitly when composing this source candidate.
 * Fork before initialization is permitted; post-initialization fork reentry
 * refuses before touching a possibly inherited locked mutex. This is not
 * post-fork OpenSSL/library recovery or permission to fork active TLS users.
 */
#include "openssl_owned_start.h"
#include "openssl_owned_arena.h"
#include "openssl_owned_config.h"
#include <openssl/crypto.h>
#include <pthread.h>
#include <stdatomic.h>
#include <sys/types.h>
#include <unistd.h>

static _Atomic pid_t start_pid;
static pthread_mutex_t start_lock = PTHREAD_MUTEX_INITIALIZER;
static int start_state;

int
u3_openssl_owned_start(void)
{
  pid_t current = getpid(), empty = 0;
  int result = 0;
  atomic_compare_exchange_strong(&start_pid, &empty, current);
  if ( atomic_load(&start_pid) != current ) return 0;
  if ( pthread_mutex_lock(&start_lock) ) return 0;
  if ( !start_state ) {
    start_state = -1; /* an initialization refusal is terminal, not a retry */
    if ( u3_openssl_arena_init(U3_OPENSSL_ARENA_BYTES) ) {
      if ( CRYPTO_set_mem_functions(u3_openssl_arena_malloc,
                                    u3_openssl_arena_realloc,
                                    u3_openssl_arena_free) ) {
        start_state = 1;
      }
      else {
        /* No owned callback was published; never affect previous allocations. */
        (void)u3_openssl_arena_destroy();
      }
    }
  }
  result = start_state == 1;
  if ( pthread_mutex_unlock(&start_lock) ) return 0;
  return result;
}

int
u3_openssl_owned_seal(void)
{
  pid_t current = getpid(), empty = 0;
  atomic_compare_exchange_strong(&start_pid, &empty, current);
  if ( atomic_load(&start_pid) != current ) return 0;
  if ( pthread_mutex_lock(&start_lock) ) return 0;
  start_state = 2;
  return !pthread_mutex_unlock(&start_lock);
}
