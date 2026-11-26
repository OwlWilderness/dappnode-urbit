#ifndef U3_OPENSSL_OWNED_ARENA_H
#define U3_OPENSSL_OWNED_ARENA_H
#include <stddef.h>
/* Explicit total mapping bound in bytes (including allocator metadata).
 * init refuses an already initialized arena. Call before OpenSSL registration.
 * All entrypoints serialize; not async-signal-safe, not fork/longjmp recovery.
 * destroy refuses outstanding blocks; caller must also quiesce every consumer.
 * malloc(0) returns NULL; free(NULL) is a no-op. Invalid pointers are fatal.
 */
int u3_openssl_arena_init(size_t bytes);
void *u3_openssl_arena_malloc(size_t, const char *, int);
void *u3_openssl_arena_realloc(void *, size_t, const char *, int);
void u3_openssl_arena_free(void *, const char *, int);
size_t u3_openssl_arena_live_blocks(void);
/* Page-granular conservative occupancy charge, NOT RSS or requested bytes.
 * Includes full fixed prefix, anchor, and every engine-owned data/chunk page,
 * including spare chunk slots and internal metadata. Peak includes transient
 * realloc overlap and staged pages later rolled back on allocation failure.
 * Snapshot is coherent under the owner mutex; no allocation, logging or reset.
 * Failures count each nonzero public malloc/realloc returning NULL while
 * initialized, including oversize requests; saturates at SIZE_MAX. Zero-size
 * calls, init refusal and internal staged attempts are not separate failures.
 * Returns 0 for NULL output/uninitialized arena (output untouched). Destroy
 * clears metrics: collect after OpenSSL cleanup and BEFORE successful destroy.
 */
typedef struct {
  size_t schema_version, capacity_bytes, charged_bytes, peak_charged_bytes;
  size_t live_blocks, allocation_failures;
} u3_openssl_arena_metrics;
int u3_openssl_arena_snapshot(u3_openssl_arena_metrics *out);
int u3_openssl_arena_destroy(void);
#endif
