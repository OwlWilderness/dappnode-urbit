#ifndef U3_ARENA_MEASURE_COLLECTOR_H
#define U3_ARENA_MEASURE_COLLECTOR_H
#include <stddef.h>
/* Explicit opt-in only: a dedicated, already-open regular public receipt file,
 * unique run/domain hashes and supervisor-assigned process generation/role.
 * Configure before startup, after daemon fork or worker exec, once per process.
 * Descriptor remains caller-owned; never share its offset with other writers.
 * No environment/argv/private state is read. No signal/callback/lock reentry.
 * fsync acknowledges record bytes, NOT directory durability or run provenance.
 * Controller must retain/read back each file and bind exact source/binary hashes.
 */
enum { U3_MEASURE_KING=1, U3_MEASURE_WORKER=2, U3_MEASURE_UTILITY=3 };
enum { U3_MEASURE_READY=1, U3_MEASURE_WARM_CRYPTO, U3_MEASURE_TLS,
       U3_MEASURE_CHURN, U3_MEASURE_STEADY, U3_MEASURE_PRE_DESTROY,
       U3_MEASURE_APPLICATION };
int u3_arena_measure_configure(int fd, const char *run_sha256,
                             const char *domain_sha256, size_t generation, int role);
/* Unconfigured hooks are no-ops returning 1, NOT evidence of collection.
 * Startup is idempotent; phases require startup; pre_destroy is terminal.
 * A write/fsync/snapshot failure poisons collection, never resets/retries it.
 * Hook status is evidence status only: never gate startup, user completion,
 * the real live-block check, arena destruction or backing teardown on this I/O.
 * Missing/undurable finals invalidate the trial, not application cleanup.
 * Snapshot after OPENSSL_cleanup, before live check/destroy, including leaks.
 */
int u3_arena_measure_startup(void);
int u3_arena_measure_phase(int phase);
int u3_arena_measure_destroyed(int success);
#endif
