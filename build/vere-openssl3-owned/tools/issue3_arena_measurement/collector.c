#include "collector.h"
#include "openssl_owned_arena.h"
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static _Atomic pid_t pid;
static int configured, poisoned, state, output_fd, process_role;
static size_t sequence, generation;
static char run_hash[65], domain_hash[65];
static u3_openssl_arena_metrics last;

static int hex_hash(const char *s) {
  if (!s) return 0;
  for (size_t i=0;i<64;i++)
    if (!s[i] || !((s[i]>='0' && s[i]<='9') || (s[i]>='a' && s[i]<='f'))) return 0;
  return !s[64];
}
static int enter(void) {
  pid_t current=getpid(), empty=0;
  atomic_compare_exchange_strong(&pid,&empty,current);
  /* Do not touch an inherited mutex after fork. No fork recovery is claimed. */
  return atomic_load(&pid)==current && !pthread_mutex_lock(&lock);
}
static int leave(int result) {
  return !pthread_mutex_unlock(&lock) && result;
}
int u3_arena_measure_configure(int fd,const char *run,const char *domain,size_t gen,int role) {
  struct stat st;
  if (fd<0 || !gen || role<1 || role>3 || !hex_hash(run) || !hex_hash(domain)
      || fstat(fd,&st) || !S_ISREG(st.st_mode)) return 0;
  if (!enter()) return 0;
  if (configured || state) return leave(0);
  memcpy(run_hash,run,65);memcpy(domain_hash,domain,65);
  output_fd=fd;generation=gen;process_role=role;configured=1;
  return leave(1);
}
static int emit(const char *phase,int snapshot) {
  char buffer[1024];
  if (poisoned || sequence==SIZE_MAX) return 0;
  if (snapshot && !u3_openssl_arena_snapshot(&last)) {poisoned=1;return 0;}
  int n=snprintf(buffer,sizeof buffer,
    "{\"schema_version\":1,\"run_sha256\":\"%s\",\"domain_sha256\":\"%s\","
    "\"generation\":%zu,\"role\":%d,\"sequence\":%zu,\"phase\":\"%s\","
    "\"capacity_bytes\":%zu,\"charged_bytes\":%zu,\"peak_charged_bytes\":%zu,"
    "\"live_blocks\":%zu,\"allocation_failures\":%zu}\n",
    run_hash,domain_hash,generation,process_role,sequence+1,phase,
    last.capacity_bytes,last.charged_bytes,last.peak_charged_bytes,
    last.live_blocks,last.allocation_failures);
  if (n<0 || (size_t)n>=sizeof buffer) {poisoned=1;return 0;}
  size_t offset=0;
  while (offset<(size_t)n) {
    ssize_t done=write(output_fd,buffer+offset,(size_t)n-offset);
    if (done<0 && errno==EINTR) continue;
    if (done<=0) {poisoned=1;return 0;}
    offset+=(size_t)done;
  }
  if (fsync(output_fd)) {poisoned=1;return 0;}
  ++sequence;return 1;
}
int u3_arena_measure_startup(void) {
  /* No identity/mutex state until explicit opt-in; silent even across fork. */
  if (!atomic_load(&pid)) return 1;
  if (!enter()) return 0;
  if (!configured) return leave(1);
  if (poisoned || state>1) return leave(0);
  if (state==1) return leave(1);
  int ok=emit("startup",1);if(ok) state=1;
  return leave(ok);
}
int u3_arena_measure_phase(int phase) {
  static const char *names[]={"", "ready", "warm_crypto", "tls", "churn", "steady", "pre_destroy", "application"};
  if (!atomic_load(&pid)) return 1;
  if (!enter()) return 0;
  if (!configured) return leave(1);
  if (state!=1 || phase<1 || phase>7) return leave(0);
  int ok=emit(names[phase],1);if(ok && phase==6) state=2;
  return leave(ok);
}
int u3_arena_measure_destroyed(int success) {
  if (!atomic_load(&pid)) return 1;
  if (!enter()) return 0;
  if (!configured) return leave(1);
  if (state!=2) return leave(0);
  int ok=emit(success ? "destroyed" : "destroy_refused",0);
  if(ok) state=3;
  return leave(ok);
}
