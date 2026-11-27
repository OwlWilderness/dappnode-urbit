"""Host allocator metrics only; no OpenSSL/Vere or workload measurement."""
import resource
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / 'tools/issue3_openssl_owned_arena'
SCRATCH = Path('/tmp')


class ArenaMetricsTests(unittest.TestCase):
    def run_c(self, body, *, internal=False):
        with tempfile.TemporaryDirectory(prefix='issue3-arena-metrics-', dir=SCRATCH) as directory:
            directory = Path(directory)
            for name in ('openssl_owned_arena.c', 'openssl_owned_arena.h', 'palloc_engine.inc'):
                data = (TOOLS / name).read_text()
                control = os.environ.get('ISSUE3_ARENA_METRICS_CONTROL')
                if control == 'no-peak' and name.endswith('.c'):
                    data = data.replace('owner.peak_charged = owner.charged;', '(void)0;')
                elif control == 'no-release' and name.endswith('.c'):
                    data = data.replace('owner.charged -= bytes;', '(void)bytes;')
                elif control not in (None, 'no-peak', 'no-release'):
                    raise ValueError('unknown control')
                (directory / name).write_text(data)
            source = directory / 'probe.c'
            source.write_text(('''#include "openssl_owned_arena.c"
''' if internal else '') + '''#include "openssl_owned_arena.h"
#include <assert.h>
#include <stdint.h>
#define M(n) u3_openssl_arena_malloc((n),0,0)
#define R(p,n) u3_openssl_arena_realloc((p),(n),0,0)
#define F(p) u3_openssl_arena_free((p),0,0)
''' + body)
            binary = directory / 'probe'
            result = subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror',
                                     '-pthread', '-fsanitize=address,undefined',
                                     '-I', str(directory), str(source),
                                     *([] if internal else [str(directory / 'openssl_owned_arena.c')]),
                                     '-o', str(binary)],
                                    capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            result = subprocess.run([str(binary)], capture_output=True, text=True, timeout=20,
                                    cwd=directory,
                                    preexec_fn=lambda: resource.setrlimit(resource.RLIMIT_CORE, (0, 0)))
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_page_charge_includes_prefix_anchor_and_internal_realloc_overlap(self):
        self.run_c('''
int main(void) {
  u3_openssl_arena_metrics a,b,c;
  assert(!u3_openssl_arena_snapshot(&a));
  assert(!u3_openssl_arena_snapshot(0));
  assert(u3_openssl_arena_init(2*1024*1024));
  assert(u3_openssl_arena_snapshot(&a));
  assert(a.schema_version==1 && a.capacity_bytes==2*1024*1024);
  assert(a.charged_bytes==4*16384 && a.peak_charged_bytes==a.charged_bytes);
  assert(!a.live_blocks && !a.allocation_failures);
  void *p=M(3*16384-32); assert(p);
  assert(u3_openssl_arena_snapshot(&b));
  assert(b.charged_bytes==a.charged_bytes+3*16384 && b.live_blocks==1);
  p=R(p,4*16384-32); assert(p);
  assert(u3_openssl_arena_snapshot(&c));
  assert(c.charged_bytes==a.charged_bytes+4*16384 && c.live_blocks==1);
  /* New storage is allocated before old storage is freed, inside _irealloc. */
  assert(c.peak_charged_bytes==a.charged_bytes+7*16384);
  F(p); assert(u3_openssl_arena_snapshot(&c));
  assert(c.charged_bytes==a.charged_bytes && !c.live_blocks);
  assert(c.peak_charged_bytes==a.charged_bytes+7*16384);
  assert(u3_openssl_arena_destroy());
  assert(!u3_openssl_arena_snapshot(&a));
  assert(u3_openssl_arena_init(128*1024));
  assert(u3_openssl_arena_snapshot(&a));
  assert(a.peak_charged_bytes==4*16384 && !a.allocation_failures);
  assert(u3_openssl_arena_destroy());
  return 0;
}
''')


    def test_directory_oracle_matches_charge_through_mixed_reuse_and_resize(self):
        self.run_c('''
static void check(void) {
  u3_openssl_arena_metrics s;
  assert(u3_openssl_arena_snapshot(&s));
  size_t occupied=0;
  for (c3_w i=0;i<HEAP.len_w;++i)
    if (u3to(u3_post,HEAP.pag_p)[i] != u3a_free_pg) ++occupied;
  size_t expected=(size_t)BASE*4+occupied*PAGE_BYTES;
  assert(s.charged_bytes==expected);
  assert(s.charged_bytes<=s.peak_charged_bytes && s.peak_charged_bytes<=s.capacity_bytes);
}
int main(void) {
  void *p[64]={0};
  assert(u3_openssl_arena_init(2*1024*1024)); check();
  for (size_t turn=0;turn<2000;++turn) {
    size_t i=(turn*17)%64, n=1+(turn*7919)%100000;
    if (turn%3==0) { F(p[i]); p[i]=0; }
    else { void *q=R(p[i],n); if(q) p[i]=q; }
    check();
  }
  for(size_t i=0;i<64;++i) { F(p[i]); check(); }
  assert(!u3_openssl_arena_live_blocks());
  assert(u3_openssl_arena_destroy());
  return 0;
}
''', internal=True)

    def test_contending_snapshots_remain_coherent(self):
        self.run_c('''
#include <pthread.h>
static void *worker(void *unused) {
  (void)unused;
  for (size_t i=0;i<500;++i) {
    void *p=M(1+(i*37)%12000); assert(p);
    void *q=R(p,1+(i*53)%20000); assert(q); F(q);
  }
  return 0;
}
int main(void) {
  pthread_t threads[4];
  assert(u3_openssl_arena_init(2*1024*1024));
  for(size_t i=0;i<4;++i) assert(!pthread_create(&threads[i],0,worker,0));
  for(size_t i=0;i<2000;++i) {
    u3_openssl_arena_metrics s;
    assert(u3_openssl_arena_snapshot(&s));
    assert(s.charged_bytes>=4*16384 && s.charged_bytes%16384==0);
    assert(s.charged_bytes<=s.peak_charged_bytes && s.peak_charged_bytes<=s.capacity_bytes);
    assert(!s.allocation_failures);
  }
  for(size_t i=0;i<4;++i) assert(!pthread_join(threads[i],0));
  u3_openssl_arena_metrics s; assert(u3_openssl_arena_snapshot(&s));
  assert(!s.live_blocks && !s.allocation_failures);
  assert(u3_openssl_arena_destroy()); return 0;
}
''')

    def test_oom_counts_public_failures_and_preserves_rollback_peak(self):
        self.run_c('''
int main(void) {
  u3_openssl_arena_metrics a,b;
  assert(u3_openssl_arena_init(128*1024));
  void *p=M(2*16384); assert(p);
  assert(u3_openssl_arena_snapshot(&a));
  assert(a.charged_bytes==7*16384);
  /* One staged chunk page fits, but its out-of-line metadata cannot. */
  assert(!M(4000));
  assert(u3_openssl_arena_snapshot(&b));
  assert(b.charged_bytes==a.charged_bytes && b.peak_charged_bytes==8*16384);
  assert(b.allocation_failures==1 && b.live_blocks==1);
  assert(!R(p,1024*1024));
  assert(!M(SIZE_MAX) && !R(p,SIZE_MAX));
  assert(!M(0) && !R(0,0)); F(0);
  assert(u3_openssl_arena_snapshot(&b));
  assert(b.allocation_failures==4 && b.charged_bytes==a.charged_bytes);
  assert(b.live_blocks==1 && !u3_openssl_arena_destroy());
  assert(!R(p,0));
  assert(u3_openssl_arena_snapshot(&b));
  assert(!b.live_blocks && b.charged_bytes==4*16384 && b.allocation_failures==4);
  assert(u3_openssl_arena_destroy());
  return 0;
}
''')


if __name__ == '__main__':
    unittest.main()
