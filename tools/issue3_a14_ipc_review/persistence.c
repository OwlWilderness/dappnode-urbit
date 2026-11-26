/* Real extracted Vere bodies; LMDB, noun and libuv seams are mocked. */
#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef uint64_t c3_d;
typedef uint32_t c3_w;
typedef int c3_o;
typedef int c3_i;
typedef unsigned char c3_y;
typedef uint64_t u3_noun;
#define c3y 0
#define c3n 1
#define c3_free free
#define u3_assert assert
#define c3__sync 123
#define u3nt(a,b,c) ((u3_noun)((a)+(b)+(c)))
#define u3i_chub(a) (a)
typedef int MDB_env;
typedef int MDB_txn;
typedef int MDB_dbi;
typedef struct { size_t mv_size; void *mv_data; } MDB_val;
#define MDB_CREATE 1
#define MDB_INTEGERKEY 2
#define MDB_NOOVERWRITE 4
static int failure, committed, sends, saves, aborts, puts_seen, step;
static MDB_txn transaction;
static int mdb_txn_begin(MDB_env *e, void *p, int f, MDB_txn **t) {
  assert(!p && !f); *t=&transaction; step=1; return failure==1;
}
static int mdb_dbi_open(MDB_txn *t, const char *s, int f, MDB_dbi *d) {
  assert(step==1 && f==(MDB_CREATE|MDB_INTEGERKEY) && !strcmp(s,"EVENTS"));
  step=2; *d=1; return failure==2;
}
static void mdb_txn_abort(MDB_txn *t) { aborts++; }
static int mdb_put(MDB_txn *t, MDB_dbi d, MDB_val *k, MDB_val *v, int f) {
  assert(step==2 && f==MDB_NOOVERWRITE && *(c3_d*)k->mv_data==11+(c3_d)committed);
  assert(k->mv_size==sizeof(c3_d) && v->mv_size==1); puts_seen++; return failure==3;
}
static int mdb_txn_commit(MDB_txn *t) {
  assert(step==2 && puts_seen==1); step=3; if(failure==4) return 1;
  committed++; puts_seen=0; return 0;
}
static void mdb_logerror(FILE *f, c3_w r, const char *s) {}
typedef struct { void *data; } uv_work_t;
typedef struct feat { struct feat *nex_u; c3_d eve_d; c3_y *hun_y; } u3_feat;
typedef struct {
  c3_d dun_d;
  MDB_env *mdb_u;
  struct { c3_d eve_d; c3_w len_w; c3_o ret_o;
    void (*don_f)(void*,c3_d,c3_o); void *ptr_v; c3_y **byt_y; size_t *siz_i; } sav_u;
  struct { u3_feat *ext_u,*ent_u; } put_u;
} u3_disk;
enum { u3_gift_fact_e, u3_gift_rest_e };
enum { u3_mars_work_e, u3_mars_save_e, u3_mars_exit_e };
typedef struct gift { struct gift *nex_u; int sat_e; c3_d eve_d,len_d; c3_y *hun_y; } u3_gift;
typedef struct { u3_disk *log_u; void *out_u; c3_d dun_d; int sat_e,mug_l;
  struct { c3_d eve_d; } sav_u; void *sil_u;
  struct { u3_gift *ext_u,*ent_u; } gif_u;
} u3_mars;
static u3_disk disk;
static u3_mars mars;
static void u3_newt_send(void *o, c3_d l, c3_y *b) {
  /* A fact reply cannot be accepted before the mock transaction committed. */
  assert(disk.dun_d>=11+(c3_d)sends && committed>sends); sends++;
}
static void u3m_save(void) { assert(disk.dun_d==mars.dun_d); saves++; }
static void _mars_gift(u3_mars *m, u3_noun n) {}
static void u3_disk_exit(u3_disk *d) {}
static void u3s_cue_xeno_done(void *p) {}
static void u3t_trace_close(void) {}
static void _mars_damp_file(void) {}
static void u3m_stop(void) {}
#include "persistence-bodies.h"
static u3_gift *gift(int sat, c3_d eve) {
  u3_gift *g=calloc(1,sizeof(*g)); assert(g); g->sat_e=sat; g->eve_d=eve; return g;
}
static void failure_oracle(void) { assert(disk.dun_d==10 && sends==0); }
int main(int argc,char **argv) {
  assert(argc>=2); disk.dun_d=10; mars.log_u=&disk; mars.dun_d=12;
  u3_gift *a=gift(u3_gift_fact_e,11), *b=gift(u3_gift_fact_e,12), *r=gift(u3_gift_rest_e,0);
  a->nex_u=b; b->nex_u=r; mars.gif_u.ext_u=a; mars.gif_u.ent_u=r;
  if(!strcmp(argv[1],"prefix")) {
    _mars_flush(&mars); assert(sends==0 && mars.gif_u.ext_u==a);
    committed=1; disk.dun_d=11; _mars_flush(&mars);
    assert(sends==1 && mars.gif_u.ext_u==b && b->nex_u==r);
    free(b); free(r);
    puts("committed prefix only; rest behind blocked fact stays queued"); return 0;
  }
  assert(argc==3); failure=atoi(argv[2]);
  /* Two facts only for the commit test; the rest-message seam is not an ACK. */
  b->nex_u=0; free(r); mars.gif_u.ent_u=b;
  mars.sat_e=u3_mars_save_e; disk.sav_u.eve_d=11; disk.sav_u.len_w=1;
  disk.sav_u.ptr_v=&mars; disk.sav_u.don_f=_mars_disk_cb;
  unsigned char byte=1,*bytes[]={&byte}; size_t sizes[]={1};
  disk.sav_u.byt_y=bytes; disk.sav_u.siz_i=sizes;
  uv_work_t work={&disk};
  if(failure) assert(!atexit(failure_oracle));
  _disk_commit_cb(&work); _disk_commit_done(&disk);
  assert(!failure && committed==1 && sends==1 && saves==0 && disk.dun_d==11);
  disk.sav_u.eve_d=12;
  _disk_commit_cb(&work); _disk_commit_done(&disk);
  assert(committed==2 && sends==2 && saves==1 && disk.dun_d==12 && !mars.gif_u.ext_u);
  puts("commit -> durable counter -> reply; snapshot waits for full prefix"); return 0;
}
