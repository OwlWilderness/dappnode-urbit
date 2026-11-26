/* Extracted newt frame decoder/callbacks; libuv dispatch and noun consumer mocked. */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
typedef int c3_o,c3_i;
typedef char c3_c;
typedef unsigned char c3_y;
typedef uint64_t c3_d;
#define c3y 0
#define c3n 1
#define c3_malloc malloc
#define c3_free free
#define c3_min(a,b) ((a)<(b)?(a):(b))
#define UV_EOF (-4095)
typedef struct { void *data; } uv_stream_t, uv_timer_t, uv_handle_t;
typedef struct { char *base; size_t len; } uv_buf_t;
enum { u3_mess_head,u3_mess_tail };
typedef struct meat { struct meat *nex_u; c3_d len_d; c3_y hun_y[]; } u3_meat;
typedef struct { int sat_e;
 struct { c3_y hed_y[5],has_y; } hed_u;
 struct { c3_d has_d; u3_meat *met_u; } tal_u;
} u3_mess;
typedef void (*u3_moor_bail)(void*,ssize_t,const c3_c*);
typedef struct { uv_stream_t pyp_u; uv_timer_t tim_u; u3_mess mes_u;
 u3_meat *ext_u,*ent_u; int fag_w; void *ptr_v;
 c3_o (*pok_f)(void*,c3_d,c3_y*); u3_moor_bail bal_f;
} u3_moat;
static int deliveries,bails,closes;
static int uv_read_stop(uv_stream_t *s) { return 0; }
static const char *uv_strerror(int e) { return "mock-EOF"; }
static int uv_timer_start(uv_timer_t *t,void (*f)(uv_timer_t*),int a,int b) { assert(f); return 0; }
static void uv_close(uv_handle_t *h,void (*f)(uv_handle_t*)) { closes++; }
static void _moat_stop_cb(uv_handle_t *h) {}
static void bail(void *p,ssize_t e,const char *s) { assert(e==UV_EOF); bails++; }
static c3_o deliver(void *p,c3_d l,c3_y *b) { assert(l==4 && !memcmp(b,"okay",4)); deliveries++; return c3y; }
static void _newt_meat_next_cb(uv_timer_t *t);
#include "framing-bodies.h"
static const unsigned char frame[]={0,4,0,0,0,'o','k','a','y'};
static void feed(u3_moat *m,int start,int len) {
  uv_buf_t buf={malloc((size_t)len), (size_t)len}; assert(buf.base);
  memcpy(buf.base,frame+start,(size_t)len); _newt_read_cb((uv_stream_t*)m,len,&buf);
}
int main(int argc,char **argv) {
  assert(argc==2); int cut=atoi(argv[1]); assert(cut>=1 && cut<=9);
  u3_moat moat={0}; moat.pok_f=deliver; moat.bal_f=bail; moat.tim_u.data=&moat;
  feed(&moat,0,cut); assert(deliveries==(cut==9));
  uv_buf_t eof={malloc(1),1}; _newt_read_cb((uv_stream_t*)&moat,UV_EOF,&eof);
  assert(bails==1); u3_newt_moat_stop(&moat,0);
  assert(closes==2 && !moat.ext_u && !moat.ent_u && moat.mes_u.sat_e==u3_mess_head);
  if(cut<9) {
    /* Separate live-stream control: partial followed by remainder delivers once. */
    u3_moat live={0}; live.pok_f=deliver; live.bal_f=bail; live.tim_u.data=&live;
    feed(&live,0,cut); assert(!deliveries); feed(&live,cut,9-cut); assert(deliveries==1);
    u3_newt_moat_stop(&live,0);
    puts("partial -> no delivery; EOF -> bail; stop -> discard");
  } else puts("complete -> delivery; EOF -> bail");
  return 0;
}
