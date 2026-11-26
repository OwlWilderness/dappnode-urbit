#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#ifndef ISSUE3_MARS_PROBE_UV_TYPES
typedef struct {int initialized, active, closing;void *data;} uv_handle_t;
typedef uv_handle_t uv_timer_t;
static int uv_timer_stop(uv_timer_t *p) {p->active=0;return 0;}
static void uv_close(uv_handle_t *p,void (*cb)(uv_handle_t*)) {
  p->closing=1;p->active=0;(void)cb;
}
static void _mars_sign_close(void) {}
#endif
typedef unsigned long long c3_d;
typedef unsigned long long u3_noun;
#define c3y 0
#define c3n 1
#define c3__sync 1
typedef struct gift {int sat_e;c3_d eve_d,len_d;void *hun_y;struct gift *nex_u;} u3_gift;
typedef struct {c3_d dun_d;struct {int ted_o;} sav_u;} probe_disk;
typedef struct {
 struct {u3_gift *ext_u,*ent_u;} gif_u;
 int sat_e;c3_d dun_d;probe_disk *log_u;
 struct {c3_d eve_d;uv_timer_t tim_u;} sav_u;void *out_u,*sil_u;int mug_l;
} u3_mars;
enum {u3_gift_rest_e=1,u3_mars_work_e=2,u3_mars_save_e=3,u3_mars_exit_e=4};
static int saves,disks,cues,traces,dumps,requested;
static void u3_newt_send(void*p,c3_d n,void*b) {(void)p;(void)n;(void)b;}
#define c3_free free
static void u3m_save(void) {saves++;}
static u3_noun u3i_chub(c3_d n) {return n;}
static u3_noun u3nt(int a,u3_noun b,int c) {return a+b+c;}
static void _mars_gift(u3_mars*m,u3_noun n) {(void)m;(void)n;}
static void u3_disk_exit(probe_disk *p) {(void)p;disks++;}
static void u3s_cue_xeno_done(void*p) {(void)p;cues++;}
static void u3t_trace_close(void) {traces++;}
static void _mars_damp_file(void) {dumps++;}
static void u3m_stop(void) {_Exit(61);}
static int u3_ssl_shutdown_pending(void) {return requested;}
static void u3_ssl_shutdown_worker(void) {requested=1;}
static void *retired;
static void (*dispose)(void*);
static void u3_ssl_shutdown_retire(void *p,void (*f)(void*)) {retired=p;dispose=f;}
/* EXTRACTED */
typedef int c3_i;
typedef struct {void *data;} uv_work_t;
#define u3_disk probe_disk
#define UV_ECANCELED (-125)
static u3_mars *active_mars;
static void _disk_commit_done(probe_disk *p) {(void)p;_mars_flush(active_mars);assert(!disks);}
static void _disk_commit(probe_disk *p) {(void)p;assert(!disks);}
/* DISK_CALLBACK */
int main(void) {
 (void)u3m_stop;(void)u3_ssl_shutdown_pending;(void)u3_ssl_shutdown_worker;(void)u3_ssl_shutdown_retire;
 (void)uv_timer_stop;(void)uv_close;(void)_mars_sign_close;
 probe_disk disk={.dun_d=5};u3_mars m={.sat_e=u3_mars_exit_e,.dun_d=5,.log_u=&disk};
 active_mars=&m;uv_work_t work={&disk};
 _disk_commit_after_cb(&work,0);assert(requested);
 /* _disk_commit_done/_disk_commit_after_cb continue using log_u after their
  * mars notification returns. The actual source callback is composed below. */
 assert(saves==1&&disks==0&&cues==1&&traces==1&&dumps==1);
 _mars_flush(&m);assert(saves==1&&disks==0);
 assert(retired==&disk&&dispose);dispose(retired);assert(disks==1);
 puts("mars:normal-frees;request;callback-return;no-reentrant-drain");
}
