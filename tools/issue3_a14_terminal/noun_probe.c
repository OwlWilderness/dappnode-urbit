/* Host-only noun/deep-handler composition. Actual functions in extracted.h;
 * road allocation, tracing, timer, libsigsegv installation and nouns are mocks.
 * Real signal() / raise(), _setjmp / _longjmp, sigsetjmp / siglongjmp. */
#define _DARWIN_C_SOURCE 1
#define _POSIX_C_SOURCE 200809L
#include <assert.h>
#include <errno.h>
#include <setjmp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>
typedef unsigned c3_l, c3_w, u3_noun;
typedef int c3_i;
typedef char c3_c;
typedef u3_noun (*u3_funk)(u3_noun);
enum { c3__over=10, c3__intr=11, c3__term=12, c3__alrm=13,
       c3__evil=14, c3__exit=15, c3__foul=16, c3__oops=17, u3_none=99,
       u3o_debug_ram=1 };
typedef struct { unsigned off_w, fow_w; } spin;
static spin spin_store;
static spin *u3t_Spin=&spin_store;
typedef struct {
    unsigned kid_p, off_w, fow_w;
    struct { u3_noun mer, tax; } bug;
    struct { jmp_buf buf; } esc;
} road;
typedef struct { road rod_u; } home_t;
static home_t home;
static road child;
static home_t *u3H=&home;
static road *u3R=&home.rod_u;
static struct { void (*sign_hold_f)(void); void (*sign_move_f)(void); unsigned wag_w; } u3C;
static sigjmp_buf u3_Signal;
static unsigned u3m_Ford_fresh_road_depth_w;
static int installed, deinstalled, held, moved, booted, boffed, released, arg_freed;
static int injection=-1, selected_bail;
static char Sigstk[65536];
#ifndef SIGSTKSZ
#define SIGSTKSZ 32768
#endif
#define u3_assert assert
#define _(x) (x)
#define u3ud(x) ((x)<1000)
#define u3a_is_cat(x) ((x)<1000)
#define u3h(x) ((void)(x),1)
#define rsignal_longjmp siglongjmp
#define rsignal_setjmp(buf) sigsetjmp((buf),1)
#ifndef timerclear
#define timerclear(x) memset((x),0,sizeof(*(x)))
#endif
#define u3l_log(...) assert(0)
typedef void *stackoverflow_context_t;
static void (*overflow_handler)(int,stackoverflow_context_t);
static int stackoverflow_install_handler(void (*f)(int,stackoverflow_context_t), void *s, size_t n) {
    assert(s && n); overflow_handler=f;
    if (injection==3) f(0,NULL);
    return 0;
}
static void stackoverflow_deinstall_handler(void) { overflow_handler=NULL; }
static void sigsegv_leave_handler(void (*f)(void *,void *,void *), void *a, void *b, void *c) __attribute__((unused));
static void sigsegv_leave_handler(void (*f)(void *,void *,void *), void *a, void *b, void *c) {
    assert(write(1,"overflow-recovery\n",18)==18); f(a,b,c);
}
static void _cm_emergency(const char *s,c3_l tag) __attribute__((unused));
static void _cm_emergency(const char *s,c3_l tag) { (void)s; (void)tag; }
static void install(int sig, void (*handler)(int)) {
    assert(signal(sig,handler)!=SIG_ERR); installed++;
    int signals[]={SIGINT,SIGTERM,SIGVTALRM};
    if (injection>=0 && injection<3 && sig==signals[injection]) assert(!raise(sig));
}
#define rsignal_install_handler install
static void deinstall(int sig) { assert(signal(sig,SIG_IGN)!=SIG_ERR); deinstalled++; }
#define rsignal_deinstall_handler deinstall
static int clear_timer(int a,const struct itimerval *b,struct itimerval *c) {
    assert(a==ITIMER_VIRTUAL && !b->it_value.tv_sec && !b->it_value.tv_usec && !c); return 0;
}
#define rsignal_setitimer clear_timer
static void hold(void) { held++; }
static void move(void) { moved++; }
static u3_noun u3i_tape(const char *s) { assert(s); return 41; }
static void u3t_boot(void) { booted++; }
static void u3t_boff(void) { boffed++; }
static void u3t_init(void) { _exit(95); }
static u3_noun _cm_signal_recover(c3_l tag,u3_noun arg) { (void)tag; (void)arg; _exit(96); }
static void u3m_stacktrace(void) { assert(0); }
static void u3z(u3_noun noun) {
    if (noun==41) released++;
    else { assert(noun==42); arg_freed++; }
}
static u3_noun u3nc(u3_noun a,u3_noun b) { return 100000+a*1000+b; }
static u3_noun u3nt(u3_noun a,u3_noun b,u3_noun c) { return 1000000+a*10000+b*100+c; }
static void u3m_hate(c3_w pad) {
    assert(pad==10); u3R=&child; child.bug.mer=41; child.bug.tax=3;
    child.off_w=8; child.fow_w=9;
}
static void u3m_timer_set(c3_w n) { assert(n); }
static c3_w u3m_time_gap_in_mil(c3_w n) { return n; }
static void u3m_grab(u3_noun a,u3_noun b) { (void)a; (void)b; assert(0); }
static u3_noun u3m_love(u3_noun n) { u3R=&home.rod_u; return n; }
#include "extracted.h"
static u3_noun work(u3_noun arg) {
    assert(arg==42);
    if (selected_bail) u3m_bail((u3_noun)selected_bail);
    return 7;
}
static void cleanup(void) { assert(write(1,"ATEXIT\n",7)==7); }
int main(int argc,char **argv) {
    assert(argc==3);
    u3C.sign_hold_f=hold; u3C.sign_move_f=move;
    if (!strcmp(argv[1],"transition")) {
        injection=atoi(argv[2]); assert(injection>=0 && injection<4);
        assert(!atexit(cleanup));
        (void)u3m_soft_top(0,10,work,42);
        _exit(97);
    }
    assert(!strcmp(argv[1],"noun")); selected_bail=atoi(argv[2]);
    u3_noun result=u3m_soft_top(0,10,work,42);
    u3_noun expected=selected_bail==c3__exit ? u3nc(2,3) :
        selected_bail==c3__evil ? u3nt(3,c3__evil,3) :
        selected_bail ? (u3_noun)selected_bail : u3nc(0,7);
    assert(result==expected && u3R==&home.rod_u);
    assert(installed==3 && held==1 && booted==1 && arg_freed==1);
    assert(deinstalled==(selected_bail ? 3 : 6));
    assert(moved==(selected_bail ? 1 : 2) && boffed==moved);
    assert(released==(selected_bail ? 1 : 0));
    if (selected_bail) assert(u3t_Spin->off_w==8 && u3t_Spin->fow_w==9);
    puts("noun-recovery-ok"); return 0;
}
