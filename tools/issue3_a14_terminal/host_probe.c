/* Host test only. Actual extracted handlers; noun/native state is synthetic.
 * Real same-thread raise(), no genuine stack exhaustion or target runtime. */
#define _POSIX_C_SOURCE 200809L
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <setjmp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
typedef unsigned c3_l;
typedef unsigned u3_noun;
enum { c3__over=10, c3__intr=11, c3__term=12, c3__alrm=13 };
typedef struct { int kid_p; } road;
typedef struct { road rod_u; } home_t;
static home_t home;
static road child, nested;
static road *u3R;
static home_t *u3H;
static sigjmp_buf u3_Signal;
#define rsignal_longjmp siglongjmp
typedef void *stackoverflow_context_t;
static pthread_mutex_t native_lock = PTHREAD_MUTEX_INITIALIZER;
static void _cm_emergency(const char *message, c3_l tag) __attribute__((unused));
static void _cm_emergency(const char *message, c3_l tag) {
    (void)message; (void)tag; assert(write(1,"ignored\n",8)==8);
}
/* Keep overflow enabled. This mock is the forbidden recovery boundary: any
 * visit is observable. It does NOT emulate libsigsegv or an exhausted stack. */
static void sigsegv_leave_handler(void (*callback)(void *,void *,void *),
                                 void *a, void *b, void *c) __attribute__((unused));
static void sigsegv_leave_handler(void (*callback)(void *,void *,void *),
                                 void *a, void *b, void *c) {
    assert(write(1,"overflow-recovery\n",18)==18); callback(a,b,c);
}
#include "handlers.h"
static void cleanup(void) { assert(write(1,"ATEXIT\n",7)==7); }
int main(int argc, char **argv) {
    assert(argc==4);
    int which=atoi(argv[1]);
    int signals[]={SIGINT,SIGTERM,SIGVTALRM};
    void (*handlers[])(int)={_cm_signal_handle_intr,_cm_signal_handle_term,_cm_signal_handle_alrm};
    assert(which>=0 && which<4);
    u3H=&home;
    if (!strcmp(argv[2],"cold")) { u3H=NULL; u3R=NULL; }
    else if (!strcmp(argv[2],"home")) u3R=&home.rod_u;
    else if (!strcmp(argv[2],"base-child")) { u3R=&home.rod_u; home.rod_u.kid_p=1; }
    else if (!strcmp(argv[2],"nested")) { home.rod_u.kid_p=1; child.kid_p=2; u3R=&nested; }
    else { assert(!strcmp(argv[2],"child")); home.rod_u.kid_p=1; u3R=&child; }
    assert(!atexit(cleanup));
    /* Neither libc flushing nor atexit/native cleanup may run on the candidate. */
    static char buffer[1024]; assert(!setvbuf(stdout,buffer,_IOFBF,sizeof(buffer)));
    fputs("BUFFERED",stdout);
    assert(!pthread_mutex_lock(&native_lock));
    assert(write(1,"armed\n",6)==6);
    if (which<3) assert(signal(signals[which],handlers[which]) != SIG_ERR);
    /* 'transition' deliberately has no current or stale jump target. */
    if (!strcmp(argv[3],"active")) {
        int jumped=sigsetjmp(u3_Signal,1);
        if (jumped) {
            assert(pthread_mutex_trylock(&native_lock)==EBUSY);
            assert(write(1,"unsafe-native-continuation\n",27)==27);
            _exit(91); /* No attempted lock repair; subprocess owns this mock. */
        }
    } else assert(!strcmp(argv[3],"transition"));
    if (which==3) _cm_signal_handle_over(0,NULL);
    else assert(!raise(signals[which]));
    assert(write(1,"returned\n",9)==9);
    _exit(92);
}
