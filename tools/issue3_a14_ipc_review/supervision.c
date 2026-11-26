/* Actual lord callbacks; process kill/stop and bail callbacks mocked. */
#include <assert.h>
#include <inttypes.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef char c3_c;
typedef int c3_i;
typedef int64_t c3_ds;
typedef struct { int tag; } uv_process_t;
enum { u3_writ_poke, u3_writ_peek, u3_writ_exit };
typedef struct { int typ_e; } u3_writ;
typedef struct lord {
  uv_process_t cub_u;
  u3_writ *ext_u;
  struct { void (*exit_f)(void*); void (*bail_f)(void*); void *ptr_v; } cb_u;
} u3_lord;
static int killed,stopped,bailed;
static int uv_process_kill(uv_process_t *p,int sig) { assert(sig==SIGKILL); killed++; return 0; }
static void _lord_stop(u3_lord *l) { stopped++; }
static void bail(void *p) { assert(killed==1 && stopped==1); bailed++; }
#include "supervision-bodies.h"
int main(int argc,char **argv) {
  assert(argc==4); u3_lord lord={0}; u3_writ head={u3_writ_poke};
  lord.cb_u.bail_f=bail;
  if(strcmp(argv[1],"none")) lord.ext_u=&head;
  if(!strcmp(argv[1],"peek")) head.typ_e=u3_writ_peek;
  if(!strcmp(argv[1],"exit")) head.typ_e=u3_writ_exit;
  _lord_on_serf_exit(&lord.cub_u,atoll(argv[2]),atoi(argv[3]));
  if(head.typ_e==u3_writ_exit) {
    assert(stopped==1 && !killed && !bailed);
    puts("exit writ -> stop even for nonzero status");
  } else {
    assert(stopped==1 && killed==1 && bailed==1);
    puts("halt -> bail; no restart");
  }
  return 0;
}
