/* Exact original manage.c branch bodies, with signal dispatch seam recorded. */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef uint32_t c3_l;
#define c3__term 1
#define c3__intr 2
#define c3__alrm 3
typedef struct { int kid_p; } road;
static struct { road rod_u; } home;
static road child,*u3R;
#define u3H (&home)
static int ignored,dispatched;
static void _cm_emergency(const char *s,c3_l sig) { assert(!strcmp(s,"ignored")); ignored++; }
static void _cm_signal_handle(c3_l sig) { dispatched++; }
#include "signals-bodies.h"
int main(int argc,char **argv) {
  assert(argc==3); u3R=!strcmp(argv[1],"child")?&child:&home.rod_u;
  home.rod_u.kid_p=!strcmp(argv[1],"base-child");
  if(!strcmp(argv[2],"intr")) _cm_signal_handle_intr(0);
  else if(!strcmp(argv[2],"term")) _cm_signal_handle_term(0);
  else _cm_signal_handle_alrm(0);
  assert(ignored+dispatched==1); puts(ignored?"ignored":"dispatch"); return 0;
}
