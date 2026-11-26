/* Compile exact _mars_flush and u3_king_done at mocked external seams.
 * Pending uv_close is deliberately NOT treated as consumer quiescence.
 */
#define PROBE_CALLER_CHECK
#define main lifecycle_fixture_main
#include "lifecycle_probe.c"
#undef main

typedef int c3_o;
typedef int c3_i;
typedef char c3_c;
typedef unsigned long long c3_d;
typedef unsigned long long u3_noun;
#define c3y 0
#define c3n 1
#define c3__sync 1
#define u3_assert(x) do { if (!(x)) exit(90); } while (0)

typedef struct gift {
  int sat_e;
  c3_d eve_d, len_d;
  void* hun_y;
  struct gift* nex_u;
} u3_gift;
typedef struct { c3_d dun_d; } probe_disk;
typedef struct {
  struct { u3_gift *ext_u, *ent_u; } gif_u;
  int sat_e;
  c3_d dun_d;
  probe_disk* log_u;
  struct { c3_d eve_d; } sav_u;
  void *out_u, *sil_u;
  int mug_l;
} u3_mars;
enum { u3_gift_rest_e = 1, u3_mars_work_e = 2, u3_mars_save_e = 3, u3_mars_exit_e = 4 };
static int saved, disk_closed, cue_closed, trace_closed, dump_closed;
static void u3_newt_send(void* out, c3_d n, void* bytes) { (void)out; (void)n; (void)bytes; }
static void c3_free(void* p) { free(p); }
static void u3m_save(void) { ++saved; }
static u3_noun u3i_chub(c3_d n) { return n; }
static u3_noun u3nt(int a, u3_noun b, int c) { return (u3_noun)a + b + (u3_noun)c; }
static void _mars_gift(u3_mars* m, u3_noun g) { (void)m; (void)g; }
static void u3_disk_exit(probe_disk* d) { (void)d; ++disk_closed; }
static void u3s_cue_xeno_done(void* p) { (void)p; ++cue_closed; }
static void u3t_trace_close(void) { ++trace_closed; }
static void _mars_damp_file(void) { ++dump_closed; }

typedef struct { int closing; } uv_handle_t;
static struct { uv_handle_t tim_u; void* pir_u; } king;
#define u3K king
static struct { int xit_i, nex_o, pep_o; } u3_Host;
static int uv_pending_close;
static int uv_is_closing(uv_handle_t* h) { return h->closing; }
static void _king_done_cb(uv_handle_t* h) { (void)h; }
static void uv_close(uv_handle_t* h, void (*callback)(uv_handle_t*)) {
  (void)callback; h->closing = 1; ++uv_pending_close;
}
static void _king_sign_close(void) {}
static void u3_term_log_exit(void) {}
static c3_c* _king_get_pace(void) { return NULL; }
static c3_i u3_king_next(c3_c* pace, c3_c** version) { (void)pace; (void)version; return -1; }
static void _king_do_upgrade(c3_c* pace, c3_c* version) { (void)pace; (void)version; }
#include "callers.h"

void probe_caller_check(void) {
  if (strcmp(mode, "mars") == 0) {
    if (saved != 1 || disk_closed != 1 || cue_closed != 1 || trace_closed != 1 || dump_closed != 1) exit(93);
    puts("mars:cleanup-before-storage-stop");
  }
  else {
    if (king.pir_u || uv_pending_close != 1) exit(94);
    puts("king:close-queued-without-drain-barrier");
  }
}

int main(int argc, char** argv) {
  mode = argc > 1 ? argv[1] : "mars";
  _cm_crypto();
  if (strcmp(mode, "mars") == 0) {
    probe_disk disk = { .dun_d = 5 };
    u3_mars mars = { .sat_e = 4, .dun_d = 5, .log_u = &disk };
    _mars_flush(&mars);  /* actual body exits on its terminal branch */
    return 91;
  }
  if (strcmp(mode, "king-live") == 0) {
    king.pir_u = &king;
    consumers = 1;
  }
  u3_Host.nex_o = c3n;
  u3_Host.pep_o = c3n;
  u3_king_done();  /* actual body schedules closes then stops immediately */
  return 92;
}
