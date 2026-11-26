/* Isolated POSIX process-owned adaptation of Vere's pinned palloc engine.
 * Not the unchanged u3a_malloc/current-road callback. No libc allocation fallback.
 */
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE 1
#endif
#include "openssl_owned_arena.h"
#include <assert.h>
#include <limits.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

/* Same fixed-width word/post ABI and selected structures as allocate.h.
 * The translation domain is this mapping, not the noun loom.
 */
typedef uint32_t c3_w;
typedef int32_t c3_ws;
typedef uint16_t c3_s;
typedef uint8_t c3_g;
typedef uint8_t c3_y;
typedef size_t c3_z;
typedef uint32_t u3_post;
#define u3p(type) u3_post
#define u3a_page 12U
#define u3a_min_log 2U
#define u3a_minimum 4U
#define u3a_crag_no (u3a_page - u3a_min_log)
#define u3a_free_pg 0U
#define u3a_head_pg 1U
#define u3a_rest_pg 2U
#define PAGE_WORDS (1U << u3a_page)
#define PAGE_BYTES (4U * PAGE_WORDS)
#define c3_wiseof(x) ((sizeof(x) + 3) / 4)
#define c3_min(a,b) ((a) < (b) ? (a) : (b))
#define c3_max(a,b) ((a) > (b) ? (a) : (b))
#define u3_assert(x) do { if (!(x)) abort(); } while (0)
#define ASAN_POISON_MEMORY_REGION(addr,size) ((void)(addr), (void)(size))
#define ASAN_UNPOISON_MEMORY_REGION(addr,size) ((void)(addr), (void)(size))
static unsigned c3_bits_word(c3_w n) { return n ? 32U - (unsigned)__builtin_clz(n) : 0; }
static unsigned c3_tz_w(c3_w n) { u3_assert(n); return (unsigned)__builtin_ctz(n); }
typedef struct _u3a_crag {
  u3p(struct _u3a_crag) nex_p;
  c3_w pag_w;
  c3_s log_s;
  c3_s fre_s;
  c3_w map_w[1];
} u3a_crag;
typedef struct _u3a_dell {
  u3p(struct _u3a_dell) nex_p;
  u3p(struct _u3a_dell) pre_p;
  c3_w pag_w;
  c3_w siz_w;
} u3a_dell;
typedef struct {
  c3_s log_s, len_s, tot_s, map_s, siz_s, hun_s, ful_s;
} u3a_hunk_dose;
static u3a_hunk_dose u3a_Hunk[u3a_crag_no];
static struct {
  c3_w *words;
  size_t bytes, live;
  size_t charged, peak_charged, allocation_failures;
  u3_post base_p, hat_p, cap_p;
  u3_post dell_begin, dell_end, dell_free;
  struct {
    u3_post fre_p, erf_p, cac_p;
    c3_ws dir_ws, off_ws;
    c3_w siz_w, len_w;
    u3_post pag_p, wee_p[u3a_crag_no];
  } heap;
} owner;
static pthread_mutex_t owner_lock = PTHREAD_MUTEX_INITIALIZER;
#define LOCK() u3_assert(!pthread_mutex_lock(&owner_lock))
#define UNLOCK() u3_assert(!pthread_mutex_unlock(&owner_lock))
#define HEAP owner.heap
#define BASE owner.base_p
#define u3a_into(p) ((void *)(owner.words + (p)))
#define u3a_outa(p) ((u3_post)((c3_w *)(p) - owner.words))
#define u3to(type,p) ((type *)u3a_into(p))
#define u3tn(type,p) ((p) ? u3to(type,p) : NULL)
#define u3of(type,p) u3a_outa((type *)(p))
#define page_to_post(p) (BASE + (HEAP.dir_ws * (c3_ws)((c3_w)((p) - HEAP.off_ws) << u3a_page)))
#define post_to_page(p) (_abs_dif((p), (c3_ws)BASE + HEAP.off_ws) >> u3a_page)

/* Called inside the owner lock at engine page transitions, not just after
 * public callbacks: realloc temporarily owns both old and new page runs. */
static void owner_charge_pages(c3_w pages) {
  size_t bytes = (size_t)pages * PAGE_BYTES;
  u3_assert(bytes <= owner.bytes - owner.charged);
  owner.charged += bytes;
  if (owner.charged > owner.peak_charged) owner.peak_charged = owner.charged;
}
static void owner_release_pages(c3_w pages) {
  size_t bytes = (size_t)pages * PAGE_BYTES;
  u3_assert(bytes <= owner.charged);
  owner.charged -= bytes;
}

/* A bounded fixed descriptor pool avoids original _free_pages allocating
 * memory from an exhausted data heap. At most one descriptor per data page,
 * plus the cached descriptor: provisioned from the explicit mapping capacity.
 */
static u3_post owner_dell_take(void) {
  u3_post p = owner.dell_free;
  u3_assert(p);
  owner.dell_free = u3to(u3a_dell,p)->nex_p;
  memset(u3a_into(p), 0, sizeof(u3a_dell));
  return p;
}
static int owner_dell_release(u3_post p) {
  if (p < owner.dell_begin || p >= owner.dell_end) return 0;
  u3_assert(!((p - owner.dell_begin) % c3_wiseof(u3a_dell)));
  u3to(u3a_dell,p)->nex_p = owner.dell_free;
  owner.dell_free = p;
  return 1;
}
static u3_post _imalloc(c3_w);
static void _ifree(u3_post);
static u3_post _extend_heap(c3_w pages) {
  /* No mutation on OOM; original directory growth is replaced by a fixed
   * maximum-sized directory in the arena metadata prefix. */
  if (pages > HEAP.siz_w - HEAP.len_w) return 0;
  u3_post p = owner.hat_p;
  owner.hat_p += pages * PAGE_WORDS;
  HEAP.len_w += pages;
  u3_assert(owner.hat_p <= owner.cap_p);
  return p;
}
#include "palloc_engine.inc"

typedef union {
  max_align_t align;
  struct { size_t bytes; uint64_t magic; } value;
} owner_header;
#define OWNER_MAGIC UINT64_C(0x75336f73736c6f77)
_Static_assert(_Alignof(max_align_t) <= 16, "palloc guarantees 16-byte alignment");
_Static_assert(sizeof(owner_header) % 16 == 0, "aligned header size");

static owner_header *owner_validate(void *p) {
  uintptr_t address = (uintptr_t)p, begin = (uintptr_t)owner.words;
  u3_assert(owner.words && address >= begin + ((size_t)owner.base_p * 4) + sizeof(owner_header));
  u3_assert(address < begin + owner.bytes && !(address % 16));
  owner_header *h = (owner_header *)p - 1;
  u3_assert(h->value.magic == OWNER_MAGIC);
  return h;
}
static void *owner_malloc(size_t bytes) {
  if (!owner.words || !bytes || bytes > UINT32_MAX - sizeof(owner_header) - 3) return NULL;
  c3_w words = (c3_w)((bytes + sizeof(owner_header) + 3) / 4);
  u3_post p = _imalloc(words);
  if (!p) return NULL;
  owner_header *h = u3to(owner_header,p);
  h->value.bytes = bytes;
  h->value.magic = OWNER_MAGIC;
  ++owner.live;
  return h + 1;
}
static void owner_free(void *p) {
  if (!p) return;
  owner_header *h = owner_validate(p);
  h->value.magic = 0;
  u3_assert(owner.live);
  --owner.live;
  _ifree(u3a_outa(h));
}

int u3_openssl_arena_init(size_t bytes) {
  int result = 0;
  LOCK();
  /* Round DOWN: never silently exceed the caller's total reservation bound.
   * UINT32_MAX bytes also keeps all signed word-offset arithmetic in range. */
  if (owner.words || bytes > UINT32_MAX || bytes / PAGE_BYTES < 8) goto done;
  bytes -= bytes % PAGE_BYTES;
  size_t pages = bytes / PAGE_BYTES;
  size_t directory_pages = (pages * sizeof(u3_post) + PAGE_BYTES - 1) / PAGE_BYTES;
  size_t dell_pages = ((pages + 1) * sizeof(u3a_dell) + PAGE_BYTES - 1) / PAGE_BYTES;
  size_t prefix_pages = 1 + directory_pages + dell_pages;
  void *mapping = mmap(NULL, bytes, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (mapping == MAP_FAILED) goto done;
  owner.words = mapping;
  owner.bytes = bytes;
  owner.charged = owner.peak_charged = (prefix_pages + 1) * PAGE_BYTES;
  HEAP.pag_p = PAGE_WORDS;
  owner.dell_begin = (u3_post)((1 + directory_pages) * PAGE_WORDS);
  owner.dell_end = owner.dell_begin + (u3_post)((pages + 1) * c3_wiseof(u3a_dell));
  for (u3_post p = owner.dell_begin; p < owner.dell_end; p += c3_wiseof(u3a_dell)) {
    u3to(u3a_dell,p)->nex_p = owner.dell_free;
    owner.dell_free = p;
  }
  BASE = (u3_post)(prefix_pages * PAGE_WORDS);
  owner.hat_p = BASE + PAGE_WORDS;
  owner.cap_p = (u3_post)(bytes / 4);
  HEAP.dir_ws = 1;
  HEAP.off_ws = 0;
  HEAP.siz_w = (c3_w)(pages - prefix_pages);
  HEAP.len_w = 1;
  u3to(u3_post,HEAP.pag_p)[0] = u3a_head_pg; /* permanent engine anchor */
  HEAP.cac_p = owner_dell_take();
  _init_once();
  result = 1;
done:
  UNLOCK();
  return result;
}
void *u3_openssl_arena_malloc(size_t n, const char *f, int l) {
  (void)f; (void)l;
  LOCK();
  void *p = owner_malloc(n);
  if (owner.words && n && !p && owner.allocation_failures < SIZE_MAX)
    ++owner.allocation_failures;
  UNLOCK();
  return p;
}
void *u3_openssl_arena_realloc(void *p, size_t n, const char *f, int l) {
  (void)f; (void)l;
  void *result = NULL;
  LOCK();
  if (!p) result = owner_malloc(n);
  else if (!n) owner_free(p);
  else {
    owner_header *h = owner_validate(p);
    if (n <= UINT32_MAX - sizeof(owner_header) - 3) {
      c3_w words = (c3_w)((n + sizeof(owner_header) + 3) / 4);
      u3_post post = _irealloc(u3a_outa(h), words);
      if (post) {
        h = u3to(owner_header,post);
        h->value.bytes = n;
        h->value.magic = OWNER_MAGIC;
        result = h + 1;
      }
    }
  }
  if (owner.words && n && !result && owner.allocation_failures < SIZE_MAX)
    ++owner.allocation_failures;
  UNLOCK();
  return result;
}
void u3_openssl_arena_free(void *p, const char *f, int l) {
  (void)f; (void)l;
  LOCK(); owner_free(p); UNLOCK();
}
size_t u3_openssl_arena_live_blocks(void) {
  LOCK(); size_t n = owner.live; UNLOCK(); return n;
}
int u3_openssl_arena_snapshot(u3_openssl_arena_metrics *out) {
  int result = 0;
  LOCK();
  if (out && owner.words) {
    *out = (u3_openssl_arena_metrics){1, owner.bytes, owner.charged,
                                    owner.peak_charged, owner.live, owner.allocation_failures};
    result = 1;
  }
  UNLOCK();
  return result;
}
int u3_openssl_arena_destroy(void) {
  int result = 0;
  LOCK();
  if (!owner.live) {
    if (!owner.words || !munmap(owner.words,owner.bytes)) {
      memset(&owner,0,sizeof owner);
      result = 1;
    }
  }
  UNLOCK();
  return result;
}
