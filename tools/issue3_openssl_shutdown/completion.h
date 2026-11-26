/* Owning-loop-thread lifecycle. No locks, event dispatch or allocator policy.
 * owner is the process identity supplied by the embedding translation unit.
 * finish is invoked ONLY after the outer event runner has returned and its
 * loop-close completion certificate was obtained, never inside a callback. */
#ifndef U3_SSL_COMPLETION_H
#define U3_SSL_COMPLETION_H
#include <stddef.h>
#include <stdint.h>

typedef struct {
  unsigned phase; /* 0 admitting, 1 requested, 2 finalizing, 3 done, 4 failed */
  size_t users;
  uintptr_t owner;
  int status;
} u3_ssl_completion;

typedef struct {
  void (*consumers)(void *);
  void (*openssl)(void *);
  size_t (*live_blocks)(void *);
  int (*destroy)(void *);
  void (*backing)(void *);
  void *context;
} u3_ssl_completion_ops;

static inline int
u3_ssl_completion_owner(u3_ssl_completion *s, uintptr_t owner)
{
  if (!owner) return 0;
  if (!s->owner) s->owner=owner;
  return s->owner==owner;
}

static inline int
u3_ssl_completion_hold(u3_ssl_completion *s, uintptr_t owner)
{
  if (!u3_ssl_completion_owner(s,owner) || s->phase || s->users==SIZE_MAX) return 0;
  ++s->users;
  return 1;
}

static inline int
u3_ssl_completion_release(u3_ssl_completion *s, uintptr_t owner)
{
  if (!u3_ssl_completion_owner(s,owner) || !s->users || s->phase>1) return 0;
  --s->users;
  return 1;
}

static inline int
u3_ssl_completion_request(u3_ssl_completion *s, uintptr_t owner, int status)
{
  if (!u3_ssl_completion_owner(s,owner) || s->phase>1) return 0;
  if (status && !s->status) s->status=status;
  s->phase=1;
  return 1;
}

/* 0 waiting, 1 complete, -1 invariant/refused backing release. */
static inline int
u3_ssl_completion_finish(u3_ssl_completion *s, uintptr_t owner,
                         int loop_closed, const u3_ssl_completion_ops *ops)
{
  if (!u3_ssl_completion_owner(s,owner)) return -1;
  if (s->phase==3) return 1;
  if (s->phase==4) return -1;
  if (s->phase!=1 || !loop_closed || s->users) return 0;
  s->phase=2; /* latch before any external callback */
  ops->consumers(ops->context);
  ops->openssl(ops->context);
  if (ops->live_blocks(ops->context) || !ops->destroy(ops->context)) {
    s->phase=4;
    return -1;
  }
  ops->backing(ops->context);
  s->phase=3;
  return 1;
}
#endif
