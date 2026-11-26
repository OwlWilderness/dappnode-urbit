/* Source-only diagnostic candidate; Linux only, not a production feature. */
#ifndef UVM_ISSUE3_DIAG_H
#define UVM_ISSUE3_DIAG_H
#if !defined(__linux__)
#error "Issue 3 diagnostic overlay is Linux-only"
#endif
#include <errno.h>
#include <stdatomic.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>
/* Exact musl declaration; unistd.h hides it without GNU/BSD feature macros.
 * Do not change feature-test macros after the target has included headers. */
extern long syscall(long, ...);
_Static_assert(ATOMIC_INT_LOCK_FREE == 2, "diagnostics require lock-free int atomics");
extern _Atomic unsigned int uvm_i3_sequence;
extern _Atomic unsigned int uvm_i3_role;
enum uvm_i3_event {
  UVM_I3_PROCESS_ENTRY = 1,
  UVM_I3_BOOT_ENTRY = 2,
  UVM_I3_WORK_ENTRY = 3,
  UVM_I3_PARENT_ENTRY = 4,
  UVM_I3_CHILD_IPC_FAIL = 5,
  UVM_I3_LOCAL_EVAL_FAIL = 6,
  UVM_I3_BOOT_MAKE_RETURN = 7,
  UVM_I3_WORK_QUEUE_RETURN = 8,
  UVM_I3_ALL_LIVE_CALLBACK = 9,
  UVM_I3_DISK_MAKE_FAIL = 10,
  UVM_I3_DISK_LOAD_FAIL = 11,
  UVM_I3_BOOT_PARSE_FAIL = 12,
  UVM_I3_BOOT_PREPARE_FAIL = 13,
  UVM_I3_META_META_FAIL = 14,
  UVM_I3_META_FAIL = 15,
  UVM_I3_DISK_SYNC_FAIL = 16,
  UVM_I3_DO_BOOT_FAIL = 17,
  UVM_I3_BOOT_READ_FAIL = 18,
  UVM_I3_VM_BOOT_FAIL = 19,
  UVM_I3_BOOT_SAVE_ENTER = 20,
  UVM_I3_BOOT_SAVE_RETURN = 21,
  UVM_I3_BOOT_CLOSE_ENTER = 22,
  UVM_I3_BOOT_CLOSE_RETURN = 23,
  UVM_I3_BOOT_EXIT_ZERO_CALL = 24,
  UVM_I3_BOOT_CHILD_SIGABRT = 25,
  UVM_I3_BOOT_CHILD_SIGSEGV = 26,
  UVM_I3_BOOT_CHILD_SIGBUS = 27,
  UVM_I3_BOOT_CHILD_SIGILL = 28,
  UVM_I3_BOOT_CHILD_SIGKILL = 29,
  UVM_I3_BOOT_CHILD_OTHER_SIGNAL = 30,
  UVM_I3_BOOT_CHILD_DIAGNOSTIC_RESERVED_EXIT = 31,
  UVM_I3_BOOT_CHILD_NONZERO = 32,
  UVM_I3_BOOT_CHILD_ZERO = 33,
  UVM_I3_WORK_CHILD_SIGABRT = 34,
  UVM_I3_WORK_CHILD_SIGSEGV = 35,
  UVM_I3_WORK_CHILD_SIGBUS = 36,
  UVM_I3_WORK_CHILD_SIGILL = 37,
  UVM_I3_WORK_CHILD_SIGKILL = 38,
  UVM_I3_WORK_CHILD_OTHER_SIGNAL = 39,
  UVM_I3_WORK_CHILD_DIAGNOSTIC_RESERVED_EXIT = 40,
  UVM_I3_WORK_CHILD_NONZERO = 41,
  UVM_I3_WORK_CHILD_ZERO = 42,
  UVM_I3_LORD_BAIL = 43,
  UVM_I3_WORK_IPC_EOF = 44,
  UVM_I3_WORK_IPC_ERROR = 45,
  UVM_I3_BOOT_IPC_ERROR = 46,
  UVM_I3_BOOT_SPAWN_CALL = 47,
  UVM_I3_BOOT_SPAWN_FAIL = 48,
  UVM_I3_WORK_SPAWN_CALL = 49,
  UVM_I3_WORK_SPAWN_FAIL = 50,
  UVM_I3_KING_BOOT_REJECT = 51,
  UVM_I3_KING_BOOT_ACCEPT = 52,
  UVM_I3_KING_BAIL = 53,
  UVM_I3_KING_EXIT_CALL = 54,
  UVM_I3_PIER_BAIL = 55,
  UVM_I3_WYRD_FAIL = 56,
  UVM_I3_WYRD_GOOD = 57,
  UVM_I3_RIPE_ACCEPT = 58,
  UVM_I3_LIBC_EXIT_ZERO = 59,
  UVM_I3_LIBC_EXIT_NONZERO = 60,
  UVM_I3_ATEXIT_ENTER = 61,
  UVM_I3_ATEXIT_RETURN = 62,
  UVM_I3_FINI_ENTER = 63,
  UVM_I3_FINI_RETURN = 64,
  UVM_I3_STDIO_ENTER = 65,
  UVM_I3_STDIO_RETURN = 66,
  UVM_I3_LIBC_FINAL_EXIT = 67,
  UVM_I3_LIBC_ABORT = 68,
  UVM_I3_OPENSSL_CLEANUP_ENTER = 69,
  UVM_I3_OPENSSL_CLEANUP_SKIP = 70,
  UVM_I3_OPENSSL_THREAD_STOP_RETURN = 71,
  UVM_I3_OPENSSL_STOP_HANDLERS_RETURN = 72,
  UVM_I3_OPENSSL_DEFAULT_CTX_RETURN = 73,
  UVM_I3_OPENSSL_CLEANUP_RETURN = 74,
  UVM_I3_OPENSSL_DIE = 75,
  UVM_I3_BOOT_REGISTER = 76,
  UVM_I3_WORK_REGISTER = 77,
};
/* Telemetry faults are NOT application failures: reserve exit 125 and invalidate
 * the entire diagnostic interpretation. No recursion into exit()/abort(). */
static inline _Noreturn void uvm_i3_invalid(void)
{
  syscall(SYS_exit_group, 125);
  for (;;) { }
}
static inline void uvm_i3_channel_check(void)
{
  int saved = errno, type = 0, domain = 0;
  socklen_t size = sizeof(int);
  if ( getsockopt(3, SOL_SOCKET, SO_TYPE, &type, &size) != 0 ||
       size != sizeof(int) || type != SOCK_DGRAM ) {
    uvm_i3_invalid();
  }
  size = sizeof(int);
  if ( getsockopt(3, SOL_SOCKET, SO_DOMAIN, &domain, &size) != 0 ||
       size != sizeof(int) || domain != AF_UNIX ) {
    uvm_i3_invalid();
  }
  errno = saved;
}
static inline void uvm_i3_emit(enum uvm_i3_event event)
{
  int saved = errno;
  /* Reservation order is not send order across threads/signals. The receiver
   * must use kernel sender attribution, not role/sequence as process identity.
   * Termination can strand a reserved but unsent final frame. */
  unsigned int seq = atomic_fetch_add_explicit(&uvm_i3_sequence, 1,
                                                memory_order_relaxed);
  unsigned int role = atomic_load_explicit(&uvm_i3_role, memory_order_relaxed);
  unsigned char frame[4];
  if ( seq >= 128 || role > 3 || event < 1 || event > 75 ) {
    uvm_i3_invalid();
  }
  frame[0] = 1; /* wire version */
  frame[1] = (unsigned char)role; /* 0=unselected, 1=parent, 2=boot, 3=work */
  frame[2] = (unsigned char)seq;
  frame[3] = (unsigned char)event;
  if ( syscall(SYS_sendto, 3, frame, sizeof(frame),
               MSG_DONTWAIT | MSG_NOSIGNAL, 0, 0) != sizeof(frame) ) {
    uvm_i3_invalid();
  }
  errno = saved;
}
/* Parent calls immediately after successful uv_spawn, before child reaping.
 * PID is routing metadata only: the collector must never persist it. */
static inline void uvm_i3_register_child(enum uvm_i3_event event, int pid)
{
  int saved = errno;
  unsigned int seq = atomic_fetch_add_explicit(&uvm_i3_sequence, 1,
                                                memory_order_relaxed);
  unsigned char frame[8];
  if ( seq >= 128 || pid <= 0 ||
       atomic_load_explicit(&uvm_i3_role, memory_order_relaxed) != 1 ||
       (event != UVM_I3_BOOT_REGISTER && event != UVM_I3_WORK_REGISTER) ) {
    uvm_i3_invalid();
  }
  frame[0] = 1; frame[1] = 1; frame[2] = (unsigned char)seq;
  frame[3] = (unsigned char)event;
  frame[4] = (unsigned char)((unsigned int)pid);
  frame[5] = (unsigned char)((unsigned int)pid >> 8);
  frame[6] = (unsigned char)((unsigned int)pid >> 16);
  frame[7] = (unsigned char)((unsigned int)pid >> 24);
  if ( syscall(SYS_sendto, 3, frame, sizeof(frame),
               MSG_DONTWAIT | MSG_NOSIGNAL, 0, 0) != sizeof(frame) ) {
    uvm_i3_invalid();
  }
  errno = saved;
}
#endif
