"""Opt-in POSIX A14 source transformation; not wired into any build recipe.

Owner selected terminal deep interruption/overflow, conditional on IPC/persistence
review before integration. A caller must still explicitly select this exact
candidate policy and target; no production path is read or written by this module.
"""
import argparse
import hashlib
import json
from pathlib import Path
import sys
import tarfile

POLICY = 'terminal-deep-handlers-and-overflow-exit1-posix-v1'
RESULT_SHA256 = '8654a18120ddf8e3ef3962c8b0d2703394d20327057640d0e6653d9addf61acb'
VERE = 'vere-8ddc4b786979574dbfcb655e3db1b634f658d0de/'
MANAGE = VERE + 'pkg/noun/manage.c'
PINS = {
    MANAGE: (62664, '2b06d6a006595ea7440690b325e8c994505a6040a97087e877a19c5e0c46d321'),
    VERE + 'pkg/noun/platform/darwin/rsignal.h':
        (458, '8d31630ed4f42d101ac4a609732f05cb736f051883ad3965e8d263bd164fdae0'),
    VERE + 'pkg/noun/platform/linux/rsignal.h':
        (455, '7c47997aa580e3538ba21d6b5ab1aa1115c3fa36909dc6caaba6a32b264ac9d6'),
}
OVERFLOW_CALLBACK = '''static void _cm_overflow(void *arg1, void *arg2, void *arg3)
{
  (void)(arg1);
  (void)(arg2);
  (void)(arg3);
  u3m_signal(c3__over);
}

'''
COMMON = '''static void
_cm_signal_handle(c3_l sig_l)
{
#ifndef U3_OS_windows
  if ( c3__over == sig_l ) {
#ifndef NO_OVERFLOW
    sigsegv_leave_handler(_cm_overflow, NULL, NULL, NULL);
#endif
  } else
#endif
  {
    u3m_signal(sig_l);
  }
}'''
TERMINAL = '''static void
_cm_signal_handle(c3_l sig_l)
{
  /* A14 terminal deep-handler policy: no native unwind or library cleanup. */
  (void)sig_l;
  _exit(1);
}'''
TERM = '''static void
_cm_signal_handle_term(int x)
{
  //  Ignore if we are using base memory from work memory, very rare.
  //
  if ( (0 != u3H->rod_u.kid_p) && (&(u3H->rod_u) == u3R) ) {
    _cm_emergency("ignored", c3__term);
  }
  else {
    _cm_signal_handle(c3__term);
  }
}'''
INTR = '''static void
_cm_signal_handle_intr(int x)
{
  //  Interrupt: stop work.  Ignore if not working, or (rarely) using base.
  //
  if ( &(u3H->rod_u) == u3R ) {
    _cm_emergency("ignored", c3__intr);
  }
  else {
    _cm_signal_handle(c3__intr);
  }
}'''
INCLUDE = '''#include <signal.h>
#ifdef U3_OS_windows
#error "A14 terminal candidate is POSIX-only; Windows is not qualified"
#endif
#include <unistd.h>'''
DELTAS = (
    ('#include <signal.h>', INCLUDE),
    (OVERFLOW_CALLBACK, ''),
    (COMMON, TERMINAL),
    (TERM, 'static void\n_cm_signal_handle_term(int x)\n{\n  _cm_signal_handle(c3__term);\n}'),
    (INTR, 'static void\n_cm_signal_handle_intr(int x)\n{\n  _cm_signal_handle(c3__intr);\n}'),
)


def require_selection(policy, target):
    if policy != POLICY:
        raise ValueError('explicit candidate policy selection required: ' + POLICY)
    if target not in ('darwin', 'linux'):
        raise ValueError('explicit POSIX target must be darwin or linux')


def transform(data, *, policy=None, target=None):
    """Return transformed complete pinned manage.c; reject drift and replay."""
    require_selection(policy, target)
    size, digest = PINS[MANAGE]
    if len(data) != size or hashlib.sha256(data).hexdigest() != digest:
        raise ValueError('manage.c pinned preimage mismatch (or already transformed)')
    text = data.decode('utf-8')
    for before, after in DELTAS:
        if text.count(before) != 1:
            raise ValueError('nonunique transformation preimage')
        text = text.replace(before, after, 1)
    result = text.encode('utf-8')
    if hashlib.sha256(result).hexdigest() != RESULT_SHA256:
        raise ValueError('candidate postimage mismatch')
    return result


def read_public(archive, *, policy=None, target=None):
    """Inspect all metadata, then read only three unique bounded pinned members.

    No extraction to disk and no last-entry-wins semantics. Headers are checked
    for both supported POSIX targets, not substituted with host headers.
    """
    require_selection(policy, target)
    with tarfile.open(archive) as stream:
        members = stream.getmembers()
        selected = {}
        for name, (size, _) in PINS.items():
            matches = [member for member in members if member.name == name]
            if len(matches) != 1 or not matches[0].isreg() or matches[0].size != size:
                raise ValueError('nonunique/nonregular/unbounded public member: ' + name)
            selected[name] = matches[0]
        result = {}
        for name, member in selected.items():
            reader = stream.extractfile(member)
            if reader is None:
                raise ValueError('unreadable public member: ' + name)
            data = reader.read(PINS[name][0] + 1)
            if len(data) != PINS[name][0] or hashlib.sha256(data).hexdigest() != PINS[name][1]:
                raise ValueError('public preimage mismatch: ' + name)
            result[name] = data
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', required=True, type=Path)
    parser.add_argument('--policy', required=True)
    parser.add_argument('--target', required=True, choices=('darwin', 'linux'))
    parser.add_argument('--emit-source', action='store_true', help='emit complete source to stdout instead of a receipt')
    args = parser.parse_args(argv)
    try:
        sources = read_public(args.archive, policy=args.policy, target=args.target)
        result = transform(sources[MANAGE], policy=args.policy, target=args.target)
    except (ValueError, OSError, tarfile.TarError) as error:
        parser.error(str(error))
    if args.emit_source:
        sys.stdout.buffer.write(result)
    else:
        print(json.dumps({'schema': 1, 'status': 'STAGED_NOT_INTEGRATED',
                          'policy': args.policy, 'target': args.target,
                          'source_sha256': {name: hashlib.sha256(data).hexdigest() for name, data in sources.items()},
                          'result_sha256': hashlib.sha256(result).hexdigest(),
                          'exit_status': 1,
                          'integration_gate': 'parent IPC/persistence review and independent verification'}, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
