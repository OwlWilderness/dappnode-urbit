"""Linux process-tree authority for this backend's newly launched child only.

PR_SET_CHILD_SUBREAPER prevents daemonized descendants escaping to container PID1.
All backend children (across request threads) are accounted for, including adopted
children in other sessions. No PID adoption, signals to groups, or force-kill.
Private service storage + cooperating package writers remain a prerequisite; this
is not a sandbox against an administrator introducing unrelated volume writers.
"""
import ctypes
import os
from pathlib import Path
import subprocess
import sys


def _subreaper(set_value=False):
    libc = ctypes.CDLL(None, use_errno=True)
    if set_value and libc.prctl(36, 1, 0, 0, 0) != 0:  # PR_SET_CHILD_SUBREAPER
        raise ValueError('Subreaper unavailable')
    value = ctypes.c_int()
    if libc.prctl(37, ctypes.byref(value), 0, 0, 0) != 0 or value.value != 1:
        raise ValueError('Subreaper unavailable')


def _children(pid):
    result = set()
    for task in (Path('/proc') / str(pid) / 'task').iterdir():
        try:
            result.update(int(n) for n in (task / 'children').read_text().split())
        except FileNotFoundError:
            # A thread that has exited no longer owns children; they reparent.
            continue
    return result


class LinuxChildBoundary:
    @classmethod
    def prepare(cls):
        if not sys.platform.startswith('linux'):
            return None
        _subreaper(set_value=True)
        if _children(os.getpid()):
            raise ValueError('Unknown backend children')
        return cls()

    def __init__(self):
        self.owner = os.getpid()
        self.namespace = os.stat('/proc/self/ns/pid').st_ino
        self.child = None

    def bind(self, child):
        if not isinstance(child, subprocess.Popen):
            raise ValueError('No actual owned process')
        self.child = child
        self.check()

    def check(self):
        if (os.getpid() != self.owner or self.child is None or
                os.stat('/proc/self/ns/pid').st_ino != self.namespace):
            raise ValueError('Process authority changed')
        _subreaper()
        code = self.child.poll()  # Reap only the exact retained Popen child.
        children = _children(self.owner)
        if code is None:
            if children != {self.child.pid}:
                raise ValueError('Unknown or descendant writer')
        elif children:
            raise ValueError('Adopted or concurrent writer')
        return code

    def settle(self):
        code = self.check()
        signalled = code is None
        if signalled:
            self.child.terminate()
            code = self.child.wait(timeout=120)
        # After exact-child reap every surviving descendant is reparented to
        # this subreaper (including setsid double forks), not container PID1.
        if self.check() is None:
            raise ValueError('Child remains active')
        return {'boundary': 'LINUX_SUBREAPER_OWNED_CHILD', 'remaining_children': 0,
                'exit_code': code, 'signal': 'SIGTERM' if signalled else 'NONE'}
