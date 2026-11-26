"""Capped PIPE transport for an explicitly supplied client (never a default).

The supervisor supplies only allowlisted control argv, not shell commands.
Client cancellation is not daemon/container cancellation: supervisor readback is
still mandatory. Exceptions intentionally contain no client output or argv.
"""
import math
import os
import selectors
import signal
import subprocess
import time
from typing import BinaryIO, cast


class TransportError(RuntimeError):
    pass


class BoundedClient:
    def __init__(self, prefix):
        if (type(prefix) is not tuple or not prefix or not os.path.isabs(prefix[0])
                or any(type(s) is not str or '\0' in s for s in prefix)):
            raise ValueError('explicit absolute client argv required')
        self.prefix = prefix
        self.last_pid = None

    def __call__(self, args, timeout, cap):
        if (not isinstance(timeout, (int, float)) or not math.isfinite(timeout)
                or not 0 < timeout <= 2400 or type(cap) is not int or not 1 <= cap <= 65536):
            raise TransportError('invalid client bounds')
        deadline = time.monotonic() + timeout
        proc = subprocess.Popen(self.prefix + tuple(args), stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                start_new_session=True, close_fds=True)
        self.last_pid = proc.pid
        stdout, stderr = cast(BinaryIO, proc.stdout), cast(BinaryIO, proc.stderr)
        output, errors = bytearray(), bytearray()
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(stdout, selectors.EVENT_READ, output)
                selector.register(stderr, selectors.EVENT_READ, errors)
                while selector.get_map():
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise TransportError('client deadline')
                    for key, _ in selector.select(remaining):
                        chunk = os.read(key.fd, min(4096, cap + 1 - len(output) - len(errors)))
                        if not chunk:
                            selector.unregister(key.fileobj)
                        else:
                            key.data.extend(chunk)
                            if len(output) + len(errors) > cap:
                                raise TransportError('client output bound')
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TransportError('client deadline')
            if proc.wait(timeout=remaining) != 0 or errors:
                raise TransportError('client failed or emitted diagnostic output')
            return bytes(output)
        except subprocess.TimeoutExpired:
            raise TransportError('client deadline') from None
        finally:
            # Session/group created by this invocation only; no ambient process
            # discovery. Always reap the direct child, even on BaseException.
            try:
                os.killpg(proc.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                proc.wait(timeout=0.2)
            except subprocess.TimeoutExpired:
                pass
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                proc.wait(timeout=0.2)
            except subprocess.TimeoutExpired:
                raise TransportError('client settlement uncertain') from None
            finally:
                stdout.close()
                stderr.close()
