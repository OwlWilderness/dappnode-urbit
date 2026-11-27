"""Bounded public report PIPE; adapted from retained lifecycle base.Docker.call.

Client settlement does NOT prove engine settlement. Caller must inspect/stop
only the exact owned container and retain uncertain intent/resources.
"""
import os
import selectors
import signal
import subprocess
import time


def output(argv, timeout=30, stderr=None, text=False):
    import io
    sink = io.BytesIO()
    process = capture(argv, sink, lambda: False, lambda: None,
                      timeout=timeout, stderr=subprocess.DEVNULL)
    if process.returncode != 0:
        raise subprocess.CalledProcessError(process.returncode, argv)
    raw = sink.getvalue()
    return raw.decode() if text else raw


def capture(argv, sink, interrupted, capacity, timeout=30, stderr=subprocess.STDOUT):
    process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=stderr, start_new_session=True)
    assert process.stdout is not None
    selector = selectors.DefaultSelector()
    total = 0
    try:
        selector.register(process.stdout, selectors.EVENT_READ)
        deadline = time.monotonic() + timeout
        while selector.get_map():
            if interrupted() or time.monotonic() >= deadline:
                raise ValueError('bounded report interrupted/deadline')
            capacity()
            for key, _ in selector.select(.2):
                chunk = os.read(key.fileobj.fileno(), 8192)
                if not chunk:
                    selector.unregister(key.fileobj)
                else:
                    total += len(chunk)
                    if total > 65536:
                        raise ValueError('public report output cap')
                    sink.write(chunk)
        process.wait(timeout=2)
        return process
    finally:
        selector.close()
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=5)
        process.stdout.close()
