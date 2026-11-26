"""Synthetic libc allocation accounting, NOT an OpenSSL/Vere workload."""
import ctypes
import json
import os
from pathlib import Path
import time
import unittest

class MemoryAccounting(unittest.TestCase):
    def test_native_heap_is_visible_in_rss_and_cgroup(self):
        libc = ctypes.CDLL(None)
        libc.malloc.argtypes = [ctypes.c_size_t]
        libc.malloc.restype = ctypes.c_void_p
        libc.free.argtypes = [ctypes.c_void_p]
        def sample():
            values = {}
            for line in Path('/proc/self/status').read_text().splitlines():
                if line.startswith(('VmRSS:', 'VmHWM:')):
                    k, v, _ = line.split()
                    values[k[:-1]] = int(v) * 1024
            for name in ('memory.current', 'memory.peak', 'memory.max'):
                values[name] = int((Path('/sys/fs/cgroup') / name).read_text())
            values['memory.events'] = dict((k, int(v)) for k, v in
                (line.split() for line in Path('/sys/fs/cgroup/memory.events').read_text().splitlines()))
            return values
        size = 32 * 1024 * 1024
        before = sample()
        ptr = libc.malloc(size)
        self.assertTrue(ptr)
        try:
            ctypes.memset(ptr, 0xA5, size)
            time.sleep(0.2)
            during = sample()
        finally:
            libc.free(ptr)
        time.sleep(0.2)
        after = sample()
        evidence = dict(scope='synthetic libc native heap only; no OpenSSL or Vere execution',
                        architecture=os.uname().machine, allocation_bytes=size,
                        before=before, during=during, after=after)
        print(json.dumps(evidence), flush=True)
        self.assertGreater(during['VmRSS'] - before['VmRSS'], size // 2)
        self.assertGreater(during['memory.current'] - before['memory.current'], size // 2)
        self.assertGreater(during['memory.current'] - after['memory.current'], size // 2)
        self.assertGreaterEqual(during['memory.peak'], during['memory.current'])
        self.assertEqual(after['memory.events']['oom_kill'], before['memory.events']['oom_kill'])
        self.assertEqual(after['memory.max'], 512 * 1024 * 1024)

if __name__ == '__main__':
    unittest.main(verbosity=2)
