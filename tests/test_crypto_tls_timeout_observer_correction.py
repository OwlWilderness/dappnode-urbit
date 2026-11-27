"""Durable synthetic regressions for independently reproduced observer defects."""
import unittest
from types import SimpleNamespace
import test_crypto_tls_timeout_observer as fixture


class CorrectionTests(unittest.TestCase):
    def test_short_decimal_read_requires_eof(self):
        m = fixture.load(); calls = []; closed = []
        chunks = iter([b'read_bytes: 1\nwrite_bytes: 2', b'0\n', b''])
        fs = SimpleNamespace(O_RDONLY=0, O_CLOEXEC=1, O_NOFOLLOW=2,
            open=lambda path, flags: 99,
            read=lambda fd, n: calls.append(n) or next(chunks), close=closed.append)
        text = m.LinuxFiles(7, fs).read('/proc/7/io', 16384)
        self.assertEqual(m.counters(text, ('read_bytes', 'write_bytes'))['write_bytes'], 20)
        self.assertEqual(len(calls), 3)
        self.assertEqual(closed, [99])

    def test_stat_requires_exact_prefix_and_delimiters(self):
        m = fixture.load(); valid = fixture.stat()
        self.assertEqual(m.parse_stat(valid, 7)['cpu_ticks'], 5)
        for raw in (valid.replace('(public', 'public', 1),
                    valid.replace('7 (', '7  (', 1),
                    valid.replace(') S ', ')xS ', 1),
                    valid.replace(') S ', ')  S ', 1),
                    valid.replace(') S ', ') S\t', 1)):
            with self.subTest(raw=raw[:50]), self.assertRaises(ValueError):
                m.parse_stat(raw, 7)

    def test_counter_names_are_literal_not_colon_normalized(self):
        m = fixture.load()
        self.assertEqual(m.counters('oom 7', ('oom',)), {'oom': 7})
        self.assertEqual(m.counters('read_bytes: 7', ('read_bytes',)), {'read_bytes': 7})
        for text, keys in [('o:om 7', ('oom',)), ('oom: 7', ('oom',)),
                           ('oom 7\no:om 8', ('oom',)),
                           ('read_bytes:: 7', ('read_bytes',)),
                           ('read_:bytes: 7', ('read_bytes',)),
                           ('read_bytes 7', ('read_bytes',)),
                           ('read_bytes: 7:0', ('read_bytes',))]:
            with self.subTest(text=text), self.assertRaises(ValueError):
                m.counters(text, keys)

    def test_read_aggregate_cap_eof_and_descriptor_error_paths(self):
        m = fixture.load()
        for size in (16384, 16385):
            calls = []; closed = []; remaining = [size]
            def read(fd, limit):
                calls.append(limit)
                if remaining[0]:
                    remaining[0] -= 1
                    return b'x'
                return b''
            fs = SimpleNamespace(O_RDONLY=0, O_CLOEXEC=1, O_NOFOLLOW=2,
                open=lambda path, flags: 99, read=read, close=closed.append)
            if size == 16384:
                self.assertEqual(len(m.LinuxFiles(7, fs).read('/proc/7/stat', 16384)), size)
            else:
                with self.assertRaises(ValueError):
                    m.LinuxFiles(7, fs).read('/proc/7/stat', 16384)
            self.assertEqual(len(calls), 16385)
            self.assertEqual(calls[-1], 1)
            self.assertEqual(closed, [99])
        for error in (OSError('read failed'), b'\xff'):
            chunks = iter([b'prefix', error, b''])
            closed = []
            def read_error(fd, limit):
                value = next(chunks)
                if isinstance(value, Exception):
                    raise value
                return value
            fs.read = read_error; fs.close = closed.append
            with self.assertRaises((OSError, ValueError)):
                m.LinuxFiles(7, fs).read('/proc/7/stat', 16384)
            self.assertEqual(closed, [99])

    def test_eof_after_endpoint_discards_backend_sample(self):
        m = fixture.load(); clock = [0]; chunks = iter([fixture.stat().encode(), b''])
        closed = []; calls = []
        def read(fd, limit):
            calls.append(limit)
            value = next(chunks)
            if not value:
                clock[0] = 10
            return value
        fs = SimpleNamespace(O_RDONLY=0, O_CLOEXEC=1, O_NOFOLLOW=2,
            open=lambda path, flags: 99, read=read, close=closed.append)
        files = m.LinuxFiles(7, fs)
        def forbidden(*args):
            self.fail('late read must not reach later snapshot operations')
        snapshot = m.Snapshot(7, 100, (1, 2), files.read, forbidden, forbidden, 100)
        collector = m.Collector(snapshot, lambda: clock[0], 10)
        collector.poll()
        self.assertEqual(collector.status, 'deadline')
        self.assertEqual(collector.samples, 0)
        self.assertEqual(len(calls), 2)
        self.assertEqual(closed, [99])


if __name__ == '__main__':
    unittest.main()
