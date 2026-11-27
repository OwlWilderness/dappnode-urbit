"""Source-only observer regression; no real proc/cgroup/engine/compiler reads."""
import importlib.util
from pathlib import Path
import unittest
from typing import Any

SOURCE = Path(__file__).resolve().parents[1] / 'tools/issue3_crypto_tls_probe/timeout_observer/observer.py'

def load():
    spec = importlib.util.spec_from_file_location('timeout_observer', SOURCE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def stat(pid=7, start=100, cpu=3):
    fields = ['S'] + ['0'] * 49
    fields[11], fields[12], fields[19] = str(cpu), '2', str(start)
    return f'{pid} (public name ) with spaces) ' + ' '.join(fields)


def sample(cpu=5) -> dict[str, Any]:
    return dict(pid=7, state='S', cpu_ticks=cpu, start_ticks=100, ticks_per_second=100,
                io_bytes={'read_bytes': 10, 'write_bytes': 20},
                cap_events={'memory.events:oom': 0, 'memory.events:oom_kill': 0,
                            'memory.events:high': 0, 'memory.events:max': 0,
                            'pids.events:max': 0, 'cpu.stat:nr_throttled': 0,
                            'cpu.stat:throttled_usec': 0},
                tmpfs_used_bytes=100, tmpfs_total_bytes=200, cache_directory_bytes=None)


class ObserverTests(unittest.TestCase):
    def test_stat_rejects_wrong_pid_and_does_not_expose_command(self):
        module = load()
        self.assertEqual(module.parse_stat(stat(), 7), dict(pid=7, state='S', cpu_ticks=5, start_ticks=100))
        with self.assertRaises(ValueError):
            module.parse_stat(stat(pid=8), 7)

    def test_snapshot_accepts_only_same_generation_and_same_executable(self):
        m = load()
        reads = {'/proc/7/stat': stat(), '/proc/7/io': 'read_bytes: 10\nwrite_bytes: 20\n',
                 '/sys/fs/cgroup/memory.events': 'oom 0\noom_kill 0\nmax 1\nhigh 0\n',
                 '/sys/fs/cgroup/pids.events': 'max 0\n',
                 '/sys/fs/cgroup/cpu.stat': 'nr_throttled 2\nthrottled_usec 3\n'}
        def read(path, maximum):
            self.assertLessEqual(len(reads[path]), maximum)
            return reads[path]
        snapshot = m.Snapshot(7, 100, (1, 2), read, lambda path: (1, 2), lambda: (100, 200), 100)
        row = snapshot(lambda: None)
        self.assertEqual(row['cpu_ticks'], 5)
        self.assertEqual(row['tmpfs_used_bytes'], 100)
        self.assertIsNone(row['cache_directory_bytes'])
        reads['/proc/7/stat'] = stat(start=101)
        with self.assertRaises(ValueError):
            snapshot(lambda: None)

    def test_collector_obeys_original_endpoint_and_finite_cadence(self):
        m = load()
        clock = [10.0]; calls = []
        def snapshot(gate):
            gate(); calls.append(clock[0]); return sample(len(calls))
        collector = m.Collector(snapshot, lambda: clock[0], 30.0)
        collector.poll(); collector.poll()
        clock[0] = 18.0; collector.poll()
        clock[0] = 30.0; collector.poll()
        self.assertEqual(calls, [10.0, 18.0])
        self.assertEqual(collector.summary()['samples'], 2)
        self.assertEqual(collector.summary()['status'], 'deadline')

    def test_snapshot_rejects_boolean_executable_identity(self):
        m = load()
        reads = {'/proc/7/stat': stat(), '/proc/7/io': 'read_bytes: 10\nwrite_bytes: 20\n',
                 '/sys/fs/cgroup/memory.events': 'oom 0\noom_kill 0\nmax 1\nhigh 0\n',
                 '/sys/fs/cgroup/pids.events': 'max 0\n',
                 '/sys/fs/cgroup/cpu.stat': 'nr_throttled 2\nthrottled_usec 3\n'}
        snapshot = m.Snapshot(7, 100, (1, 2), lambda path, maximum: reads[path],
                              lambda path: (True, 2), lambda: (100, 200), 100)
        with self.assertRaises(ValueError):
            snapshot(lambda: None)

    def test_deadline_crossed_during_io_discards_late_snapshot(self):
        m = load(); clock = [10.0]
        def snapshot(gate):
            gate(); clock[0] = 20.0; gate(); return sample()
        collector = m.Collector(snapshot, lambda: clock[0], 20.0)
        collector.poll()
        self.assertEqual(collector.summary()['status'], 'deadline')
        self.assertEqual(collector.summary()['samples'], 0)

    def test_observer_degradation_is_sticky_not_lifecycle_failure(self):
        m = load(); calls = []
        def snapshot(gate):
            calls.append(1); raise PermissionError('private diagnostic')
        collector = m.Collector(snapshot, lambda: 10.0, 30.0)
        collector.poll(); collector.poll()
        self.assertEqual(calls, [1])
        self.assertEqual(collector.summary()['status'], 'degraded')
        self.assertNotIn('private', str(collector.summary()))
        self.assertIsNone(collector.summary()['compiler_success'])

    def test_cpu_io_and_cap_deltas_do_not_claim_stage_or_descendants(self):
        m = load(); clock = [10.0]; current = [sample()]
        collector = m.Collector(lambda gate: current[0], lambda: clock[0], 130.0)
        collector.poll(); current[0] = sample(15)
        current[0]['io_bytes']['read_bytes'] = 100
        current[0]['cap_events']['memory.events:max'] = 3
        clock[0] = 18.0; collector.poll()
        row = collector.summary()
        self.assertEqual(row['own_cpu_ticks_delta'], 10)
        self.assertEqual(row['io_bytes_delta']['read_bytes'], 90)
        self.assertEqual(row['cap_event_deltas']['memory.events:max'], 3)
        self.assertIsNone(row['compiler_stage']); self.assertIsNone(row['descendant_cpu'])

    def test_generation_change_and_counter_reset_never_fabricate_progress(self):
        m = load(); clock = [10.0]; current = [sample(20)]
        collector = m.Collector(lambda gate: current[0], lambda: clock[0], 40.0)
        collector.poll(); current[0] = sample(5); clock[0] = 18.0; collector.poll()
        self.assertIsNone(collector.summary()['own_cpu_ticks_delta'])
        current[0]['start_ticks'] = 101; clock[0] = 26.0; collector.poll()
        self.assertEqual(collector.summary()['status'], 'degraded')
        self.assertEqual(collector.summary()['samples'], 2)

    def test_fixed_namespace_rejects_private_fields_and_nonfinite_counters(self):
        m = load()
        for bad in (dict(sample(), argv=['private']), dict(sample(), cpu_ticks=True),
                    dict(sample(), cpu_ticks=float('nan')), dict(sample(), cache_directory_bytes=1)):
            with self.subTest(bad=str(bad)), self.assertRaises(ValueError):
                m.public_row(bad)
        for text in ('max 1\nmax 2', 'max -1', 'max 18446744073709551616', 'private 1'):
            with self.subTest(text=text), self.assertRaises(ValueError):
                m.counters(text, ('max',))

    def test_aggregate_cap_and_public_summary_are_detached(self):
        import json
        m = load(); clock = [10.0]; row = sample(m.MAX)
        row['io_bytes'] = {key: m.MAX for key in row['io_bytes']}
        row['cap_events'] = {key: m.MAX for key in row['cap_events']}
        row['tmpfs_used_bytes'] = row['tmpfs_total_bytes'] = m.MAX
        collector = m.Collector(lambda gate: row, lambda: clock[0], 130.0)
        for value in range(10, 130, 8):
            clock[0] = float(value); collector.poll()
        saved = collector.summary()
        self.assertLessEqual(saved['attempts'], 16)
        self.assertLessEqual(len(json.dumps(saved, separators=(',', ':')).encode()), 4096)
        saved['first']['cpu_ticks'] = 0
        self.assertEqual(collector.summary()['first']['cpu_ticks'], m.MAX)
        clock[0] = 130.0; collector.poll()
        self.assertEqual(collector.summary()['status'], 'deadline')

    def test_monotonic_clock_and_endpoint_cannot_be_renewed(self):
        m = load()
        for end in (10.0, 131.0, float('inf'), True):
            with self.subTest(end=end), self.assertRaises(ValueError):
                m.Collector(lambda gate: sample(), lambda: 10.0, end)
        clock = [10.0]
        collector = m.Collector(lambda gate: sample(), lambda: clock[0], 30.0)
        collector.poll(); clock[0] = 9.0; collector.poll()
        self.assertEqual(collector.summary()['status'], 'degraded')

    def test_linux_files_reader_is_fixed_path_bounded_and_no_follow(self):
        from types import SimpleNamespace
        m = load(); opened = []; closed = []
        chunks = iter((b'public', b''))
        fs = SimpleNamespace(O_RDONLY=0, O_CLOEXEC=1, O_NOFOLLOW=2,
            open=lambda path, flags: opened.append((path, flags)) or 99,
            read=lambda fd, maximum: next(chunks), close=lambda fd: closed.append(fd),
            stat=lambda path: SimpleNamespace(st_dev=1, st_ino=2),
            statvfs=lambda path: SimpleNamespace(f_blocks=100, f_bfree=60, f_frsize=4096))
        files = m.LinuxFiles(7, fs)
        self.assertEqual(files.read('/proc/7/stat', 16384), 'public')
        self.assertEqual(opened, [('/proc/7/stat', 3)]); self.assertEqual(closed, [99])
        self.assertEqual(files.identity('/proc/7/exe'), (1, 2))
        self.assertEqual(files.usage(), (40*4096, 100*4096))
        with self.assertRaises(ValueError): files.read('/proc/8/environ', 16384)
        with self.assertRaises(ValueError): files.identity('/proc/8/exe')
        fs.read = lambda fd, maximum: b'x' * maximum
        with self.assertRaises(ValueError): files.read('/proc/7/stat', 16384)
        self.assertEqual(closed, [99, 99])

    def test_backend_snapshot_collector_compose_without_live_observations(self):
        from types import SimpleNamespace
        m = load(); clock = [10.0]; current = [5]; descriptors = {}; opened = []
        raw = {'/proc/7/io': b'read_bytes: 10\nwrite_bytes: 20\n',
               '/sys/fs/cgroup/memory.events': b'oom 0\noom_kill 0\nhigh 0\nmax 0\n',
               '/sys/fs/cgroup/pids.events': b'max 0\n',
               '/sys/fs/cgroup/cpu.stat': b'nr_throttled 0\nthrottled_usec 0\n'}
        def open_file(path, flags):
            fd = len(opened) + 100; opened.append(path); descriptors[fd] = (path, False); return fd
        def read_file(fd, maximum):
            path, consumed = descriptors[fd]
            descriptors[fd] = (path, True)
            if consumed:
                return b''
            return stat(cpu=current[0]).encode() if path.endswith('/stat') else raw[path]
        fs = SimpleNamespace(O_RDONLY=0, O_CLOEXEC=1, O_NOFOLLOW=2,
            open=open_file, read=read_file, close=lambda fd: descriptors.pop(fd),
            stat=lambda path: SimpleNamespace(st_dev=1, st_ino=2),
            statvfs=lambda path: SimpleNamespace(f_blocks=100, f_bfree=60, f_frsize=4096))
        files = m.LinuxFiles(7, fs)
        snapshot = m.Snapshot(7, 100, (1, 2), files.read, files.identity, files.usage, 100)
        collector = m.Collector(snapshot, lambda: clock[0], 40.0)
        collector.poll(); current[0] = 15; clock[0] = 18.0; collector.poll()
        row = collector.summary()
        self.assertEqual(row['samples'], 2); self.assertEqual(row['own_cpu_ticks_delta'], 10)
        self.assertEqual(row['status'], 'observed'); self.assertEqual(descriptors, {})
        self.assertEqual(len(opened), 12)
        self.assertIsNone(row['compiler_success'])

    def test_observer_source_exists(self):
        self.assertTrue(SOURCE.is_file(), 'bounded timeout observer source absent')

if __name__ == '__main__':
    unittest.main()
