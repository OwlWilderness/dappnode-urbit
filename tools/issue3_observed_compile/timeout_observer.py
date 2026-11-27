"""Source-only successor; not wired into any execution controller.

No process/engine entrypoint, admission, grant, timer reset or background thread.
All reads are injected, so importing/constructing performs no live observation.
"""


import json
import math
import os
from typing import Any


def parse_stat(raw, expected_pid) -> dict[str, Any]:
    """Parse only numeric own-process counters; never emit command text."""
    if type(raw) is not str or len(raw) > 16384 or type(expected_pid) is not int or not 0 < expected_pid < 2**31:
        raise ValueError('bounded stat required')
    close = raw.rfind(')')
    if (not raw.startswith(f'{expected_pid} (') or close < len(f'{expected_pid} (') or
            raw[close + 1:close + 2] != ' ' or raw[close + 3:close + 4] != ' '):
        raise ValueError('process identity mismatch')
    tail = raw[close + 2:].split()
    if len(tail) < 20 or tail[0] not in ('R', 'S', 'D', 'Z', 'T', 't', 'X', 'x', 'K', 'W', 'P', 'I'):
        raise ValueError('stat fields')
    values = [int(tail[i]) for i in (11, 12, 19)]
    if not all(0 <= value <= 2**63-1 for value in values) or values[0] + values[1] > 2**63-1:
        raise ValueError('stat counters')
    return dict(pid=expected_pid, state=tail[0], cpu_ticks=values[0]+values[1], start_ticks=values[2])


class LinuxFiles:
    """Explicit, inert-until-called read-only backend; no filesystem walk.

    Intended ONLY for a separately accepted isolated Linux guest. Supplying this
    backend neither certifies Linux/containment nor authorizes observation.
    Inject fs in tests; default os is never called during import/construction.
    """
    def __init__(self, pid, fs=os):
        if type(pid) is not int or not 0 < pid < 2**31:
            raise ValueError('fixed positive pid')
        self.pid, self.fs = pid, fs
        self.allowed = {f'/proc/{pid}/stat', f'/proc/{pid}/io'} | {
            '/sys/fs/cgroup/' + name for name in ('memory.events', 'pids.events', 'cpu.stat')}

    def read(self, path, maximum):
        if path not in self.allowed or type(maximum) is not int or maximum != 16384:
            raise ValueError('fixed bounded observer path')
        fs = self.fs
        fd = fs.open(path, fs.O_RDONLY | fs.O_CLOEXEC | fs.O_NOFOLLOW)
        try:
            # A short read is not EOF: never accept a truncated decimal value.
            # At most maximum+1 bytes and maximum+2 reads (one-byte chunks/EOF).
            # Blocking calls still require the caller's separately reaped watchdog.
            data = bytearray()
            while len(data) <= maximum:
                chunk = fs.read(fd, maximum + 1 - len(data))
                if not chunk:
                    return data.decode('ascii')
                data.extend(chunk)
            raise ValueError('virtual-file byte cap')
        finally:
            fs.close(fd)

    def identity(self, path):
        if path != f'/proc/{self.pid}/exe':
            raise ValueError('only exact proc exe identity')
        info = self.fs.stat(path)
        return info.st_dev, info.st_ino

    def usage(self):
        info = self.fs.statvfs('/work')
        return (info.f_blocks-info.f_bfree)*info.f_frsize, info.f_blocks*info.f_frsize


MAX = 2**63 - 1

def integer(value):
    if type(value) is not int or not 0 <= value <= MAX:
        raise ValueError('bounded integer required')
    return value


def counters(raw, keys):
    if type(raw) is not str or len(raw) > 16384:
        raise ValueError('bounded counters required')
    result = {}
    proc_io = set(keys).issubset({'read_bytes', 'write_bytes'})
    expected = {key + ':' if proc_io else key: key for key in keys}
    for line in raw.splitlines():
        parts = line.split()
        if not parts:
            continue
        token = parts[0]
        if ':' in token and (not proc_io or token.count(':') != 1 or not token.endswith(':')):
            raise ValueError('malformed counter name')
        if token in expected:
            key = expected[token]
            if len(parts) != 2 or key in result:
                raise ValueError('duplicate or malformed counter')
            result[key] = integer(int(parts[1]))
    if set(result) != set(keys):
        raise ValueError('missing counters')
    return result


class Snapshot:
    """Read fixed Linux virtual files only via explicitly supplied callbacks.

    read(path, maximum) must do a bounded non-following open/read of virtual files;
    identity('/proc/PID/exe') intentionally follows only the exact proc exe link
    and returns (device, inode). usage() returns /work used,total bytes without a
    directory walk. No raw paths, command names, environment or exception text
    enter the public result. Caller must authenticate compiler inode and process
    start ticks independently; these supplied values are not owner authority.
    """
    def __init__(self, pid, start_ticks, executable_identity, read, identity, usage, ticks_per_second):
        integer(pid); integer(start_ticks)
        if pid == 0 or pid >= 2**31 or type(executable_identity) is not tuple or len(executable_identity) != 2:
            raise ValueError('exact process identity required')
        for value in executable_identity:
            integer(value)
        integer(ticks_per_second)
        if not 0 < ticks_per_second <= 1000000 or not all(callable(f) for f in (read, identity, usage)):
            raise ValueError('explicit snapshot readers required')
        self.pid, self.start = pid, start_ticks
        self.executable = executable_identity
        self.read, self.identity, self.usage, self.hz = read, identity, usage, ticks_per_second

    def __call__(self, gate):
        def read(path):
            gate()
            raw = self.read(path, 16384)
            gate()
            if type(raw) is not str or len(raw) > 16384:
                raise ValueError('reader byte cap')
            return raw
        def identity():
            gate()
            value = self.identity(f'/proc/{self.pid}/exe')
            gate()
            if type(value) is not tuple or len(value) != 2 or any(type(v) is not int for v in value) or value != self.executable:
                raise ValueError('executable generation mismatch')
        first = parse_stat(read(f'/proc/{self.pid}/stat'), self.pid)
        if first['start_ticks'] != self.start:
            raise ValueError('process generation mismatch')
        identity()
        io = counters(read(f'/proc/{self.pid}/io'), ('read_bytes', 'write_bytes'))
        caps = {}
        for name, keys in (('memory.events', ('oom', 'oom_kill', 'high', 'max')),
                           ('pids.events', ('max',)), ('cpu.stat', ('nr_throttled', 'throttled_usec'))):
            caps.update({name + ':' + key: value for key, value in
                         counters(read('/sys/fs/cgroup/' + name), keys).items()})
        gate()
        used, total = self.usage()
        gate()
        integer(used); integer(total)
        if used > total:
            raise ValueError('tmpfs accounting')
        identity()
        last = parse_stat(read(f'/proc/{self.pid}/stat'), self.pid)
        if last['start_ticks'] != self.start or last['cpu_ticks'] < first['cpu_ticks']:
            raise ValueError('process changed during snapshot')
        return dict(last, ticks_per_second=self.hz, io_bytes=io, cap_events=caps,
                    tmpfs_used_bytes=used, tmpfs_total_bytes=total, cache_directory_bytes=None)


CAP_KEYS = ('memory.events:oom', 'memory.events:oom_kill', 'memory.events:high',
            'memory.events:max', 'pids.events:max', 'cpu.stat:nr_throttled', 'cpu.stat:throttled_usec')
ROW_KEYS = {'pid', 'start_ticks', 'state', 'cpu_ticks', 'ticks_per_second', 'io_bytes',
            'cap_events', 'tmpfs_used_bytes', 'tmpfs_total_bytes', 'cache_directory_bytes'}


def public_row(row):
    if type(row) is not dict or set(row) != ROW_KEYS:
        raise ValueError('fixed observer projection')
    for key in ('pid', 'start_ticks', 'cpu_ticks', 'ticks_per_second', 'tmpfs_used_bytes', 'tmpfs_total_bytes'):
        integer(row[key])
    if not 0 < row['pid'] < 2**31 or not 0 < row['ticks_per_second'] <= 1000000 or row['tmpfs_used_bytes'] > row['tmpfs_total_bytes']:
        raise ValueError('observer counter domain')
    if row['state'] not in ('R', 'S', 'D', 'Z', 'T', 't', 'X', 'x', 'K', 'W', 'P', 'I') or row['cache_directory_bytes'] is not None:
        raise ValueError('observer state/cache semantics')
    for name, keys in (('io_bytes', ('read_bytes', 'write_bytes')), ('cap_events', CAP_KEYS)):
        if type(row[name]) is not dict or set(row[name]) != set(keys):
            raise ValueError('finite observer counters')
        for value in row[name].values():
            integer(value)
    return json.loads(json.dumps(row, allow_nan=False))


class Collector:
    """Callable monitor with no scheduler/thread and no lifecycle decisions.

    At most 16 snapshots, 8s apart within the caller's SAME <=120s monotonic
    work endpoint. Gate before and after every supplied I/O. Synchronous reads
    cannot be preempted here: the separately accepted outer watchdog must bound
    blocking I/O. Missing/late/invalid observation degrades evidence only.
    """
    def __init__(self, snapshot, clock, deadline):
        now = clock()
        if not callable(snapshot) or type(now) not in (int, float) or not math.isfinite(now) or now < 0:
            raise ValueError('explicit observer clock/snapshot')
        if type(deadline) not in (int, float) or not math.isfinite(deadline) or not 0 < deadline-now <= 120:
            raise ValueError('unchanged work endpoint required')
        self.snapshot, self.clock, self.deadline = snapshot, clock, deadline
        self.next_due, self.last_clock = now, now
        self.attempts, self.samples = 0, 0
        self.first, self.last = None, None
        self.status = 'unobserved'

    def gate(self):
        now = self.clock()
        if type(now) not in (int, float) or not math.isfinite(now) or now < self.last_clock:
            raise ValueError('monotonic observer clock')
        self.last_clock = now
        if now >= self.deadline:
            raise TimeoutError('original work endpoint reached')
        return now

    def poll(self):
        if self.status in ('degraded', 'deadline', 'sample-cap'):
            return
        try:
            now = self.gate()
            if now < self.next_due:
                return
            if self.attempts >= 16:
                self.status = 'sample-cap'
                return
            self.attempts += 1
            self.next_due = now + 8
            row = public_row(self.snapshot(self.gate))
            self.gate()
            if self.first is not None and any(row[key] != self.first[key] for key in ('pid', 'start_ticks', 'ticks_per_second')):
                raise ValueError('observer generation changed')
            self.first = self.first if self.first is not None else row
            self.last = row
            self.samples += 1
            self.status = 'observed'
        except TimeoutError:
            self.status = 'deadline'
        except (OSError, ValueError, TypeError, OverflowError):
            self.status = 'degraded'

    __call__ = poll

    def summary(self):
        # Numeric CPU/I/O deltas are work proxies, not compiler stage or success.
        cpu_delta, cap_deltas, io_deltas = None, None, None
        if self.samples >= 2:
            assert self.first is not None and self.last is not None
            if self.last['cpu_ticks'] >= self.first['cpu_ticks']:
                cpu_delta = self.last['cpu_ticks'] - self.first['cpu_ticks']
            def deltas(key):
                before, after = self.first[key], self.last[key]
                return {name: after[name]-before[name] if after[name] >= before[name] else None for name in before}
            cap_deltas, io_deltas = deltas('cap_events'), deltas('io_bytes')
        row = dict(schema='issue3-timeout-observer-v1', status=self.status, attempts=self.attempts,
                   samples=self.samples, first=self.first, last=self.last,
                   own_cpu_ticks_delta=cpu_delta, io_bytes_delta=io_deltas, cap_event_deltas=cap_deltas,
                   compiler_stage=None, compiler_success=None, descendant_cpu=None,
                   cache_directory_bytes=None, evidence_only=True)
        encoded = json.dumps(row, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
        if len(encoded) > 4096:
            raise ValueError('aggregate observer output cap')
        return json.loads(encoded)


