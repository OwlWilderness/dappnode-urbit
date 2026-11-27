"""Bounded public compiler observer, selected only by the late driver.

Metadata and activity are not cache validation, step completion or an ETA.
No observer assessment can extend a deadline or cancel a build.
"""
import hashlib
import os
from pathlib import Path
import re
import time
from typing import Any

PRESSURE_FILES = ('memory.current', 'memory.peak', 'memory.events', 'cpu.stat',
                  'cpu.pressure', 'memory.pressure', 'io.pressure')
PRESSURE_COMMAND = ("printf '\\nI3_CGROUP_BEGIN\\n'; for f in "+' '.join(PRESSURE_FILES)+
    "; do printf 'FILE %s\\n' \"$f\"; if [ -r /sys/fs/cgroup/\"$f\" ]; then "
    "head -c 4096 /sys/fs/cgroup/\"$f\"; printf '\\n'; else printf 'unavailable\\n'; fi; "
    "done; printf 'I3_CGROUP_END\\n'")


def pressure_sample(text, previous=None, now=None):
    """Exact builder-visible cgroup counters; absent PSI never a compile fault."""
    now = time.monotonic() if now is None else now
    files, unavailable, current, healthy = {}, [], None, True
    if len(text) > 32768 or 'I3_CGROUP_BEGIN\n' not in text or 'I3_CGROUP_END' not in text:
        return dict(healthy=False, monotonic=now, files={}, unavailable=list(PRESSURE_FILES), delta={},
                    last_success_monotonic=(previous or {}).get('last_success_monotonic'))
    body = text.split('I3_CGROUP_BEGIN\n',1)[1].split('I3_CGROUP_END',1)[0]
    try:
        for line in body.splitlines():
            if line.startswith('FILE '):
                current = line[5:]
                if current not in PRESSURE_FILES or current in files:
                    raise ValueError('unexpected counter')
                files[current] = {}
            elif line and current:
                parts = line.split()
                if parts == ['unavailable']:
                    unavailable.append(current)
                elif len(parts) == 1:
                    files[current]['value'] = int(parts[0])
                elif current.endswith('.pressure'):
                    files[current][parts[0]] = {k:float(v) for k,v in (p.split('=',1) for p in parts[1:])}
                else:
                    files[current][parts[0]] = int(parts[1])
    except (ValueError, IndexError):
        healthy = False
    unavailable = sorted(set(unavailable) | (set(PRESSURE_FILES)-set(files)))
    delta, reset = {}, []
    for name in ('cpu.stat', 'memory.events'):
        delta[name] = {}
        for key, value in files.get(name, {}).items():
            old = (previous or {}).get('files',{}).get(name,{}).get(key)
            if old is not None:
                if value < old:
                    reset.append(name+'.'+key)
                else:
                    delta[name][key] = value-old
    rate = None
    elapsed = now-(previous or {}).get('monotonic', now)
    usage = delta.get('cpu.stat',{}).get('usage_usec')
    if elapsed > 0 and usage is not None:
        rate = usage/1000000/elapsed
    healthy = healthy and any(bool(v) for v in files.values())
    return dict(healthy=healthy, monotonic=now, files=files, unavailable=unavailable, delta=delta,
        last_success_monotonic=now if healthy else (previous or {}).get('last_success_monotonic'),
        counter_reset=reset, cpu_seconds_per_wall_second=rate,
        quota_normalized_usage=None if rate is None else rate/2,
        scope='builder cgroup including descendants; overlaps compiler PG, never add',
        baseline_files=(previous or {}).get('baseline_files', files))


def cache_sample(output, source, max_entries=100000, seconds=.5) -> dict[str, Any]:
    """Only sibling compiler caches and installed output; shared scan budget."""
    deadline = time.monotonic()+seconds
    scanned, complete, errors, roots = 0, True, 0, {}
    for label, root in (('global', output/'zig-cache'), ('local', output/'zig-local-cache'),
                        ('output', source/'zig-out')):
        count = size = newest = objects = archives = 0
        fingerprint = 0  # commutative metadata fingerprint, not content authentication
        present = root.exists()
        pending = [root] if present else []
        while pending and complete:
            directory = pending.pop()
            if directory.is_symlink():
                errors += 1
                continue
            try:
                with os.scandir(directory) as entries:
                    for entry in entries:
                        if scanned >= max_entries or time.monotonic() >= deadline:
                            complete = False
                            break
                        scanned += 1
                        if entry.is_symlink():
                            continue
                        if entry.is_dir(follow_symlinks=False):
                            pending.append(Path(entry.path))
                        elif entry.is_file(follow_symlinks=False):
                            st = entry.stat(follow_symlinks=False)
                            # Include metadata/manifests as cache activity, not only .o.
                            count += 1
                            objects += int(entry.name.endswith('.o'))
                            archives += int(entry.name.endswith('.a'))
                            size += st.st_size
                            newest = max(newest, st.st_mtime_ns)
                            item = f'{Path(entry.path).relative_to(root)}:{st.st_size}:{st.st_mtime_ns}\n'
                            fingerprint ^= int.from_bytes(hashlib.sha256(item.encode()).digest(), 'big')
            except FileNotFoundError:
                errors += 1
            except OSError:
                errors += 1
        roots[label] = dict(present=present, files=count, bytes=size, newest_ns=newest,
                            object_files=objects, archive_files=archives,
                            metadata_sha256=f'{fingerprint:064x}', complete=complete and errors == 0)
    return dict(roots=roots, scanned=scanned, errors=errors, complete=complete and errors == 0)


def read_small(path, limit=4096):
    with path.open('rb') as stream:
        data = stream.read(limit+1)
    if len(data) > limit:
        raise ValueError('observer input capped')
    return data.decode(errors='replace')


def process_sample(pgid, proc=Path('/proc'), max_entries=4096, max_rows=64, seconds=.15) -> dict[str, Any]:
    """Own ticks only; identity is (pid,start_ticks), not a reusable PID."""
    deadline = time.monotonic()+seconds
    rows, errors, complete, scanned = [], 0, True, 0
    with os.scandir(proc) as entries:
        for entry in entries:
            scanned += 1
            if scanned > max_entries or time.monotonic() > deadline:
                complete = False
                break
            if not entry.name.isdigit():
                continue
            try:
                p = Path(entry.path)
                text = read_small(p/'stat')
                fields = text.rsplit(')', 1)[1].split()
                comm = text.split('(', 1)[1].rsplit(')', 1)[0]
                rows.append(dict(pid=int(entry.name), ppid=int(fields[1]), pgid=int(fields[2]),
                    start_ticks=int(fields[19]), state=fields[0], name=comm[:64],
                    own_cpu_ticks=int(fields[11])+int(fields[12]), rss_pages=int(fields[21])))
            except FileNotFoundError:
                continue  # process exit race, not an observer failure
            except (OSError, ValueError, IndexError):
                errors += 1
    selected = {r['pid'] for r in rows if r['pgid'] == pgid or r['pid'] == pgid}
    for _ in range(len(rows)):
        extra = {r['pid'] for r in rows if r['ppid'] in selected} - selected
        if not extra:
            break
        selected |= extra
    table = sorted((r for r in rows if r['pid'] in selected), key=lambda r: r['pid'])
    if len(table) > max_rows:
        complete = False
    table = table[:max_rows]
    for row in table:
        p = proc/str(row['pid'])
        if time.monotonic() >= deadline:
            row['io'] = None
            row['executable_basename'] = None
            complete = False
            continue
        try:
            row['io'] = {k:int(v) for k,v in (line.split(':',1) for line in read_small(p/'io').splitlines())
                         if k in ('rchar','wchar','read_bytes','write_bytes','syscr','syscw')}
            # Recheck identity after reading I/O: reused PIDs must not mix counters.
            fields = read_small(p/'stat').rsplit(')',1)[1].split()
            if int(fields[19]) != row['start_ticks']:
                row['io'] = None
                complete = False
        except (OSError,ValueError,IndexError):
            row['io'] = None
        try:
            row['executable_basename'] = Path(os.readlink(p/'exe')).name[:64]
        except OSError:
            row['executable_basename'] = None
    return dict(table=table, own_cpu_ticks=sum(r['own_cpu_ticks'] for r in table),
                complete=complete and errors == 0, errors=errors, scanned=scanned)


class StageDiagnostics:
    """Drop-in late-only observer; original Attempt owns all safety decisions."""
    def __init__(self, attempt, log_path, cwd, interval=30, quiet_seconds=120):
        self.attempt, self.log_path, self.cwd = attempt, log_path, cwd
        self.interval, self.quiet_seconds = interval, quiet_seconds
        self.offset, self.stream_limit, self.capped = 0, 2*1024**2, False
        self.last_sample = float('-inf')
        self.entered = self.last_semantic = self.last_active = time.monotonic()
        self.previous = self.semantic = None
        self.previous_caches = None
        self.previous_log_bytes = None
        self.last_success, self.failures = None, 0
        self.sink_failed = False
        self.preview_capped = False
        self.was_healthy = True
        self.preview_names, self.preview_tail = set(), ''

    def emit(self, status, **values):
        # Shared across phases; do not reset telemetry allowance on stage entry.
        import json
        used = getattr(self.attempt, '_progress_bytes', 0)
        size = len(json.dumps(dict(status=status, **values)).encode())+256
        if used+size > 8*1024**2:
            if not getattr(self.attempt, '_progress_capped', False):
                self.attempt._progress_capped = True
                try:
                    self.attempt.event('observer-capped', limit_bytes=8*1024**2,
                                       assessment='observer-degraded', safety_action='none')
                except Exception:
                    self.failures += 1
            return
        self.attempt._progress_bytes = used+size
        try:
            self.attempt.event(status, **values)
            self.sink_failed = False
        except Exception:
            self.failures += 1
            self.sink_failed = True

    def update(self, pgid, force=False):
        now = time.monotonic()
        healthy, failure, sample, caches, log_bytes = True, None, {}, {}, None
        churn, cache_deltas, log_delta, active = False, {}, None, False
        try:
            log_bytes = self.log_path.stat().st_size
            if self.offset < min(log_bytes, self.stream_limit):
                with self.log_path.open('rb') as log:
                    log.seek(self.offset)
                    data = log.read(min(32768, self.stream_limit-self.offset))
                self.offset += len(data)
                text = data.decode(errors='replace')
                for path in re.findall(r'ar rcs (\S{1,512}\.a)(?: |\n)', self.preview_tail+text):
                    if len(self.preview_names) < 128:
                        self.preview_names.add(Path(path).name)
                    elif Path(path).name not in self.preview_names:
                        self.preview_capped = True
                self.preview_tail = text[-1024:]
                self.emit('compiler-output', text=text)
            if log_bytes > self.stream_limit and not self.capped:
                self.capped = True
                self.emit('compiler-stream-capped', limit_bytes=self.stream_limit)
            if not force and now-self.last_sample < self.interval:
                return
            sample = process_sample(pgid)
            source = self.cwd if self.attempt.current == 'vere-build' else self.attempt.output/'__not_source__'
            caches = cache_sample(self.attempt.output, source)
            healthy = sample['complete'] and caches['complete'] and all(r['io'] is not None for r in sample['table'])
            identity = {(r['pid'], r['start_ticks']): r for r in sample['table']}
            log_delta = None if self.previous_log_bytes is None else log_bytes-self.previous_log_bytes
            active = log_delta is not None and log_delta != 0
            for row in identity.values():
                row['own_cpu_delta_ticks'] = None
            if self.previous is not None:
                churn = identity.keys() != self.previous.keys()
                for key, row in identity.items():
                    old = self.previous.get(key)
                    if old is not None:
                        row['own_cpu_delta_ticks'] = max(0,row['own_cpu_ticks']-old['own_cpu_ticks'])
                        active |= row['own_cpu_ticks'] > old['own_cpu_ticks']
                        if old['io'] is not None and row['io'] is not None:
                            active |= any(value > old['io'].get(k, value) for k, value in row['io'].items())
            signature = (len(self.preview_names), tuple((k, v['metadata_sha256']) for k, v in caches['roots'].items()))
            if healthy:
                if signature != self.semantic:
                    self.last_semantic = now
                if active or churn or signature != self.semantic:
                    self.last_active = now
                if self.previous_caches is not None:
                    cache_deltas = {k:{field:v[field]-self.previous_caches[k][field]
                        for field in ('files','bytes','object_files','archive_files')} for k,v in caches['roots'].items()}
                self.previous_caches = caches['roots']
                self.previous_log_bytes = log_bytes
                self.semantic, self.previous = signature, identity
                self.last_success = now
        except Exception as error:
            # Never turn observer I/O/parse failures into compiler failure/stall.
            healthy, failure = False, type(error).__name__
            if not force and now-self.last_sample < self.interval:
                return
        self.last_sample = now
        healthy = healthy and not self.sink_failed
        if healthy and not self.was_healthy:
            # An observation gap cannot establish continuous inactivity.
            self.last_active = now
        self.was_healthy = healthy
        if not healthy:
            self.failures += 1
        quiet = now-self.last_semantic
        assessment = ('observer-degraded' if not healthy else
                      'suspected-idle' if now-self.last_active >= 600 else
                      'slow-active-no-milestone' if quiet >= self.quiet_seconds and (active or churn) else
                      'idle-warning' if quiet >= self.quiet_seconds else 'observing')
        self.emit('progress', monotonic=now, phase=self.attempt.current,
            phase_elapsed_seconds=round(now-self.entered, 3), assessment=assessment,
            no_milestone_seconds=round(quiet, 3), safety_action='none', useful_work_proven=False,
            archive_preview_names=sorted(self.preview_names), archive_preview_count=len(self.preview_names),
            preview_limit=128, log_bytes=log_bytes, mirrored_bytes=self.offset, processes=sample, caches=caches,
            preview_capped=self.preview_capped,
            log_delta_bytes=log_delta,
            process_churn=churn, cache_deltas=cache_deltas,
            observer=dict(healthy=healthy, failures=self.failures, error=failure,
                          phase_sink_failures=getattr(self.attempt,'_phase_observer_failures',0),
                          last_success_monotonic=self.last_success))

    def tail(self):
        try:
            with self.log_path.open('rb') as log:
                log.seek(max(0, log.seek(0, 2)-12000))
                self.emit('compiler-tail', text=log.read(12000).decode(errors='replace'))
        except OSError as error:
            self.emit('observer-tail-failed', error=type(error).__name__, safety_action='none')
