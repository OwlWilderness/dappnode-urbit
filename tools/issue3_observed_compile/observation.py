"""Popen-owned read-only binding; no launch, authority or import-time I/O.

All synchronous reads run inside phase_worker.fork_supervise's absolute endpoint.
An authenticated executable file and private accounting mounts are prerequisites,
not supplied PID/start assertions. Domain identities are checked around each
snapshot; this is not an atomic exec attestation or descendant CPU observation.
"""
import math
import os
from . import timeout_observer as observer
from .stage import save_new
from . import wire


class Session:
    """Finite immutable cumulative receipts. Telemetry loss never changes capture outcome."""
    def __init__(self,process,executable,deadline,evidence,clock):
        self.binding=None; self.collector=None; self.evidence=evidence; self.index=0
        self.clock=clock; self.deadline=deadline; self.disabled=False
        try:
            self.binding,snapshot=bind(process,executable,None,clock,deadline)
            self.collector=observer.Collector(snapshot,clock,deadline)
        except Exception:
            self.disabled=True

    def poll(self):
        if self.index>=16: return
        try:
            if self.collector is None:
                if self.index: return
                empty=observer.Collector(lambda gate:None,lambda:0.,1.)
                empty.status='degraded'
                summary=empty.summary()
            else:
                before=self.collector.attempts
                self.collector.poll()
                if self.collector.attempts==before: return
                summary=self.collector.summary()
            row=dict(schema='issue3-compile-observation-v1',binding=self.binding,summary=summary)
            # Exact frame cap, not just aggregate cap: include name/envelope/newline.
            from .output_contract import observation_record, observation_name, frame
            name=observation_name(self.index)
            observation_record(row)
            frame(name,row)
            if self.clock()>=self.deadline: return
            save_new(self.evidence/name.split('/')[-1],wire.encoded(row))
            self.index+=1
        except Exception:
            self.disabled=True
            self.index=16


class Files(observer.LinuxFiles):
    def __init__(self, pid, fs=os):
        super().__init__(pid,fs)
        self.allowed |= {f'/proc/{pid}/cgroup','/proc/self/cgroup','/proc/self/mountinfo'}
        self.hz = fs.sysconf('SC_CLK_TCK')

    def identity(self,path):
        if path not in (f'/proc/{self.pid}/exe','/toolchain/zig','/sys/fs/cgroup','/work'):
            raise ValueError('fixed binding identity path')
        info=self.fs.stat(path,follow_symlinks=path.endswith('/exe'))
        return info.st_dev,info.st_ino


def bind(process, executable, files, clock, deadline):
    """Called only after real Popen returns, with that owned handle, never profile PID."""
    pid=process.pid
    backend=files if files is not None else Files(pid)
    last=clock()
    def gate():
        nonlocal last
        now=clock()
        if type(now) not in (int,float) or not math.isfinite(now) or now<last:
            raise ValueError('binding clock')
        last=now
        if now>=deadline: raise TimeoutError('original work endpoint')
    def read(path):
        gate(); value=backend.read(path,16384); gate(); return value
    def identity(path):
        gate(); value=backend.identity(path); gate()
        if type(value) is not tuple or len(value)!=2:
            raise ValueError('domain identity')
        for v in value: observer.integer(v)
        return value
    first=observer.parse_stat(read(f'/proc/{pid}/stat'),pid)
    compiler=identity(executable)
    if identity(f'/proc/{pid}/exe')!=compiler: raise ValueError('executable mismatch')
    cgroup=identity('/sys/fs/cgroup'); tmpfs=identity('/work')
    def domains():
        if read(f'/proc/{pid}/cgroup')!='0::/\n' or read('/proc/self/cgroup')!='0::/\n':
            raise ValueError('private unified accounting membership')
        mounts=[line.split() for line in read('/proc/self/mountinfo').splitlines()]
        for path,kind,access in (('/work','tmpfs','rw'),('/sys/fs/cgroup','cgroup2','ro')):
            selected=[m for m in mounts if len(m)>8 and m[4]==path and '-' in m]
            if len(selected)!=1 or access not in selected[0][5].split(',') or selected[0][selected[0].index('-')+1]!=kind:
                raise ValueError('accounting mount domain')
        if identity('/sys/fs/cgroup')!=cgroup or identity('/work')!=tmpfs:
            raise ValueError('accounting generation changed')
    domains()
    last_stat=observer.parse_stat(read(f'/proc/{pid}/stat'),pid)
    if last_stat['start_ticks']!=first['start_ticks'] or identity(f'/proc/{pid}/exe')!=compiler:
        raise ValueError('process generation changed at binding')
    snapshot=observer.Snapshot(pid,first['start_ticks'],compiler,backend.read,backend.identity,backend.usage,backend.hz)
    def sample(sample_gate):
        sample_gate(); domains(); sample_gate()
        row=snapshot(sample_gate)
        domains(); sample_gate()
        return row
    return dict(pid=pid,start_ticks=first['start_ticks'],executable=list(compiler),cgroup=list(cgroup),tmpfs=list(tmpfs)),sample
