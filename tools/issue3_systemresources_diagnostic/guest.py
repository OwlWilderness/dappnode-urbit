"""Single-use public-input compiler diagnostic; no import-time execution.

No ptrace, added capabilities or seccomp exception. QEMU_STRACE requests the
engine user-emulator's own syscall logging; unsupported engines may ignore it.
Only allocation/thread/limit/affinity lines and compiler error lines are retained.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import selectors
import signal
import subprocess
import sys
import time

CALLS=rb'(mmap|mmap2|mprotect|munmap|brk|clone|clone3|sched_getaffinity|prlimit64|setrlimit)'
class TraceFilter:
    def __init__(self, cap):
        self.cap=cap
        self.retained=bytearray()
        self.first_failure=None
        self.total=0
        self.selected=0
    def feed(self,line):
        self.total+=len(line)
        m=re.search(rb'\b'+CALLS+rb'\(',line)
        if m:
            self.selected+=1
            err=re.search(rb'= -1 errno=(\d+)',line)
            if err and m[1] in (b'mmap',b'mmap2',b'mprotect',b'brk',b'clone',b'clone3') and self.first_failure is None:
                self.first_failure={'syscall':m[1].decode(),'errno':int(err[1]),'line':line.decode('utf8','replace').strip()}
        if m or line.startswith(b'error:'):
            if len(self.retained)+len(line)>self.cap: raise ValueError('selected trace cap')
            self.retained.extend(line)

STATUS={'Name','State','VmPeak','VmSize','VmRSS','VmHWM','VmData','VmStk','VmExe','VmLib','VmPTE','VmSwap','Threads','Cpus_allowed_list','Mems_allowed_list','NoNewPrivs','Seccomp','CapEff'}
CG=('memory.max','memory.swap.max','memory.current','memory.peak','memory.events','pids.max','pids.current','pids.peak','pids.events','cpu.max','cpu.stat','cpuset.cpus.effective')
def read(path):
    try:
        with open(path) as f: return f.read(16384)
    except OSError as exc: return 'UNAVAILABLE:'+str(exc.errno)
def snapshot(pid):
    root='/proc/'+str(pid)
    status={k:v.strip() for line in read(root+'/status').splitlines() if ':' in line for k,v in [line.split(':',1)] if k in STATUS}
    return {'pid':pid,'status':status,'limits':read(root+'/limits'),
            'cgroup':{k:read('/sys/fs/cgroup/'+k).strip() for k in CG},
            'tmpfs':{p:{'available':(s:=os.statvfs(p)).f_bavail*s.f_frsize,'free_inodes':s.f_favail} for p in ('/work','/output')},
            'engine_free_bytes':(s:=os.statvfs('/')).f_bavail*s.f_frsize,
            'at_monotonic':time.monotonic()}
def emit(kind,data):
    print(json.dumps({'kind':kind,'data':data},sort_keys=True),flush=True)

def child(argv):
    # Applied in same child which execs pinned compiler; no memory/pid relaxation.
    os.umask(0o077)
    for k,v in ((resource.RLIMIT_AS,1073741824),(resource.RLIMIT_NPROC,64),(resource.RLIMIT_NOFILE,64),
                (resource.RLIMIT_CPU,120),(resource.RLIMIT_FSIZE,67108864),(resource.RLIMIT_CORE,0)):
        resource.setrlimit(k,(v,v))
    Path('/output/effective-child.json').write_text(json.dumps(snapshot(os.getpid()),sort_keys=True))
    env={'PATH':'/usr/bin:/bin','LC_ALL':'C','HOME':'/work','TMPDIR':'/work',
         'ZIG_LOCAL_CACHE_DIR':'/work/zig-local','ZIG_GLOBAL_CACHE_DIR':'/work/zig-global','QEMU_STRACE':'1'}
    os.execve(argv[0],argv,env)

def main():
    conf=json.loads(Path('/diagnostic/config.json').read_text())
    if len(sys.argv)>1 and sys.argv[1]=='--child':
        child(conf['argv']); return
    for key,pin in conf['runtime'].items():
        path=pin['path']; data=Path(path).read_bytes()
        assert len(data)==pin['bytes'] and hashlib.sha256(data).hexdigest()==pin['sha256'],key+' identity'
    assert os.getuid()==os.getgid()==10000
    before=snapshot(os.getpid())
    assert {k:before['cgroup'][k] for k in ('memory.max','memory.swap.max','pids.max','cpu.max')}=={
        'memory.max':'1073741824','memory.swap.max':'0','pids.max':'64','cpu.max':'100000 100000'}
    assert before['engine_free_bytes']>=16*1024**3,'engine admission floor'
    # Selected executables only, not process environment, maps, filesystem or secrets.
    emit('preflight',{'snapshot':before,'self_exe':os.readlink('/proc/self/exe'),
         'tracer_available':{p:os.access(p,os.X_OK) for p in ('/usr/bin/strace','/bin/strace','/usr/bin/qemu-x86_64','/usr/bin/qemu-x86_64-static')},
         'mechanism':'QEMU_STRACE=1 on compiler exec only; no security exceptions'})
    started=time.monotonic(); end=started+conf['compile_seconds']
    proc=subprocess.Popen([sys.executable,'-I','-S','/diagnostic/guest.py','--child'],cwd='/work',
        env={'PATH':'/usr/bin:/bin','LC_ALL':'C','PYTHONDONTWRITEBYTECODE':'1'},
        stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
    assert proc.stdout is not None and proc.stderr is not None
    emit('compiler_pid',{'pid':proc.pid,'pgid':proc.pid})
    filt=TraceFilter(conf['selected_trace_bytes']); pending=b''; stdout=bytearray(); samples=[]; reason='EXIT'
    try:
        with selectors.DefaultSelector() as sel:
            sel.register(proc.stdout,selectors.EVENT_READ,'stdout'); sel.register(proc.stderr,selectors.EVENT_READ,'stderr')
            while sel.get_map():
                if time.monotonic()>=end: reason='DEADLINE'; raise TimeoutError('compiler deadline')
                samples.append(snapshot(proc.pid))
                assert len(samples)<=12000,'telemetry samples cap'
                for key,_ in sel.select(.01):
                    data=os.read(key.fd,8192)
                    if not data: sel.unregister(key.fileobj); continue
                    if key.data=='stdout':
                        stdout.extend(data); assert len(stdout)<=1048576,'stdout cap'
                    else:
                        pending+=data
                        assert filt.total+len(pending)<=conf['raw_stderr_bytes'],'raw trace budget'
                        while b'\n' in pending:
                            line,pending=pending.split(b'\n',1); filt.feed(line+b'\n')
                        assert len(pending)<=65536,'trace line cap'
            if pending: filt.feed(pending)
            proc.wait(timeout=max(.01,end-time.monotonic()))
    except Exception as exc:
        if reason=='EXIT': reason=type(exc).__name__+': '+str(exc)
    finally:
        for sig in (signal.SIGTERM,signal.SIGKILL):
            try: os.killpg(proc.pid,sig)
            except ProcessLookupError: pass
        proc.wait(timeout=2)
        proc.stdout.close();proc.stderr.close()
    emit('effective_child',json.loads(Path('/output/effective-child.json').read_text()) if Path('/output/effective-child.json').exists() else {'missing':True})
    for row in samples: emit('sample',row)
    emit('selected_trace',filt.retained.decode('utf8','replace'))
    emit('compiler_result',{'returncode':proc.returncode,'reason':reason,'reaped':True,'elapsed_seconds':time.monotonic()-started,
        'first_failed_allocation_or_thread':filt.first_failure,'raw_stderr_bytes':filt.total,'selected_lines':filt.selected,
        'stdout_bytes':len(stdout),'stdout_sha256':hashlib.sha256(stdout).hexdigest(),
        'syscall_observable':filt.selected>0,'after':snapshot(os.getpid()),'runtime_cases':0,
        'artifacts':{n:Path('/output/'+n).exists() for n in ('probe','probe.map')},
        'unknown_if_unobservable':'No selected emulator self-trace syscall lines. QEMU_STRACE may be unsupported/ignored by engine-managed emulator; no ptrace installed or security exception attempted.' if filt.selected==0 else None})

if __name__=='__main__': main()
