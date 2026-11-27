"""Isolated Linux bootstrap and bounded public export. No Docker or host fallback.

Run with the pinned canonical Python -I -S script path. Heartbeats precede a
single tar stream; target stdout/stderr remain in their separate bounded files.
"""
import hashlib
import json
import os
from pathlib import Path
import struct
import sys
import tarfile
import threading
import time

if __package__ in (None,''):
    sys.path.insert(0,'/controller')
from tools.issue3_crypto_tls_probe import execution, output_contract, prepare, supervisor, wire
from tools.issue3_crypto_tls_probe.stage import open_regular, save_new


def public_json(path,limit=8*1024**2):
    with open_regular(path) as f: data=f.read(limit+1)
    return prepare.parse_json(data.decode(),limit)


def loader_identity(python,loader):
    """Check actual executable PT_INTERP, not a caller-chosen unrelated loader."""
    with open_regular(Path(python['path'])) as f:
        header=f.read(64)
        prepare.require(header[:6]==b'\x7fELF\x02\x01' and len(header)==64,'ELF64 Python required')
        offset=struct.unpack_from('<Q',header,32)[0]
        stride,count=struct.unpack_from('<HH',header,54)
        prepare.require(stride==56 and 0<count<=128,'Python program-header bound')
        found=[]
        for i in range(count):
            f.seek(offset+i*stride); row=f.read(stride)
            prepare.require(len(row)==stride,'short Python program header')
            if struct.unpack_from('<I',row)[0]==3:
                position=struct.unpack_from('<Q',row,8)[0]; size=struct.unpack_from('<Q',row,32)[0]
                prepare.require(1<size<=512,'loader path bound')
                f.seek(position); found.append(f.read(size))
    prepare.require(found==[loader['path'].encode()+b'\0'],'actual canonical ELF loader binding required')
    deadline=time.monotonic()+5
    for pin in (python,loader):
        execution.verify_public_file(Path(pin['path']),{k:pin[k] for k in ('bytes','sha256')},deadline)
    prepare.require(sys.executable==python['path'],'canonical Python invocation required')


def namespace_controls(phase,proc=Path('/proc'),cgroup=Path('/sys/fs/cgroup')):
    membership=(proc/'self/cgroup').read_text().strip()
    prepare.require(membership=='0::/','private unified cgroup identity required')
    mounts=[line.split() for line in (proc/'self/mountinfo').read_text().splitlines()]
    selected=[m for m in mounts if len(m)>8 and m[4]=='/sys/fs/cgroup' and '-' in m and m[m.index('-')+1]=='cgroup2']
    prepare.require(len(selected)==1 and 'ro' in selected[0][5].split(','),'readonly cgroup2 mount required')
    stats=os.statvfs('/')
    return dict(cgroup=membership,controls=execution.effective_controls(phase,cgroup),
                engine_free_bytes=stats.f_bavail*stats.f_frsize,observed_unix=time.time())


def emit_early(root,stream,sent):
    """Parent-only stream writer: finite immutable snapshots, no target streams."""
    order=['stage-'+s+'.json' for s in output_contract.STAGES]
    order+=list(output_contract.AUTH_FILES)
    order+=['compile/'+n+'.json' for n in ('inherited-controls','child-controls','pid','process')]
    order+=['compile/timing-'+event+'.json' for event in supervisor.TIMING_EVENTS]
    for name in order:
        if name in sent: continue
        path=root/name
        if not path.is_file(): continue
        # Child files are fsynced but may be visible before the final write.
        # Retry an incomplete snapshot on the next heartbeat; never send it.
        try: data=public_json(path,16384)
        except (ValueError,UnicodeError): continue
        data=output_contract.early_record(name,data)
        frame=b'ISSUE3_EVIDENCE '+json.dumps(dict(name=name,data=data),sort_keys=True,separators=(',',':')).encode()+b'\n'
        prepare.require(len(frame)<=4096 and frame.endswith(b'\n'),'early frame byte bound')
        stream.write(frame); stream.flush(); sent.add(name)


def emit_export(phase,root,stream):
    allowed=output_contract.allowed(phase)
    rows=[]; total=0
    for p in root.rglob('*'):
        prepare.require(not p.is_symlink(),'output symlink refused')
        if p.is_dir(): continue
        name=p.relative_to(root).as_posix()
        prepare.require(name in allowed and len(rows)<128,'public output allowlist')
        with open_regular(p) as f: size=os.fstat(f.fileno()).st_size
        total+=size
        prepare.require(size<=67108864 and total<=94*1024**2,'export byte bounds')
        rows.append((name,p,size))
    stream.write(b'ISSUE3_EXPORT\n'); stream.flush()
    with tarfile.open(fileobj=stream,mode='w|',format=tarfile.USTAR_FORMAT) as archive:
        for name,p,size in sorted(rows):
            with open_regular(p) as f:
                info=tarfile.TarInfo(name); info.size=size; info.mode=0o444
                archive.addfile(info,f)
    stream.flush()


def fork_supervise(child,heartbeat,seconds):
    """Fork before any threads; the target's preexec_fn stays single-threaded."""
    import signal
    prepare.require(threading.active_count()==1,'single-threaded phase bootstrap required')
    prepare.require(0<seconds<=330,'bounded phase child')
    pid=os.fork()
    if pid==0:
        try:
            os.setsid()
            code=child()
        except BaseException:
            code=125
        os._exit(code if type(code) is int else 125)
    reaped=False; deadline=time.monotonic()+seconds; error=None
    try:
        while True:
            heartbeat()
            got,status=os.waitpid(pid,os.WNOHANG)
            if got==pid:
                reaped=True; return status
            if time.monotonic()>=deadline: raise TimeoutError('phase child deadline')
            time.sleep(min(.1,max(0,deadline-time.monotonic())))
    except BaseException as exc:
        error=exc
        raise
    finally:
        if not reaped:
            try: os.kill(pid,signal.SIGKILL)
            except ProcessLookupError: pass
            os.waitpid(pid,0)
            reaped=True
        if error is not None: setattr(error,'direct_child_reaped',reaped)


def supervise_export(child,heartbeat,seconds,phase,root,stream):
    """Export even after guest deadline/observer failure; settlement is separate."""
    reason='EXIT'; code=125; reaped=False
    try:
        code=os.waitstatus_to_exitcode(fork_supervise(child,heartbeat,seconds))
        reaped=True
    except Exception as exc:
        reason='TIMEOUT' if isinstance(exc,TimeoutError) else 'SUPERVISOR_FAILURE'
        reaped=getattr(exc,'direct_child_reaped',False)
    save_new(root/'supervisor.json',wire.encoded(dict(reason=reason,returncode=code,
        direct_child_reaped=reaped,descendants_independently_reaped=False)))
    emit_export(phase,root,stream)
    return code


def main():
    prepare.require(sys.platform=='linux' and os.getuid()==10000 and os.getgid()==10000,'isolated worker identity')
    profile=public_json(Path('/request/profile.json')); phase=profile['phase']
    grant=public_json(Path('/request/grant.json'),1048576)
    work_end=output_contract.work_deadline(phase,profile)
    loader_identity(profile['python'],profile['loader'])
    sent=set(); next_guest=0.0
    def heartbeat():
        nonlocal next_guest
        emit_early(Path('/output'),sys.stdout.buffer,sent)
        now=time.monotonic()
        if now<next_guest: return
        # Poll early evidence at 0.1s independently of guest telemetry. At most
        # 661 guest + 28 early frames over 330s fit the unchanged 1000-line
        # preamble budget, including its terminal export marker.
        next_guest=now+.5
        guest=namespace_controls(phase)
        sys.stdout.buffer.write(b'ISSUE3_GUEST '+json.dumps(guest,sort_keys=True).encode()+b'\n')
        sys.stdout.buffer.flush()
    def child():
        success=False; error=None
        try:
            # No target until independent host inspection publishes admission.
            deadline=time.monotonic()+5
            while not Path('/observer/readback.json').is_file():
                prepare.require(time.monotonic()<deadline,'outer observer startup deadline')
                time.sleep(.05)
            def readback():
                row=public_json(Path('/observer/readback.json'),16384)
                prepare.require(0<=time.time()-row['observed_unix']<2,'fresh outer heartbeat required')
                return row['projection']
            execution.execute(profile,grant,phase,readback)
            success=True
        except BaseException as exc:
            error=type(exc).__name__+': '+str(exc)[:1000]
        save_new(Path('/output/worker.json'),wire.encoded(dict(success=success,error=error,
                 heartbeat_errors=[],phase=phase,final_elf_acceptance=False)))
        return 0 if success else 1
    seconds=work_end+output_contract.FINALIZATION_SECONDS-output_contract.EXPORT_SECONDS-time.monotonic()
    code=supervise_export(child,heartbeat,seconds,
        phase,Path('/output'),sys.stdout.buffer)
    return code


if __name__=='__main__':
    raise SystemExit(main())
