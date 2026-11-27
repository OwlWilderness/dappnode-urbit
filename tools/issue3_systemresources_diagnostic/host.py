"""One-shot SystemResources diagnostic. Explicit --execute required.

Uses prior immutable descriptor as INPUT identity only, never replays its grant.
Exclusive engine: active60s inclusive of create/bootstrap/compile, settlement60s.
Independent exact-ID watchdog. No cleanup/retry/runtime matrix/B operations.
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

REPO=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(REPO))
from tools.issue3_crypto_tls_probe import supervisor, wire
from tools.issue3_crypto_tls_probe.docker_transport import DockerCLI
from tools.issue3_crypto_tls_probe.outer import STATE

ROOT=Path('/tmp/issue3-b04-systemresources-d01-20261031')
PRIOR=Path('/tmp/issue3-b04-probe-approved-20261031-a02')
NAME='issue3-b04-probe-systemresources-d01-20261031'
CAP=32*1024**2

def put(root,name,data):
    p=root/name
    with p.open('xb') as f: f.write(wire.encoded(data))

def pin(p):
    p=Path(p); h=hashlib.sha256()
    with p.open('rb') as f:
        while b:=f.read(1048576): h.update(b)
    return {'bytes':p.stat().st_size,'sha256':h.hexdigest()}

def make_command(profile, diagnostic):
    cmd=['create','--name='+profile['name'],'--label=org.uvm.issue3='+profile['name'],
         '--platform=linux/amd64','--pull=never','--network=none','--log-driver=none','--rm=false',
         '--read-only','--user=10000:10000','--cap-drop=ALL','--security-opt=no-new-privileges:true',
         '--restart=no','--ulimit=core=0','--memory=1073741824','--memory-swap=1073741824',
         '--cpus=1','--pids-limit=64','--cgroupns=private','--ipc=none','--workdir=/controller',
         '--env=PYTHONDONTWRITEBYTECODE=1','--env=PYTHONPATH=/controller','--env=TMPDIR=/work',
         '--env=LD_PRELOAD=','--env=LD_AUDIT=','--env=LD_LIBRARY_PATH=','--env=LD_DEBUG=','--env=GLIBC_TUNABLES=',
         '--tmpfs=/work:rw,nosuid,nodev,size=268435456,mode=0700,uid=10000,gid=10000',
         '--tmpfs=/output:rw,nosuid,nodev,size=268435456,mode=0700,uid=10000,gid=10000',
         '--entrypoint='+profile['python']['path']]
    for key,src in sorted({**profile['mounts'],'diagnostic':str(diagnostic)}.items()):
        cmd.append('--mount=type=bind,source='+src+',target=/'+key+',readonly,bind-nonrecursive=true')
    return cmd+[profile['base']['image_id'],'-I','-S','/diagnostic/guest.py']

def immutable(row): return {k:v for k,v in row.items() if k not in STATE}

def settle(d,cid,expected):
    row=d.inspect(cid)
    assert row is not None and immutable(row)==expected,'exact owned control readback'
    if row['running']: d.kill(cid,timeout=8)
    row=d.inspect(cid)
    assert row and immutable(row)==expected and row['running'] is False and row['pid']==0,'PID0 settlement'
    return row

def guard(root,parent,deadline):
    data=json.loads((root/'ownership.json').read_text()); p=data['profile']
    d=DockerCLI(p,root/'watchdog-transport'); d.identity(p)
    put(root,'watchdog-ready.json',{'pid':os.getpid(),'parent':parent,'deadline_monotonic':deadline})
    result={}
    try:
        while time.monotonic()<deadline and os.getppid()==parent and not (root/'controller-settled.json').exists():
            time.sleep(.1)
        result={'settled':True,'state':settle(d,data['cid'],data['controls']),'target_retry':False}
    except BaseException as exc: result={'settled':False,'error':type(exc).__name__+': '+str(exc)}
    put(root,'watchdog-result.json',result)
    return 0 if result['settled'] else 1

def execute():
    ROOT.mkdir(mode=0o755) # Fresh attempt namespace: refuses existing/spent identity.
    p=json.loads((PRIOR/'compile-profile.json').read_text())
    p['name']=NAME
    for k in ('request','observer'):
        path=ROOT/k; path.mkdir(mode=0o755); p['mounts'][k]=str(path)
    d=DockerCLI(p,ROOT/'preflight-transport')
    d.identity(p)
    assert not d.query(['ps','-q','--no-trunc']),'exclusive engine not idle'
    assert not d.collision(NAME),'fresh name collision'
    assert shutil.disk_usage(ROOT).free>=16*1024**3,'unchanged16GiB host admission'
    d.verify_inputs(p)
    protected={str(x):pin(x) for x in (
        REPO/'docs/openssl-candidate-evidence/b04-probe-approved-a02-20261031.json',
        REPO/'docs/openssl-candidate-evidence/b04-probe-approved-a02-20261031-evidence.tar.gz')}
    assert list(protected.values())[0]['sha256']=='b607adbe8a1c756f3674caff35e49b6f39b7b03af8042b4a2b6f208a8edaf878'
    assert list(protected.values())[1]['sha256']=='1a14e7b8e2943be48b88483f80b1a6efa3f3f032591be8a45855c53e2dfe5382'
    put(ROOT,'protected-before.json',protected)
    diagnostic=ROOT/'diagnostic'; diagnostic.mkdir(mode=0o755)
    shutil.copyfile(Path(__file__).with_name('guest.py'),diagnostic/'guest.py'); (diagnostic/'guest.py').chmod(0o444)
    conf={'attempt':'systemresources-d01-20261031','argv':list(supervisor.compile_argv()),
          'runtime':{k:p[k] for k in ('python','loader')},'compile_seconds':60,
          'raw_stderr_bytes':16*1024**2,'selected_trace_bytes':8*1024**2}
    put(diagnostic,'config.json',conf); (diagnostic/'config.json').chmod(0o444)
    cmd=make_command(p,diagnostic)
    active_deadline=time.monotonic()+60
    deadline=active_deadline+60
    put(ROOT,'intent.json',{'approved':True,'scope':'ONE bounded compiler diagnostic; independent B allowed only after safe settlement',
        'profile_input_only':p,'command':cmd,'config':conf,'diagnostic_files':{n:pin(diagnostic/n) for n in ('guest.py','config.json')},
        'host_source':pin(__file__),'active_deadline_monotonic':active_deadline,'settlement_deadline_monotonic':deadline,
        'active_seconds':60,'settlement_seconds':60,'combined_capture_bytes':CAP,
        'compiler_invocations_max':1,'runtime_cases':0,'automatic_retry':False,'security_exceptions':[],
        'fresh_input_verification':{'inputs':len(p['manifest']['files']),'toolchain_files':len(p['toolchain']['files'])},
        'host_free_before':shutil.disk_usage(ROOT).free})
    put(ROOT,'create-spent.json',{'at':time.monotonic(),'name':NAME})
    cid=None; watchdog=None; attach=None; error=None; stopped=None
    try:
        cid=d.create(cmd)
        assert len(cid)==64
        row=d.inspect(cid); assert row and not row['running'] and row['pid']==0
        # Exact controls derived from inherited frozen sandbox, with only public
        # diagnostic RO mount and entry script changed.
        from tools.issue3_crypto_tls_probe.outer import expected
        want=expected(p,cid)
        want['cmd']=['-I','-S','/diagnostic/guest.py']
        want['mount_options'].append({'source':str(diagnostic),'target':'/diagnostic','readonly':True,'nonrecursive':True})
        want['mount_options'].sort(key=lambda x:x['target'])
        want['mounts'].append({'type':'bind','source':str(diagnostic),'destination':'/diagnostic','rw':False})
        want['mounts'].sort(key=lambda x:x['destination'])
        assert immutable(row)==immutable(want),'inherited controls drift'
        put(ROOT,'ownership.json',{'cid':cid,'profile':p,'controls':immutable(row)})
        watchdog=subprocess.Popen([sys.executable,'-I','-S',str(Path(__file__).resolve()),'--guard',str(ROOT),str(os.getpid()),str(active_deadline)],
            stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True,close_fds=True)
        put(ROOT,'watchdog-pid.json',{'pid':watchdog.pid})
        while not (ROOT/'watchdog-ready.json').exists():
            assert watchdog.poll() is None and time.monotonic()<active_deadline,'watchdog admission'
            time.sleep(.05)
        assert not d.query(['ps','-q','--no-trunc']),'engine changed before start'
        remaining=active_deadline-time.monotonic(); assert remaining>0
        put(ROOT,'compiler-allowance-spent.json',{'cid':cid,'one_start':True,'at':time.monotonic()})
        print('\a',end='',flush=True)
        budget=dict(supervisor.BUDGETS['compile'],seconds=remaining,stdout=CAP-2048,stderr=2048,combined_capture=CAP,file_bytes=CAP)
        def monitor():
            assert shutil.disk_usage(ROOT).free>=16*1024**3,'host floor during diagnostic'
        attach=supervisor.capture(d.argv+('start','--attach',cid),ROOT/'attach',budget,deadline=active_deadline,monitor=monitor)
    except BaseException as exc:
        error=type(exc).__name__+': '+str(exc)
    finally:
        if cid:
            ownership=ROOT/'ownership.json'
            if ownership.exists():
                try:
                    owned=json.loads(ownership.read_text()); stopped=settle(d,cid,owned['controls'])
                    put(ROOT,'controller-settled.json',{'settled':True,'state':stopped})
                except BaseException as exc: error=(error or '')+' settlement: '+str(exc)
        if watchdog:
            try: watchdog.wait(timeout=max(.01,deadline-time.monotonic()))
            except subprocess.TimeoutExpired: error=(error or '')+' watchdog not reaped'
    guard_result=json.loads((ROOT/'watchdog-result.json').read_text()) if (ROOT/'watchdog-result.json').exists() else None
    independent=DockerCLI(p,ROOT/'independent-transport')
    final=independent.inspect(cid) if cid else None
    running=independent.query(['ps','-q','--no-trunc'])
    protected_after={k:pin(k) for k in protected}
    put(ROOT,'protected-after.json',protected_after)
    result={'schema':'issue3-systemresources-diagnostic-v1','attempt':'systemresources-d01-20261031','cid':cid,
        'error':error,'attach':attach,'watchdog_result':guard_result,'watchdog_reaped':watchdog is not None and watchdog.poll() is not None,
        'independent_final':final,'running_container_ids':running.splitlines(),'history_unchanged':protected==protected_after,
        'engine_slot_released':bool(final and final['running'] is False and final['pid']==0 and not running and guard_result and guard_result.get('settled') and watchdog and watchdog.poll() is not None),
        'crypto_tls_qualified':False,'A_pass':False,'automatic_retry':False,'cleanup_performed':False,
        'completed_monotonic':time.monotonic(),'settlement_deadline_monotonic':deadline}
    put(ROOT,'result.json',result)
    print(json.dumps({'root':str(ROOT),'cid':cid,'error':error,'engine_slot_released':result['engine_slot_released'],'attach':attach},indent=2))
    return 0 if result['engine_slot_released'] else 1

if __name__=='__main__':
    if len(sys.argv)>1 and sys.argv[1]=='--guard': raise SystemExit(guard(Path(sys.argv[2]),int(sys.argv[3]),float(sys.argv[4])))
    if sys.argv[1:]!=['--execute']: raise SystemExit('Requires explicit --execute; import/test never launches')
    raise SystemExit(execute())
