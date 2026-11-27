"""Explicit Docker lifecycle for the original-library probe; prepare never mutates.

Descriptor/grant inputs are owner/controller trust-boundary inputs, not signatures.
No implicit target run, pull, exec, retry, deletion or cleanup. The production
transport is CLI bound to an explicit Unix endpoint, never environment context.
"""
import hashlib
import json
import math
import os
from pathlib import Path
import re
import shutil
import time

from . import bind_b04 as binder
from . import execution, prepare as validation, supervisor
from .stage import save_new

REQUIRED = ('base', 'python', 'loader', 'amd64_execution_binding', 'transport',
            'controllers', 'toolchain', 'manifest', 'mounts', 'name', 'phase', 'host_controllers', 'host_python', 'experiment', 'settlement_allowance_seconds')
CID = r'[0-9a-f]{64}'
LIMIT = 268435456
PHASE_SECONDS = {'compile':120, 'run':330}


def prepare(profile, transport=None):
    """Pure presence plan, not descriptor authenticity or execution readiness."""
    missing = [key for key in REQUIRED if key not in profile or profile[key] is None]
    return dict(schema='issue3-probe-outer-plan-v1', ready=False,
                complete_fields=not missing, missing=missing, target_executed=False,
                profile_sha256=hashlib.sha256(binder.encoded(profile)).hexdigest())


def compile_profile(snapshot,compiler,manifest,mounts,name,emulation=None):
    """Pure descriptor assembly, not provenance authentication or physical staging.

    Pass bind_public('original')['manifest'] and cached-inputs.json['compiler'].
    Source hashes are refreshed here; every mounted byte is reverified by run.
    Absent independent emulation evidence stays None, never an inferred grant.
    """
    import sys
    from .docker_transport import CONTROLLERS
    from . import release
    return dict(base=snapshot['base'],python=snapshot['python'],loader=snapshot['loader'],
        transport=snapshot['transport'],amd64_execution_binding=emulation,
        controllers={n:supervisor.digest(validation.HERE/n) for n in sorted(CONTROLLERS)},
        host_controllers={n:supervisor.digest(validation.HERE/n) for n in ('outer.py','docker_transport.py','watchdog.py')},
        host_python=supervisor.digest(Path(sys.executable).resolve(),256*1024**2),
        host_settlement_controllers={n:supervisor.digest(validation.HERE/n)
            for n in ('settlement.py','settlement_verifier.py')},
        toolchain=dict(archive_sha256=compiler['archive']['sha256'],compiler_sha256=compiler['compiler']['sha256'],
                       inventory_sha256=compiler['sysroot_inventory_sha256'],files=compiler['files']),
        manifest=manifest,mounts=mounts,name=name,phase='compile',pair='original',
        experiment=dict(deadline_monotonic=time.monotonic()+510,ceiling_seconds=510),
        source_closure=release.inventory(Path(__file__).resolve().parents[2]),
        descriptor_policy=dict(scope='compile-only',compile_nofile=256,runtime_nofile=64,runtime_authorized=False),
        settlement_allowance_seconds=60)


def prior_compile(profile):
    from .phase_worker import public_json
    pin=profile['compile_receipt']; path=Path(pin['path'])
    execution.verify_public_file(path,{k:pin[k] for k in ('bytes','sha256')},time.monotonic()+2)
    receipt=public_json(path)
    original=public_json(path.parent/'intent.json')['profile']
    validation.require(receipt.get('status')=='TRANSPORT_SETTLED' and receipt.get('settled') is True and
        receipt.get('profile_sha256')==hashlib.sha256(binder.encoded(original)).hexdigest() and
        original.get('phase')=='compile' and original.get('experiment')==profile['experiment'] and
        receipt['process']['export'].get('phase')=='compile' and
        receipt['process']['export'].get('artifact_validated') is True and
        receipt['process']['export'].get('binary')==profile['probe'] and
        type(receipt.get('settlement_elapsed_seconds')) in (int,float) and
        0<=receipt['settlement_elapsed_seconds']<60 and
        profile['settlement_allowance_seconds']==60-receipt['settlement_elapsed_seconds'],
        'exact compile lineage/shared settlement budget required')
    return receipt


def run_profile(compile_receipt,program,request,observer,name):
    """Nonexecuting successor constructor. Never resets the experiment ceiling."""
    raise ValueError('compile-only successor excludes runtime')
    from .phase_worker import public_json
    path=Path(compile_receipt)
    receipt=public_json(path); original=public_json(path.parent/'intent.json')['profile']
    validation.require('descriptor_policy' not in original, 'compile-only diagnostic excludes runtime successor')
    profile=dict(original,phase='run',name=name,probe=receipt['process']['export']['binary'],
        compile_receipt=dict(path=str(path),**supervisor.digest(path,8*1024**2)),
        settlement_allowance_seconds=60-receipt['settlement_elapsed_seconds'])
    profile['mounts']=dict(original['mounts'],program=program,request=request,observer=observer)
    prior_compile(profile)
    return profile


def grant_for(profile, expires):
    """Payload helper ONLY. Calling it does not supply owner approval."""
    return dict(approved=True,phase=profile['phase'],expires_unix=expires,
        binding_sha256=hashlib.sha256(binder.encoded(profile)).hexdigest(),
        owner_scope='one-original-retained-library-experiment')


def validate(profile):
    require = validation.require
    require(profile.get('phase')=='compile','compile-only successor')
    supervisor.descriptor_budget(profile,'compile')
    if 'descriptor_policy' in profile:
        supervisor.descriptor_budget(profile, profile.get('phase'))
    require(not prepare(profile)['missing'], 'missing outer descriptor fields')
    require(profile['phase'] in PHASE_SECONDS and profile.get('pair') == 'original', 'explicit original phase')
    exp=profile['experiment']; allowance=profile['settlement_allowance_seconds']
    require(type(exp) is dict and exp.get('ceiling_seconds')==510 and
        type(exp.get('deadline_monotonic')) in (int,float) and math.isfinite(exp['deadline_monotonic']) and
        0<exp['deadline_monotonic']-time.monotonic()<=510 and
        type(allowance) in (int,float) and math.isfinite(allowance) and 0<allowance<=60 and
        (profile['phase']!='compile' or allowance==60),'fixed experiment/shared settlement envelope')
    require(re.fullmatch(r'issue3-b04-probe-[a-z0-9-]{4,60}',profile['name']), 'exclusive probe name')
    base = profile['base']
    require(re.fullmatch('sha256:'+CID,base.get('image_id','')) and
        base.get('os') == 'linux' and base.get('architecture') == 'amd64' and
        base.get('volumes') == 0 and base.get('onbuild') == 0, 'cached non-volume AMD64 Linux base')
    for name in ('python','loader'):
        pin = profile[name]
        require(type(pin) is dict and re.fullmatch(r'/[A-Za-z0-9_./+-]+',pin.get('path','')) and
            Path(pin['path']).as_posix() == pin['path'] and '..' not in Path(pin['path']).parts and
            type(pin.get('bytes')) is int and 0 < pin['bytes'] <= 256*1024**2 and
            re.fullmatch(CID,pin.get('sha256','')), 'canonical pinned '+name)
    binding=profile['amd64_execution_binding']
    require(type(binding) is dict and binding.get('kind') in ('native','exact-emulator','engine-managed-platform'), 'execution platform binding')
    if binding['kind']=='engine-managed-platform':
        require(binding == dict(kind='engine-managed-platform',engine_id=profile['transport']['engine_id'],
            endpoint=profile['transport']['endpoint'],platform='linux/amd64',
            emulator_identity_verified=False,provenance_limitation_accepted=True),
            'explicit engine-managed platform provenance limitation required')
    require(binding.get('kind') != 'exact-emulator' or re.fullmatch(CID,binding.get('sha256','')),
            'exact emulator identity required')
    mounts=profile['mounts']
    keys={'inputs','controller','toolchain','request','observer'} | ({'program'} if profile['phase']=='run' else set())
    require(set(mounts)==keys, 'exact readonly mount namespace')
    for source in mounts.values():
        require(type(source) is str and re.fullmatch(r'/[A-Za-z0-9_./+-]+',source) and
                '..' not in Path(source).parts and Path(source).as_posix()==source, 'canonical mount path')
    require(len(set(mounts.values()))==len(mounts), 'distinct mount roots')
    if profile['phase']=='run':
        require(type(profile.get('probe')) is dict, 'separate compiled program binding')


def phase_seconds(profile):
    remaining=profile['experiment']['deadline_monotonic']-time.monotonic()-profile['settlement_allowance_seconds']
    validation.require(remaining>0,'experiment deadline before phase start')
    return min(PHASE_SECONDS[profile['phase']],remaining)


def settlement_deadline(profile,folder):
    from . import settlement
    return settlement.acquire(profile,folder)['deadline_monotonic']


def guest_limits(phase):
    budget=supervisor.BUDGETS[phase]
    return {'memory.max':str(budget['memory']),'memory.swap.max':'0',
            'pids.max':str(budget['pids']),'cpu.max':'100000 100000'}


def command(profile):
    validate(profile)
    b=supervisor.BUDGETS[profile['phase']]
    cmd=['create','--name='+profile['name'],'--label=org.uvm.issue3='+profile['name'],
         '--platform=linux/amd64','--pull=never','--network=none','--log-driver=none','--rm=false',
         '--read-only','--user=10000:10000','--cap-drop=ALL','--security-opt=no-new-privileges:true',
         '--restart=no','--ulimit=core=0','--memory='+str(b['memory']),
         '--memory-swap='+str(b['memory']),'--cpus=1','--pids-limit='+str(b['pids']),
         '--cgroupns=private','--ipc=none','--workdir=/controller',
         '--env=PYTHONDONTWRITEBYTECODE=1','--env=PYTHONPATH=/controller',
         '--env=TMPDIR=/work','--env=LD_PRELOAD=','--env=LD_AUDIT=',
         '--env=LD_LIBRARY_PATH=','--env=LD_DEBUG=','--env=GLIBC_TUNABLES=',
         '--tmpfs=/work:rw,nosuid,nodev,size=268435456,mode=0700,uid=10000,gid=10000',
         '--tmpfs=/output:rw,nosuid,nodev,size=268435456,mode=0700,uid=10000,gid=10000',
         '--entrypoint='+profile['python']['path']]
    for key,source in sorted(profile['mounts'].items()):
        target='/'+key
        cmd.append('--mount=type=bind,source='+source+',target='+target+',readonly,bind-nonrecursive=true')
    return cmd+[profile['base']['image_id'],'-I','-S','/controller/tools/issue3_observed_compile/phase_worker.py']


def expected(profile,cid):
    b=supervisor.BUDGETS[profile['phase']]
    # Keep State fields separate from immutable controls. Missing fields refuse.
    return dict(id=cid,name='/'+profile['name'],label=profile['name'],image=profile['base']['image_id'],
        user='10000:10000',entrypoint=[profile['python']['path']],
        cmd=['-I','-S','/controller/tools/issue3_observed_compile/phase_worker.py'],
        readonly=True,network='none',logging='none',privileged=False,ports=0,
        memory=b['memory'],swap=b['memory'],cpus=1000000000,pids=b['pids'],
        cap_drop=['ALL'],cap_add=None,security=['no-new-privileges:true'],restart='no',
        cgroupns='private',ipc='none',pid_mode='',devices=[],device_requests=None,
        binds=None,volumes_from=None,auto_remove=False,core=[dict(Name='core',Soft=0,Hard=0)],
        mount_options=sorted([dict(source=v,target='/'+k,readonly=True,nonrecursive=True) for k,v in profile['mounts'].items()],key=lambda m:m['target']),
        tmpfs={x:'rw,nosuid,nodev,size=268435456,mode=0700,uid=10000,gid=10000' for x in ('/work','/output')},
        mounts=sorted([dict(type='bind',source=v,destination='/'+k,rw=False) for k,v in profile['mounts'].items()],
                      key=lambda m:m['destination']),
        status='created',running=False,pid=0,exit_code=0,oom_killed=False,started_at='0001-01-01T00:00:00Z')


STATE = {'status','running','pid','exit_code','oom_killed','started_at'}


def controls(profile,cid,row):
    require=validation.require
    want=expected(profile,cid)
    require(type(row) is dict and set(row)==set(want), 'complete independent inspect fields required')
    require({k:v for k,v in row.items() if k not in STATE} ==
            {k:v for k,v in want.items() if k not in STATE}, 'container identity/controls drift')
    require(type(row['pid']) is int and type(row['exit_code']) is int and
            type(row['running']) is bool and type(row['oom_killed']) is bool and
            type(row['started_at']) is str, 'typed state readback required')
    return row


def projection(profile,cid):
    b=supervisor.BUDGETS[profile['phase']]; t=profile['transport']
    return dict(image_id=profile['base']['image_id'],network='none',readonly=True,swap=0,
        transport_path=t['path'],transport_sha256=t['sha256'],engine_endpoint=t['endpoint'],
        engine_id=t['engine_id'],amd64_execution_binding=profile['amd64_execution_binding'],
        memory=b['memory'],cpu=1,pids=b['pids'],user='10000:10000',caps=[],restart='no',ports=[],volumes=[],core=0,
        inputs_readonly=True,toolchain_readonly=True,controller_readonly=True,
        probe_readonly=profile['phase']=='run',bounded_work_bytes=LIMIT,bounded_output_bytes=LIMIT,
        owned_container_id=cid)


def atomic_json(path,data):
    temp=path.with_suffix('.next')
    save_new(temp,binder.encoded(data))
    temp.chmod(0o444)
    os.replace(temp,path)
    fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try: os.fsync(fd)
    finally: os.close(fd)


def settle(profile,cid,daemon,deadline):
    """Independent exact-ID settlement still permitted after the phase grant expires."""
    def remaining(maximum):
        remaining=deadline-time.monotonic()
        validation.require(remaining>0,'settlement deadline; exact-owned manual recovery required')
        return min(maximum,remaining)
    def read():
        return controls(profile,cid,daemon.inspect(cid,timeout=remaining(5)))
    row=read()
    if row['running']:
        try: daemon.stop(cid,timeout=remaining(10))
        except Exception: pass  # A lost stop response is not stopped evidence.
        row=read()
        if row['running']:
            try: daemon.kill(cid,timeout=remaining(5))
            except Exception: pass
            row=read()
    validation.require(time.monotonic()<deadline and row['running'] is False and row['pid']==0 and
        row['status'] in ('created','exited') and row['oom_killed'] is False,
        'stopped/PID0/non-OOM settlement readback required')
    return row


def run(profile,grant,folder,daemon):
    """One explicit create/start; preserves every failure, including partial create.

    daemon is the trusted independent provider. Production CLI below uses bounded
    exact endpoint requests. Fixtures cannot qualify any target cryptography.
    """
    validate(profile)
    phase=profile['phase']
    execution.check_grant(profile,grant,phase)
    if phase=='run': prior_compile(profile)
    folder=Path(folder)
    folder.mkdir(mode=0o700)
    save_new(folder/'intent.json',binder.encoded(dict(profile=profile,grant=grant,controller_pid=os.getpid())))
    cid=None; error=None; state=None; process=None; settlement_end=None
    try:
        daemon.identity(profile)
        validation.require(not daemon.collision(profile['name']),'container name collision')
        if hasattr(daemon,'verify_inputs'): daemon.verify_inputs(profile)
        execution.check_grant(profile,grant,phase)
        phase_end=time.monotonic()+phase_seconds(profile)
        if hasattr(daemon,'arm_guard'): daemon.arm_guard(profile,folder,deadline=phase_end)
        execution.check_grant(profile,grant,phase)
        validation.require(shutil.disk_usage(folder).free>=16*1024**3,'fresh host 16GiB admission required')
        execution.check_grant(profile,grant,phase)
        save_new(folder/'create-spent.json',binder.encoded(dict(name=profile['name'],automatic_retry=False)))
        try:
            created=daemon.create(command(profile))
            validation.require(re.fullmatch(CID,created or ''),'uncertain created container ID')
            cid=created
        except BaseException:
            # Only the exact fresh exclusive name + full immutable projection can
            # recover an ID after a create response is lost. Never blindly stop a name.
            row=daemon.inspect(profile['name'])
            if row is not None:
                recovered=row.get('id','')
                validation.require(re.fullmatch(CID,recovered),'partial create identity')
                controls(profile,recovered,row)
                cid=recovered
                save_new(folder/'owned.json',binder.encoded(dict(container_id=cid,partial_create=True)))
            raise
        save_new(folder/'owned.json',binder.encoded(dict(container_id=cid,partial_create=False)))
        row=controls(profile,cid,daemon.inspect(cid))
        validation.require(row==expected(profile,cid),'created stopped initial state required')
        worker=dict(profile,container_id=cid,phase_deadline_unix=time.time()+phase_end-time.monotonic())
        worker_grant=grant_for(worker,grant['expires_unix'])
        request=Path(profile['mounts']['request'])
        save_new(request/'profile.json',binder.encoded(worker))
        save_new(request/'grant.json',binder.encoded(worker_grant))
        # Host files are public read-only guest inputs, not an authority channel.
        for path in request.iterdir(): path.chmod(0o444)
        request.chmod(0o755)
        observer=Path(profile['mounts']['observer']); observer.chmod(0o755)
        execution.check_grant(profile,grant,phase)
        daemon.identity(profile)
        execution.check_grant(profile,grant,phase)
        save_new(folder/'started.json',binder.encoded(dict(container_id=cid,phase=phase)))
        generation=[None]
        def monitor(guest):
            row=controls(profile,cid,daemon.inspect(cid))
            if row['running'] is False and row['status']=='exited' and row['pid']==0:
                validation.require(generation[0] is not None and row['oom_killed'] is False and
                                   row['started_at']==generation[0][1],
                                   'unobserved or OOM phase exit')
                return  # Do not refresh admission from a stopped container.
            validation.require(row['running'] is True and row['status']=='running' and row['pid']>0 and
                row['oom_killed'] is False and row['started_at']!='0001-01-01T00:00:00Z','running identity required')
            current=(row['pid'],row['started_at'])
            validation.require(generation[0] in (None,current),'container generation drift')
            generation[0]=current
            validation.require(type(guest) is dict and guest.get('controls')==guest_limits(phase) and
                guest.get('cgroup')=='0::/' and type(guest.get('engine_free_bytes')) is int and
                type(guest.get('observed_unix')) in (int,float) and
                0<=time.time()-guest['observed_unix']<2,
                'same private-cgroup worker receipt required')
            data=dict(projection(profile,cid),host_free_bytes=shutil.disk_usage(folder).free,
                      engine_free_bytes=guest['engine_free_bytes'],observed_unix=time.time())
            execution.admission(data)
            atomic_json(observer/'readback.json',dict(observed_unix=time.time(),projection=data))
            (observer/'readback.json').chmod(0o444)
        execution.check_grant(profile,grant,phase)
        remaining=phase_end-time.monotonic()
        validation.require(remaining>15,'insufficient finalization headroom before attach')
        process=daemon.attach(cid,folder,remaining,monitor)
        validation.require(process['reason']=='EXIT' and process['returncode']==0 and process['reaped'] is True,
                           'phase transport failure or timeout')
        validation.require(type(process.get('export')) is dict and
            process['export'].get('artifact_validated') is True and not process.get('early_error'),
            'phase export failed or incomplete')
    except BaseException as exc:
        error=type(exc).__name__+': '+str(exc)[:1000]
    finally:
        settlement_started=time.monotonic()
        try: settlement_end=settlement_deadline(profile,folder)
        except BaseException as exc:
            error=(error+'; ' if error else '')+'shared endpoint '+type(exc).__name__+': '+str(exc)[:1000]
        if cid:
            try:
                validation.require(settlement_end is not None,'shared endpoint unavailable')
                if hasattr(daemon,'bind_settlement'): daemon.bind_settlement(folder,deadline=settlement_end)
                state=settle(profile,cid,daemon,settlement_end)
            except BaseException as exc: error=(error+'; ' if error else '')+'settlement '+type(exc).__name__+': '+str(exc)[:1000]
        elif (folder/'create-spent.json').exists():
            error=(error+'; ' if error else '')+'container identity unresolved; exact-name manual readback required'
    if error is None and (state is None or state['status']!='exited' or state['exit_code']!=0):
        error='independent successful phase exit readback missing'
    result=dict(schema='issue3-probe-outer-v1',status='TRANSPORT_SETTLED' if error is None else 'FAILED_NO_RETRY',
        profile_sha256=hashlib.sha256(binder.encoded(profile)).hexdigest(),
        container_id=cid,settled=state is not None,state=state,error=error,process=process,
        target_qualified=False,final_elf_acceptance=False,cleanup_performed=False,automatic_retry=False)
    save_new(folder/'outer-result.json',binder.encoded(result))
    # Guard completion and independent read-only verification are part of this
    # invocation, not a later handoff. All consume the first published endpoint.
    for method,key,receipt in (('finish_guard','watchdog','watchdog-readback.json'),
            ('verify_settlement','independent_verification','independent-verification-readback.json')):
        try:
            validation.require(settlement_end is not None and time.monotonic()<settlement_end,
                               'shared settlement endpoint exhausted')
            validation.require(hasattr(daemon,method),'independent '+method+' provider unavailable')
            result[key]=getattr(daemon,method)(folder,deadline=settlement_end)
            validation.require(type(result[key]) is dict,'complete independent '+method+' result required')
        except BaseException as exc:
            result[key]=dict(settled=False,safety_verified=False,release_allowed=False,
                error=type(exc).__name__+': '+str(exc)[:1000])
        save_new(folder/receipt,binder.encoded(result[key]))
    verified=result['independent_verification']
    result['settlement_timing_certified']=(settlement_end is not None and time.monotonic()<settlement_end and
        verified.get('checked_within_shared_deadline') is True)
    result['slot_status']=('RELEASED' if state is not None and result['watchdog'].get('settled') is True and
        verified.get('safety_verified') is True and verified.get('release_allowed') is True and
        result['settlement_timing_certified'] else 'HELD_UNRESOLVED')
    if result['slot_status']!='RELEASED':
        result['status']='FAILED_NO_RETRY'
        result['error']=(result['error']+'; ' if result['error'] else '')+'integrated independent settlement unresolved'
    result['settlement_deadline_monotonic']=settlement_end
    from . import settlement
    endpoint=settlement.read(profile,folder) if settlement_end is not None else None
    result['settlement_elapsed_seconds']=time.monotonic()-(endpoint['start_monotonic'] if endpoint else settlement_started)
    result['outcomes']=dict(attach=process.get('reason') if process else None,
        compiler=process.get('compiler') if process else None,
        export=process.get('export') if process else None,
        settlement=dict(stopped_pid0_non_oom=state is not None,
                        container_exit_code=state['exit_code'] if state else None,
                        watchdog=result.get('watchdog'),independent_verification=verified,
                        timing_certified=result['settlement_timing_certified']))
    save_new(folder/'final-result.json',binder.encoded(result))
    return result


def main():
    import argparse
    from .docker_transport import DockerCLI
    from .phase_worker import public_json
    parser=argparse.ArgumentParser(description=__doc__)
    group=parser.add_mutually_exclusive_group()
    group.add_argument('--prepare',action='store_true',help='pure plan only; default')
    group.add_argument('--execute-phase',action='store_true',help='explicit one create/start; requires fresh exact grant')
    parser.add_argument('--profile',type=Path)
    parser.add_argument('--grant',type=Path)
    parser.add_argument('--attempt',type=Path)
    args=parser.parse_args()
    profile=public_json(args.profile) if args.profile else {}
    if not args.execute_phase:
        print(binder.encoded(prepare(profile)).decode(),end=''); return 0
    validate(profile)
    grant=public_json(args.grant,1048576) if args.grant else {}
    execution.check_grant(profile,grant,profile['phase'])
    validation.require(args.attempt is not None and args.attempt.is_absolute() and
        args.attempt.parent==Path('/tmp') and
        args.attempt.parent==args.attempt.parent.resolve() and
        re.fullmatch(r'issue3-b04-probe-[a-z0-9-]{4,60}',args.attempt.name),'fresh owned scratch attempt required')
    daemon=DockerCLI(profile,args.attempt/'transport')
    result=run(profile,grant,args.attempt,daemon)
    print(binder.encoded(result).decode(),end='')
    return 0 if result['status']=='TRANSPORT_SETTLED' else 1


if __name__=='__main__': raise SystemExit(main())
