"""Read-only exact-owned settlement verification; never top a stopped container.

A safety observation is independent of compiler success and deadline compliance.
No process table/argv/environment collection, retry, cleanup or target mutation.
"""
import os
import math
import time

from . import outer


def process_absent(kind, pid):
    """Probe only an explicitly owned PID/group; permission errors are unresolved."""
    try:
        (os.kill if kind=='pid' else os.killpg)(pid,0)
    except ProcessLookupError:
        return True
    return False


def verify(profile,cid,daemon,deadline,owned_pids,owned_pgids,
           process_absent=process_absent,clock=time.monotonic):
    result: dict = dict(safety_verified=False,checked_within_shared_deadline=False,
                release_allowed=False,docker_top_invoked=False,state=None,error=None)
    try:
        outer.validation.require(type(deadline) in (int,float) and math.isfinite(deadline),
                                 'finite shared settlement endpoint required')
        outer.validation.require(type(cid) is str and outer.re.fullmatch(outer.CID,cid),
                                 'exact owned container ID required')
        for ids in (owned_pids,owned_pgids):
            outer.validation.require(type(ids) is list and len(ids)<=4 and
                all(type(pid) is int and pid>1 for pid in ids), 'finite exact-owned process IDs required')
        def remaining():
            value=deadline-clock()
            outer.validation.require(value>0,'shared settlement endpoint expired')
            return min(5,value)
        remaining()
        daemon.identity(profile,deadline=deadline)
        state=outer.controls(profile,cid,daemon.inspect(cid,timeout=remaining()))
        result['state']=state
        want=outer.expected(profile,cid)
        outer.validation.require(outer.binder.encoded({k:v for k,v in state.items() if k not in outer.STATE})==
            outer.binder.encoded({k:v for k,v in want.items() if k not in outer.STATE}),
            'strict container identity/controls types drift')
        zero='0001-01-01T00:00:00Z'
        consistent=((state['status']=='created' and state['started_at']==zero and state['exit_code']==0) or
                    (state['status']=='exited' and state['started_at'] not in ('',zero)))
        outer.validation.require(state['running'] is False and state['pid']==0 and consistent and
            state['oom_killed'] is False,
            'stopped/PID0/non-OOM verification required')
        inventory=daemon.query(['ps','-q','--no-trunc'],timeout=remaining())
        result['running_container_ids']=inventory.splitlines()
        outer.validation.require(inventory=='','exclusive engine running inventory not empty')
        for kind,ids in (('pid',owned_pids),('pgid',owned_pgids)):
            for pid in ids:
                remaining()
                outer.validation.require(process_absent(kind,pid),'owned process still present or unresolved')
        result['safety_verified']=True
        result['checked_within_shared_deadline']=clock()<deadline
        result['release_allowed']=result['checked_within_shared_deadline']
    except Exception as exc:
        result['error']=type(exc).__name__+': '+str(exc)[:1000]
    return result


def owned_processes(folder,include_watchdog=True):
    """Read only fixed public PID receipts, never host process tables/argv."""
    from pathlib import Path
    from .watchdog import read_json
    folder=Path(folder); pids=[]; groups=[]
    if include_watchdog:
        row=read_json(folder/'watchdog-pid.json')
        outer.validation.require(set(row)=={'pid'},'exact watchdog PID receipt required')
        pids.append(row['pid'])
    attach=folder/'attach/pid.json'
    if attach.exists():
        row=read_json(attach)
        outer.validation.require(set(row)=={'pid','pgid'} and row['pid']==row['pgid'],
                                 'exact isolated attach group receipt required')
        pids.append(row['pid']); groups.append(row['pgid'])
    elif (folder/'started.json').exists():
        raise ValueError('attach process identity missing; settlement unresolved')
    return pids,groups


def main(argv=None):
    import argparse
    from . import settlement, wire
    from .docker_transport import DockerCLI
    from .stage import save_new
    from .watchdog import read_json
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--folder',type=outer.Path,required=True)
    args=parser.parse_args(argv); folder=args.folder
    profile=read_json(folder/'intent.json')['profile']
    endpoint=settlement.read(profile,folder)  # Read only: never acquire/reset here.
    cid=read_json(folder/'owned.json')['container_id']
    try:
        pids,groups=owned_processes(folder)
        daemon=DockerCLI(profile,folder/'independent-verification-transport')
        if hasattr(daemon,'bind_settlement'):
            daemon.bind_settlement(folder,deadline=endpoint['deadline_monotonic'])
        result=verify(profile,cid,daemon,endpoint['deadline_monotonic'],pids,groups,
                      process_absent=process_absent,clock=time.monotonic)
    except Exception as exc:
        result=dict(safety_verified=False,checked_within_shared_deadline=False,release_allowed=False,
                    docker_top_invoked=False,error=type(exc).__name__+': '+str(exc)[:1000])
    result.update(verifier_pid=os.getpid(),container_id=cid,
        profile_sha256=endpoint['profile_sha256'],deadline_monotonic=endpoint['deadline_monotonic'])
    save_new(folder/'independent-verification.json',wire.encoded(result))
    return 0 if result['release_allowed'] else 1


if __name__=='__main__': raise SystemExit(main())
