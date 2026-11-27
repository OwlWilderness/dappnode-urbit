"""Separate-process exact-owned settlement guard. Never creates or starts a target.

Survives controller exit, not host/daemon loss. Missing/mismatched fields never
become permission to kill. Unresolved settlement retains a manual-recovery receipt.
"""
import json
import os
from pathlib import Path
import time

from . import outer, wire, settlement
from .stage import open_regular, save_new


def read_json(path):
    with open_regular(path) as f: raw=f.read(8*1024**2+1)
    if len(raw)>8*1024**2: raise ValueError('watchdog receipt bound')
    return json.loads(raw)


def guard(profile,folder,daemon,parent_alive,deadline):
    folder=Path(folder); cid=None; state=None; error=None
    try:
        while parent_alive() and time.monotonic()<deadline:
            done=folder/'outer-result.json'
            if done.is_file():
                row=read_json(done)
                if row.get('settled') is True: break
                # A reported settlement failure is grounds for one bounded
                # independent settlement, not for a new target invocation.
                break
            wait_end=deadline
            if (folder/settlement.NAME).exists():
                wait_end=min(wait_end,settlement.read(profile,folder)['deadline_monotonic'])
            if time.monotonic()>=wait_end: break
            time.sleep(min(.2,wait_end-time.monotonic()))
        if (folder/'create-spent.json').is_file():
            endpoint=outer.settlement_deadline(profile,folder)
            settlement.remaining(endpoint)
            if hasattr(daemon,'bind_settlement'): daemon.bind_settlement(folder,deadline=endpoint)
            owned=folder/'owned.json'
            if owned.is_file():
                cid=read_json(owned)['container_id']
                outer.validation.require(outer.re.fullmatch(outer.CID,cid),'watchdog exact ID')
            else:
                row=daemon.inspect(profile['name'],timeout=settlement.remaining(endpoint,5))
                if row is not None:
                    cid=row.get('id','')
                    outer.validation.require(outer.re.fullmatch(outer.CID,cid),'watchdog recovered ID')
                    outer.controls(profile,cid,row)
            if cid is not None:
                state=outer.settle(profile,cid,daemon,endpoint)
            else:
                raise ValueError('watchdog container identity unresolved; no release')
        result=dict(container_id=cid,settled=state is not None,state=state,error=None,
                    target_started=False,cleanup_performed=False)
    except BaseException as exc:
        error=type(exc).__name__+': '+str(exc)[:1000]
        result=dict(container_id=cid,settled=False,state=None,error=error,
                    target_started=False,cleanup_performed=False)
    result['release_allowed']=False
    if state is not None and not parent_alive():
        # This already-independent process completes the read-only verifier if
        # its owner died. It excludes itself, never the dead owner's attach group.
        try:
            from . import settlement_verifier as verifier
            pids,groups=verifier.owned_processes(folder,include_watchdog=False)
            pids.append(read_json(folder/'intent.json')['controller_pid'])
            verified=verifier.verify(profile,cid,daemon,endpoint,pids,groups,
                process_absent=verifier.process_absent,clock=time.monotonic)
            result['independent_verification']=verified
            result['observer_self_excluded']=True
            result['release_allowed']=verified['release_allowed']
        except Exception as exc:
            result['verification_error']=type(exc).__name__+': '+str(exc)[:1000]
    save_new(folder/'watchdog-result.json',wire.encoded(result))
    return result


def main():
    import argparse
    from .docker_transport import DockerCLI
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--folder',type=Path,required=True)
    parser.add_argument('--parent',type=int,required=True)
    parser.add_argument('--deadline',type=float,required=True)
    args=parser.parse_args()
    profile=read_json(args.folder/'intent.json')['profile']
    daemon=DockerCLI(profile,args.folder/'watchdog-transport')
    daemon.identity(profile,deadline=args.deadline)
    save_new(args.folder/'watchdog-ready.json',wire.encoded(dict(pid=os.getpid(),settlement_only=True)))
    def alive():
        # Direct child reparenting detects controller death without trusting a
        # potentially reused PID slot. The fixed ceiling remains independent.
        return os.getppid()==args.parent
    result=guard(profile,args.folder,daemon,alive,args.deadline)
    return 0 if result['error'] is None else 1


if __name__=='__main__':
    raise SystemExit(main())
