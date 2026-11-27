"""Separate-process lifecycle metadata verifier; never starts, stops or tops targets."""
import os
from pathlib import Path
import sys
import time
import base
import settlement


def process_absent(kind, pid):
    try:
        (os.kill if kind == 'pid' else os.killpg)(pid, 0)
    except ProcessLookupError:
        return True
    return False


def verify(d, engine_id, owned, deadline, pids, groups, *, absent=process_absent, clock=time.monotonic):
    import run_lifecycle as life
    result: dict = dict(safety_verified=False, release_allowed=False, checked_within_shared_deadline=False,
                  docker_top_invoked=False, states=[])
    try:
        def remaining():
            value = deadline-clock()
            base.require(value > 0)
            return min(5, value)
        base.require(0 < len(owned) <= 2 and len({cid for _,cid in owned}) == len(owned))
        for ids in (pids, groups):
            base.require(type(ids) is list and len(ids) <= 10000 and
                         all(type(pid) is int and pid > 1 for pid in ids))
        base.require(base.canonical(d.call(['info', '--format', base.ENGINE_FMT], timeout=remaining())) ==
                     base.canonical(dict(id=engine_id, running=0)))
        for p, cid in owned:
            base.require(isinstance(cid, str) and life.re.fullmatch(base.HEX, cid))
            state = life.inspect_owned(d, p, cid)
            # canonical bytes prevent bool/int equality from weakening controls.
            controls = {k:v for k,v in state.items() if k not in ('id','status','running','pid','exit','oom')}
            base.require(base.canonical(controls) == base.canonical(life.expected(p)))
            base.require(state['status'] in ('created','exited') and state['running'] is False and type(state['pid']) is int and
                         state['pid'] == 0 and state['oom'] is False)
            result['states'].append(state)
        inventory = d.call(['container', 'ls', '-q', '--no-trunc'], binary=True, timeout=remaining())
        base.require(inventory == b'')
        for kind, ids in (('pid',pids), ('pgid',groups)):
            for pid in ids:
                remaining()
                base.require(absent(kind,pid))
        result['safety_verified'] = True
        result['checked_within_shared_deadline'] = clock() < deadline
        result['release_allowed'] = result['checked_within_shared_deadline']
    except BaseException as exc:
        result['error_type'] = type(exc).__name__  # no exception strings/argv/private content
    return result


def owned_processes(folder, watchdog=True, controller=False):
    folder = Path(folder)
    pids, groups = [], []
    if watchdog:
        row = settlement.read_json(folder/'lifecycle-watchdog-pid.json', 4096)
        base.require(set(row) == {'pid','pgid'} and row['pid'] == row['pgid'])
        pids.append(row['pid']); groups.append(row['pgid'])
    if controller:
        pids.append(settlement.read_json(folder/'lifecycle-control.json',4096)['controller_pid'])
    # No process table, argv or environment scan; fixed per-owned-client receipts only.
    for root in sorted(folder.glob('lifecycle-rpc-*')):
        base.safe(str(root), True)
        base.require((root/'intent.json').is_file())
        row = settlement.read_json(root/'pid.json',4096)
        base.require(set(row) == {'pid','pgid'} and row['pid'] == row['pgid'])
        pids.append(row['pid']); groups.append(row['pgid'])
    return sorted(set(pids)), sorted(set(groups))


def owned_containers(folder, plan):
    import run_lifecycle as life
    owned = []
    for phase in ('bootstrap','reopen'):
        intent = folder/(phase+'-create-intent.json')
        receipt = folder/(phase+'-owned.json')
        if intent.exists():
            p = life.phase_plan(plan['epoch'],phase)
            base.require(settlement.read_json(intent,4096) == dict(name=p['container']))
            row = settlement.read_json(receipt if receipt.exists() else folder/(phase+'-recovered-owned.json'),4096)
            base.require(set(row) == {'id'})
            owned.append((p,row['id']))
        else:
            base.require(not receipt.exists())
    return owned


def main():
    import run_lifecycle as life
    life.require_bound()
    folder = life.TASK
    plan = settlement.read_json(folder/'plan.json')
    context = settlement.read_json(folder/'lifecycle-control.json',4096)
    base.require(context['plan_sha256'] == life.hashlib.sha256(base.canonical(plan)).hexdigest() and context['epoch'] == plan['epoch'])
    endpoint = settlement.read(folder,context)
    deadline = endpoint['deadline']
    settlement.remaining(deadline)
    pids, groups = owned_processes(folder)
    # The still-live invoking controller is explicitly excluded; it must reap this
    # verifier and verify its group before publishing a release receipt.
    base.require(os.getppid() == context['controller_pid'])
    d = base.Docker(dict(life.phase_plan(plan['epoch'],'bootstrap'),epoch=plan['epoch']+'-verify'))
    d.deadline = deadline
    result = verify(d,plan['engine_id'],owned_containers(folder,plan),deadline,pids,groups)
    # Include verifier RPCs, which were not present in the first inventory.
    pids, groups = owned_processes(folder)
    for kind, ids in (('pid',pids),('pgid',groups)):
        for pid in ids:
            settlement.remaining(deadline)
            base.require(process_absent(kind,pid))
    result.update(verifier_pid=os.getpid(), context_sha256=settlement.context_hash(context),
                  deadline=deadline, controller_self_excluded=context['controller_pid'])
    base.durable(str(folder/'lifecycle-independent-verification.json'), result)
    return 0 if result['release_allowed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
