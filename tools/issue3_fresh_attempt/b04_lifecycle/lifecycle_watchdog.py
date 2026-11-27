"""Separate host settlement observer/recovery guard; never creates/starts a target.

Parent loss can recover exact owned resources but cannot self-certify its own
absence: slot remains held for explicit independent closeout. No renewal/retry.
"""
import os
import time
import base
import settlement


def resolve_owned(folder, plan, d):
    import run_lifecycle as life
    owned = []
    for phase in ('bootstrap','reopen'):
        intent = folder/(phase+'-create-intent.json')
        if not intent.exists():
            continue
        p = life.phase_plan(plan['epoch'],phase)
        base.require(settlement.read_json(intent,4096) == dict(name=p['container']))
        receipt = folder/(phase+'-owned.json')
        recovered = folder/(phase+'-recovered-owned.json')
        if receipt.exists() or recovered.exists():
            row = settlement.read_json(receipt if receipt.exists() else recovered,4096)
            base.require(set(row) == {'id'})
            cid = row['id']
        else:
            # A lost create reply may be recovered only by this exact fresh name,
            # then full-ID/image/name/epoch authentication before any stop.
            state = d.call(['container','inspect','--format',base.CONTAINER_FMT,p['container']])
            cid = state.get('id')
            base.require(isinstance(cid,str) and life.re.fullmatch(base.HEX,cid))
            base.inspect(d,p,cid)
            base.durable(str(recovered),dict(id=cid))
        base.require(isinstance(cid,str) and life.re.fullmatch(base.HEX,cid))
        owned.append((p,cid))
    return owned


def guard(folder, context, plan, d, parent_alive):
    result = dict(settled=False,release_allowed=False,parent_lost=False,
                  context_sha256=settlement.context_hash(context),deadline=None)
    try:
        while parent_alive() and time.monotonic() < context['execution_end']:
            if (folder/'lifecycle-owner-settled.json').exists():
                break
            wait_end = context['execution_end']
            if (folder/settlement.NAME).exists():
                wait_end = min(wait_end,settlement.read(folder,context)['deadline'])
            if time.monotonic() >= wait_end:
                break
            time.sleep(min(.1,max(0,wait_end-time.monotonic())))
        result['parent_lost'] = not parent_alive()
        endpoint = settlement.acquire(folder,context)
        d.deadline = result['deadline'] = endpoint['deadline']
        settlement.remaining(d.deadline)
        import run_lifecycle as life
        info = d.call(['info','--format',base.ENGINE_FMT],timeout=settlement.remaining(d.deadline,5))
        base.require(set(info) == {'id','running'} and info['id'] == plan['engine_id'] and
                     type(info['running']) is int and info['running'] >= 0)
        owned = resolve_owned(folder,plan,d)
        base.require(len({cid for _,cid in owned}) == len(owned))
        for p,cid in owned:
            settlement.remaining(d.deadline)
            life.recover_owned(d,p,cid)
        settlement.remaining(d.deadline)
        result['settled'] = True
    except BaseException as exc:
        result['error_type'] = type(exc).__name__
    base.durable(str(folder/'lifecycle-watchdog-result.json'),result)
    return result


def main():
    import run_lifecycle as life
    life.require_bound()
    folder = life.TASK
    context = settlement.read_json(folder/'lifecycle-control.json',4096)
    plan = settlement.read_json(folder/'plan.json')
    base.require(context['plan_sha256'] == life.hashlib.sha256(base.canonical(plan)).hexdigest() and context['epoch'] == plan['epoch'])
    settlement.context_hash(context)
    base.require(os.getppid() == context['controller_pid'])
    d = base.Docker(dict(life.phase_plan(plan['epoch'],'bootstrap'),epoch=plan['epoch']+'-watchdog'))
    d.deadline = context['execution_end']
    base.durable(str(folder/'lifecycle-watchdog-ready.json'),
                 dict(pid=os.getpid(),context_sha256=settlement.context_hash(context)))
    row = guard(folder,context,plan,d,lambda:os.getppid() == context['controller_pid'])
    return 0 if row['settled'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
