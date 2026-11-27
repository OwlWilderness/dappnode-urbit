from gate import preflight
CONFIG = preflight(__file__, 'lifecycle')
#!/usr/bin/env python3
# Prepared successor; historical controller is immutable.
import sys
sys.dont_write_bytecode = True
import os
os.environ['PYTHONDONTWRITEBYTECODE'] = '1'
import hashlib
import io
import json
from pathlib import Path
import re
import shutil
import signal
import tarfile
import time
import uuid
import base

TASK = Path(__file__).absolute().parent
ROOT = TASK.parent
SCRATCH = Path(CONFIG['scratch'])
BINDING_STATE = CONFIG['state']
IMAGE = CONFIG['artifacts']['image']
PILL = Path(CONFIG['inputs']['pill']['path'])
BINDING = CONFIG['inputs']['binding']['sha256']
GIB = 1024**3
# Actual combined image and independent readback; still requires a fresh plan/authority.
BINDING_PATH = Path(CONFIG['inputs']['binding']['path'])
RECEIPT_PATH = Path(CONFIG['inputs']['receipt']['path'])
RECEIPT_SHA = CONFIG['inputs']['receipt']['sha256']
EXECUTABLE_SHA = CONFIG['artifacts']['executable_sha256']
ADAPTER_SHA = CONFIG['artifacts']['adapter_sha256']
EXECUTABLE_SIZE = CONFIG['artifacts']['executable_size']
ADAPTER_SIZE = CONFIG['artifacts']['adapter_size']


def require_bound():
    # No environment/CLI override. Parent must insert verified actual inputs,
    # then freeze a NEW plan and explicit authority; BOUND is not authorization.
    if BINDING_STATE != 'BOUND':
        raise base.Refusal('UNBOUND: actual combined artifact/image/receipt pending')
    base.require(isinstance(IMAGE, str) and re.fullmatch('sha256:' + base.HEX, IMAGE))
    for digest in (BINDING, RECEIPT_SHA, EXECUTABLE_SHA, ADAPTER_SHA):
        base.require(isinstance(digest, str) and re.fullmatch(base.HEX, digest))
    for size in (EXECUTABLE_SIZE, ADAPTER_SIZE):
        base.require(type(size) is int and size > 0)
    for path in (BINDING_PATH, RECEIPT_PATH):
        base.require(isinstance(path, Path) and path.is_absolute() and '..' not in path.parts)


def phase_plan(epoch, phase):
    base.require(re.fullmatch('[0-9a-f]{32}', epoch) and phase in ('bootstrap', 'reopen'))
    return dict(epoch=epoch, phase=phase, task=str(TASK), image=IMAGE,
                container='issue3-life-' + epoch + '-' + phase,
                volume='issue3-life-' + epoch + '-state',
                guest=str(TASK / 'lifecycle_guest.py'), pill=str(PILL),
                bind_prefix=CONFIG['bind_prefix'], docker_host=CONFIG['docker_host'])


def create_argv(p):
    args = base.create_argv(p)
    args[-1] = p['phase']
    if p['phase'] == 'reopen':
        args = [x for x in args if 'target=/bootstrap.pill,' not in x]
    return args


def expected(p):
    result = base.expected_container(p)
    result['cmd'][-1] = p['phase']
    if p['phase'] == 'reopen':
        result['mounts'] = [m for m in result['mounts'] if m['destination'] != '/bootstrap.pill']
    return result


def snapshot(d):
    ids = d.call(['container', 'ls', '-aq'], binary=True).decode().split()
    fmt = base.projection({'id': '.Id', 'image': '.Image', 'status': '.State.Status',
                          'pid': '.State.Pid', 'exit': '.State.ExitCode', 'oom': '.State.OOMKilled'})
    containers = {}
    for cid in ids:
        item = d.call(['container', 'inspect', '--format', fmt, cid])
        containers[item['id']] = item
    def rows(args):
        return sorted(d.call(args, binary=True).decode().splitlines())
    return dict(containers=containers,
                volumes=rows(['volume', 'ls', '--format={{.Name}}']),
                networks=rows(['network', 'ls', '--no-trunc', '--format={{.ID}}']),
                images=rows(['image', 'ls', '--no-trunc', '--format={{.ID}} {{.Repository}}:{{.Tag}}']))


def preserved(before, after, cids, volume):
    return (all(after['containers'].get(k) == v for k, v in before['containers'].items()) and
            set(after['containers']) == set(before['containers']) | set(cids) and
            set(after['volumes']) == set(before['volumes']) | {volume} and
            before['networks'] == after['networks'] and before['images'] == after['images'])


def capacity(initial=None):
    free = shutil.disk_usage(SCRATCH).free
    base.require(free >= (CONFIG['budget']['admission_bytes'] if initial is None else CONFIG['budget']['floor_bytes']))
    if initial is not None:
        base.require(initial - free <= CONFIG['budget']['growth_bytes'])
    base.require(base.usage(str(SCRATCH)) <= 10 * GIB)
    return free


def pinned_inputs():
    require_bound()
    paths = [TASK / x for x in ('base.py', 'lifecycle_guest.py', 'run_lifecycle.py', 'gate.py', 'config.json')]
    paths += [PILL, BINDING_PATH, RECEIPT_PATH]
    pins = {str(path): base.pinned(str(path)) for path in paths}
    base.require(pins[str(PILL)] == base.PILL_SHA and PILL.stat().st_size == base.PILL_SIZE)
    base.require(pins[str(BINDING_PATH)] == BINDING)
    base.require(pins[str(RECEIPT_PATH)] == RECEIPT_SHA)
    raw = base.pinned(str(RECEIPT_PATH), 1024**2, True)
    base.require(hashlib.sha256(raw).hexdigest() == RECEIPT_SHA)
    try:
        receipt = base.strict(raw)
        base.require(isinstance(receipt, dict))
        base.require(type(receipt['schema_version']) is int and receipt['schema_version'] == 1)
        base.require(all(receipt[k] == 'PASS' for k in ('status', 'static_verification', 'independent_readback')))
        base.require(type(receipt['build_exit_code']) is int and receipt['build_exit_code'] == 0)
        base.require(receipt['image_id'] == IMAGE and receipt['binding_sha256'] == BINDING)
        summary = receipt['verification_summary']
        base.require(isinstance(summary, dict) and summary['executable_sha256'] == EXECUTABLE_SHA
                     and summary['adapter_sha256'] == ADAPTER_SHA)
    except (KeyError, TypeError, ValueError):
        raise base.Refusal('image verification receipt invalid') from None
    return pins


def image_check(d):
    base.require(d.call(['image', 'inspect', '--format', base.IMAGE_FMT, IMAGE]) ==
                 dict(id=IMAGE, arch='amd64', os='linux', user='10000:10000', volumes=['/urbit']))


def prepare():
    require_bound()
    pins = pinned_inputs()
    base.require(not (TASK / 'plan.json').exists() and not (TASK / 'spent.json').exists())
    base.require(base.safe(str(TASK), True).st_mode & 0o777 == 0o700)
    initial = capacity()
    epoch = uuid.uuid4().hex
    p = phase_plan(epoch, 'bootstrap')
    d = base.Docker(dict(p, epoch=epoch + '-prepare'))
    info = d.call(['info', '--format', base.ENGINE_FMT])
    base.require(info['running'] == 0)
    image_check(d)
    plan = dict(schema=1, epoch=epoch, image=IMAGE, engine_id=info['id'],
                pins=pins, baseline=snapshot(d), host_free_bytes=initial,
                phases={phase: create_argv(phase_plan(epoch, phase)) for phase in ('bootstrap', 'reopen')})
    base.require(p['volume'] not in plan['baseline']['volumes'])
    base.durable(str(TASK / 'plan.json'), plan)
    return hashlib.sha256(base.canonical(plan)).hexdigest()


def validate_report(r, phase):
    keys = set('schema phase success checks native_launches bootstrap_exit resume_exit http_status forced_kill guest diagnostics'.split())
    base.require(isinstance(r, dict) and set(r) == keys and r['schema'] == 2 and r['phase'] == phase)
    checks = base.CHECKS if phase == 'bootstrap' else [x for x in base.CHECKS if x != base.CHECKS[2]]
    base.require(isinstance(r['checks'], list) and r['checks'] == checks[:len(r['checks'])])
    base.require(type(r['success']) is bool and type(r['forced_kill']) is bool)
    for key in ('native_launches', 'bootstrap_exit', 'resume_exit', 'http_status'):
        base.require(r[key] is None or type(r[key]) is int and -255 <= r[key] <= 1000)
    base.require(set(r['diagnostics']) == set(base.DIAGNOSTICS))
    for key, (low, high, nullable) in base.DIAGNOSTICS.items():
        v = r['diagnostics'][key]
        base.require(v is None and nullable or type(v) is int and low <= v <= high)
    guest_keys = set('memory_available_bytes state_free_bytes root_free_bytes cgroup_memory_max_bytes cgroup_current_bytes'.split())
    base.require(isinstance(r['guest'], dict) and set(r['guest']) in (set(), guest_keys))
    base.require(all(type(v) is int and 0 <= v <= 2**63-1 for v in r['guest'].values()))
    return r


def read_report(d, cid, phase):
    name = 'official-lifecycle-result-' + phase + '.json'
    raw = d.call(['cp', cid + ':/urbit/control/' + name, '-'], binary=True)
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:') as archive:
        members = archive.getmembers()
        base.require(len(members) == 1 and members[0].isreg() and members[0].name == name and 0 < members[0].size <= 16384)
        r = base.strict(archive.extractfile(members[0]).read(16385))
    return validate_report(r, phase)


def require_pass(r, phase):
    base.require(r['success'] is True and r['forced_kill'] is False)
    base.require(r['checks'] == (base.CHECKS if phase == 'bootstrap' else [x for x in base.CHECKS if x != base.CHECKS[2]]))
    base.require(r['guest']['memory_available_bytes'] >= 5 * GIB + GIB // 2)
    base.require(r['guest']['cgroup_memory_max_bytes'] == 5 * GIB)
    base.require(r['guest']['cgroup_memory_max_bytes'] - r['guest']['cgroup_current_bytes'] >= 4 * GIB)
    base.require(r['guest']['state_free_bytes'] >= 8 * GIB and r['guest']['root_free_bytes'] >= 8 * GIB)
    base.require(r['native_launches'] == (2 if phase == 'bootstrap' else 1))
    base.require(r['bootstrap_exit'] == (0 if phase == 'bootstrap' else None))
    base.require(r['resume_exit'] == 0 and r['http_status'] == 200)
    diag = r['diagnostics']
    base.require(diag['stage'] == 9 and diag['failure'] == 0 and diag['cleanup_failure'] == 0)
    base.require(diag['cleanup_exit'] == 0 and diag['resume_poll_exit'] is None and diag['login_200_consecutive'] == 2)
    base.require(diag['last_login_status'] == 200)


def authorize(plan):
    base.require(not (TASK / 'spent.json').exists())
    digest = hashlib.sha256(base.canonical(plan)).hexdigest()
    base.authorize({'task': str(TASK), 'epoch': plan['epoch']}, digest)
    base.require(plan['pins'] == pinned_inputs() and plan['image'] == IMAGE)
    for phase in ('bootstrap', 'reopen'):
        base.require(plan['phases'][phase] == create_argv(phase_plan(plan['epoch'], phase)))


def inspect_owned(d, p, cid):
    state = base.inspect(d, p, cid)
    base.require({k: v for k, v in state.items() if k not in ('id', 'status', 'pid', 'exit', 'oom')} == expected(p))
    return state


def recover_owned(d, p, cid):
    # Exact id/image/name/epoch ownership still mandatory; configuration drift
    # must not prevent stopping the owned process that triggered the refusal.
    state = base.inspect(d, p, cid)
    if state['status'] not in ('created', 'exited') or state['pid'] != 0:
        d.call(['stop', '--time=150', cid], binary=True, timeout=175)
        state = base.inspect(d, p, cid)
    base.require(state['status'] in ('created', 'exited') and state['pid'] == 0)
    return state


def run():
    require_bound()
    plan = base.strict(base.pinned(str(TASK / 'plan.json'), 1024**2, True))
    authorize(plan)
    p = phase_plan(plan['epoch'], 'bootstrap')
    d = base.Docker(dict(p, epoch=plan['epoch'] + '-run'))
    base.require(d.call(['info', '--format', base.ENGINE_FMT]) == dict(id=plan['engine_id'], running=0))
    base.require(snapshot(d) == plan['baseline'])
    image_check(d)
    initial = capacity()
    authorize(plan)
    preflight(__file__, 'lifecycle')
    base.durable(str(TASK / 'spent.json'), dict(epoch=plan['epoch'], plan_sha256=hashlib.sha256(base.canonical(plan)).hexdigest()))
    result = dict(success=False, image=IMAGE, reports={}, owned={}, cleanup_performed=False, retry_authorized=False)
    active = None
    stage = 1
    try:
        base.durable(str(TASK / 'volume-create-intent.json'), dict(volume=p['volume']))
        raw = d.call(['volume', 'create', '--driver=local', '--label=' + base.LABEL + '=' + p['epoch'], p['volume']], binary=True)
        base.require(raw == (p['volume'] + '\n').encode())
        volume = d.call(['volume', 'inspect', '--format', base.VOLUME_FMT, p['volume']])
        base.require(volume == dict(name=p['volume'], driver='local', label=p['epoch'], options_count=0))
        base.durable(str(TASK / 'volume-owned.json'), volume)
        for phase in ('bootstrap', 'reopen'):
            p = phase_plan(plan['epoch'], phase)
            stage = 2 if phase == 'bootstrap' else 3
            base.require(plan['pins'] == pinned_inputs())
            image_check(d)
            capacity(initial)
            # The first container must be settled before any second create/start.
            for prior_phase, prior_cid in result['owned'].items():
                s = inspect_owned(d, phase_plan(plan['epoch'], prior_phase), prior_cid)
                base.require(s['status'] == 'exited' and s['pid'] == 0 and s['exit'] == 0 and not s['oom'])
            base.durable(str(TASK / (phase + '-create-intent.json')), dict(name=p['container']))
            cid = d.call(create_argv(p), binary=True).decode().strip()
            base.require(re.fullmatch(base.HEX, cid))
            result['owned'][phase] = cid
            base.durable(str(TASK / (phase + '-owned.json')), dict(id=cid))
            active = (p, cid)
            state = inspect_owned(d, p, cid)
            base.require(state['status'] == 'created' and state['pid'] == 0)
            base.durable(str(TASK / (phase + '-prestart.json')), state)
            base.require(plan['pins'] == pinned_inputs())
            capacity(initial)
            print(phase + ': starting exact image; ship output discarded', flush=True)
            base.durable(str(TASK / (phase + '-start-intent.json')), dict(id=cid))
            d.call(['start', cid], binary=True)
            start = time.monotonic()
            next_progress = start
            while True:
                state = inspect_owned(d, p, cid)
                if state['status'] == 'exited':
                    break
                base.require(state['status'] == 'running' and time.monotonic() - start < (1100 if phase == 'bootstrap' else 500))
                capacity(initial)
                if time.monotonic() >= next_progress:
                    print(phase + ': running, elapsed_s=' + str(int(time.monotonic() - start)), flush=True)
                    next_progress = time.monotonic() + 30
                time.sleep(3)
            base.durable(str(TASK / (phase + '-final.json')), state)
            base.require(state['pid'] == 0 and not state['oom'])
            report = read_report(d, cid, phase)
            base.durable(str(TASK / (phase + '-report.json')), report)
            result['reports'][phase] = report
            base.require(state['exit'] == 0)
            require_pass(report, phase)
            active = None
            print(phase + ': HTTP 200 twice, clean stop 0; retained', flush=True)
        result['success'] = True
    except BaseException:
        result['failure_stage'] = stage
    finally:
        if active:
            q, cid = active
            try:
                state = recover_owned(d, q, cid)
                base.durable(str(TASK / 'recovery-stopped.json'), state)
            except BaseException:
                result['manual_recovery_required'] = True
        try:
            after = snapshot(d)
            base.durable(str(TASK / 'final-inventory.json'), after)
            result['preserved'] = preserved(plan['baseline'], after, result['owned'].values(), p['volume'])
            result['active_after'] = [k for k, v in after['containers'].items() if v['pid'] != 0]
            result['pins_unchanged'] = plan['pins'] == pinned_inputs()
            result['host_free_bytes_final'] = capacity(initial)
            image_check(d)
            result['success'] &= result['preserved'] and result['pins_unchanged'] and not result['active_after']
        except BaseException:
            result['success'] = False
            result['closeout_incomplete'] = True
        base.durable(str(TASK / 'result.json'), result)
    return result


if __name__ == '__main__':
    def interrupted(signum, frame):
        raise InterruptedError()
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    if sys.argv[1:] == ['prepare']:
        print(prepare())
    elif sys.argv[1:] == ['run']:
        result = run()
        print(json.dumps(result, sort_keys=True))
        raise SystemExit(0 if result['success'] else 1)
    else:
        raise SystemExit(64)
