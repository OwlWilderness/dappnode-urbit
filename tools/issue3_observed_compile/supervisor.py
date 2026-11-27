"""Bounded sequential compile/run supervision; no import-time execution.

host_fixture exercises process mechanics only. Target entry is a separately
approved isolated Linux worker; a host process is NEVER a target fallback.
"""
import hashlib
import json
import math
import os
from pathlib import Path
import resource
import selectors
import signal
import subprocess
import sys
import time

from . import wire as binder
from . import prepare
from .stage import save_new, open_regular, checked_read

BUDGETS = {
    # memory is the aggregate cgroup charge ceiling, including tmpfs/page cache.
    # address_space is a distinct per-process virtual reservation ceiling. Keep
    # both historical caps; changing/removing AS needs a separate exact decision.
    'compile': dict(seconds=120, memory=1073741824, address_space=1073741824, pids=64, cpu=1,
                    stdout=1048576, stderr=1048576, combined_capture=1048576,file_bytes=67108864,nofile=64),
    'run': dict(seconds=20, memory=268435456, address_space=268435456, pids=16, cpu=1,
                stdout=16384, stderr=16384, file_bytes=1048576,nofile=64),
}
CASES = [(m, 'none') for m in prepare.MODES] + [('crypto', f) for f in ('init','sha','siv')] + [
    ('tls13', f) for f in ('cert','ctx','ca','ssl','bio')]


def descriptor_budget(profile, phase):
    """Explicit one-shot diagnostic policy; never authorizes runtime."""
    policy = profile.get('descriptor_policy')
    prepare.require(type(policy) is dict and policy == dict(scope='compile-only',
        compile_nofile=256, runtime_nofile=64, runtime_authorized=False) and
        type(policy.get('compile_nofile')) is int and
        type(policy.get('runtime_nofile')) is int and
        policy.get('runtime_authorized') is False and phase == 'compile',
        'exact compile-only descriptor policy required; runtime excluded')
    return dict(BUDGETS['compile'], nofile=policy['compile_nofile'])


def digest(path, limit=67108864):
    with open_regular(path) as f:
        size = os.fstat(f.fileno()).st_size
        prepare.require(size <= limit, 'evidence byte bound')
        h,read_bytes = hashlib.sha256(),0
        while True:
            data = f.read(min(1048576,limit-read_bytes+1))
            if not data:
                break
            read_bytes += len(data)
            prepare.require(read_bytes <= limit,'evidence grew beyond cap')
            h.update(data)
        prepare.require(size == read_bytes == os.fstat(f.fileno()).st_size,'evidence size drift')
    return dict(bytes=size, sha256=h.hexdigest())


def wait_control_ack(path, controls, deadline):
    """No exec before the host fsyncs the exact public preexec controls."""
    while not path.is_file():
        if time.monotonic()>=deadline: raise TimeoutError('durable controls acknowledgement deadline')
        time.sleep(.02)
    with open_regular(path) as stream: data=stream.read(1025)
    prepare.require(len(data)<=1024 and json.loads(data)==dict(sha256=hashlib.sha256(binder.encoded(controls)).hexdigest()),
                    'controls acknowledgement binding')
    if time.monotonic()>=deadline: raise TimeoutError('durable controls acknowledgement deadline')


TIMING_EVENTS = ('capture-entry', 'popen-call-ready', 'preexec-entry', 'controls-installed',
                 'ack-wait-entry', 'ack-accepted', 'preexec-ready', 'preexec-failure', 'popen-return')
TIMING_SITES = ('popen-constructor', 'preexec-controls', 'control-ack', 'capture-streams',
                'capture-monitor', 'exit-wait', 'capture-open', 'pid-receipt', 'timing-receipt')


def timing_event(event, end, *, failure_site=None, timeout_site=None, observed=None):
    """Finite public metadata only; same process-namespace monotonic clock."""
    prepare.require(event in TIMING_EVENTS, 'timing event allowlist')
    now = time.monotonic() if observed is None else observed
    return dict(event=event, monotonic_seconds=now, remaining_work_seconds=max(0, end-now),
                failure_site=failure_site, timeout_site=timeout_site)


def capture(argv, evidence, budget, *, deadline=None, target_evidence=False, scratch=None, monitor=None, control_ack=None, timing_evidence=False, postexec_observation=False):
    """Own one process group, cap both streams, kill group and reap on all exits.

    Single-threaded controller only (preexec_fn sets rlimits). RLIMIT_AS is not
    claimed as an aggregate process memory or macOS memory guarantee. Real target
    use additionally requires independently checked Linux cgroups/container caps.
    Children escaping the process group require the outer container settlement.
    Popen itself is synchronous and this loop cannot interrupt a blocked
    constructor/preexec. Early timing survives that gap; the existing outer
    supervisor endpoint remains the bound. No fresh allowance is introduced.
    """
    prepare.require(type(argv) is tuple and argv and os.path.isabs(argv[0]) and
                    all(type(a) is str and '\0' not in a for a in argv), 'explicit argv')
    for name in ('seconds','memory','pids','cpu','stdout','stderr','file_bytes'):
        prepare.require(type(budget[name]) in (int,float) and math.isfinite(budget[name]) and
                        budget[name] > 0, 'positive finite budget')
    address_space = budget.get('address_space', budget['memory'])
    prepare.require(type(address_space) is int and address_space > 0, 'finite virtual address ceiling')
    nofile = budget.get('nofile')
    prepare.require(type(nofile) is int and nofile in (64,256), 'explicit approved descriptor ceiling')
    start = time.monotonic()
    end = min(start + budget['seconds'], deadline) if deadline is not None else start + budget['seconds']
    prepare.require(end > start, 'phase deadline before launch')
    evidence = Path(evidence)
    evidence.mkdir(mode=0o700)  # Atomic one-shot claim, before Popen.
    scratch = Path(scratch) if scratch else evidence
    save_new(evidence/'intent.json', binder.encoded(dict(argv=argv, budget=budget,
                 target_evidence=target_evidence, automatic_retry=False)))
    proc, reason, reaped = None, 'EXIT', False
    streams, counts = {}, {'stdout':0, 'stderr':0}
    error = None
    site, timeout_site = 'capture-open', None
    popen_return = None
    observation_session = None
    def stamp(event, **fields):
        if timing_evidence:
            save_new(evidence/('timing-'+event+'.json'), binder.encoded(timing_event(event,end,**fields)))
    stamp('capture-entry', observed=start)

    def install_limits():
        os.umask(0o077)
        if target_evidence:
            save_new(evidence/'inherited-controls.json',binder.encoded(dict(
                rlimit_nofile=resource.getrlimit(resource.RLIMIT_NOFILE),observation='child-before-controls')))
        for kind, value in ((resource.RLIMIT_CORE, 0), (resource.RLIMIT_NOFILE,nofile),
                            (resource.RLIMIT_CPU,math.ceil(budget['seconds'])),
                            (resource.RLIMIT_FSIZE,budget['file_bytes'])):
            resource.setrlimit(kind, (value,value))
        if sys.platform == 'linux':
            resource.setrlimit(resource.RLIMIT_AS,(address_space,address_space))
        elif target_evidence:
            raise ValueError('target requires Linux effective controls; no host fallback')
        # NPROC is UID-wide, not a host transport process-tree bound. Apply it
        # only to the isolated target UID; real target pids.max is also checked.
        if target_evidence and hasattr(resource, 'RLIMIT_NPROC'):
            resource.setrlimit(resource.RLIMIT_NPROC, (budget['pids'], budget['pids']))
        if target_evidence:
            # CPU quota is throughput, not sched_getaffinity/getCpuCount. Select
            # only an inherited allowed CPU; never assume guest CPU zero exists.
            inherited = sorted(os.sched_getaffinity(0))
            prepare.require(bool(inherited), 'empty inherited child CPU affinity')
            selected = {inherited[0]}
            os.sched_setaffinity(0, selected)
            actual = sorted(os.sched_getaffinity(0))
            prepare.require(actual == sorted(selected), 'effective child CPU affinity mismatch')
            controls = dict(cpu_affinity=actual, inherited_cpu_affinity=inherited,
                rlimit_as=resource.getrlimit(resource.RLIMIT_AS),
                rlimit_nproc=resource.getrlimit(resource.RLIMIT_NPROC),
                rlimit_cpu=resource.getrlimit(resource.RLIMIT_CPU),
                rlimit_nofile=resource.getrlimit(resource.RLIMIT_NOFILE),
                rlimit_fsize=resource.getrlimit(resource.RLIMIT_FSIZE),
                rlimit_core=resource.getrlimit(resource.RLIMIT_CORE),
                observation='child-preexec', post_exec_observation=False,
                memory_accounting='RLIMIT_AS is virtual; independently verified cgroup memory.max is physical charge')
            prepare.require(controls['rlimit_as'] == (address_space,address_space) and
                            controls['rlimit_nofile'] == (nofile,nofile) and
                            controls['rlimit_nproc'] == (budget['pids'],budget['pids']),
                            'effective child rlimit mismatch')
            save_new(evidence/'child-controls.json', binder.encoded(controls))
            return controls
        return None

    def limits():
        # Child writes immutable receipts: parent Python mutations do not cross fork.
        child_site = 'preexec-controls'
        try:
            stamp('preexec-entry')
            controls = install_limits()
            stamp('controls-installed')
            if target_evidence and control_ack is not None:
                child_site = 'control-ack'
                stamp('ack-wait-entry')
                wait_control_ack(Path(control_ack),controls,min(end,time.monotonic()+5))
                stamp('ack-accepted')
            stamp('preexec-ready')
            # Final durable timing I/O also debits the original work endpoint.
            if time.monotonic() >= end:
                raise TimeoutError('original work endpoint before exec')
        except BaseException as exc:
            stamp('preexec-failure', failure_site=child_site,
                  timeout_site=child_site if isinstance(exc,TimeoutError) else None)
            raise

    try:
        for name in counts:
            streams[name] = (evidence/name).open('xb')
        site = 'popen-constructor'
        stamp('popen-call-ready')
        if time.monotonic() >= end:
            reason = 'TIMEOUT'
            raise TimeoutError('original work endpoint before Popen')
        proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, close_fds=True, start_new_session=True,
            cwd=scratch, env={'PATH':'/usr/bin:/bin','LC_ALL':'C','HOME':str(scratch),
                              'TMPDIR':str(scratch),'ZIG_LOCAL_CACHE_DIR':str(scratch/'zig-local'),
                              'ZIG_GLOBAL_CACHE_DIR':str(scratch/'zig-global')}, preexec_fn=limits)
        popen_return = time.monotonic()
        site = 'timing-receipt'
        stamp('popen-return',observed=popen_return)  # NOT compiler work/progress.
        site = 'pid-receipt'
        save_new(evidence/'pid.json', binder.encoded(dict(pid=proc.pid, pgid=proc.pid)))
        if postexec_observation:
            from .observation import Session
            observation_session = Session(proc,argv[0],end,evidence,time.monotonic)
        site = 'capture-streams'
        with selectors.DefaultSelector() as selector:
            selector.register(proc.stdout, selectors.EVENT_READ, 'stdout')
            selector.register(proc.stderr, selectors.EVENT_READ, 'stderr')
            while selector.get_map():
                if observation_session is not None:
                    observation_session.poll()
                if monitor is not None:
                    site = 'capture-monitor'
                    for stream in streams.values(): stream.flush()
                    monitor()
                site = 'capture-streams'
                remaining = end - time.monotonic()
                if remaining <= 0:
                    reason = 'TIMEOUT'
                    raise TimeoutError('process deadline')
                for key, _ in selector.select(min(remaining, .1)):
                    name = key.data
                    available = budget[name] - counts[name]
                    if budget.get('combined_capture'):
                        available = min(available,budget['combined_capture']-sum(counts.values()))
                    data = os.read(key.fd, min(4096, available + 1))
                    if not data:
                        selector.unregister(key.fileobj)
                        continue
                    streams[name].write(data[:available])
                    counts[name] += min(len(data), available)
                    if len(data) > available:
                        reason = 'OUTPUT_LIMIT'
                        raise ValueError('bounded capture exceeded')

            site = 'exit-wait'
            remaining = end-time.monotonic()
            if remaining <= 0:
                reason = 'TIMEOUT'
                raise TimeoutError('exit deadline')
            try:
                proc.wait(timeout=remaining)
            except subprocess.TimeoutExpired:
                reason = 'TIMEOUT'
                raise TimeoutError('exit deadline') from None
    except BaseException as exc:
        error = exc
        if isinstance(exc, TimeoutError):
            timeout_site = site
        if reason == 'EXIT':
            reason = 'INTERRUPTED' if not isinstance(exc, Exception) else 'LAUNCH_OR_CAPTURE_FAILURE'
    finally:
        if proc is not None:
            # Even after direct child exit, an inherited-pipe grandchild may live.
            for sig in (signal.SIGTERM, signal.SIGKILL):
                try:
                    os.killpg(proc.pid, sig)
                except ProcessLookupError:
                    pass
                try:
                    # Explicit absolute endpoints also bound reap waits; no
                    # fresh grace interval after a shared settlement expires.
                    proc.wait(timeout=.2 if deadline is None else min(.2,max(0,deadline-time.monotonic())))
                    reaped = True
                except subprocess.TimeoutExpired:
                    pass
            for pipe in (proc.stdout,proc.stderr):
                if pipe is not None:
                    pipe.close()
        for stream in streams.values():
            stream.flush()
            os.fsync(stream.fileno())
            stream.close()
        child_controls = None
        if target_evidence and (evidence/'child-controls.json').is_file():
            with open_regular(evidence/'child-controls.json') as control_stream:
                data = control_stream.read(16385)
            prepare.require(len(data) <= 16384, 'child control receipt byte bound')
            child_controls = json.loads(data)
        result = dict(schema='issue3-b04-process-v1', reason=reason,
            returncode=proc.returncode if proc else None, reaped=reaped,
            elapsed_seconds=time.monotonic()-start, target_evidence=target_evidence,
            address_space_rlimit=sys.platform == 'linux',
            child_controls=child_controls,
            descendants_independently_reaped=False,
            argv_sha256=hashlib.sha256(binder.encoded(argv)).hexdigest(),
            capture={n:digest(evidence/n, int(budget[n])) for n in streams}, budget=budget,
            error=type(error).__name__ if error else None)
        if timing_evidence:
            # A killed/blocked constructor may have only the early receipts;
            # absent events are unobserved, never substituted by capture entry.
            from .output_contract import timing_record
            events = {}
            receipt_error = bool(error and site=='timing-receipt')
            for event in TIMING_EVENTS:
                path = evidence/('timing-'+event+'.json')
                if not path.is_file():
                    continue
                try:
                    with open_regular(path) as stream:
                        data = stream.read(1025)
                    prepare.require(len(data)<=1024, 'timing receipt byte bound')
                    events[event] = timing_record(json.loads(data),event)
                except (OSError, ValueError, UnicodeError):
                    receipt_error = True
            child_failure = events.get('preexec-failure', {})
            result['timing'] = dict(schema='issue3-b04-capture-timing-v1',
                clock='process-namespace-monotonic', capture_entry_monotonic=start,
                work_deadline_monotonic=end, effective_entry_seconds=end-start,
                popen_return_monotonic=popen_return,
                preexec_entry_monotonic=events.get('preexec-entry',{}).get('monotonic_seconds'),
                remaining_at_popen_return_seconds=max(0,end-popen_return) if popen_return is not None else None,
                failure_site=child_failure.get('failure_site') or (site if error else None),
                timeout_site=child_failure.get('timeout_site') or timeout_site,
                postexec_progress=None, postexec_cpu_seconds=None, postexec_state=None,
                cache_observation=None, receipt_error=receipt_error, events=events)
        save_new(evidence/'process.json', binder.encoded(result))
    if error is not None and not isinstance(error, Exception):
        raise error
    return result


def host_fixture(argv, evidence, seconds=2, cap=16384):
    """Explicitly synthetic, never upgrades the result into target acceptance."""
    budget = dict(BUDGETS['run'], seconds=seconds, stdout=cap, stderr=cap)
    return capture(argv, evidence, budget, target_evidence=False)


def compile_argv(compiler='/toolchain/zig', stage='/inputs',
                 source='/controller/tools/issue3_observed_compile/probe.c',
                 output='/output/probe'):
    return (compiler, 'cc', '-target', 'x86_64-linux-musl', '-std=c11', '-O1', '-g0',
        '-pthread', '-static', '-I',stage+'/include','-I',stage+'/arena', source,
        stage+'/arena/openssl_owned_arena.c', stage+'/lib/libssl.a',
        stage+'/lib/libaes_siv.a', stage+'/lib/libcrypto.a',
        '-Wl,--print-map', '-o', output)


def retain_link_map(output, row):
    """Keep Zig 0.15.2 LLD's stdout map without discarding the raw capture.

    This is retained-probe evidence, NOT authenticated final-b04 link provenance.
    The compile stdout/combined caps remain unchanged; overflow fails the compile.
    """
    prepare.require(row['reason'] == 'EXIT' and row['returncode'] == 0 and
                    row['reaped'] is True, 'successful reaped compile required for map')
    output = Path(output)
    limit = BUDGETS['compile']['stdout']
    with open_regular(output/'compile/stdout') as stream:
        data = stream.read(limit+1)
    prepare.require(len(data) <= limit, 'compile map stdout bound')
    pin = dict(bytes=len(data), sha256=hashlib.sha256(data).hexdigest())
    prepare.require(pin == row['capture']['stdout'], 'compile map capture identity')
    lines = data.splitlines()
    prepare.require(len(lines) > 1 and lines[0].split() ==
                    [b'VMA', b'LMA', b'Size', b'Align', b'Out', b'In', b'Symbol'] and
                    any(line.strip() for line in lines[1:]), 'LLD stdout map required')
    save_new(output/'probe.map', data)
    return pin


def execute_matrix(program, evidence, invoke, *, deadline=None):
    """Stop at first failed case; invoke is an isolated transport, never a shell.

    The transport must return capture+readback provenance, not just a successful
    status. This orchestration API alone does not authenticate the transport.
    """
    evidence = Path(evidence)
    evidence.mkdir(mode=0o700)
    save_new(evidence/'intent.json', binder.encoded(dict(cases=CASES, program=program,
             seconds=330, automatic_retry=False)))
    deadline = min(deadline,time.monotonic()+330) if deadline is not None else time.monotonic()+330
    records = []
    try:
        for index,(mode,fault) in enumerate(CASES):
            prepare.require(time.monotonic() < deadline, 'whole runtime deadline')
            directory = evidence/f'{index:02d}-{mode}-{fault}'
            row = invoke((program,mode,fault),directory,BUDGETS['run'],deadline)
            prepare.require(time.monotonic() <= deadline,'late runtime acknowledgement')
            prepare.require(row['reaped'] is True and row['reason'] == 'EXIT' and
                            row['settled'] is True and row['controls_verified'] is True,
                            'unsettled/uncontrolled process')
            with open_regular(directory/'stdout') as stream:
                stdout = stream.read(16385)
            prepare.require(len(stdout) <= 16384,'runtime stdout byte bound')
            prepare.validate_result(stdout.decode('utf-8'),row['returncode'],mode,fault)
            records.append(dict(mode=mode,fault=fault,process=row))
        result = dict(status='RETAINED_COMPOSITION_CASES_PASS_UNAUTHENTICATED_TRANSPORT', cases=records,
                      final_elf_acceptance=False, target_evidence=False,
                      execution_provenance_verified=False)
    except BaseException as exc:
        save_new(evidence/'matrix-failed.json',binder.encoded(dict(status='STOPPED_NO_RETRY',
                 completed=len(records), error=type(exc).__name__, detail=str(exc)[:1000])))
        raise
    save_new(evidence/'matrix.json',binder.encoded(result))
    return result
