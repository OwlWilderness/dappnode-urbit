"""One owner-authorized owned-recipe trial. No ship, retry or deletion.

Separate from frozen historical controllers. Docker-container driver controls
bound the dedicated daemon's cgroup, including descendant RUN processes; storage
and deadline stopping remain sampled/best effort, not hard quotas/containment.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import shlex
import signal
import subprocess
import time

GIB = 1024**3
IMAGE = 'moby/buildkit@sha256:cec9f139f45e93c5c69c60f8b07cfad9f43f4ef6b6a6cd917527fea5ff2e3dea'
IMAGE_ID = 'sha256:f27f9c00a3aca2c219642d1500610eade3ddcb6b873ea8847852ab156663d32f'
MEMORY = 6*GIB
CONTEXT = 'desktop-linux'
SCRATCH = Path('/tmp')
FORMAT = '{"id":{{json .Id}},"image":{{json .Image}},"name":{{json .Name}},"memory":{{.HostConfig.Memory}},"swap":{{.HostConfig.MemorySwap}},"quota":{{.HostConfig.CpuQuota}},"period":{{.HostConfig.CpuPeriod}},"restart":{{json .HostConfig.RestartPolicy.Name}},"running":{{.State.Running}},"pid":{{.State.Pid}},"oom":{{.State.OOMKilled}},"exit":{{.State.ExitCode}}}'
FORMAT = FORMAT[:-1] + ',"cpuset":{{json .HostConfig.CpusetCpus}}}'


def record(folder, name, value):
    with (folder / name).open('x') as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())


def run(args, timeout: float = 15):
    return subprocess.check_output(['docker', '--context', CONTEXT, *args], timeout=timeout, stderr=subprocess.STDOUT, text=True)


def hashes(root):
    manifest = json.loads((root / 'owned-recipe.json').read_text())
    result = {}
    for name, expected in manifest['files'].items():
        path = root / name
        if path.resolve() != path.absolute() or not path.is_file():
            raise ValueError('nonregular recipe file: ' + name)
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual != expected:
            raise ValueError('recipe drift: ' + name)
        result[name] = actual
    result['owned-recipe.json'] = hashlib.sha256((root / 'owned-recipe.json').read_bytes()).hexdigest()
    return result


class StorageBudget:
    """Sampled stop policy, never a disk quota or an authorization grant.

    Defaults retain the historical 18/8/10 GiB policy. Smaller growth must be
    explicitly selected by an owner-approved invocation; reserve cannot shrink.
    Headroom is an additional stop margin for observation/settlement overshoot,
    not a proven upper bound on writes during that interval.
    """
    reserve_bytes = 10*GIB

    def __init__(self, max_growth_bytes=8*GIB, stop_headroom_bytes=0):
        if type(max_growth_bytes) is not int or not 0 < max_growth_bytes <= 8*GIB:
            raise ValueError('growth budget must be positive integer bytes, at most 8 GiB')
        if type(stop_headroom_bytes) is not int or stop_headroom_bytes < 0:
            raise ValueError('stop headroom must be nonnegative integer bytes')
        self.max_growth_bytes = max_growth_bytes
        self.stop_headroom_bytes = stop_headroom_bytes
        self.stop_free_bytes = self.reserve_bytes + stop_headroom_bytes
        self.host_initial_bytes = self.stop_free_bytes + max_growth_bytes
        # Preserve the compiler's unchanged 14 GiB initial/8 GiB guest guards.
        self.engine_initial_bytes = max(14*GIB, self.host_initial_bytes)

    def receipt(self):
        return dict(reserve_bytes=self.reserve_bytes, max_growth_bytes=self.max_growth_bytes,
                    stop_headroom_bytes=self.stop_headroom_bytes, stop_free_bytes=self.stop_free_bytes,
                    host_initial_bytes=self.host_initial_bytes, engine_initial_bytes=self.engine_initial_bytes,
                    enforcement='sampled-best-effort-not-quota')


def storage(host, engine, initial_host=None, initial_engine=None, *, budget=None):
    budget = budget if budget is not None else StorageBudget()
    if (initial_host is None) != (initial_engine is None):
        raise ValueError('both initial storage measurements required')
    values = [host, engine] + ([] if initial_host is None else [initial_host, initial_engine])
    if any(type(value) is not int or value < 0 for value in values):
        raise ValueError('invalid storage measurement')
    if host < (budget.host_initial_bytes if initial_host is None else budget.stop_free_bytes):
        raise ValueError('host free admission/reserve')
    if engine < (budget.engine_initial_bytes if initial_engine is None else budget.stop_free_bytes):
        raise ValueError('engine free admission/reserve')
    if initial_host is not None and initial_host-host >= budget.max_growth_bytes:
        raise ValueError('host observed growth bound')
    if initial_engine is not None and initial_engine-engine >= budget.max_growth_bytes:
        raise ValueError('engine observed growth bound')


def controls(data, name, cid=None, bootstrap=False):
    expected = dict(image=IMAGE_ID, name='/buildx_buildkit_' + name + '0',
                    memory=MEMORY, swap=MEMORY, cpuset='0-1', restart='no')
    if not bootstrap:
        expected.update(quota=200000, period=100000)
    if any(data.get(k) != v for k, v in expected.items()) or (cid and data.get('id') != cid):
        raise ValueError('builder identity/control drift')
    if not re.fullmatch('[0-9a-f]{64}', data.get('id', '')):
        raise ValueError('invalid builder identity')


def cgroups(text):
    lines = text.splitlines()
    if lines[:3] != [str(MEMORY), '0', '200000 100000']:
        raise ValueError('effective cgroup v2 limits unsupported/mismatched: ' + repr(lines[:3]))
    return dict(memory_max=int(lines[0]), swap_max=int(lines[1]), cpu_max=lines[2])


def platform_admission(platforms, emulator):
    if 'linux/amd64' in platforms:
        return 'worker-advertised'
    if emulator:
        # Pinned BuildKit getEmulator() uses its bundled helper when archutil
        # does not report native/binfmt support. Advertisement is not a gate.
        return 'buildkit-bundled-qemu-not-native-advertisement'
    raise ValueError('AMD64 neither advertised nor bundled emulator available')


def build_command(name, root, output, attempt):
    return ['docker', '--context', CONTEXT, 'buildx', 'build', '--builder', name,
            '--platform=linux/amd64', '--progress=plain', '--provenance=false',
            '--target=evidence', '--build-arg', 'UVM_OPENSSL_ARENA_BYTES=134217728',
            '--build-arg', 'UVM_BUILD_ATTEMPT_ID=' + attempt,
            '--output', 'type=local,dest=' + str(output), str(root)]


def setup_command(name, config):
    return ['buildx', 'create', '--name', name, '--driver', 'docker-container', '--config', str(config),
            '--driver-opt', 'image=' + IMAGE, CONTEXT]


def container_command(name):
    # Buildx v0.11.2 has no resource driver opts. Its Bootstrap explicitly
    # reuses/starts an existing same-name container. Create that exact dedicated
    # daemon with Docker's supported controls BEFORE starting it, not unbounded
    # bootstrap followed by a late update. No other existing container is used.
    container = 'buildx_buildkit_' + name + '0'
    return ['container', 'create', '--name', container, '--pull', 'never', '--init', '--privileged',
            '--memory', str(MEMORY), '--memory-swap', str(MEMORY),
            '--cpu-period', '100000', '--cpu-quota', '200000', '--cpuset-cpus', '0-1',
            '--restart', 'no', '--label', 'org.issue3.attempt=' + name,
            '--mount', 'type=volume,source=' + container + '_state,target=/var/lib/buildkit',
            IMAGE_ID, '--config', '/etc/buildkit/buildkitd.toml']


def reuse_adapter():
    import importlib.util
    spec = importlib.util.spec_from_file_location('issue3_cache_reuse', Path(__file__).with_name('cache_reuse.py'))
    assert spec is not None and spec.loader is not None
    reuse = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(reuse)
    return reuse


def execute(root, evidence, attempt, authorized, prepared=None, *,
            max_growth_bytes=8*GIB, stop_headroom_bytes=0,
            cache_reuse_receipt=None, cache_reuse_sha256=None, time_budget=None):
    if cache_reuse_receipt is None and cache_reuse_sha256 is None:
        if time_budget is not None:
            raise ValueError('explicit time budget requires cache reuse late path')
        return _execute(root, evidence, attempt, authorized, prepared,
                        max_growth_bytes=max_growth_bytes, stop_headroom_bytes=stop_headroom_bytes)
    if prepared is not None or authorized != 'owner-approved-one-amd64-cache-reuse-trial':
        raise ValueError('cache reuse needs separate explicit authorization; never --prepared')
    if max_growth_bytes != 6*GIB or stop_headroom_bytes != GIB:
        raise ValueError('cache reuse requires unchanged explicit 17/6/1/10 GiB controls')
    reuse = reuse_adapter()
    reuse.time_budget_checked(time_budget)
    import sys
    trial = sys.modules.get(__name__)
    # Some host tests load this module without registering it in sys.modules.
    if trial is None:
        from types import SimpleNamespace
        trial = SimpleNamespace(**globals())
    with reuse.lock(trial):
        request = reuse.validate(trial, cache_reuse_receipt, cache_reuse_sha256,
                                 root, evidence, attempt)
        if time_budget != request.get('time_budget'):
            raise ValueError('explicit time budget readiness mismatch')
        # Global per-attempt interlock, independent of the chosen evidence path.
        # Admission failure closes this execution too; never opportunistically retry.
        record(SCRATCH, attempt+'.attempt.json', dict(attempt=attempt, evidence=str(evidence.absolute()),
               receipt_sha256=cache_reuse_sha256, authorization=authorized, cache=request['cache']))
        return _execute(root, evidence, attempt, 'owner-approved-one-amd64-trial',
                        max_growth_bytes=max_growth_bytes, stop_headroom_bytes=stop_headroom_bytes,
                        reuse=(reuse, request, trial))


def _execute(root, evidence, attempt, authorized, prepared=None, *,
             max_growth_bytes=8*GIB, stop_headroom_bytes=0, reuse=None):
    if authorized != 'owner-approved-one-amd64-trial':
        raise ValueError('missing explicit owner authorization binding')
    budget = StorageBudget(max_growth_bytes, stop_headroom_bytes)
    selected_time = None if reuse is None else reuse[1].get('time_budget')
    build_seconds = 2400 if selected_time is None else selected_time['outer_seconds']
    if not re.fullmatch('issue3-owned-[a-z0-9-]{6,50}', attempt):
        raise ValueError('invalid attempt identity')
    evidence = evidence.absolute()
    if evidence.parent != SCRATCH or evidence.exists():
        raise ValueError('evidence must be fresh direct scratch child')
    prior = None
    if prepared is not None:
        prepared = prepared.absolute()
        if prepared.parent != SCRATCH or prepared == evidence:
            raise ValueError('prepared evidence identity')
        prior = json.loads((prepared / 'result.json').read_text())
        if (prior.get('attempt') != attempt or prior.get('build_launched') is not False or
                prior.get('status') != 'PRELAUNCH_BLOCKED' or prior.get('settled') is not True or
                (prepared / 'spent.json').exists() or (prepared / 'build-consumed.json').exists()):
            raise ValueError('prepared trial spent/uncertain/not same attempt')
    binding = hashes(root)
    host0 = shutil.disk_usage(SCRATCH).free
    if type(host0) is not int or host0 < budget.host_initial_bytes:
        raise ValueError('host initial admission')
    evidence.mkdir(mode=0o700)
    record(evidence, 'authorization.json', dict(owner_grant='Current explicit preparation plus ONE AMD64 owned build approval',
        attempt=attempt, arena_bytes=134217728, trial_only=True, failure_model='attended-best-effort-stop-retain',
        memory=MEMORY, memory_swap_total=MEMORY, cpu_quota=200000, cpu_period=100000,
        build_seconds=build_seconds, settlement_seconds=60, time_budget=selected_time,
        host_initial_free=host0, recipe=binding,
        storage_budget=budget.receipt(),
        launcher_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()))
    if reuse is not None:
        record(evidence, 'cache-reuse-authorization.json', dict(
            authorization='owner-approved-one-amd64-cache-reuse-trial', request=reuse[1]))
    frozen = evidence / 'frozen-recipe'
    frozen.mkdir()
    for name in binding:
        dest = frozen / name
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(root / name, dest)
    hashes(frozen)
    name = attempt if reuse is None else reuse[1]['cache']['builder']
    container = 'buildx_buildkit_' + name + '0'
    cid = None
    process = None
    result: dict = dict(attempt=attempt, status='PRELAUNCH_BLOCKED', build_launched=False, build_exit_code=None,
                  artifact_complete=False, settled=False, error=None)
    if prepared is not None:
        record(evidence, 'prepared-binding.json', dict(path=str(prepared),
            result_sha256=hashlib.sha256((prepared / 'result.json').read_bytes()).hexdigest(),
            same_frozen_recipe=hashes(prepared / 'frozen-recipe') == binding))
        if hashes(prepared / 'frozen-recipe') != binding:
            raise ValueError('prepared recipe drift')
        result['prepared_from'] = str(prepared)
    started = time.monotonic()
    host_baseline = host0 if reuse is None else max(host0, reuse[1]['baseline']['host_free'])
    pressure_observer = None if reuse is None else reuse[0].load('progress_observer')
    pressure_previous = None
    def inspect(bootstrap=False):
        data = json.loads(run(['inspect', '--format', FORMAT, cid or container]))
        controls(data, name, cid, bootstrap)
        return data
    def sample() -> dict:
        nonlocal pressure_previous
        command = 'df -Pk /var/lib/buildkit; cat /proc/meminfo | head -n 3'
        if pressure_observer is not None:
            command += '; timeout 1 sh -c '+shlex.quote(pressure_observer.PRESSURE_COMMAND)+'; :'
        text = run(['exec', cid, 'sh', '-c', command], timeout=10)
        rows = text.splitlines()
        engine = int(rows[1].split()[3])*1024
        point = dict(unix=time.time(), host_free=shutil.disk_usage(SCRATCH).free, engine_free=engine,
                     engine_public=text.split('I3_CGROUP_BEGIN',1)[0])
        if pressure_observer is not None:
            pressure = pressure_observer.pressure_sample(text, pressure_previous)
            point['cgroup_observer'] = pressure
            if pressure['healthy']:
                pressure_previous = pressure
        return point
    def interrupt(signum, frame):
        raise RuntimeError('supervisor interrupted by signal ' + str(signum))
    previous = {s: signal.signal(s, interrupt) for s in (signal.SIGTERM, signal.SIGINT)}
    try:
        if reuse is not None:
            adapter, request, trial = reuse
            if not request['created_unix'] <= time.time() <= request['expires_unix']:
                raise ValueError('stale reuse readiness before bootstrap')
            adapter.inspect_stopped(trial)
            cid = request['cache']['container_id']
            data = inspect()
            record(evidence, 'setup-intent.json', dict(builder=name, image=IMAGE, image_id=IMAGE_ID,
                cache_reuse=request['cache'], fresh_attempt=attempt))
            record(evidence, 'prestart-controls.json', data)
            effective_dockerfile, local_deps = adapter.stage(trial, evidence, frozen, request)
            # Staging performs I/O after the initial readiness/identity checks.
            # Recheck at the actual mutation boundary, not just before staging.
            adapter.inspect_stopped(trial)
            if not request['created_unix'] <= time.time() <= request['expires_unix']:
                raise ValueError('stale reuse readiness before bootstrap')
        elif prepared is None:
            if run(['ps', '-aq', '--filter', 'name=^/' + container + '$']).strip():
                raise ValueError('builder name occupied')
            if run(['volume', 'ls', '--filter', 'name=^' + container + '_state$', '--format', '{{.Name}}']).strip():
                raise ValueError('builder state volume name occupied')
            record(evidence, 'setup-intent.json', dict(builder=name, image=IMAGE, image_id=IMAGE_ID))
            config = evidence / 'buildkitd.toml'
            config.write_text('[worker.oci]\n  gc = false\n  max-parallelism = 2\n[worker.containerd]\n  enabled = false\n')
            cmd = setup_command(name, config)
            record(evidence, 'builder-create-command.json', cmd)
            record(evidence, 'builder-create.json', dict(output=run(cmd, 30)))
            create = container_command(name)
            record(evidence, 'container-create-command.json', create)
            cid = run(create, 30).strip()
            if not re.fullmatch('[0-9a-f]{64}', cid):
                cid = None
                raise ValueError('invalid dedicated container create acknowledgement')
            data = inspect()
            if data['running'] or data['pid'] != 0:
                raise ValueError('new builder not exclusively stopped before bootstrap')
            record(evidence, 'prestart-controls.json', data)
            run(['cp', str(config), cid + ':/etc/buildkit/buildkitd.toml'])
        else:
            cid = prior['container_id']
            data = inspect()
            if data['running'] or data['pid'] != 0:
                raise ValueError('prepared builder no longer stopped')
            record(evidence, 'setup-intent.json', dict(builder=name, image=IMAGE, image_id=IMAGE_ID,
                                                      prepared_from=str(prepared), container_id=cid))
            record(evidence, 'prestart-controls.json', data)
        record(evidence, 'builder-bootstrap.json', dict(output=run(['buildx', 'inspect', name, '--bootstrap'], 120)))
        data = inspect()
        record(evidence, 'builder-controls.json', data)
        effective = run(['exec', cid, 'sh', '-c',
            'cat /sys/fs/cgroup/memory.max /sys/fs/cgroup/memory.swap.max /sys/fs/cgroup/cpu.max'])
        record(evidence, 'effective-cgroups.json', cgroups(effective))
        if reuse is not None:
            config = run(['exec', cid, 'cat', '/etc/buildkit/buildkitd.toml'])
            if hashlib.sha256(config.encode()).hexdigest() != reuse[0].CONFIG_SHA:
                raise ValueError('reused builder config drift')
        platforms = run(['exec', cid, 'buildctl', 'debug', 'workers', '-v'])
        record(evidence, 'worker-platforms.json', dict(output=platforms))
        emulator = ''
        if 'linux/amd64' not in platforms:
            try:
                emulator = run(['exec', cid, 'sh', '-c',
                    'buildkit-qemu-x86_64 --version && sha256sum "$(command -v buildkit-qemu-x86_64)"'])
            except subprocess.CalledProcessError:
                pass
        record(evidence, 'emulator.json', dict(output=emulator))
        first = sample()
        engine_baseline = first['engine_free'] if reuse is None else max(first['engine_free'], reuse[1]['baseline']['engine_free'])
        record(evidence, 'admission.json', first)
        storage(first['host_free'], first['engine_free'], budget=budget)
        # Include setup/evidence growth in the host budget, not just build time.
        storage(first['host_free'], first['engine_free'], host_baseline, engine_baseline, budget=budget)
        if reuse is not None:
            record(evidence, 'reuse-measurement-baseline.json', dict(host_free=host_baseline,
                engine_free=engine_baseline, prior=reuse[1]['baseline'], fresh_host=host0, fresh_admission=first))
        record(evidence, 'platform-admission.json', dict(mode=platform_admission(platforms, emulator)))
        mem_available = re.search(r'MemAvailable:\s+(\d+) kB', first['engine_public'])
        if not mem_available or int(mem_available[1])*1024 < MEMORY:
            raise ValueError('engine available memory below 6 GiB')
        if hashes(root) != binding or hashes(frozen) != binding:
            raise ValueError('recipe changed before launch')
        # Consume before launching, including a failed exec/transport.
        cmd = build_command(name, frozen, evidence / 'artifact', attempt)
        if reuse is not None:
            adapter, request, trial = reuse
            if not request['created_unix'] <= time.time() <= request['expires_unix']:
                raise ValueError('stale reuse readiness before client')
            adapter.load('local_dependencies').verify(adapter.DEPENDENCIES)
            adapter.verify_staged(evidence, frozen, request)
            cmd[-1:-1] = ['--file', str(effective_dockerfile), '--build-context', 'issue3deps='+str(local_deps)]
        if prepared is not None:
            record(prepared, 'build-consumed.json', dict(evidence=str(evidence), unix=time.time(), attempt=attempt))
        # One absolute wall deadline delivered to the late driver; independent
        # monotonic outer ceiling never resets on progress or clock movement.
        deadline = time.monotonic() + build_seconds
        deadline_unix = time.time() + build_seconds
        if selected_time is not None:
            cmd[-1:-1] = ['--build-arg', 'UVM_OUTER_DEADLINE_UNIX='+str(deadline_unix)]
        record(evidence, 'spent.json', dict(command=cmd, unix=time.time(), deadline_seconds=build_seconds,
            outer_deadline_unix=deadline_unix, time_budget=selected_time))
        result['build_launched'] = True
        result['status'] = 'FAIL'

        result['build_started_unix'] = time.time()
        with (evidence / 'build.log').open('xb') as log, (evidence / 'monitor.jsonl').open('x') as monitor:
            client_env = None if reuse is None else dict(os.environ, BUILDKIT_NO_CLIENT_TOKEN='1')
            process = subprocess.Popen(cmd, stdout=log, stderr=subprocess.STDOUT,
                                       start_new_session=True, env=client_env)
            while True:
                state = inspect()
                point = sample()
                point['builder'] = state
                monitor.write(json.dumps(point, sort_keys=True) + '\n')
                monitor.flush()
                storage(point['host_free'], point['engine_free'], host_baseline, engine_baseline, budget=budget)
                if not state['running'] or state['oom']:
                    raise RuntimeError('builder stopped/OOM')
                code = process.poll()
                if code is not None:
                    result['build_exit_code'] = code
                    break
                if time.monotonic() >= deadline:
                    raise RuntimeError(str(build_seconds)+'-second build deadline')
                time.sleep(min(5, max(0, deadline-time.monotonic())))
        if code != 0:
            raise RuntimeError('build client failed with exit ' + str(code))
        required = ['urbit', 'candidate.json', 'source-materials.tar.gz', 'public-libraries.json']
        if reuse is not None:
            required += ['local-dependencies.json', 'local-build-binding.json', 'effective.Dockerfile',
                         'local_build.py', 'local_dependencies.py', 'progress_observer.py']
        if not all((evidence / 'artifact' / x).is_file() for x in required):
            raise RuntimeError('incomplete public artifact delivery')
        result['artifact_complete'] = True
        result['status'] = 'COMPILE_PASS'
    except BaseException as error:
        result['error'] = type(error).__name__ + ': ' + str(error)
        if isinstance(error, subprocess.CalledProcessError):
            result['public_control_output'] = error.output
    finally:
        settlement = time.monotonic() + 60
        if process is not None and process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGTERM)
                process.wait(timeout=5)
            except Exception:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait(timeout=3)
                except Exception:
                    pass
        if process is not None:
            result['build_exit_code'] = process.poll()
        try:
            # No stop of pre-existing resources: setup intent must exist and
            # exact name/image/control identity must match before mutation.
            if (evidence / 'setup-intent.json').exists():
                data = inspect(bootstrap=True)
                cid = data['id']
                if data['running']:
                    run(['stop', '--time', '5', cid], max(1, min(15, settlement-time.monotonic())))
                data = inspect(bootstrap=True)
                result['settled'] = not data['running'] and data['pid'] == 0
                record(evidence, 'settlement.json', data)
                result['container_id'] = cid
        except Exception as error:
            result['settlement_error'] = str(error)
        if not result['settled'] and result['build_launched']:
            result['status'] = 'UNSETTLED'
        result['elapsed_seconds'] = round(time.monotonic()-started, 3)
        result['ended_unix'] = time.time()
        record(evidence, 'result.json', result)
        for s, handler in previous.items():
            signal.signal(s, handler)
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--recipe', type=Path, required=True)
    p.add_argument('--evidence', type=Path, required=True)
    p.add_argument('--attempt', required=True)
    p.add_argument('--authorization', required=True)
    p.add_argument('--prepared', type=Path)
    p.add_argument('--cache-reuse-receipt', type=Path)
    p.add_argument('--cache-reuse-sha256')
    p.add_argument('--max-growth-bytes', type=int, default=8*GIB,
                   help='Explicit approved observed-growth stop budget; default 8 GiB, never a quota')
    p.add_argument('--stop-headroom-bytes', type=int, default=0,
                   help='Explicit approved margin above immutable 10 GiB reserve; default 0')
    a = p.parse_args()
    reuse_options = {} if a.cache_reuse_receipt is None and a.cache_reuse_sha256 is None else dict(
        cache_reuse_receipt=a.cache_reuse_receipt, cache_reuse_sha256=a.cache_reuse_sha256)
    result = execute(a.recipe.absolute(), a.evidence, a.attempt, a.authorization, a.prepared,
                     max_growth_bytes=a.max_growth_bytes, stop_headroom_bytes=a.stop_headroom_bytes, **reuse_options)
    print(json.dumps(result, indent=2, sort_keys=True))
    raise SystemExit(0 if result['status'] == 'COMPILE_PASS' else 1)


if __name__ == '__main__':
    main()
