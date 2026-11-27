"""Explicit b02 cache identity, separate from a fresh one-shot attempt.

Preparation is NOT approval. Receipts expire in five minutes and the launch API
requires their SHA256 and a separate owner authorization. No Docker mutation here.
"""
import argparse
from contextlib import contextmanager
import fcntl
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import time

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
HISTORY = REPO/'docs/openssl-candidate-evidence/owned-trial-20261029-b02-exec-20261030.json'
HISTORY_SHA = '95deada7f30b62c7867cb346c352ef3c62124407faddf95cb851de02f286ea52'
DEPENDENCIES = Path('/tmp/issue3-b02-fetch-diagnosis-20261030-0745')
CACHE = dict(builder='issue3-owned-20261029-b02',
             container_id='8c1e55a9cdd2c77c443a75c82c5939e8cc0c1e237bf6208f71108e00d53bf519',
             volume='buildx_buildkit_issue3-owned-20261029-b020_state')
CONFIG_SHA = '678eb74df54bf325d6e489f64ad385864ac7fe88cbff290e35c514e3c02ca770'
SPENT_ATTEMPTS = frozenset(('issue3-owned-20261029-b01', CACHE['builder']))
APPROVED_TIME_BUDGET = dict(vere_seconds=3300, outer_seconds=3600,
                            settlement_seconds=60, export_allowance_seconds=120)


def time_budget_checked(value):
    if value is not None and (value != APPROVED_TIME_BUDGET or
            any(type(v) is not int for v in value.values())):
        raise ValueError('unsupported approved time budget')
    return value


def load(name):
    spec = importlib.util.spec_from_file_location('issue3_reuse_'+name, HERE/(name+'.py'))
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def sha(path):
    path = load('local_dependencies').regular(path)
    return hashlib.sha256(path.read_bytes()).hexdigest()


def history(trial, root):
    if sha(HISTORY) != HISTORY_SHA:
        raise ValueError('historical receipt drift')
    public = json.loads(HISTORY.read_text())
    prior = Path(public['evidence'])
    for name in ('authorization.json', 'admission.json', 'result.json', 'spent.json', 'build.log', 'buildkitd.toml'):
        if sha(prior/name) != public['evidence_hashes'][name]['sha256']:
            raise ValueError('spent history changed: ' + name)
    binding = trial.hashes(root)
    if binding != public['bindings'] or binding != trial.hashes(prior/'frozen-recipe'):
        raise ValueError('reuse requires exact b02 recipe bindings')
    result = json.loads((prior/'result.json').read_text())
    if (result.get('attempt') != CACHE['builder'] or result.get('container_id') != CACHE['container_id'] or
            result.get('build_launched') is not True or result.get('settled') is not True or result.get('status') != 'FAIL'):
        raise ValueError('cache history identity/settlement mismatch')
    auth = json.loads((prior/'authorization.json').read_text())
    admission = json.loads((prior/'admission.json').read_text())
    return dict(recipe=binding, prior=str(prior),
                baseline=dict(host_free=auth['host_initial_free'], engine_free=admission['engine_free']))


def prepare(trial, root, evidence, attempt, now=None, *, time_budget=None):
    time_budget_checked(time_budget)
    if not re.fullmatch('issue3-owned-[a-z0-9-]{6,50}', attempt) or attempt in SPENT_ATTEMPTS:
        raise ValueError('fresh attempt identity required; spent b01/b02 cannot replay')
    evidence = Path(evidence).absolute()
    if evidence.resolve() != evidence or evidence.parent != trial.SCRATCH or evidence.exists():
        raise ValueError('fresh direct scratch evidence required')
    old = history(trial, root)
    now = time.time() if now is None else now
    return dict(schema='issue3-b02-cache-reuse-v1', execution_authorized=False,
                attempt=attempt, evidence=str(evidence), created_unix=now, expires_unix=now+300,
                cache=CACHE, history_sha256=HISTORY_SHA, **old,
                dependencies=load('local_dependencies').verify(DEPENDENCIES),
                dependency_dir=str(DEPENDENCIES),
                adapter={n: sha(HERE/n) for n in ('cache_reuse.py', 'local_dependencies.py', 'local_build.py', 'buildkit_trial.py', 'progress_observer.py')},
                budget=trial.StorageBudget(6*trial.GIB, trial.GIB).receipt(),
                **({} if time_budget is None else dict(time_budget=time_budget)))


def inspect_stopped(trial):
    data = json.loads(trial.run(['inspect', '--format', trial.FORMAT, CACHE['container_id']]))
    trial.controls(data, CACHE['builder'], CACHE['container_id'])
    if data.get('running') is not False or data.get('pid') != 0 or data.get('oom') is not False:
        raise ValueError('cache builder active/uncertain/OOM')
    mounts = json.loads(trial.run(['inspect', '--format', '{{json .Mounts}}', CACHE['container_id']]))
    state = [m for m in mounts if m.get('Destination') == '/var/lib/buildkit']
    if len(state) != 1 or state[0].get('Type') != 'volume' or state[0].get('Name') != CACHE['volume'] or state[0].get('RW') is not True:
        raise ValueError('cache state volume identity mismatch')
    refs = trial.run(['ps', '-aq', '--no-trunc', '--filter', 'volume='+CACHE['volume']]).split()
    if refs != [CACHE['container_id']]:
        raise ValueError('cache volume has concurrent/unexpected references')
    builder = trial.run(['buildx', 'inspect', CACHE['builder']])
    for field, value in [('Name', CACHE['builder']), ('Driver', 'docker-container'), ('Endpoint', trial.CONTEXT)]:
        if not re.search(r'^'+field+r':\s*'+re.escape(value)+r'\s*$', builder, re.M):
            raise ValueError('Buildx builder identity mismatch: ' + field)
    return data


def validate(trial, path, digest, root, evidence, attempt, now=None):
    if not re.fullmatch('[0-9a-f]{64}', digest or '') or sha(path) != digest:
        raise ValueError('reuse receipt hash mismatch')
    request = json.loads(Path(path).read_text())
    now = time.time() if now is None else now
    created, expires = request.get('created_unix'), request.get('expires_unix')
    if type(created) not in (float, int) or type(expires) not in (float, int) or not created <= now <= expires or expires-created != 300:
        raise ValueError('stale/invalid reuse readiness')
    expected = prepare(trial, root, evidence, attempt, now=created,
                       time_budget=request.get('time_budget'))
    if request != expected:
        raise ValueError('reuse identity/pin/recipe/adapter binding mismatch')
    inspect_stopped(trial)
    return request


@contextmanager
def lock(trial):
    path = trial.SCRATCH/(CACHE['builder']+'.reuse.lock')
    if path.is_symlink():
        raise ValueError('nonregular reuse lock')
    with path.open('a+') as stream:
        try:
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise ValueError('concurrent cache reuse') from error
        try:
            yield
        finally:
            fcntl.flock(stream, fcntl.LOCK_UN)


def dockerfile(original, time_budget=None):
    time_budget_checked(time_budget)
    old = ('    python3 candidate.py --build --arena-bytes "$UVM_OPENSSL_ARENA_BYTES" --output /work/attempt \\\n')
    if original.count(old) != 1 or original.count('ARG UVM_BUILD_ATTEMPT_ID\n') != 1:
        raise ValueError('unsupported cache recipe layout')
    # Separate named context introduced ONLY after the completed library stage.
    effective = original.replace('ARG UVM_BUILD_ATTEMPT_ID\n',
        'ARG UVM_BUILD_ATTEMPT_ID\nCOPY --from=issue3deps / /local-deps/\n').replace(old,
        '    python3 /local-deps/local_build.py --build --arena-bytes "$UVM_OPENSSL_ARENA_BYTES" --output /work/attempt \\\n')
    if time_budget is not None:
        effective = effective.replace('ARG UVM_BUILD_ATTEMPT_ID\n',
            'ARG UVM_BUILD_ATTEMPT_ID\nARG UVM_OUTER_DEADLINE_UNIX\n').replace(
            '--build --arena-bytes', '--build --vere-seconds 3300 --export-allowance-seconds 120 '
            '--outer-deadline-unix "$UVM_OUTER_DEADLINE_UNIX" --arena-bytes')
    return effective


def stage(trial, evidence, frozen, request):
    import shutil
    if any(sha(HERE/n) != digest for n, digest in request['adapter'].items()):
        raise ValueError('reuse adapter drift')
    deps = evidence/'local-deps'
    deps.mkdir()
    for name in ('local_dependencies.py', 'local_build.py', 'progress_observer.py'):
        shutil.copyfile(HERE/name, deps/name)
    for name in request['dependencies']:
        shutil.copyfile(DEPENDENCIES/(name+'.tar.gz'), deps/(name+'.tar.gz'))
    load('local_dependencies').verify(deps)
    effective = evidence/'reuse.Dockerfile'
    effective.write_text(dockerfile((frozen/'Dockerfile').read_text(), request.get('time_budget')))
    shutil.copyfile(effective, deps/'effective.Dockerfile')
    trial.record(evidence, 'reuse-binding.json', dict(request=request, effective_dockerfile_sha256=sha(effective),
        context_files={p.name: sha(p) for p in sorted(deps.iterdir())}))
    return effective, deps


def verify_staged(evidence, frozen, request):
    expected_dockerfile = hashlib.sha256(dockerfile((frozen/'Dockerfile').read_text(), request.get('time_budget')).encode()).hexdigest()
    expected = {name: request['adapter'][name] for name in ('local_dependencies.py', 'local_build.py', 'progress_observer.py')}
    expected.update({name+'.tar.gz': value['sha256'] for name, value in request['dependencies'].items()})
    expected['effective.Dockerfile'] = expected_dockerfile
    if (sha(evidence/'reuse.Dockerfile') != expected_dockerfile or
            {p.name: sha(p) for p in (evidence/'local-deps').iterdir()} != expected or
            any(sha(HERE/n) != digest for n, digest in request['adapter'].items())):
        raise ValueError('staged local input drift')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('recipe', 'evidence', 'output'):
        p.add_argument('--'+name, type=Path, required=True)
    p.add_argument('--attempt', required=True)
    a = p.parse_args()
    trial = load('buildkit_trial')
    request = prepare(trial, a.recipe.absolute(), a.evidence, a.attempt)
    inspect_stopped(trial)
    with a.output.open('x') as stream:
        json.dump(request, stream, indent=2, sort_keys=True)
        stream.write('\n')
    print(sha(a.output))


if __name__ == '__main__':
    main()
