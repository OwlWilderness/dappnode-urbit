"""Late-stage driver; leave original recipe/cache identity untouched.

The original candidate performs its ordinary exclusive preparation and cache
validation. Seed only the fresh attempt's package cache with actual pinned Zig,
then invoke its unchanged compiler. No manifest/pin rewriting or old-cache writes.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import signal
import sys
import time
from contextlib import contextmanager

sys.path.insert(0, '/recipe')
import candidate
import local_dependencies
import progress_observer


def configure_budget(attempt, vere_seconds, outer_deadline_unix, export_allowance_seconds):
    """Only the explicitly selected late Vere command gets a longer bound.

    Delegate cancellation, capacity checks, observer and reaping to frozen run().
    Wall-clock remaining allowance is additionally bounded by the independent
    monotonic outer supervisor. Clock jumps cannot extend that outer ceiling.
    """
    import math
    if (vere_seconds != 3300 or export_allowance_seconds != 120 or
            type(outer_deadline_unix) not in (int, float) or
            not math.isfinite(outer_deadline_unix) or
            outer_deadline_unix > time.time()+3600):
        raise ValueError('unsupported approved late time budget')
    original = attempt.run
    def run(stage, argv, cwd, env, *args, **kwargs):
        if stage == 'vere-build':
            if args or kwargs:
                raise ValueError('ambiguous Vere time budget')
            effective = min(vere_seconds, outer_deadline_unix-time.time()-export_allowance_seconds)
            if effective <= 0:
                raise ValueError('no remaining outer budget after export allowance')
            attempt.event('vere-time-budget', requested_seconds=vere_seconds,
                          effective_seconds=effective, outer_deadline_unix=outer_deadline_unix,
                          export_allowance_seconds=export_allowance_seconds)
            kwargs['timeout'] = effective
        return original(stage, argv, cwd, env, *args, **kwargs)
    attempt.run = run


@contextmanager
def phase(attempt, name):
    before = time.monotonic()
    def note(status, **values):
        try:
            attempt.event(status, phase=name, monotonic=time.monotonic(), **values)
        except Exception:
            attempt._phase_observer_failures = getattr(attempt, '_phase_observer_failures', 0)+1
    note('phase-entered')
    try:
        yield
    except BaseException:
        note('phase-failed', elapsed_seconds=time.monotonic()-before)
        raise
    else:
        note('phase-returned', elapsed_seconds=time.monotonic()-before)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--build', action='store_true', required=True)
    p.add_argument('--arena-bytes', type=int, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--input-dir', type=Path, required=True)
    p.add_argument('--openssl-cache', type=Path, required=True)
    p.add_argument('--attempt-id', required=True)
    p.add_argument('--vere-seconds', type=int)
    p.add_argument('--outer-deadline-unix', type=float)
    p.add_argument('--export-allowance-seconds', type=int)
    a = p.parse_args()
    selected_budget = (a.vere_seconds, a.outer_deadline_unix, a.export_allowance_seconds)
    if any(v is not None for v in selected_budget) and any(v is None for v in selected_budget):
        raise ValueError('complete explicit late time budget required')
    if (not candidate.re.fullmatch('issue3-owned-[a-z0-9-]{6,50}', a.attempt_id) or
            a.attempt_id in ('issue3-owned-20261029-b01', 'issue3-owned-20261029-b02')):
        raise ValueError('fresh authorized attempt label required')
    candidate.owned.capacity(a.arena_bytes)
    candidate.owned.validate_recipe(candidate.HERE)
    # Late-only substitution: keep original recipes, timeout and safety loop.
    candidate.StageDiagnostics = progress_observer.StageDiagnostics
    lock = json.loads((candidate.HERE/'inputs.json').read_text())
    attempt = candidate.Attempt(a.output.resolve())
    if a.vere_seconds is not None:
        configure_budget(attempt, *selected_budget)
    attempt.event('authorization-label', attempt_id=a.attempt_id, driver='local-dependencies-v1')
    previous = signal.signal(signal.SIGTERM, candidate.stop_on_sigterm)
    try:
        with phase(attempt, 'openssl-validation'):
            local_dependencies.verify_openssl(a.openssl_cache,
                a.openssl_cache/lock['inputs']['openssl']['root'])
        with phase(attempt, 'source-preparation'):
            trees = candidate.prepare(attempt, lock, a.input_dir, arena_bytes=a.arena_bytes)
        with phase(attempt, 'local-package-validation'):
            local_dependencies.seed(Path(__file__).parent, trees['zig']/'zig', attempt.output, trees['vere'])
        with phase(attempt, 'compile-and-delivery'):
            candidate.compile_candidate(attempt, lock, trees, openssl_cache=a.openssl_cache)
        delivery = attempt.output/'delivery'
        for name in ('local-dependencies.json',):
            shutil.copyfile(attempt.output/name, delivery/name)
        for name in ('local_build.py', 'local_dependencies.py', 'progress_observer.py', 'effective.Dockerfile'):
            shutil.copyfile(Path(__file__).parent/name, delivery/name)
        receipt = {n: hashlib.sha256((delivery/n).read_bytes()).hexdigest() for n in
                   ('local-dependencies.json', 'local_build.py', 'local_dependencies.py', 'progress_observer.py', 'effective.Dockerfile')}
        (delivery/'local-build-binding.json').write_text(json.dumps(receipt, indent=2)+'\n')
        candidate.CapacityGuard(attempt.output).check(force=True)
    except candidate.BuildStopped:
        attempt.event('stopped', reason='SIGTERM')
        raise SystemExit(128+signal.SIGTERM)
    except Exception as error:
        attempt.event('failed', error_type=type(error).__name__, detail=str(error))
        raise SystemExit(1)
    finally:
        signal.signal(signal.SIGTERM, previous)


if __name__ == '__main__':
    main()
