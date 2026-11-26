"""Conditional multi-process receipt validation/arithmetic. Never authorizes a run.

All observations/provenance/population are externally supplied and unverified.
No Docker, process inspection, payloads, source build or runtime is invoked.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

ROLES = {1: 'king', 2: 'worker', 3: 'utility'}
PHASES = {'ready', 'warm_crypto', 'tls', 'churn', 'steady', 'application'}
RECORD_FIELDS = {'schema_version', 'run_sha256', 'domain_sha256', 'generation', 'role',
                 'sequence', 'phase', 'capacity_bytes', 'charged_bytes',
                 'peak_charged_bytes', 'live_blocks', 'allocation_failures'}
FIELDS = {'schema_version', 'run_sha256', 'domain_sha256', 'binary_sha256',
          'recipe_sha256', 'collector_sha256', 'workload_sha256', 'processes',
          'population', 'lifecycle', 'non_arena_upper_bound_bytes', 'memory_limit_bytes',
          'oom_events', 'resource_bounds_satisfied', 'required_phases'}
PAGE, MINIMUM, MAXIMUM = 16384, 131072, 4294950912


def exact(obj, fields):
    if type(obj) is not dict or set(obj) != fields:
        raise ValueError('complete allowlisted fields required')


def number(value, name, minimum=0):
    if type(value) is not int or value < minimum:
        raise ValueError(name + ' must be an explicit integer >= ' + str(minimum))
    return value


def capacity(value):
    number(value, 'capacity', MINIMUM)
    if value > MAXIMUM or value % PAGE:
        raise ValueError('capacity outside exact recipe bounds/alignment')
    return value


def assess(receipt, *, arena_headroom_bytes, system_headroom_bytes):
    exact(receipt, FIELDS)
    margin = number(arena_headroom_bytes, 'arena headroom')
    system = number(system_headroom_bytes, 'system headroom')
    if type(receipt['schema_version']) is not int or receipt['schema_version'] != 1:
        raise ValueError('unsupported receipt schema')
    for key in sorted(FIELDS):
        if key.endswith('_sha256'):
            if type(receipt[key]) is not str or not re.fullmatch('[0-9a-f]{64}', receipt[key]):
                raise ValueError('exact lower-case SHA256 required: ' + key)
    if receipt['resource_bounds_satisfied'] is not True or number(receipt['oom_events'], 'OOM events'):
        raise ValueError('failed resource bounds/OOM trial')
    other = number(receipt['non_arena_upper_bound_bytes'], 'same-domain non-arena upper bound')
    limit = number(receipt['memory_limit_bytes'], 'effective same-domain limit', 1)
    exact(receipt['population'], set(ROLES.values()))
    population = {k: number(v, 'admitted ' + k + ' population')
                  for k, v in receipt['population'].items()}
    required = receipt['required_phases']
    if (type(required) is not list or not required or any(type(p) is not str or p not in PHASES for p in required)
            or len(required) != len(set(required)) or 'ready' not in required):
        raise ValueError('explicit unique allowlisted phase envelope including ready required')
    processes = receipt['processes']
    if type(processes) is not list or not processes:
        raise ValueError('complete process generation inventory required')
    identities, peaks, candidates, common_capacity = {}, [], {}, None
    for proc in processes:
        exact(proc, {'generation', 'role', 'init_success', 'destroy_success', 'exit_status', 'records'})
        gen = number(proc['generation'], 'process generation', 1)
        role = number(proc['role'], 'role', 1)
        if role not in ROLES or gen in identities:
            raise ValueError('duplicate process generation/invalid role')
        if proc['init_success'] is not True or proc['destroy_success'] is not True:
            raise ValueError('incomplete init/destroy outcome')
        if number(proc['exit_status'], 'exit status') != 0:
            raise ValueError('unsuccessful process exit')
        rows = proc['records']
        if type(rows) is not list or len(rows) < 4:
            raise ValueError('missing complete lifecycle records')
        previous_peak, phases, cap = 0, [], 0
        for seq, row in enumerate(rows, 1):
            exact(row, RECORD_FIELDS)
            for key in ('schema_version', 'generation', 'role', 'sequence'):
                number(row[key], key, 1)
            if (row['schema_version'] != 1 or row['generation'] != gen or row['role'] != role
                    or row['sequence'] != seq or any(row[k] != receipt[k] for k in ('run_sha256', 'domain_sha256'))):
                raise ValueError('record identity/domain/run/sequence mismatch')
            cap = capacity(row['capacity_bytes'])
            if common_capacity is None:
                common_capacity = cap
            if common_capacity != cap:
                raise ValueError('exact configured capacity changed within trial')
            charge = number(row['charged_bytes'], 'page charge', 1)
            peak = number(row['peak_charged_bytes'], 'peak page charge', 1)
            number(row['live_blocks'], 'live blocks')
            if (charge % PAGE or peak % PAGE or not charge <= peak <= cap or peak < previous_peak
                    or number(row['allocation_failures'], 'allocation failures')):
                raise ValueError('invalid/regressing charge peak or allocation failure')
            previous_peak = peak
            if type(row['phase']) is not str:
                raise ValueError('allowlisted phase required')
            phases.append(row['phase'])
        if (phases[0] != 'startup' or phases[-2:] != ['pre_destroy', 'destroyed']
                or any(p not in PHASES for p in phases[1:-2]) or not set(required) <= set(phases[1:-2])):
            raise ValueError('missing/misordered lifecycle/required phase')
        if rows[-2]['live_blocks'] or rows[-1]['live_blocks']:
            raise ValueError('nonempty final snapshot')
        if any(rows[-1][k] != rows[-2][k] for k in
               ('capacity_bytes', 'charged_bytes', 'peak_charged_bytes', 'live_blocks', 'allocation_failures')):
            raise ValueError('destroy outcome must retain pre-destroy metrics')
        candidate = capacity(max(cap, ((previous_peak + margin + PAGE - 1) // PAGE) * PAGE))
        identities[gen] = role
        candidates[role] = max(candidates.get(role, 0), candidate)
        peaks.append(dict(generation=gen, role=role, peak_charged_bytes=previous_peak,
                          successful_capacity_bytes=cap))
    # Supervisor order is independent from process sequence; no clock/RSS peak subtraction.
    events = receipt['lifecycle']
    if type(events) is not list:
        raise ValueError('supervisor lifecycle inventory required')
    active, started, exited = set(), set(), set()
    max_concurrent = 0
    for event in events:
        exact(event, {'generation', 'event'})
        gen = number(event['generation'], 'lifecycle generation', 1)
        if gen not in identities:
            raise ValueError('unlisted process generation')
        if event['event'] == 'start' and gen not in started:
            active.add(gen)
            started.add(gen)
        elif event['event'] == 'exit' and gen in active:
            active.remove(gen)
            exited.add(gen)
        else:
            raise ValueError('duplicate/misordered lifecycle event')
        for role, name in ROLES.items():
            if sum(identities[g] == role for g in active) > population[name]:
                raise ValueError('concurrent population exceeds admitted bound')
        max_concurrent = max(max_concurrent, len(active))
    if active or started != set(identities) or exited != set(identities):
        raise ValueError('incomplete supervisor lifecycle')
    for role, name in ROLES.items():
        if population[name] and role not in candidates:
            raise ValueError('admitted role has no successful capacity observation')
    full = sum(population[name] * candidates.get(role, 0) for role, name in ROLES.items())
    envelope = full + other + system
    canonical = json.dumps(receipt, sort_keys=True, separators=(',', ':')).encode()
    return dict(schema_version=1, input_canonical_sha256=hashlib.sha256(canonical).hexdigest(),
                process_peaks=peaks, admitted_population=population,
                observed_max_concurrent_processes=max_concurrent,
                estimated_capacity_bytes_by_role={ROLES[r]: c for r, c in candidates.items()},
                explicit_per_arena_headroom_bytes=margin, explicit_system_headroom_bytes=system,
                full_concurrent_arena_capacity_bytes=full,
                same_domain_non_arena_upper_bound_bytes=other,
                worst_case_resident_envelope_bytes=envelope, input_memory_limit_bytes=limit,
                arithmetic_admission=('within-input-bound-only' if envelope <= limit else 'refused-input-bound-exceeded'),
                production_authorized=False, evidence_verified=False)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate JSON field')
        result[key] = value
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--receipt', required=True, type=Path)
    parser.add_argument('--arena-headroom-bytes', required=True, type=int)
    parser.add_argument('--system-headroom-bytes', required=True, type=int)
    args = parser.parse_args(argv)
    try:
        receipt = json.loads(args.receipt.read_text(), object_pairs_hook=unique_object)
        result = assess(receipt, arena_headroom_bytes=args.arena_headroom_bytes,
                        system_headroom_bytes=args.system_headroom_bytes)
    except (OSError, ValueError) as exc:
        print('REFUSED: ' + str(exc), file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0 if result['arithmetic_admission'] == 'within-input-bound-only' else 2


if __name__ == '__main__':
    sys.exit(main())
