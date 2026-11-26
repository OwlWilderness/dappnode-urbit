"""Host-only, conditional arena sizing arithmetic; never a build/run admission grant.

No measurement collector exists in this module or the selected arena. In particular,
live_blocks() is a count, not an occupied-byte high-water. Do not substitute RSS,
configured mmap length or host fixture capacities for measured arena use.
"""
import argparse
import json
from pathlib import Path
import re
import sys

PAGE_BYTES = 16384
MIN_BYTES = 131072
MAX_BYTES = 4294950912  # selected recipe's upper bound, below UINT32_MAX
FIELDS = {'schema_version', 'binary_sha256', 'workload', 'measurement_method',
          'peak_arena_in_use_bytes', 'successful_arena_capacity_bytes',
          'peak_other_resident_bytes', 'memory_limit_bytes'}


def nonnegative(value, name):
    if type(value) is not int or value < 0:
        raise ValueError(name + ' must be an explicit nonnegative integer byte count')
    return value


def assess(measurements, *, arena_headroom_bytes, system_headroom_bytes):
    """Assess an externally supplied measurement envelope, not verify provenance.

    Other resident peak must exclude arena residency and encompass concurrent
    non-arena memory over the measured workload. The entire new arena mapping is
    conservatively treated as resident for this arithmetic; it can be less in
    reality. Observed arena use is not sufficient to prove fragmentation safety.
    """
    if type(measurements) is not dict or set(measurements) != FIELDS:
        raise ValueError('complete measurement fields required; unknown fields refused')
    if measurements['schema_version'] != 1 or type(measurements['schema_version']) is not int:
        raise ValueError('unsupported measurement schema')
    digest = measurements['binary_sha256']
    if type(digest) is not str or not re.fullmatch('[0-9a-f]{64}', digest):
        raise ValueError('exact-binary SHA256 identifier required')
    for field in ('workload', 'measurement_method'):
        if type(measurements[field]) is not str or not measurements[field].strip():
            raise ValueError(field + ' must identify the external observation')
    peak = nonnegative(measurements['peak_arena_in_use_bytes'], 'peak_arena_in_use_bytes')
    observed = nonnegative(measurements['successful_arena_capacity_bytes'],
                           'successful_arena_capacity_bytes')
    other = nonnegative(measurements['peak_other_resident_bytes'], 'peak_other_resident_bytes')
    limit = nonnegative(measurements['memory_limit_bytes'], 'memory_limit_bytes')
    margin = nonnegative(arena_headroom_bytes, 'arena_headroom_bytes')
    system_margin = nonnegative(system_headroom_bytes, 'system_headroom_bytes')
    if not MIN_BYTES <= observed <= MAX_BYTES or observed % PAGE_BYTES:
        raise ValueError('observed successful capacity outside exact recipe bounds/alignment')
    if peak > observed:
        raise ValueError('measured arena use exceeds observed successful arena capacity')
    candidate = max(observed, ((peak + margin + PAGE_BYTES - 1) // PAGE_BYTES) * PAGE_BYTES,
                    MIN_BYTES)
    if candidate > MAX_BYTES:
        raise ValueError('estimate exceeds exact recipe capacity bound')
    envelope = candidate + other + system_margin
    return dict(measured_peak_arena_in_use_bytes=peak,
                measured_successful_arena_capacity_bytes=observed,
                measured_peak_other_resident_bytes=other,
                input_memory_limit_bytes=limit,
                estimated_arena_capacity_bytes=candidate,
                explicit_arena_headroom_bytes=margin,
                explicit_system_headroom_bytes=system_margin,
                worst_case_resident_envelope_bytes=envelope,
                arithmetic_admission=('within-input-bound-only' if envelope <= limit
                                      else 'refused-input-bound-exceeded'),
                production_authorized=False,
                evidence_verified=False)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--measurements', required=True, type=Path)
    parser.add_argument('--arena-headroom-bytes', required=True, type=int)
    parser.add_argument('--system-headroom-bytes', required=True, type=int)
    args = parser.parse_args(argv)
    try:
        data = json.loads(args.measurements.read_text())
        result = assess(data, arena_headroom_bytes=args.arena_headroom_bytes,
                        system_headroom_bytes=args.system_headroom_bytes)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print('REFUSED: ' + str(exc), file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0 if result['arithmetic_admission'] == 'within-input-bound-only' else 2


if __name__ == '__main__':
    sys.exit(main())
