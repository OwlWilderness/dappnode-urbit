"""Lifecycle-only immutable 210s endpoint. Never imports the 60s probe profile."""
import errno
import hashlib
import math
import os
from pathlib import Path
import tempfile
import time
import base

NAME = 'lifecycle-settlement-endpoint'



def remaining(deadline, maximum=None):
    value = deadline - time.monotonic()
    base.require(type(deadline) in (int, float) and math.isfinite(value) and value > 0)
    return value if maximum is None else min(maximum, value)


def read_json(path, limit=1024**2):
    return base.strict(base.pinned(str(path), limit, True))


def context_hash(context):
    base.require(set(context) == {'schema', 'plan_sha256', 'epoch', 'controller_pid',
                                 'execution_start', 'execution_end'})
    base.require(type(context['schema']) is int and context['schema'] == 1)
    base.require(type(context['controller_pid']) is int and context['controller_pid'] > 1)
    import re
    base.require(isinstance(context['plan_sha256'], str) and re.fullmatch(base.HEX, context['plan_sha256']))
    base.require(isinstance(context['epoch'], str) and re.fullmatch('[0-9a-f]{32}', context['epoch']))
    a, b = context['execution_start'], context['execution_end']
    base.require(all(type(v) in (float, int) and math.isfinite(v) for v in (a, b)) and b-a == 1600)
    return hashlib.sha256(base.canonical(context)).hexdigest()


def read(folder, context):
    row = read_json(Path(folder)/NAME/'endpoint.json', 4096)
    base.require(set(row) == {'schema', 'context_sha256', 'start', 'deadline', 'allowance_seconds'})
    base.require(row['schema'] == 'issue3-lifecycle-settlement-v1' and
                 row['context_sha256'] == context_hash(context) and
                 type(row['allowance_seconds']) is int and row['allowance_seconds'] == 210)
    start, end = row['start'], row['deadline']
    base.require(all(type(v) in (int, float) and math.isfinite(v) for v in (start, end)) and
                 context['execution_start'] <= start < end and
                 end == min(start + 210, context['execution_end'] + 210))
    return row


def acquire(folder, context):
    folder = Path(folder)
    base.safe(str(folder), True)
    context_hash(context)
    target = folder/NAME
    if target.exists() or target.is_symlink():
        return read(folder, context)
    now = time.monotonic()
    end = min(now + 210, context['execution_end'] + 210)
    base.require(context['execution_start'] <= now < end)
    row = dict(schema='issue3-lifecycle-settlement-v1', context_sha256=context_hash(context),
               start=now, deadline=end, allowance_seconds=210)
    candidate = Path(tempfile.mkdtemp(prefix='lifecycle-endpoint-candidate-', dir=folder))
    base.durable(str(candidate/'endpoint.json'), row)
    os.chmod(candidate/'endpoint.json', 0o400)
    try:
        os.rename(candidate, target)
    except OSError as exc:
        if exc.errno not in (errno.EEXIST, errno.ENOTEMPTY):
            raise
    fd = os.open(folder, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    return read(folder, context)
