"""One immutable host-monotonic settlement endpoint per fresh attempt.

Publish a fully fsynced nonempty directory by atomic rename. Contenders keep
unpublished candidates as evidence; no polling/retry, partial-file reads or
endpoint replacement. These small host receipts grant no target authority.
"""
import errno
import hashlib
import json
import math
import os
from pathlib import Path
import tempfile
import time

from . import prepare, wire
from .stage import open_regular, save_new

NAME='shared-settlement-endpoint'


def remaining(deadline, maximum=None):
    value=deadline-time.monotonic()
    prepare.require(math.isfinite(value) and value>0,'shared settlement endpoint expired')
    return value if maximum is None else min(maximum,value)


def read(profile,folder):
    with open_regular(Path(folder)/NAME/'endpoint.json') as stream:
        data=stream.read(4097)
    prepare.require(len(data)<=4096,'settlement endpoint receipt cap')
    row=json.loads(data)
    keys={'schema','profile_sha256','start_monotonic','deadline_monotonic',
          'experiment_deadline_monotonic','allowance_seconds','nonresettable'}
    prepare.require(type(row) is dict and set(row)==keys,'complete settlement endpoint required')
    start=row['start_monotonic']; end=row['deadline_monotonic']
    exp=profile['experiment']['deadline_monotonic']; allowance=profile['settlement_allowance_seconds']
    prepare.require(all(type(v) in (int,float) and math.isfinite(v)
        for v in (start,end,exp,allowance,row['experiment_deadline_monotonic'],row['allowance_seconds'])) and
        0<allowance<=60 and start<end and end==min(start+allowance,exp) and
        row['experiment_deadline_monotonic']==exp and row['allowance_seconds']==allowance and
        row['schema']=='issue3-probe-settlement-endpoint-v1' and row['nonresettable'] is True and
        row['profile_sha256']==hashlib.sha256(wire.encoded(profile)).hexdigest(),
        'settlement endpoint identity/envelope drift')
    return row


def acquire(profile,folder):
    folder=Path(folder)
    prepare.require(folder.is_absolute() and folder==folder.resolve(),'canonical settlement folder required')
    target=folder/NAME
    if target.exists() or target.is_symlink(): return read(profile,folder)
    now=time.monotonic(); exp=profile['experiment']['deadline_monotonic']
    allowance=profile['settlement_allowance_seconds']
    prepare.require(type(allowance) in (int,float) and math.isfinite(allowance) and
        0<allowance<=60 and type(exp) in (int,float) and math.isfinite(exp) and now<exp,
        'fixed shared settlement envelope exhausted or invalid')
    row=dict(schema='issue3-probe-settlement-endpoint-v1',
        profile_sha256=hashlib.sha256(wire.encoded(profile)).hexdigest(),
        start_monotonic=now,deadline_monotonic=min(now+allowance,exp),
        experiment_deadline_monotonic=exp,allowance_seconds=allowance,nonresettable=True)
    candidate=Path(tempfile.mkdtemp(prefix='settlement-endpoint-candidate-',dir=folder))
    save_new(candidate/'endpoint.json',wire.encoded(row))
    (candidate/'endpoint.json').chmod(0o444)
    try: os.rename(candidate,target)
    except OSError as exc:
        if exc.errno not in (errno.EEXIST,errno.ENOTEMPTY): raise
    fd=os.open(folder,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try: os.fsync(fd)
    finally: os.close(fd)
    return read(profile,folder)
