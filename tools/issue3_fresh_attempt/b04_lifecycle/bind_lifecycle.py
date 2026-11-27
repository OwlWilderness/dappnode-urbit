#!/usr/bin/env python3
"""Bind a fresh copy to B's genuine selected-file inventory; no engine by default.

--execute-approved-lifecycle is the explicit continuation of the existing owner
new independent one-shot owner grant. Genuine B PASS is required; A remains unqualified.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import gate
from gate import FROZEN_FILES as FILES

HERE = Path(__file__).absolute().parent
ROOT = HERE.parents[2]
SCRATCH = Path('/tmp')
ELF = SCRATCH / 'issue3-owned-trial-20261030-b04-observed/artifact/urbit'
PILL = SCRATCH / 'uvm-local-candidate-xyk06zr3/urbit-v4.6.pill'

OWNER_GRANT = gate.INDEPENDENT_OWNER_GRANT


def seal(path):
    raw = gate.read_public(str(path), 256*1024**2)
    return dict(path=str(path), size=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def exclusive(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def bind(task, inventory, inventory_sha256, owner_policy=None):
    # Authenticate required B evidence before any task creation; a fixture is not B PASS.
    raw = gate.read_public(str(inventory))
    gate.require(gate.digest(inventory_sha256) and hashlib.sha256(raw).hexdigest() == inventory_sha256,
                 'independently retained B inventory SHA256 required')
    config = gate.strict(gate.read_public(str(HERE / 'config.json')))
    config['state'] = 'BOUND'
    r = gate.strict(raw)
    config['artifacts']['image'] = r.get('image', {}).get('image_id')
    paths = dict(binary=ELF, adapter=ROOT/'build/runtime-b04.py', binding=ROOT/'build/vere-owned-b04.json',
                 receipt=inventory, pill=PILL, dockerfile=ROOT/'build/Dockerfile.b04',
                 notice_manifest=ROOT/'build/notice-files.json')
    config['inputs'] = {k: seal(v) for k,v in paths.items()}
    gate.require(config['inputs']['receipt']['sha256'] == inventory_sha256, 'receipt changed')
    if owner_policy is not None:
        config['owner_policy'] = seal(owner_policy)
    gate.validate_bindings(config)
    task = Path(task)
    gate.require(task.is_absolute() and task.parent == SCRATCH and
                 task.name.startswith('issue3-b04-life-') and '..' not in task.parts,
                 'fresh direct scratch child required')
    gate.safe(str(SCRATCH), True)
    sources = {n: gate.read_public(str(HERE/n)) for n in FILES if n != 'config.json'}
    sources['lifecycle_guest.py'] = sources['lifecycle_guest.py'].replace(
        b"BINDING_STATE = 'UNBOUND'", b"BINDING_STATE = 'BOUND'")
    sources['config.json'] = (json.dumps(config, sort_keys=True, indent=2)+'\n').encode()
    os.mkdir(task, 0o700)  # exclusive; failed partial preparation is retained, never resumed
    for name, data in sources.items():
        exclusive(task/name, data)
    bundle = dict(schema=1, task=str(task), files={n: hashlib.sha256(v).hexdigest() for n,v in sources.items()})
    exclusive(task/'bundle.json', (json.dumps(bundle,sort_keys=True)+'\n').encode())
    gate.preflight(str(task/'run_lifecycle.py'), 'lifecycle')
    return task


def execute_approved(task):
    config = gate.strict(gate.read_public(str(task/'config.json')))
    gate.validate_independent_policy(gate.receipt(config['owner_policy']),
        config['artifacts']['image'], config['inputs']['receipt']['sha256'])
    # prepare is read-only engine metadata plus a fresh local plan; no ship yet.
    subprocess.run([sys.executable, str(task/'run_lifecycle.py'), 'prepare'],
                   stdin=subprocess.DEVNULL, check=True, timeout=300)
    raw = gate.read_public(str(task/'plan.json'))
    plan = gate.strict(raw)
    # base.canonical is sorted compact JSON with no terminal newline.
    digest = hashlib.sha256(json.dumps(plan,sort_keys=True,separators=(',',':'),allow_nan=False).encode()).hexdigest()
    approval = dict(schema=1, authorized=True, epoch=plan['epoch'], plan_sha256=digest, owner_grant=OWNER_GRANT)
    exclusive(task/'authorization.json', json.dumps(approval,sort_keys=True).encode())
    # No second wrapper process/timeout that could kill the settlement controller.
    os.execv(sys.executable, [sys.executable, str(task/'run_lifecycle.py'), 'run'])


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--task',required=True,type=Path)
    parser.add_argument('--inventory',required=True,type=Path)
    parser.add_argument('--inventory-sha256',required=True)
    parser.add_argument('--owner-policy',type=Path,required=True)
    parser.add_argument('--execute-approved-lifecycle',action='store_true')
    args=parser.parse_args()
    task=bind(args.task,args.inventory,args.inventory_sha256,args.owner_policy)
    if args.execute_approved_lifecycle:
        execute_approved(task)
    print(json.dumps(dict(status='BOUND_NOT_EXECUTED',task=str(task),image_identity_from_actual_B_receipt=True)))


if __name__ == '__main__':
    main()
