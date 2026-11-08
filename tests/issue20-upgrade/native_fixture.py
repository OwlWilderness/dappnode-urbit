"""Synthetic native-0.1.6 retained metadata; never native authority or ship data."""
import hashlib
import json
import os
from pathlib import Path


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def seed_native(root):
    root = Path(root)
    control = root / 'control'
    evidence = root / 'legacy015-evidence'
    evidence.mkdir(mode=0o700)
    saved = evidence / ('legacy015-' + 'b'*32)
    saved.mkdir(mode=0o700)
    def write(path, raw):
        path.write_bytes(raw)
        path.chmod(0o600)
        return digest(raw)
    def encode(value):
        return json.dumps(value, sort_keys=True).encode()
    runtime = b'{"state":"RUNNING"}\n'
    write(control / 'runtime.json', runtime)
    job = (control / 'job.json').read_bytes()
    roots = {k: [p.stat().st_dev, p.stat().st_ino] for k,p in
             [('pier',root/'pier'),('uploads',root/'uploads'),('control',control),('evidence',evidence)]}
    bindings = {k: [str(p), p.stat().st_dev, p.stat().st_ino] for k,p in
                [('pier',root/'pier'),('control',control),('evidence',evidence),
                 ('ship',root/'pier/ship'),('marker',root/'pier/ship/.urb'),
                 ('runtime.json',control/'runtime.json'),('job.json',control/'job.json')]}
    # Opaque synthetic receipt is retained history, NOT used for startup authority.
    receipt = b'{"synthetic_history":true}'
    command = {'policy':'TRUSTED_NATIVE_ADMIN_MAINTENANCE_V1','generation':'c'*64,
               'sequence':2,'transaction':'d'*32,'operation':'start','expires':1,
               'old_container_id':'1'*64,'container_id':'2'*64,'sources':{},
               'native_receipt_sha256':digest(receipt),'runtime_sha256':digest(b'{"state":"STOPPED"}\n'),
               'job_sha256':digest(job),'confirmation':'Start the retained pier after native legacy015 repair',
               'prior_state_sha256':None}
    raw = encode(command)
    hashes = {name:write(saved/name, data) for name,data in
              [('runtime.before',runtime),('job.before',job),('bindings.json',encode(bindings)),
               ('native-command.json',b'{"synthetic_repair_history":true}'),('native-receipt.json',receipt)]}
    state = {'build':'legacy015-permanent-recovery-1','state':'WRITER_ADMITTED','generation':'c'*64,
             'roots':roots,'evidence':saved.name,'evidence_hashes':hashes,
             'runtime_sha256':command['runtime_sha256'],'job_sha256':digest(job),
             'native_sequence':2,'native_command_raw':raw.decode(),'native_pending':command,
             'native_command_sha256':digest(raw),'native_outcome':'COMPLETE',
             'native_container_id':'2'*64,'native_old_container_id':'1'*64,
             'native_completed':{'sequence':2,'operation':'start','command_sha256':digest(raw),
                                 'runtime_sha256':digest(runtime),'job_sha256':digest(job)}}
    state_sha = write(control/'legacy-recovery-state.json',encode(state))
    status = {'policy':command['policy'],'generation':'c'*64,'durable_generation':'c'*64,
              'state':state['state'],'sequence':2,'sources':{},'feature_retained':True,'error':None,
              'outcome':'COMPLETE','runtime_sha256':digest(runtime),'job_sha256':digest(job),
              'state_sha256':state_sha,'command_sha256':digest(raw)}
    write(control/'native-file-status.json',encode(status))
    return state


def snapshot(root):
    """Fixture-only synthetic tree snapshot including inode/mode, no production pier reads."""
    root = Path(root)
    return {str(p.relative_to(root)): {'inode':p.stat().st_ino,'mode':p.stat().st_mode & 0o777,
             'uid':p.stat().st_uid,'gid':p.stat().st_gid,
             'sha256':digest(p.read_bytes()) if p.is_file() else None}
            for p in root.rglob('*')}
