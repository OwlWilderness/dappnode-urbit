"""Stopped-only migration under LIVE outside-writer admission; no Importer init.

Original journals/job are preserved byte-for-byte in root-only host evidence.
Only intact committed imports are eligible. A transaction admits each slot's
original or its own single exact target, including rename-before-fsync ambiguity.
No PID/boot/lock observation grants scope proof. No runtime is started here.
"""
import fcntl
import json
import os
import re
import uuid
from maintenance_provider import (Blocked, StorageAdmission, atomic, decode,
                                  encode, identity, open_root, read_raw)


def runtime_record(raw, storage):
    if raw is None:
        return None
    record = decode(raw)
    if not isinstance(record, dict) or record.get('state') not in (
            'STOPPED', 'STARTING', 'RUNNING', 'FAULT', 'RECOVERY_REQUIRED'):
        raise Blocked()
    if set(record) == {'state'}:
        return record
    if (set(record) != {'version', 'state', 'generation', 'boot_id', 'storage'} or
            type(record['version']) is not int or record['version'] not in (2, 3) or
            not isinstance(record['generation'], str) or not re.fullmatch('[a-f0-9]{32}', record['generation']) or
            not isinstance(record['boot_id'], str) or
            not re.fullmatch(r'[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}', record['boot_id']) or
            record['storage'] != storage):
        raise Blocked()
    return record


def ready_import(raw):
    """Same committed-job bounds as Importer, but no constructor side effects."""
    try:
        job = decode(raw)
        if (not isinstance(job, dict) or job['state'] != 'READY_LOCKED' or
                not isinstance(job['id'], str) or not re.fullmatch('[a-f0-9]{32}', job['id']) or
                type(job['offset']) is not int or type(job['total_bytes']) is not int or
                not 0 < job['offset'] == job['total_bytes'] <= 8 * 1024**3 or
                type(job['expanded_limit']) is not int or not 0 < job['expanded_limit'] <= 64 * 1024**3):
            raise ValueError()
        return job
    except Exception:
        raise Blocked('IMPORT_STATE_UNPROVABLE') from None


def recover_stopped(storage, admission):
    if type(admission) is not StorageAdmission:
        raise Blocked()
    admission.check()
    provider = admission.provider
    if os.path.abspath(storage) != str(provider.storage):
        raise Blocked()
    fds = []
    try:
        roots = {}
        for name in ('pier', 'uploads', 'control'):
            roots[name] = open_root(provider.storage / name, provider.owner_uid)
            fds.append(roots[name])
        # Supplement containment with existing cooperative writer locks. Never
        # treat their availability as positive cessation evidence.
        fcntl.flock(roots['pier'], fcntl.LOCK_EX | fcntl.LOCK_NB)
        lock = os.open('writer.lock', os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK,
                       dir_fd=roots['control'])
        fds.append(lock)
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if set(os.listdir(roots['pier'])) - {'.runtime-owner.json'} != {'ship'}:
            raise Blocked('IMPORT_STATE_UNPROVABLE')
        ship = open_root(provider.storage / 'pier/ship', provider.owner_uid)
        fds.append(ship)
        marker = os.open('.urb', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=ship)
        fds.append(marker)
        if os.listdir(roots['uploads']):
            raise Blocked('IMPORT_STATE_UNPROVABLE')
        storage_id = {name: identity(fd) for name, fd in
                      (('pier', roots['pier']), ('control', roots['control']), ('ship', ship))}
        job_raw = read_raw(roots['control'], 'job.json', uid=provider.owner_uid, limit=65536)
        ready_import(job_raw)
        slots = ((roots['pier'], '.runtime-owner.json'), (roots['control'], 'runtime.json'))
        originals = [read_raw(directory, name, uid=provider.owner_uid, limit=4096) for directory, name in slots]
        transaction_id = provider.state['transaction']
        if transaction_id is None:
            records = [runtime_record(raw, storage_id) for raw in originals]
            # Missing old owner is an admitted legacy shape, not blanket repair
            # of lost v3 ownership. An owner-first interrupted v3 write is allowed
            # when control is absent/legacy, since scope destruction is positive.
            if records[1] is not None and records[1].get('version') == 3 and records[0] is None:
                raise Blocked()
            if records[0] is not None and records[0].get('version') != 3:
                raise Blocked()
            transaction_id = uuid.uuid4().hex
            from runtime import _boot_id
            target = {'version': 3, 'state': 'STOPPED', 'generation': uuid.uuid4().hex,
                      'boot_id': _boot_id() or '00000000-0000-0000-0000-000000000000',
                      'storage': storage_id}
            transaction = {'version': 1, 'container': provider.state['container'],
                           'layout': provider.state['layout'], 'storage': storage_id,
                           'originals': [None if raw is None else raw.hex() for raw in originals],
                           'job': job_raw.hex(), 'target': target}
            atomic(provider.directory, transaction_id + '.json', encode(transaction))
            provider.save(transaction=transaction_id)
        else:
            if not re.fullmatch('[a-f0-9]{32}', transaction_id):
                raise Blocked()
            transaction = decode(read_raw(provider.directory, transaction_id + '.json',
                                          uid=os.geteuid(), limit=262144))
            if (transaction['version'] != 1 or transaction['container'] != provider.state['container'] or
                    transaction['layout'] != provider.state['layout'] or transaction['storage'] != storage_id or
                    transaction['job'] != job_raw.hex()):
                raise Blocked()
            target = transaction['target']
            if runtime_record(encode(target), storage_id)['state'] != 'STOPPED' or target['version'] != 3:
                raise Blocked()
        target_raw = encode(target)
        # Before EACH write revalidate BOTH slots; never repair foreign/missing
        # initialized evidence even after a prior successful own partial write.
        for index, (directory, name) in enumerate(slots):
            admission.check()
            for slot_index, (slot_fd, slot_name) in enumerate(slots):
                raw = read_raw(slot_fd, slot_name, uid=provider.owner_uid, limit=4096)
                original = transaction['originals'][slot_index]
                allowed_original = None if original is None else bytes.fromhex(original)
                if raw not in (allowed_original, target_raw):
                    raise Blocked()
                # A slot already read back/durably written by this invocation can
                # no longer regress to original (even if original was absent).
                if slot_index < index or provider.state['progress'][slot_index] == 2:
                    if raw != target_raw:
                        raise Blocked()
            if read_raw(roots['control'], 'job.json', uid=provider.owner_uid, limit=65536) != job_raw:
                raise Blocked('IMPORT_STATE_UNPROVABLE')
            if provider.state['progress'][index] != 2:
                progress = list(provider.state['progress'])
                progress[index] = 1  # only this exact target is now attempted
                provider.save(progress=progress)
                atomic(directory, name, target_raw, uid=provider.owner_uid, staging=roots['control'])
                progress = list(provider.state['progress'])
                progress[index] = 2
                provider.save(progress=progress)
        admission.check()
        if any(read_raw(fd, name, uid=provider.owner_uid) != target_raw for fd, name in slots):
            raise Blocked()
        return target
    except Blocked:
        raise
    except Exception:
        raise Blocked('RECOVERY_WRITE_UNCERTAIN') from None
    finally:
        for fd in reversed(fds):
            os.close(fd)
