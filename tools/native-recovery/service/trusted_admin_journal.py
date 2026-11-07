"""Separate TRUSTED_NATIVE_ADMIN_MAINTENANCE journal policy.

Not the generic host-exclusion API. A root-delivered bounded command delegates an
authorized administrator's completed native stop/install sequence, under declared
noninterference and ordinary-container-confinement assumptions. Local rechecks
authenticate that delegation and physical journals, NOT fresh native observations,
complete escaped-process enumeration, an imageID, or a hostile-root-proof lease.
The original generic helper remains unchanged; its stronger contract is not met
by this policy. Preserve its atomic transaction/evidence algorithm below.
"""
import contextlib
import fcntl
import json
import os
from pathlib import Path
import re
import stat
import uuid


class RecoveryRefused(Exception):
    pass


class RecoveryUncertain(Exception):
    pass


def _directory(path):
    """Existing private directory only, no symlink ancestor or implicit mkdir."""
    path = Path(os.path.abspath(path))
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        info = os.fstat(fd)
        if len(path.parts) < 2 or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o077:
            raise RecoveryRefused('Existing private service-owned directories required.')
        return fd
    except BaseException:
        os.close(fd)
        raise


def _read(parent, name, limit):
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
    with os.fdopen(fd, 'rb') as source:
        info = os.fstat(source.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or
                stat.S_IMODE(info.st_mode) & 0o077 or info.st_nlink != 1 or info.st_size > limit):
            raise RecoveryRefused('Unsafe legacy journal.')
        raw = source.read(limit + 1)
        if len(raw) > limit:
            raise RecoveryRefused('Oversize legacy journal.')
        return raw, info


def _object(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise RecoveryRefused('Duplicate legacy journal key.')
            result[key] = value
        return result
    try:
        result = json.loads(raw, object_pairs_hook=pairs)
    except (ValueError, UnicodeError):
        raise RecoveryRefused('Malformed legacy journal.') from None
    if type(result) is not dict:
        raise RecoveryRefused('Legacy journal object required.')
    return result


def _write(parent, name, raw):
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
    with os.fdopen(fd, 'wb') as output:
        output.write(raw)
        output.flush()
        os.fsync(output.fileno())


def recover(pier, control, evidence, *, permit):
    """Repair runtime.json under explicitly delegated trusted-admin maintenance.

    All arguments are existing private directories. Evidence must be disjoint;
    a unique retained transaction directory records original runtime/job bytes.
    Returns its path ONLY after file+directory fsync and exact readback. Caller
    must keep host exclusion fail-closed on ANY exception, particularly uncertain
    rename/directory-fsync outcomes. No built-in shell/Docker or live fallback.
    """
    if permit is None or not callable(getattr(permit, 'verify_delegation', None)):
        raise RecoveryRefused('Trusted native-admin command delegation required.')
    target = {key: Path(os.path.abspath(value)) for key, value in
              (('pier', pier), ('control', control), ('evidence', evidence))}
    values = list(target.values())
    for i, first in enumerate(values):
        for second in values[i + 1:]:
            if os.path.commonpath((first, second)) in (str(first), str(second)):
                raise RecoveryRefused('Directories must be separate and non-nested.')
    permit.verify_delegation(target)
    with contextlib.ExitStack() as stack:
        def hold(fd):
            stack.callback(os.close, fd)
            return fd
        dirs = {key: hold(_directory(path)) for key, path in target.items()}
        # Supplemental cooperating-writer locks: never offered as cessation proof.
        fcntl.flock(dirs['pier'], fcntl.LOCK_EX | fcntl.LOCK_NB)
        lock = hold(os.open('writer.lock', os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dirs['control']))
        info = os.fstat(lock)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or
                stat.S_IMODE(info.st_mode) & 0o077 or info.st_nlink != 1):
            raise RecoveryRefused('Unsafe legacy writer lock.')
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if os.listdir(dirs['pier']) != ['ship']:
            raise RecoveryRefused('Expected exact legacy ship-only pier layout.')
        ship = hold(os.open('ship', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=dirs['pier']))
        marker = hold(os.open('.urb', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=ship))
        raw, runtime_stat = _read(dirs['control'], 'runtime.json', 4096)
        job_raw, job_stat = _read(dirs['control'], 'job.json', 65536)
        runtime, job = _object(raw), _object(job_raw)
        if set(runtime) != {'state'} or runtime['state'] not in ('STARTING', 'RUNNING', 'FAULT', 'RECOVERY_REQUIRED'):
            raise RecoveryRefused('Existing non-STOPPED one-key legacy intent required.')
        fields = {'id', 'state', 'offset', 'total_bytes', 'expanded_limit', 'expanded_bytes', 'files'}
        if (set(job) != fields or type(job['id']) is not str or
                not re.fullmatch('[a-f0-9]{32}', job['id']) or job['state'] != 'READY_LOCKED' or
                any(type(job[k]) is not int for k in ('offset', 'total_bytes', 'expanded_limit', 'expanded_bytes', 'files')) or
                not 0 < job['offset'] == job['total_bytes'] <= 8 * 1024**3 or
                not 0 < job['expanded_bytes'] <= job['expanded_limit'] <= 64 * 1024**3 or job['files'] < 1):
            raise RecoveryRefused('Unambiguous committed legacy READY_LOCKED import required.')
        bindings = {}
        for key, fd in {**dirs, 'ship': ship, 'marker': marker}.items():
            path = (target[key] if key in target else
                    target['pier'] / 'ship' / '.urb' if key == 'marker' else target['pier'] / 'ship')
            st = os.fstat(fd)
            bindings[key] = (path, st.st_dev, st.st_ino)
        for key, st in (('runtime.json', runtime_stat), ('job.json', job_stat)):
            bindings[key] = (target['control'] / key, st.st_dev, st.st_ino)
        def check():
            permit.verify_delegation(target, bindings)  # Local delegation, not a native lease.
            for path, dev, ino in bindings.values():
                st = os.stat(path, follow_symlinks=False)
                if (st.st_dev, st.st_ino) != (dev, ino):
                    raise RecoveryRefused('Bound legacy inode changed.')
            if (_read(dirs['control'], 'job.json', 65536)[0] != job_raw or
                    _read(dirs['control'], 'runtime.json', 4096)[0] != raw):
                raise RecoveryRefused('Legacy journal bytes changed under exclusion.')
        check()
        transaction = 'legacy015-' + uuid.uuid4().hex
        os.mkdir(transaction, mode=0o700, dir_fd=dirs['evidence'])
        saved = hold(os.open(transaction, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=dirs['evidence']))
        _write(saved, 'runtime.before', raw)
        _write(saved, 'job.before', job_raw)
        _write(saved, 'bindings.json', json.dumps({k: [str(p), d, i] for k, (p, d, i) in bindings.items()}).encode())
        os.fsync(saved)
        os.fsync(dirs['evidence'])
        pending = '.legacy015-' + uuid.uuid4().hex
        stopped = b'{"state":"STOPPED"}\n'
        try:
            _write(dirs['control'], pending, stopped)
            check()
            try:
                os.replace(pending, 'runtime.json', src_dir_fd=dirs['control'], dst_dir_fd=dirs['control'])
                os.fsync(dirs['control'])
                actual, st = _read(dirs['control'], 'runtime.json', 4096)
                bindings['runtime.json'] = (target['control'] / 'runtime.json', st.st_dev, st.st_ino)
                permit.verify_delegation(target, bindings)
                if actual != stopped or _read(dirs['control'], 'job.json', 65536)[0] != job_raw:
                    raise RecoveryRefused('Repair readback mismatch.')
            except BaseException as error:
                raise RecoveryUncertain('Replace/durability uncertain; retain host exclusion and original evidence; do not Start.') from error
        finally:
            try:
                os.unlink(pending, dir_fd=dirs['control'])
            except FileNotFoundError:
                pass
        return target['evidence'] / transaction


if __name__ == '__main__':
    raise SystemExit('BLOCKED: no live host cessation/exclusion authority integrated; library only. No stopped-assertion CLI.')
