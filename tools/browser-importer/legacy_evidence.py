"""Read-only native-0.1.6 history admission, never native recovery authority.

A completed native operation may precede a fresh package management boot. Pending,
interrupted, malformed or changed history must instead retain its native fence.
Nothing here settles a process or repairs a journal. The existing PID1 capability
and explicit local Recover remain necessary to reconcile a stale RUNNING intent.
Native journals and receipts remain in place and are never refreshed or replayed.
"""
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import re
import stat


def _object(raw):
    def unique(pairs):
        result = dict(pairs)
        if len(result) != len(pairs):
            raise ValueError('Duplicate native history field')
        return result
    value = json.loads(raw, object_pairs_hook=unique)
    if type(value) is not dict:
        raise ValueError('Native history object required')
    return value


def _directory(path):
    path = Path(os.path.abspath(path))
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        info = os.fstat(fd)
        if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o077:
            raise ValueError('Private native history directory required')
        return fd
    except BaseException:
        os.close(fd)
        raise


def _read(fd, name):
    leaf = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
    with os.fdopen(leaf, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or
                stat.S_IMODE(info.st_mode) & 0o077 or info.st_nlink != 1 or info.st_size > 65536):
            raise ValueError('Unsafe native history file')
        raw = stream.read(65537)
        if len(raw) != info.st_size:
            raise ValueError('Native history changed')
        return raw


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def validate_native_history(pier, uploads, control):
    """Validate retained native metadata before any successor importer writes.

    Missing native markers keep ordinary installations unchanged. An evidence root
    without its state, or a status without state, is NOT a clean installation.
    Historical hashes authenticate preservation only, never native Stop authority.
    Assumes exclusive package volume ownership and administrator noninterference.
    """
    control = Path(os.path.abspath(control))
    with ExitStack() as stack:
        def hold(path):
            fd = _directory(path)
            stack.callback(os.close, fd)
            return fd
        fd = hold(control)
        evidence = control.parent / 'legacy015-evidence'
        # lstat catches dangling symlinks as markers, rather than hiding them.
        names = set(os.listdir(fd))
        try:
            os.stat(evidence, follow_symlinks=False)
            evidence_present = True
        except FileNotFoundError:
            evidence_present = False
        if not evidence_present and not names & {'legacy-recovery-state.json', 'native-file-status.json'}:
            return
        raw = _read(fd, 'legacy-recovery-state.json')
        state = _object(raw)
        command_raw = state.get('native_command_raw')
        if not isinstance(command_raw, str):
            raise ValueError('Retained native command required')
        command = _object(command_raw)
        completed = state.get('native_completed', {})
        sequence = state.get('native_sequence')
        operation = command.get('operation')
        if (state.get('build') != 'legacy015-permanent-recovery-1' or
                state.get('native_outcome') != 'COMPLETE' or
                state.get('state') not in ('REPAIRED', 'WRITER_ADMITTED') or
                type(sequence) is not int or sequence < 1 or
                command.get('policy') != 'TRUSTED_NATIVE_ADMIN_MAINTENANCE_V1' or
                command != state.get('native_pending') or command.get('sequence') != sequence or
                command.get('generation') != state.get('generation') or
                operation not in ('repair', 'start', 'stop', 'reconcile') or
                (state['state'] == 'WRITER_ADMITTED') != (operation == 'start') or
                _sha(command_raw.encode()) != state.get('native_command_sha256') or
                completed.get('sequence') != sequence or completed.get('operation') != operation or
                completed.get('command_sha256') != state.get('native_command_sha256')):
            raise ValueError('Unsettled native transaction remains fenced')
        for value in (state.get('generation'), state.get('native_command_sha256'),
                      state.get('job_sha256'), completed.get('runtime_sha256')):
            if not isinstance(value, str) or not re.fullmatch('[a-f0-9]{64}', value):
                raise ValueError('Malformed native history binding')
        job = _read(fd, 'job.json')
        if (_sha(job) != state['job_sha256'] or completed.get('job_sha256') != state['job_sha256']):
            raise ValueError('Original native import changed')
        expected_roots = {'pier':Path(pier), 'uploads':Path(uploads), 'control':control, 'evidence':evidence}
        if type(state.get('roots')) is not dict or set(state['roots']) != set(expected_roots):
            raise ValueError('Native root bindings required')
        for key, path in expected_roots.items():
            info = os.fstat(hold(path))
            if state['roots'][key] != [info.st_dev, info.st_ino]:
                raise ValueError('Native physical root changed')
        retained = [(state.get('evidence'), state.get('evidence_hashes'),
                     {'runtime.before','job.before','bindings.json','native-command.json','native-receipt.json'})]
        history = state.get('native_reconciliations', [])
        if type(history) is not list or len(history) > 128:
            raise ValueError('Malformed native history')
        for entry in history:
            if type(entry) is not dict or set(entry) != {'directory','hashes'}:
                raise ValueError('Malformed native reconciliation')
            retained.append((entry['directory'],entry['hashes'],
                             {'state.before','native-command.json','native-receipt.json'}
                             if str(entry['directory']).startswith('native-resume-') else
                             {'runtime.before','job.before','bindings.json'}))
        seen = set()
        for directory, hashes, fields in retained:
            if (not isinstance(directory, str) or
                    not re.fullmatch('(legacy015-|native-resume-)[a-f0-9]{32}', directory) or
                    directory in seen or type(hashes) is not dict or set(hashes) != fields):
                raise ValueError('Malformed native evidence reference')
            seen.add(directory)
            saved = hold(evidence / directory)
            if set(os.listdir(saved)) != fields:
                raise ValueError('Unexpected native evidence entry')
            for name, digest in hashes.items():
                if _sha(_read(saved, name)) != digest:
                    raise ValueError('Native evidence changed')
            if 'job.before' in fields and _read(saved, 'job.before') != job:
                raise ValueError('Native import evidence changed')
        if set(os.listdir(hold(evidence))) != seen:
            raise ValueError('Unaccounted native evidence directory')
        if 'native-file-status.json' in names:
            status = _object(_read(fd, 'native-file-status.json'))
            if (status.get('policy') != command['policy'] or status.get('sequence') != sequence or
                    status.get('outcome') != 'COMPLETE' or status.get('error') is not None or
                    status.get('state') != state['state'] or status.get('state_sha256') != _sha(raw) or
                    status.get('command_sha256') != state['native_command_sha256']):
                raise ValueError('Unsettled native status remains fenced')
