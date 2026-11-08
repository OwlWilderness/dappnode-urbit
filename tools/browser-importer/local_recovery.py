"""Bounded, private, fsynced lifecycle evidence beneath the existing control root."""
import hashlib
import json
import os
import re
import stat
import uuid


class RecoveryJournal:
    LIMIT = 128

    def __init__(self, control_fd):
        self.fd = None
        self.control_fd = control_fd  # borrowed; lifetime is owned by ManagedImporter
        try:
            os.mkdir('local-recovery', mode=0o700, dir_fd=control_fd)
            os.fsync(control_fd)
        except FileExistsError:
            pass
        self.fd = os.open('local-recovery', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                          dir_fd=control_fd)
        info = os.fstat(self.fd)
        if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
            self.close()
            raise ValueError('Unsafe recovery storage')
        try:
            self.records = {}
            names = os.listdir(self.fd)
            if len(names) > self.LIMIT:
                raise ValueError('Recovery evidence limit')
            for name in names:
                if not re.fullmatch('[a-f0-9]{32}\\.json', name):
                    raise ValueError('Uncertain recovery write')
                record = self.read(name[:-5])
                self.records[record['operation_id']] = record
            sequences = sorted(r['sequence'] for r in self.records.values())
            if sequences != list(range(1, len(sequences) + 1)):
                raise ValueError('Invalid recovery sequence')
        except BaseException:
            self.close()
            raise

    def read(self, operation_id):
        self.validate()
        fd = os.open(operation_id + '.json', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                     dir_fd=self.fd)
        with os.fdopen(fd, 'rb') as stream:
            info = os.fstat(stream.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or
                    stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1 or info.st_size > 32768):
                raise ValueError('Unsafe recovery evidence')
            def unique(pairs):
                value = dict(pairs)
                if len(value) != len(pairs):
                    raise ValueError('Duplicate recovery field')
                return value
            record = json.loads(stream.read(32769), object_pairs_hook=unique)
        if (not isinstance(record, dict) or set(record) != {'operation_id', 'sequence', 'outcome', 'evidence'} or
                record['operation_id'] != operation_id or type(record['sequence']) is not int or
                record['sequence'] < 1 or record['outcome'] not in ('PENDING', 'COMPLETE', 'REFUSED') or
                not isinstance(record['evidence'], dict)):
            raise ValueError('Invalid recovery evidence')
        evidence = record['evidence']
        prior = evidence.get('prior_runtime')
        if (not isinstance(prior, dict) or set(prior) != {'state'} or
                prior['state'] not in ('RUNNING', 'STARTING', 'FAULT', 'RECOVERY_REQUIRED')):
            raise ValueError('Invalid prior lifecycle evidence')
        keys = {'prior_runtime'}
        if 'original_runtime' in evidence:
            keys.add('original_runtime')
            original = evidence['original_runtime']
            if (not isinstance(original, dict) or set(original) != {'utf8', 'sha256'} or
                    not isinstance(original['utf8'], str) or len(original['utf8'].encode()) > 4096 or
                    hashlib.sha256(original['utf8'].encode()).hexdigest() != original['sha256'] or
                    json.loads(original['utf8'], object_pairs_hook=unique) != prior):
                raise ValueError('Invalid original runtime evidence')
        if record['outcome'] == 'REFUSED':
            keys.add('error')
            if evidence.get('error') != 'CESSATION_NOT_ESTABLISHED':
                raise ValueError('Invalid refusal evidence')
        if record['outcome'] == 'COMPLETE':
            keys.update(('boundary', 'remaining_children', 'exit_code', 'signal', 'result_runtime'))
            boot = evidence.get('boundary') == 'LINUX_PID1_MANAGEMENT_BOOT'
            if boot:
                keys.update(('boot_id', 'namespace', 'supervisor_start', 'backend_pid'))
                if ('original_runtime' not in evidence or
                        not isinstance(evidence.get('boot_id'), str) or
                        not re.fullmatch('[a-f0-9]{32}', evidence['boot_id']) or
                        any(type(evidence.get(k)) is not int or evidence[k] <= 0 for k in
                            ('namespace', 'supervisor_start', 'backend_pid')) or
                        evidence.get('signal') != 'NONE' or evidence.get('exit_code') is not None):
                    raise ValueError('Invalid management boot evidence')
            if (evidence.get('boundary') not in ('LINUX_SUBREAPER_OWNED_CHILD', 'LINUX_PID1_MANAGEMENT_BOOT') or
                    type(evidence.get('remaining_children')) is not int or evidence['remaining_children'] != 0 or
                    (not boot and type(evidence.get('exit_code')) is not int) or
                    evidence.get('signal') not in ('SIGTERM', 'NONE') or evidence.get('result_runtime') != 'STOPPED'):
                raise ValueError('Invalid cessation evidence')
        if set(evidence) != keys:
            raise ValueError('Unexpected recovery evidence')
        return record

    def save(self, record):
        self.validate()
        name = record['operation_id'] + '.json'
        if record['operation_id'] in self.records:
            # Revalidate an existing target before replacing it.
            self.read(record['operation_id'])
        elif len(self.records) >= self.LIMIT:
            raise ValueError('Recovery evidence limit')
        else:
            try:
                os.stat(name, dir_fd=self.fd, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise ValueError('Unregistered recovery evidence')
        pending = '.pending-' + uuid.uuid4().hex
        fd = os.open(pending, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=self.fd)
        with os.fdopen(fd, 'w') as stream:
            json.dump(record, stream, sort_keys=True)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(pending, name, src_dir_fd=self.fd, dst_dir_fd=self.fd)
        os.fsync(self.fd)
        self.records[record['operation_id']] = record

    def validate(self):
        held = os.fstat(self.fd)
        named = os.stat('local-recovery', dir_fd=self.control_fd, follow_symlinks=False)
        if (not stat.S_ISDIR(named.st_mode) or named.st_uid != os.geteuid() or
                stat.S_IMODE(named.st_mode) != 0o700 or
                (held.st_dev, held.st_ino) != (named.st_dev, named.st_ino)):
            raise ValueError('Recovery evidence directory changed')

    def latest(self):
        return max(self.records.values(), key=lambda r: r['sequence'], default=None)

    def pending(self):
        return any(r['outcome'] == 'PENDING' for r in self.records.values())

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None
