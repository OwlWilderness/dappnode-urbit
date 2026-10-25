"""One-time, fail-closed private credential enrollment storage.

This module provides no listener, bootstrap authority, or network route by itself.
Do not expose it over HTTP without an independently accepted private TLS origin.
"""
import contextlib
import fcntl
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import stat

from importer import ImportError as StorageRefused, private_root, rename_without_replace


class EnrollmentRefused(Exception):
    """Aggregate denial; never include configuration, paths, or secrets."""


class CredentialEnrollment:
    def __init__(self, control_root, authority_digest):
        self.root = Path(control_root)
        self.authority_digest = authority_digest

    @contextlib.contextmanager
    def _locked(self):
        root_fd = None
        lock_fd = None
        try:
            root_fd = private_root(self.root)
            lock_fd = os.open('enrollment.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW,
                              0o600, dir_fd=root_fd)
            info = os.fstat(lock_fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or
                    stat.S_IMODE(info.st_mode) != 0o600):
                raise EnrollmentRefused('Enrollment unavailable; operator recovery required.')
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
            yield root_fd
        except (OSError, ValueError, TypeError, StorageRefused):
            raise EnrollmentRefused('Enrollment unavailable; operator recovery required.') from None
        finally:
            if lock_fd is not None:
                os.close(lock_fd)
            if root_fd is not None:
                os.close(root_fd)

    @staticmethod
    def _state(root_fd):
        try:
            if any(name.startswith('.auth-stage-') for name in os.listdir(root_fd)):
                return 'FAULT_LOCKED'
            try:
                fd = os.open('auth.json', os.O_RDONLY | os.O_NOFOLLOW, dir_fd=root_fd)
            except FileNotFoundError:
                return 'UNENROLLED'
            with os.fdopen(fd, 'rb') as source:
                info = os.fstat(source.fileno())
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or
                        stat.S_IMODE(info.st_mode) != 0o600):
                    return 'FAULT_LOCKED'
                data = source.read(4097)
            if len(data) > 4096:
                return 'FAULT_LOCKED'
            record = json.loads(data)
            if (not isinstance(record, dict) or set(record) != {'version', 'consumed', 'salt', 'hash'} or
                    type(record['version']) is not int or record['version'] != 1 or
                    record['consumed'] is not True or
                    not isinstance(record['salt'], str) or
                    not isinstance(record['hash'], str) or
                    not re.fullmatch('[a-f0-9]{32}', record['salt']) or
                    not re.fullmatch('[a-f0-9]{128}', record['hash'])):
                return 'FAULT_LOCKED'
            return 'ENROLLED'
        except (OSError, ValueError, TypeError, KeyError):
            return 'FAULT_LOCKED'

    def state(self):
        try:
            with self._locked() as root_fd:
                return self._state(root_fd)
        except EnrollmentRefused:
            return 'FAULT_LOCKED'

    def enroll(self, authority, password):
        """Durably publish one verifier; never overwrite or return it."""
        try:
            with self._locked() as root_fd:
                if self._state(root_fd) != 'UNENROLLED':
                    raise EnrollmentRefused('Enrollment unavailable; operator recovery required.')
                digest = self.authority_digest
                if (not isinstance(digest, str) or not re.fullmatch('[a-f0-9]{64}', digest) or
                        not isinstance(authority, str) or not 32 <= len(authority) <= 256 or
                        not isinstance(password, str) or not 12 <= len(password) <= 1024):
                    raise EnrollmentRefused('Enrollment unavailable; operator recovery required.')
                if not hmac.compare_digest(hashlib.sha256(authority.encode()).hexdigest(), digest):
                    raise EnrollmentRefused('Enrollment unavailable; operator recovery required.')
                salt = secrets.token_bytes(16)
                verifier = hashlib.scrypt(password.encode(), salt=salt, n=16384, r=8, p=1)
                record = json.dumps({'version': 1, 'consumed': True, 'salt': salt.hex(),
                                     'hash': verifier.hex()}, separators=(',', ':')).encode()
                name = f'.auth-stage-{secrets.token_hex(16)}'
                fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                             0o600, dir_fd=root_fd)
                with os.fdopen(fd, 'wb') as output:
                    os.fchmod(output.fileno(), 0o600)
                    output.write(record)
                    output.flush()
                    os.fsync(output.fileno())
                # Persist the stage name first. If publish durability fails,
                # the staged intent or the verifier remains after recovery.
                os.fsync(root_fd)
                rename_without_replace(root_fd, name, root_fd, 'auth.json')
                os.fsync(root_fd)
                return 'ENROLLED'
        except EnrollmentRefused:
            raise
        except Exception:
            # A staging file or published verifier may already exist. Neither
            # case authorizes a retry or a first-visitor claim.
            raise EnrollmentRefused('Enrollment unavailable; operator recovery required.') from None
