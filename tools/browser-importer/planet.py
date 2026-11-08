"""One-shot fresh planet creation under ManagedImporter's existing writer locks.

No recovery of interrupted creation is attempted. The immutable attempt fences
both import and creation even when no pier exists. A clean -x completion commits
an ordinary READY_LOCKED job, STOPPED; a separate authenticated Start is needed.
"""
import json
import os
import re
import stat
import subprocess
import tempfile
import threading
import uuid

from importer import ImportError
from runtime import ManagedImporter, UpdatedRuntimeAdapter, LinuxChildBoundary


def valid_identity(value):
    # Shape is not chain ownership/canonical @p proof. Match the owner-configured
    # public literal exactly; never guess, normalize, spawn or reset an identity.
    return isinstance(value, str) and re.fullmatch(r'~[a-z]{6}-[a-z]{6}', value) is not None


class PlanetImporter(ManagedImporter):
    def __init__(self, *args, planet_identity=None, runtime_adapter=None, **kwargs):
        self.planet_identity = os.environ.get('URBIT_PLANET') if planet_identity is None else planet_identity
        if not valid_identity(self.planet_identity):
            raise ImportError('Configure the exact owner-selected public planet identity first.')
        self.provisioning = None
        self._provision_attempted = False
        self._provision_abort = False
        super().__init__(*args, runtime_adapter=(UpdatedRuntimeAdapter() if runtime_adapter is None else runtime_adapter), **kwargs)
        try:
            try:
                fd = os.open('fresh-planet.json', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                             dir_fd=self.control_fd)
            except FileNotFoundError:
                fd = None
            if fd is not None:
                self._provision_attempted = True
                with os.fdopen(fd, 'rb') as source:
                    info = os.fstat(source.fileno())
                    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or
                            stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1 or info.st_size > 1024):
                        raise ValueError()
                    record = json.loads(source.read(1025))
                if (set(record) != {'identity', 'state'} or record['identity'] != self.planet_identity or
                        record['state'] not in ('ATTEMPTED', 'COMPLETE')):
                    raise ValueError()
                self.provisioning = record
        except Exception:
            # Preserve locks until service exit, as for uncertain lifecycle state.
            raise ImportError('Fresh creation evidence needs owner review; preserve the volume.') from None

    def _provision_record(self, state, *, first=False):
        record = {'identity': self.planet_identity, 'state': state}
        name = 'fresh-planet.json' if first else '.fresh-complete-' + uuid.uuid4().hex
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=self.control_fd)
        with os.fdopen(fd, 'w') as output:
            json.dump(record, output)
            output.flush()
            os.fsync(output.fileno())
        if not first:
            os.replace(name, 'fresh-planet.json', src_dir_fd=self.control_fd, dst_dir_fd=self.control_fd)
        os.fsync(self.control_fd)
        self.provisioning = record

    def create(self, **kwargs):
        with self.mutex:
            if self._provision_attempted:
                raise ImportError('Fresh creation was already attempted; import/reset is fenced.')
            return super().create(**kwargs)

    def provision(self, *, identity, key, confirmed_unused):
        with self._launch_slot():
            if (identity != self.planet_identity or not valid_identity(identity) or confirmed_unused is not True or
                    not isinstance(key, bytes) or not 1 <= len(key) <= 65536 or self._closed or self._closing or
                    self._provision_attempted or self.job is not None or os.listdir(self.pier_fd) or
                    self.runtime['state'] != 'STOPPED' or self._recovery_fault or self.recovery_journal.pending()):
                raise ImportError('Fresh creation requires the configured unused planet and empty inactive storage.')
            # Set in-memory fence BEFORE first persistence; ambiguous errors never
            # become retry permission in the same backend.
            self._provision_attempted = True
            secret = None
            try:
                self._provision_record('ATTEMPTED', first=True)
                self.job = dict(id=uuid.uuid4().hex, state='RECOVERY_REQUIRED', offset=0, total_bytes=0,
                                expanded_limit=self.max_expanded_bytes, expanded_bytes=0, files=0)
                self._persist()
                self.runtime = {'state': 'STARTING'}
                self._persist_runtime()
                if self._boot_boundary is not None:
                    self._boot_boundary.close()
                    self._boot_boundary = None
                # Anonymous descriptor, never a selectable path or argv secret.
                # Linux uses memfd; portable source tests use an unlinked private
                # temporary inode. There is no retained key upload or retry route.
                if hasattr(os, 'memfd_create'):
                    secret = os.fdopen(os.memfd_create('planet-boot', os.MFD_CLOEXEC), 'w+b')
                else:
                    secret = tempfile.TemporaryFile(dir=self.control, prefix='.fresh-key-')
                secret.write(key)
                secret.flush()
                secret.seek(0)
                key = None
                self.worker = threading.Thread(target=self._initialize, args=(secret,), name='fresh-planet')
                self.worker.start()
                secret = None  # worker owns the descriptor from here
            except Exception:
                if secret is not None:
                    secret.close()
                self.runtime = {'state': 'FAULT'}
                raise ImportError('Fresh creation is fenced; preserve state for owner review. Do not retry.') from None
            return self.status()

    def _initialize(self, secret):
        try:
            with self.mutex:
                if self._provision_abort:
                    raise ValueError()
                boundary = LinuxChildBoundary.prepare()
                self.child = self.runtime_adapter.create(self.pier_fd, self.planet_identity, secret.fileno())
                self._child_boundary = None
                if boundary is not None and isinstance(self.child, subprocess.Popen):
                    boundary.bind(self.child)
                    self._child_boundary = boundary
            # -x naturally exits only when the creation callback completes.
            code = self.child.wait()
            with self.mutex:
                if self._provision_abort or code != 0:
                    raise ValueError()
                if self._child_boundary is not None:
                    if self._child_boundary.settle()['exit_code'] != 0:
                        raise ValueError()
                ship = self._safe_ship()
                try:
                    os.fsync(ship)
                finally:
                    os.close(ship)
                os.fsync(self.pier_fd)
                self.runtime = {'state': 'STOPPED'}
                self._persist_runtime()
                self._provision_record('COMPLETE')
                self.job['state'] = 'READY_LOCKED'
                self._persist()
                self.child = None
                self._child_boundary = None
        except Exception:
            with self.mutex:
                self.runtime = {'state': 'FAULT'}
                # Retain original job and launch intent on all uncertainty.
                # No auto retry, cleanup, reset, data repair or adopted writer.
        finally:
            secret.close()

    def stop(self):
        with self.mutex:
            if self.provisioning and (self.provisioning['state'] != 'COMPLETE' or
                                       not self.job or self.job['state'] != 'READY_LOCKED'):
                self._provision_abort = True
                if self.child is not None and self.child.poll() is None:
                    if self._child_boundary is not None:
                        self._child_boundary.settle()
                    else:
                        self.child.terminate()
                        self.child.wait(timeout=120)
                raise ImportError('Fresh creation interrupted or uncertain; preserved and permanently fenced for owner review.')
            return super().stop()

    def start(self, **kwargs):
        with self.mutex:
            if self._provision_attempted and (not self.provisioning or self.provisioning['state'] != 'COMPLETE'):
                raise ImportError('Interrupted fresh creation cannot be started or repaired by lifecycle recovery.')
            return super().start(**kwargs)

    def status(self):
        with self.mutex:
            result = super().status()
            result['runtime_selection'] = 'retained-amd64-curl-baseline'
            result['provisioning'] = dict(self.provisioning) if self.provisioning else None
            result['planet_identity'] = self.planet_identity
            result['provision_available'] = bool(not self._provision_attempted and not self.job and
                                                self.runtime['state'] == 'STOPPED' and not self._closing and not self._closed)
            if self._provision_attempted and (not self.provisioning or self.provisioning['state'] != 'COMPLETE'):
                result['start_available'] = False
                result['local_recovery_available'] = False
            return result

    def close(self):
        if self.worker is not None and self.worker.is_alive() and self._provision_attempted:
            try:
                self.stop()
            except ImportError:
                pass
        return super().close()
