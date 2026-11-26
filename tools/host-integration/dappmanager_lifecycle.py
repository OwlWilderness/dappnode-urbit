"""Opt-in trusted host lifecycle adaptor; not a stock Dappmanager hook.

Only the separately patched manager may request activation. Every engine mutation
is under the canonical integration lock plus the existing Provider storage lease.
This module is deliberately outside the package build context/export.
"""


import fcntl
import os
from pathlib import Path
import stat
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'browser-importer'))
from maintenance_provider import (Blocked, CANONICAL_AUTHORITY, Docker, Provider,
                                  identity, open_root, read_raw)
from maintenance import ready_import
from importer import private_root, rename_without_replace
import base64
import re
import uuid
from owner_tls import _certificate


class Admission:
    """Before-volume lock shared by every activation and maintenance request."""
    def __enter__(self):
        self.root = private_root(CANONICAL_AUTHORITY)
        self.fd = None
        try:
            self.fd = os.open('dappmanager.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW,
                              0o600, dir_fd=self.root)
            info = os.fstat(self.fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or
                    info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600):
                raise Blocked('INTEGRATION_LOCK_REFUSED')
            fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            os.fsync(self.root)
            return self
        except BaseException:
            self.__exit__(None, None, None)
            raise

    def __exit__(self, *_):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None
        os.close(self.root)


def prepare_empty_storage(storage, *, uid=10000, gid=10000):
    """Only a just-created local volume, never repair/reinitialize existing data.

    Caller holds Admission, has verified Docker local/no options/no consumers,
    and proves volume absence before its own volume-create acknowledgement.
    Partial initialization deliberately remains refused rather than auto-repaired.
    """
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in Path(storage).parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        if os.listdir(fd) or os.fstat(fd).st_uid != os.geteuid():
            raise Blocked('VIRGIN_STORAGE_REQUIRED')
        os.fchmod(fd, 0o700)
        for name in ('pier', 'uploads', 'control'):
            os.mkdir(name, 0o700, dir_fd=fd)
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            try:
                os.fchmod(child, 0o700)
                os.fchown(child, uid, gid)
                os.fsync(child)
            finally:
                os.close(child)
        os.fchown(fd, uid, gid)
        os.fsync(fd)
    finally:
        os.close(fd)


class ComposeBackend:
    """Fixed root-approved, JSON Compose input; never takes a manager pathname."""
    def __init__(self, plan, docker):
        self.plan, self.docker = plan, docker
        self.fresh = False

    def prepare(self, *, existing_only=False):
        name = self.plan['volume']
        names = self.docker.call('volume', 'ls', '--format', '{{.Name}}').decode('ascii').splitlines()
        self.fresh = name not in names
        if self.fresh:
            if existing_only:
                raise Blocked()
            if self.docker.call('volume', 'create', '--driver', 'local', name).decode('ascii').strip() != name:
                raise Blocked('VOLUME_CREATE_UNCERTAIN')
        volume = self.docker.volume(name)
        storage = Path(volume['mountpoint'])
        if (not storage.is_absolute() or volume != {
                'name': name, 'driver': 'local', 'scope': 'local',
                'options_empty': True, 'mountpoint': str(storage)}):
            raise Blocked('LOCAL_VOLUME_REQUIRED')
        if self.fresh:
            if self.docker.consumers(storage):
                raise Blocked()
            prepare_empty_storage(storage)
        return storage

    def create(self):
        path = self.plan['compose_path']
        self.docker.call('compose', '-f', path, 'create', '--no-recreate', 'ship')
        cid = self.docker.call('compose', '-f', path, 'ps', '-aq').decode('ascii').strip()
        import re
        if not re.fullmatch('[a-f0-9]{64}', cid):
            raise Blocked('CREATE_ID_UNCERTAIN')
        return cid


class StartAcknowledgementDocker(Docker):
    """Provider ACTIVE remains durable; broker returns after verified start.

    Unlike the companion CLI, an HTTP installer request cannot hold a lease until
    container exit. This explicit adapter replaces ONLY wait/observation. It does
    not weaken pre-start confinement, restart policy, enrollment or ACTIVE writes.
    Subsequent maintenance reacquires both locks and positively settles the scope.
    """
    def wait(self, cid):
        item = self.inspect(cid)
        if item is None or item['running'] is not True:
            raise Blocked('START_ACK_UNCERTAIN_ACTIVE_RETAINED')


class PreimportUpdateRefused(Blocked):
    """Finite branch identity; not inferred from an arbitrary error string."""


def replacement_preflight(provider):
    """Eligibility only, not cessation proof; repeat full validation after stop.

    Pre-import handoff is unsupported. Refuse it read-only while the registered
    predecessor still runs, rather than discovering this after destructive
    containment. The canonical integration/storage leases are already held.
    """
    provider.check()
    fds = []
    try:
        control = open_root(provider.storage / 'control', provider.owner_uid)
        fds.append(control)
        ready_import(read_raw(control, 'job.json', uid=provider.owner_uid, limit=65536))
        pier = open_root(provider.storage / 'pier', provider.owner_uid)
        fds.append(pier)
        if set(os.listdir(pier)) - {'.runtime-owner.json'} != {'ship'}:
            raise Blocked()
        uploads = open_root(provider.storage / 'uploads', provider.owner_uid)
        fds.append(uploads)
        if os.listdir(uploads):
            raise Blocked()
        ship = open_root(provider.storage / 'pier/ship', provider.owner_uid)
        fds.append(ship)
        marker = os.open('.urb', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=ship)
        fds.append(marker)
    except (Blocked, OSError, ValueError):
        raise PreimportUpdateRefused('PREIMPORT_UPDATE_REFUSED') from None
    finally:
        for fd in reversed(fds):
            os.close(fd)


class Lifecycle:
    def __init__(self, backend, admission, provider):
        self.backend = backend
        self.admission = admission
        self.provider = provider

    def activate(self):
        with self.admission:
            storage = self.backend.prepare()
            with self.provider(storage) as provider:
                if provider.state is None and not self.backend.fresh:
                    raise Blocked()
                if provider.state is not None:
                    replacement_preflight(provider)
                    provider.recover()
                cid = self.backend.create()
                provider.enroll(cid)
                provider.run()
                return {'state': 'ACTIVE', 'container': cid}

    def upload_certificate(self, container, filename, content):
        # No path is supplied by the manager. Parse before acquiring storage.
        if (not isinstance(container, str) or not re.fullmatch('[a-f0-9]{64}', container) or
                filename not in ('root-ca.pem', 'server.pem') or
                not isinstance(content, str) or len(content) > 87384):
            raise Blocked('PUBLIC_CERTIFICATE_REQUIRED')
        try:
            raw = base64.b64decode(content, validate=True)
            if not raw or len(raw) > 65536 or base64.b64encode(raw).decode('ascii') != content:
                raise ValueError()
            _certificate(raw)  # one real public X509 PEM, never a key/bundle
        except (ValueError, TypeError):
            raise Blocked('PUBLIC_CERTIFICATE_REQUIRED') from None
        with self.admission:
            storage = self.backend.prepare(existing_only=True)
            with self.provider(storage) as provider:
                provider.check()
                if (provider.state is None or provider.state['phase'] != 'ACTIVE' or
                        provider.state['container'] != container):
                    raise Blocked('REGISTERED_ACTIVE_SCOPE_REQUIRED')
                item = provider.confined(container)
                provider.check_consumers(container)
                if item['running'] is not True:
                    raise Blocked('REGISTERED_ACTIVE_SCOPE_REQUIRED')
                fds = []
                try:
                    # Borrow the exact package TLS lock. Never create or repair it.
                    control = open_root(storage / 'control', provider.owner_uid)
                    fds.append(control)
                    lock = os.open('.owner-tls.lock', os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK,
                                   dir_fd=control)
                    fds.append(lock)
                    info = os.fstat(lock)
                    if (not stat.S_ISREG(info.st_mode) or info.st_uid != provider.owner_uid or
                            info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600):
                        raise Blocked('TLS_LOCK_REFUSED')
                    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    private = open_root(storage / 'control/owner-tls', provider.owner_uid)
                    fds.append(private)
                    public = open_root(storage / 'control/owner-tls-public', provider.owner_uid)
                    fds.append(public)
                    if (any(name.startswith('.dappmanager-cert-') for name in os.listdir(control)) or
                            {'activation.json', 'validated', '.validate'} & set(os.listdir(private)) or
                            not set(os.listdir(public)) <= {'request.pem', 'root-ca.pem', 'server.pem'} or
                            filename in os.listdir(public)):
                        raise Blocked('TLS_IMMUTABLE_OR_UNCERTAIN')
                    # Revalidate directory/lock identity before the actual write.
                    provider.check()
                    if identity(lock) != [os.stat('.owner-tls.lock', dir_fd=control,
                                                 follow_symlinks=False).st_dev,
                                          os.stat('.owner-tls.lock', dir_fd=control,
                                                 follow_symlinks=False).st_ino]:
                        raise Blocked('TLS_LOCK_REFUSED')
                    stage = '.dappmanager-cert-' + uuid.uuid4().hex
                    fd = os.open(stage, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                 0o600, dir_fd=control)
                    try:
                        with os.fdopen(fd, 'wb') as output:
                            if output.write(raw) != len(raw):
                                raise Blocked('CERTIFICATE_WRITE_UNCERTAIN')
                            output.flush()
                            os.fchmod(output.fileno(), 0o444)
                            os.fsync(output.fileno())
                    except BaseException:
                        # Evidence remains; never replay a failed/uncertain transfer.
                        raise
                    rename_without_replace(control, stage, public, filename)
                    os.fsync(public)
                    os.fsync(control)
                    return {'state': 'CERTIFICATE_STORED', 'container': container, 'filename': filename}
                finally:
                    for fd in reversed(fds):
                        os.close(fd)

    def recover(self):
        with self.admission:
            storage = self.backend.prepare(existing_only=True)
            with self.provider(storage) as provider:
                provider.recover()
                return {'state': 'RECOVERED_STOPPED'}
