"""Root Linux host authority for managed, exclusive local Docker storage.

This is NOT an attestation service for historical/unregistered containers. Every
writer must be admitted here from virgin storage. Daemon unless-stopped restart
is supported within durable ACTIVE intent; Compose replacement must be serialized
through this authority. Trusted host administration, local rootful Docker without
userns remapping, stable exclusive local storage, and no outside mounts/writers
are required. Root/admin compromise and whole-storage rollback are out of scope.
Serialized registry/evidence alone never grants a migration capability.
"""
# Script and -m execution must enter the canonical module before defining any
# capability classes. Otherwise maintenance imports a second StorageAdmission
# and correctly rejects the CLI's __main__ instance at its exact-type gate.
if __name__ == '__main__':
    from maintenance_provider import main
    raise SystemExit(main())

import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time
from importer import private_root

CANONICAL_AUTHORITY = Path('/var/lib/uvm-maintenance')


class Blocked(Exception):
    def __init__(self, reason='PRIOR_SCOPE_UNPROVABLE'):
        super().__init__('BLOCKED: ' + reason)


def identity(fd):
    info = os.fstat(fd)
    return [info.st_dev, info.st_ino]


def open_root(path, uid):
    """No creation, no symlinks in ancestors, service-owned private final root."""
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in Path(os.path.abspath(path)).parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        info = os.fstat(fd)
        if info.st_uid != uid or stat.S_IMODE(info.st_mode) & 0o077:
            raise Blocked()
        return fd
    except BaseException:
        os.close(fd)
        raise


def read_raw(directory, name, *, uid, limit=131072):
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    except FileNotFoundError:
        return None
    with os.fdopen(fd, 'rb') as source:
        info = os.fstat(source.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != uid or
                stat.S_IMODE(info.st_mode) & 0o077 or info.st_nlink != 1 or info.st_size > limit):
            raise Blocked()
        raw = source.read(limit + 1)
        if len(raw) > limit:
            raise Blocked()
        return raw


def decode(raw):
    def unique(pairs):
        result = dict(pairs)
        if len(result) != len(pairs):
            raise Blocked()
        return result
    return json.loads(raw, object_pairs_hook=unique)


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def atomic(directory, name, raw, *, uid=None, staging=None):
    """Retain pending on fault; stage pier writes in control, not pier layout."""
    import uuid
    source_directory = directory if staging is None else staging
    if os.fstat(source_directory).st_dev != os.fstat(directory).st_dev:
        raise Blocked()
    pending = '.maintenance-' + uuid.uuid4().hex
    fd = os.open(pending, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                 0o600, dir_fd=source_directory)
    with os.fdopen(fd, 'wb') as target:
        if uid is not None and os.geteuid() != uid:
            os.fchown(target.fileno(), uid, uid)
        target.write(raw)
        target.flush()
        os.fsync(target.fileno())
    os.replace(pending, name, src_dir_fd=source_directory, dst_dir_fd=directory)
    os.fsync(directory)
    if source_directory != directory:
        os.fsync(source_directory)


class Docker:
    """Local fixed daemon, curated inspect only. No Env, logs or broad inspect."""
    FORMAT = ('{"id":{{json .Id}},"status":{{json .State.Status}},'
              '"running":{{json .State.Running}},"started":{{json .State.StartedAt}},'
              '"user":{{json .Config.User}},"privileged":{{json .HostConfig.Privileged}},'
              '"pid_mode":{{json .HostConfig.PidMode}},"userns":{{json .HostConfig.UsernsMode}},'
              '"restart":{{json .HostConfig.RestartPolicy.Name}},'
              '"caps_add":{{json .HostConfig.CapAdd}},"caps_drop":{{json .HostConfig.CapDrop}},'
              '"security":{{json .HostConfig.SecurityOpt}},"devices":{{if .HostConfig.Devices}}true{{else}}false{{end}},'
              '"mounts":[{{range $i, $m := .Mounts}}{{if $i}},{{end}}'
              '{{with $m}}{"Type":{{json .Type}},"Source":{{json .Source}},'
              '"Destination":{{json .Destination}},"RW":{{json .RW}},'
              '"Name":{{json .Name}}}{{end}}{{end}}]}')

    def __init__(self, executable='/usr/bin/docker', *, endpoint=None, compose=None):
        self.executable = executable
        self.endpoint = endpoint
        self.compose = compose
        info = decode(self.call('info', '--format',
                                '{"os":{{json .OSType}},"security":{{json .SecurityOptions}}}'))
        if info['os'] != 'linux' or any('rootless' in s or 'userns' in s for s in info['security']):
            raise Blocked()

    def call(self, *args, timeout=180):
        from bounded_child import collect, compose_command, command_env
        import time
        endpoint = self.endpoint if self.endpoint is not None else time.monotonic()+timeout
        work_end = min(endpoint-2,time.monotonic()+timeout)
        try:
            argv = (compose_command(self.compose,args[1:],work_end) if args and args[0]=='compose'
                    else [self.executable,'--host','unix:///var/run/docker.sock',*args])
            return collect(argv,endpoint,work_end,limit=1024*1024,env=command_env())['stdout']
        except ValueError:
            raise Blocked() from None

    def ids(self):
        values = self.call('ps', '-aq', '--no-trunc').decode('ascii').splitlines()
        if len(values) > 4096 or any(not re.fullmatch('[a-f0-9]{64}', x) for x in values):
            raise Blocked()
        return values

    def inspect(self, cid):
        if cid not in self.ids():
            return None
        item = decode(self.call('inspect', '--format', self.FORMAT, cid))
        # The formatter is the acquisition boundary; the parser also refuses
        # unexpected fields rather than silently accepting broader responses.
        fields = {'id', 'status', 'running', 'started', 'user', 'privileged',
                  'pid_mode', 'userns', 'restart', 'caps_add', 'caps_drop',
                  'security', 'devices', 'mounts'}
        mount_fields = {'Type', 'Source', 'Destination', 'RW', 'Name'}
        if (not isinstance(item, dict) or set(item) != fields or
                not isinstance(item['mounts'], list) or
                any(not isinstance(mount, dict) or set(mount) != mount_fields
                    for mount in item['mounts'])):
            raise Blocked()
        return item

    def volume(self, name):
        if not isinstance(name, str) or not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_.-]*', name):
            raise Blocked()
        return decode(self.call('volume', 'inspect', '--format',
            '{"name":{{json .Name}},"driver":{{json .Driver}},"scope":{{json .Scope}},'
            '"mountpoint":{{json .Mountpoint}},"options_empty":{{if .Options}}false{{else}}true{{end}}}', name))

    def consumers(self, storage):
        consumers = []
        root = os.stat(storage)
        for cid in self.ids():
            item = self.inspect(cid)
            if item is None:
                raise Blocked()
            for mount in item['mounts']:
                source = mount.get('Source', '')
                # Includes ancestors/descendants, readonly consumers too. Inspection
                # is supplementary to mandatory single-authority orchestration.
                if (source and (os.path.commonpath([source, str(storage)]) in (source, str(storage)))):
                    consumers.append(cid)
                    break
                if source and os.path.exists(source):
                    info = os.stat(source)
                    if (info.st_dev, info.st_ino) == (root.st_dev, root.st_ino):
                        consumers.append(cid)
                        break
        return consumers

    def stop(self, cid):
        self.call('update', '--restart=no', cid, timeout=30)
        self.call('stop', '--time', '150', cid, timeout=170)

    def remove(self, cid):
        self.call('rm', cid, timeout=30)  # NEVER -v; retain every storage byte

    def start(self, cid):
        self.call('start', cid, timeout=30)

    def restart(self, cid, policy):
        if policy not in ('no', 'unless-stopped'):
            raise Blocked()
        self.call('update', '--restart=' + policy, cid, timeout=30)

    def wait(self, cid):
        # Bounded individual calls; lifetime admission is intentionally held until
        # container exit or launcher loss. Loss leaves ACTIVE intent, not proof.
        while True:
            item = self.inspect(cid)
            if item is None:
                raise Blocked()
            if not item['running']:
                return
            time.sleep(.25)


class StorageAdmission:
    """Live internal capability: not deserializable, not caller confirmation."""
    def __init__(self, provider):
        self.provider = provider

    def check(self):
        provider = self.provider
        if (provider._admission is not self or not provider.live or
                provider.state is None or provider.state['phase'] not in ('DESTROYED', 'RECOVERED')):
            raise Blocked()
        provider.check()
        provider.check_consumers()


class Provider:
    def __init__(self, authority, storage, *, docker, owner_uid=10000):
        self.authority = Path(os.path.abspath(authority))
        self.storage = Path(os.path.abspath(storage))
        if os.path.commonpath([self.authority, self.storage]) in (str(self.authority), str(self.storage)):
            raise Blocked()
        self.docker, self.owner_uid = docker, owner_uid
        self.fds = []
        self.live = False
        self._write_uncertain = False
        self._admission = None
        self.successor = None
        self.state = None

    def _require_host(self):
        if (not sys.platform.startswith('linux') or os.geteuid() != 0 or self.owner_uid != 10000 or
                self.authority != CANONICAL_AUTHORITY):
            raise Blocked()

    def __enter__(self):
        self._require_host()
        try:
            self.storage_fd = open_root(self.storage, self.owner_uid)
            self.fds.append(self.storage_fd)
            self.storage_id = identity(self.storage_fd)
            # Same underlying storage, not a caller-selected authority lock.
            # Trusted orchestration must never replace/rollback these roots.
            fcntl.flock(self.storage_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.authority_fd = private_root(self.authority)
            self.fds.append(self.authority_fd)
            key = hashlib.sha256(encode(self.storage_id)).hexdigest()
            try:
                os.mkdir(key, 0o700, dir_fd=self.authority_fd)
                os.fsync(self.authority_fd)
            except FileExistsError:
                pass
            self.directory = private_root(self.authority / key, create=False)
            self.fds.append(self.directory)
            self.lock = os.open('admission.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK,
                                0o600, dir_fd=self.directory)
            self.fds.append(self.lock)
            info = os.fstat(self.lock)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or
                    stat.S_IMODE(info.st_mode) & 0o077 or info.st_nlink != 1):
                raise Blocked()
            fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.live = True
            raw = read_raw(self.directory, 'registry.json', uid=os.geteuid())
            self.state = None if raw is None else decode(raw)
            self.check()
            return self
        except BaseException:
            self.__exit__(None, None, None)
            raise

    def __exit__(self, *_):
        self.live = False
        self._admission = None
        for fd in reversed(self.fds):
            os.close(fd)
        self.fds.clear()

    def layout(self):
        if set(os.listdir(self.storage_fd)) != {'pier', 'uploads', 'control'}:
            raise Blocked()
        result = {'storage': self.storage_id}
        for name in ('pier', 'uploads', 'control'):
            fd = open_root(self.storage / name, self.owner_uid)
            try:
                result[name] = identity(fd)
            finally:
                os.close(fd)
        return result

    def check(self):
        if not self.live or self._write_uncertain:
            raise Blocked()
        fd = open_root(self.storage, self.owner_uid)
        try:
            if identity(fd) != self.storage_id:
                raise Blocked()
        finally:
            os.close(fd)
        current = os.stat('admission.lock', dir_fd=self.directory, follow_symlinks=False)
        if [current.st_dev, current.st_ino] != identity(self.lock):
            raise Blocked()
        if self.state is not None:
            if (set(self.state) != {'version', 'layout', 'container', 'phase', 'transaction', 'progress'} or
                    type(self.state['version']) is not int or self.state['version'] != 1 or
                    self.state['layout'] != self.layout() or
                    not isinstance(self.state['progress'], list) or len(self.state['progress']) != 2 or
                    any(type(x) is not int or x not in (0, 1, 2) for x in self.state['progress']) or
                    (self.state['transaction'] is not None and
                     not re.fullmatch('[a-f0-9]{32}', self.state['transaction'])) or
                    not re.fullmatch('[a-f0-9]{64}', self.state['container']) or
                    self.state['phase'] not in ('ENROLLED', 'ACTIVE', 'QUIESCED', 'DESTROYED', 'RECOVERED')):
                raise Blocked()
            raw = read_raw(self.directory, 'registry.json', uid=os.geteuid())
            if raw is None or decode(raw) != self.state:
                raise Blocked()

    def _commit_registry(self, state):
        self._write_uncertain = True
        atomic(self.directory, 'registry.json', encode(state))
        self.state = state
        self._write_uncertain = False

    def save(self, **updates):
        self._commit_registry(dict(self.state, **updates))

    def confined(self, cid, *, created=False):
        if not re.fullmatch('[a-f0-9]{64}', cid):
            raise Blocked()
        item = self.docker.inspect(cid)
        if (item is None or item['id'] != cid or item['user'] not in ('10000', '10000:10000') or
                item['privileged'] is not False or item['pid_mode'] not in ('', 'private') or
                item['userns'] not in ('', 'host') or item['restart'] not in ('no', 'unless-stopped') or
                item['caps_add'] or set(item['caps_drop'] or []) != {'ALL'} or
                not any(x in ('no-new-privileges', 'no-new-privileges:true') for x in item['security'] or []) or
                item['devices']):
            raise Blocked()
        mounts = item['mounts']
        if (len(mounts) != 1 or mounts[0].get('Type') not in ('bind', 'volume') or
                mounts[0].get('Source') != str(self.storage) or
                mounts[0].get('Destination') != '/urbit' or mounts[0].get('RW') is not True):
            raise Blocked()
        if mounts[0]['Type'] == 'volume':
            name = mounts[0].get('Name')
            volume = self.docker.volume(name)
            if volume != {'name': name, 'driver': 'local', 'scope': 'local',
                          'mountpoint': str(self.storage), 'options_empty': True}:
                raise Blocked()
        if created and (item['status'] != 'created' or item['running'] is not False or
                        item['started'] != '0001-01-01T00:00:00Z'):
            raise Blocked()
        return item

    def enroll(self, cid):
        self.check()
        self.confined(cid, created=True)
        if set(self.docker.consumers(self.storage)) != {cid}:
            raise Blocked()
        if self.state is None:
            layout = self.layout()
            if any(os.listdir(self.storage / name) for name in ('pier', 'uploads', 'control')):
                raise Blocked()
            self.state = {'version': 1, 'layout': layout, 'container': cid,
                          'phase': 'ENROLLED', 'transaction': None, 'progress': [0, 0]}
            self._commit_registry(self.state)
        elif self.state['phase'] == 'RECOVERED':
            self.save(container=cid, phase='ENROLLED', transaction=None, progress=[0, 0])
        else:
            raise Blocked()
        self.check()

    def run(self):
        self.check()
        if self.state is None or self.state['phase'] != 'ENROLLED':
            raise Blocked()
        cid = self.state['container']
        item = self.confined(cid, created=True)
        if set(self.docker.consumers(self.storage)) != {cid}:
            raise Blocked()
        self.save(phase='ACTIVE')  # durable intent BEFORE the external start
        # Restore only the new scope's descriptor policy, never the removed prior
        # scope. Default Compose unless-stopped stays within durable ACTIVE intent.
        policy = item['restart']
        self.docker.restart(cid, policy)
        if self.confined(cid, created=True)['restart'] != policy:
            raise Blocked()
        self.docker.start(cid)
        self.docker.wait(cid)
        # Even exit0 does not clear intent; full outside-scope settlement belongs
        # to recovery. No process/boot observation substitutes for that boundary.

    def check_consumers(self, prior=None):
        allowed = set() if prior is None else {prior}
        if self.successor is not None:
            self.confined(self.successor, created=True)
            allowed.add(self.successor)
        if set(self.docker.consumers(self.storage)) != allowed:
            raise Blocked()

    def contain(self):
        self.check()
        if self.state is None or self.state['phase'] not in ('ACTIVE', 'ENROLLED', 'QUIESCED', 'DESTROYED', 'RECOVERED'):
            raise Blocked()
        cid = self.state['container']
        if self.state['phase'] in ('ACTIVE', 'ENROLLED'):
            self.confined(cid)
            self.check_consumers(prior=cid)
            self.docker.stop(cid)
            item = self.confined(cid)
            if (item['restart'] != 'no' or item['running'] is not False or
                    item['status'] not in ('exited', 'created')):
                raise Blocked()
            # docker stop acknowledgement + namespace-init exit under admitted
            # PID confinement positively settles every descendant. Persist before
            # removal so a crash after rm is retryable without guessing absence.
            self.save(phase='QUIESCED')
        if self.state['phase'] == 'QUIESCED':
            item = self.docker.inspect(cid)
            if item is not None:
                self.confined(cid)
                if (item['restart'] != 'no' or item['running'] is not False or
                        item['status'] not in ('exited', 'created')):
                    raise Blocked()
                self.docker.remove(cid)
                if self.docker.inspect(cid) is not None:
                    raise Blocked()
            self.save(phase='DESTROYED')
        self.check_consumers()
        self._admission = StorageAdmission(self)
        self._admission.check()
        return self._admission

    def recover(self, *, successor=None):
        self.check()
        if successor is not None:
            if self.state is None or successor == self.state['container']:
                raise Blocked()
            self.confined(successor, created=True)
        self.successor = successor
        admission = self.contain()
        from maintenance import recover_stopped
        result = recover_stopped(self.storage, admission)
        self.save(phase='RECOVERED')
        return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--authority', default='/var/lib/uvm-maintenance')
    parser.add_argument('--storage', required=True)
    commands = parser.add_subparsers(dest='command', required=True)
    enroll = commands.add_parser('enroll', help='admit never-started scope on virgin storage, or recovered successor')
    enroll.add_argument('--container', required=True)
    commands.add_parser('run', help='hold host admission through explicit container lifetime; no auto ship Start')
    recovery = commands.add_parser('recover', help='destroy admitted prior scope and migrate intact ready import to STOPPED')
    recovery.add_argument('--successor', help='created successor; enroll/start under same host lease after migration')
    args = parser.parse_args(argv)
    try:
        if not sys.platform.startswith('linux') or os.geteuid() != 0:
            raise Blocked()
        with Provider(args.authority, args.storage, docker=Docker()) as provider:
            if args.command == 'enroll':
                provider.enroll(args.container)
                print('ENROLLED_NO_START')
            elif args.command == 'run':
                provider.run()
                print('SCOPE_EXITED_RECOVERY_REQUIRED')
            else:
                provider.recover(successor=args.successor)
                print('RECOVERED_STOPPED', flush=True)
                if args.successor:
                    provider.enroll(args.successor)
                    provider.run()
        return 0
    except Exception as error:
        print(str(error) if isinstance(error, Blocked) else 'BLOCKED: PRIOR_SCOPE_UNPROVABLE', file=sys.stderr)
        return 78
