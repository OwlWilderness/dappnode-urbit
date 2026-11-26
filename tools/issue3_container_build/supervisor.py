"""Ordinary-container supervision. No default client, CLI, or approval generator.

Only an injected bounded transport may touch an engine. No BuildKit operation,
retry, deletion, logs, attach, export, commit, or prune exists in this module.
"""
from dataclasses import asdict, dataclass
import hashlib
import json
import os
import re
import stat
import time
from pathlib import Path


class Refused(RuntimeError):
    pass


@dataclass(frozen=True)
class Input:
    path: str
    size: int
    sha256: str


@dataclass(frozen=True)
class Plan:
    attempt: str
    image: str
    command: tuple
    inputs: tuple
    seconds: int = 60
    memory: int = 536870912
    nano_cpus: int = 1000000000
    pids: int = 64
    work_bytes: int = 134217728
    platform: str = 'linux/amd64'
    evidence: str = 'UNBOUND'

    @property
    def digest(self):
        return hashlib.sha256(canonical({'plan': asdict(self), 'controls': expected(self)})).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def expected(plan) -> dict:
    return dict(path=plan.command[0], args=list(plan.command[1:]),
                memory=plan.memory, swap=plan.memory, nano_cpus=plan.nano_cpus,
                pids=plan.pids, network='none', readonly=True, log='none',
                restart='no', privileged=False, cap_add=None, cap_drop=['ALL'],
                security=['no-new-privileges'], user='65534:65534', workdir='/work',
                auto_remove=False, devices=0, device_requests=0, ports=0,
                ulimits=[dict(Name='core', Hard=0, Soft=0)],
                mounts=[dict(source=f.path, target='/input/' + str(i), rw=False, type='bind')
                        for i, f in enumerate(plan.inputs)],
                tmpfs={'/work': 'rw,nosuid,nodev,size=' + str(plan.work_bytes) + ',mode=1777',
                       '/tmp': 'rw,noexec,nosuid,nodev,size=16777216,mode=1777'})


# Every template expression selects an allowlisted nonsecret leaf. Never whole
# Config/HostConfig/State/Labels/Mounts, environment, command history, or logs.
LEAVES = dict(id='.Id', name='.Name', image='.Image', path='.Path', args='.Args',
              attempt='index .Config.Labels "org.issue3.attempt"',
              binding='index .Config.Labels "org.issue3.binding"',
              memory='.HostConfig.Memory', swap='.HostConfig.MemorySwap',
              nano_cpus='.HostConfig.NanoCpus', pids='.HostConfig.PidsLimit',
              network='.HostConfig.NetworkMode', readonly='.HostConfig.ReadonlyRootfs',
              log='.HostConfig.LogConfig.Type', restart='.HostConfig.RestartPolicy.Name',
              privileged='.HostConfig.Privileged', cap_add='.HostConfig.CapAdd',
              cap_drop='.HostConfig.CapDrop', security='.HostConfig.SecurityOpt',
              user='.Config.User', workdir='.Config.WorkingDir', auto_remove='.HostConfig.AutoRemove',
              devices='len .HostConfig.Devices', device_requests='len .HostConfig.DeviceRequests',
              ports='len .HostConfig.PortBindings', ulimits='.HostConfig.Ulimits',
              tmpfs='.HostConfig.Tmpfs', status='.State.Status', pid='.State.Pid',
              running='.State.Running', restarting='.State.Restarting',
              oom='.State.OOMKilled', exit='.State.ExitCode')
FORMAT = '{' + ','.join(json.dumps(k) + ':{{json (' + v + ')}}' for k, v in LEAVES.items())
FORMAT += ',"mounts":[{{range $i,$m := .Mounts}}{{if $i}},{{end}}'
FORMAT += '{"source":{{json $m.Source}},"target":{{json $m.Destination}},'
FORMAT += '"rw":{{json $m.RW}},"type":{{json $m.Type}}}{{end}}]}'
OWNERSHIP_FORMAT = '{' + ','.join(json.dumps(k) + ':{{json (' + LEAVES[k] + ')}}'
    for k in ('id', 'name', 'image', 'attempt', 'binding', 'status', 'pid',
              'running', 'restarting', 'oom', 'exit')) + '}'


def create_args(plan):
    controls = expected(plan)
    args = ['container', 'create', '--name', plan.attempt, '--pull', 'never',
            '--label', 'org.issue3.attempt=' + plan.attempt,
            '--label', 'org.issue3.binding=' + plan.digest, '--platform', plan.platform,
            '--memory', str(plan.memory), '--memory-swap', str(plan.memory),
            '--cpus', str(plan.nano_cpus // 1000000000) + '.' + str(plan.nano_cpus % 1000000000).zfill(9),
            '--pids-limit', str(plan.pids), '--network', 'none', '--read-only',
            '--log-driver', 'none', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
            '--restart', 'no', '--no-healthcheck', '--user', '65534:65534',
            '--workdir', '/work', '--ulimit', 'core=0:0', '--entrypoint', plan.command[0]]
    for dest, options in controls['tmpfs'].items():
        args += ['--tmpfs', dest + ':' + options]
    for mount in controls['mounts']:
        args += ['--mount', 'type=bind,source=' + mount['source'] + ',target=' + mount['target'] + ',readonly']
    return tuple(args + [plan.image] + list(plan.command[1:]))


def identity(plan, data, cid=None):
    if not (data.get('name') == '/' + plan.attempt and data.get('image') == plan.image
            and data.get('attempt') == plan.attempt and data.get('binding') == plan.digest
            and (cid is None or data.get('id') == cid)):
        raise Refused('identity mismatch')


def settled(data):
    return (data.get('status') in ('created', 'exited', 'dead')
            and type(data.get('pid')) is int and data['pid'] == 0
            and data.get('running') is False and data.get('restarting') is False)


def validate(plan, grant):
    if type(plan) is not Plan or type(grant) is not dict:
        raise Refused('UNBOUND: no frozen plan and owner grant')
    if (not re.fullmatch(r'issue3-build-[0-9a-f]{32}', plan.attempt)
            or not re.fullmatch(r'sha256:[0-9a-f]{64}', plan.image)
            or type(plan.command) is not tuple or not plan.command
            or len(plan.command) > 64 or not plan.command[0].startswith('/')
            or any(type(s) is not str or not s or len(s) > 1024 or any(ord(c) < 32 for c in s)
                   for s in plan.command)
            or plan.platform not in ('linux/amd64', 'linux/arm64')
            or type(plan.inputs) is not tuple or not 1 <= len(plan.inputs) <= 32):
        raise Refused('invalid frozen identifiers/argv/inputs')
    for field, low, high in [('seconds', 1, 2400), ('memory', 67108864, 8589934592),
                             ('nano_cpus', 100000000, 4000000000), ('pids', 1, 256),
                             ('work_bytes', 1048576, plan.memory // 2)]:
        value = getattr(plan, field)
        if type(value) is not int or not low <= value <= high:
            raise Refused('unsupported resource bound')
    if (grant.get('authorized') is not True or grant.get('action') != 'execute'
            or grant.get('binding') != plan.digest
            or type(grant.get('expires_unix')) is not int
            or not time.time() < grant['expires_unix'] <= time.time() + 3600
            or type(grant.get('owner_grant')) is not str or not 1 <= len(grant['owner_grant']) <= 256
            or grant.get('failure_model') != 'attended-best-effort-stop-retain'):
        raise Refused('missing/mismatched/expired owner grant')


def safe_path(path):
    if not path.is_absolute() or path != path.resolve():
        raise Refused('noncanonical or symlink path')
    for part in (path, *path.parents):
        mode = part.lstat().st_mode
        if stat.S_ISLNK(mode) or mode & 0o022:
            raise Refused('symlink or group/world-writable path')


def verify_inputs(plan, clock, deadline):
    for item in plan.inputs:
        if clock() >= deadline:
            raise Refused('input verification deadline')
        if (type(item) is not Input or type(item.path) is not str or ',' in item.path
                or any(ord(c) < 32 for c in item.path) or type(item.size) is not int
                or not 0 <= item.size <= 134217728
                or not re.fullmatch('[0-9a-f]{64}', item.sha256)):
            raise Refused('invalid public file descriptor')
        path = Path(item.path)
        safe_path(path)
        if not stat.S_ISREG(path.lstat().st_mode):
            raise Refused('public input must be a regular file before open')
        with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as stream:
            before = os.fstat(stream.fileno())
            if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                    or before.st_uid != os.getuid() or before.st_mode & 0o222
                    or before.st_size != item.size):
                raise Refused('public input not a frozen owned single-link regular file')
            digest = hashlib.sha256()
            remaining = item.size
            while remaining:
                if clock() >= deadline:
                    raise Refused('input verification deadline')
                chunk = stream.read(min(65536, remaining))
                if not chunk:
                    raise Refused('input shortened')
                digest.update(chunk)
                remaining -= len(chunk)
            after = os.fstat(stream.fileno())
            if stream.read(1) or before != after or digest.hexdigest() != item.sha256:
                raise Refused('public input drift')


def record(directory, name, value):
    # Exclusive, durable evidence; partial writes consume the attempt too.
    fd = os.open(directory / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(canonical(value))
        stream.flush()
        os.fsync(stream.fileno())
    fd = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def supervise(plan, grant, evidence, transport, *, clock=time.monotonic):
    validate(plan, grant)
    deadline = clock() + plan.seconds
    verify_inputs(plan, clock, deadline)
    evidence = Path(evidence)
    if str(evidence) != plan.evidence:
        raise Refused('UNBOUND or different evidence identity')
    safe_path(evidence)
    info = evidence.stat()
    if not evidence.is_dir() or info.st_uid != os.getuid() or info.st_mode & 0o077 or any(evidence.iterdir()):
        raise Refused('evidence directory must be new, private, owned and empty')
    validate(plan, grant)  # Input observations may outlive admission authority.
    try:
        record(evidence, 'attempt.json', dict(schema=1, binding=plan.digest, plan=asdict(plan)))
    except FileExistsError:
        raise Refused('attempt consumed') from None
    def ask(args):
        remaining = deadline - clock()
        if remaining <= 0:
            raise Refused('operation deadline')
        timeout = remaining if args[:2] == ('container', 'wait') else min(5, remaining)
        data = transport(tuple(args), timeout, 65536)
        if type(data) is not bytes or len(data) > 65536:
            raise Refused('transport output bound')
        if clock() > deadline:
            raise Refused('late control acknowledgement')
        return data
    call = lambda *args: ask(('container', *args))
    cid, closed, status, intent, interruption = None, False, 'FAIL', False, None

    def inspect(target, controls=False):
        data = json.loads(call('inspect', '--format', FORMAT if controls else OWNERSHIP_FORMAT, target))
        identity(plan, data, cid)
        if not re.fullmatch('[0-9a-f]{64}', data.get('id', '')):
            raise Refused('invalid container ID')
        if controls and any(canonical(data.get(k)) != canonical(v) for k, v in expected(plan).items()):
            raise Refused('containment mismatch')
        return data

    try:
        if call('ls', '--all', '--no-trunc', '--filter', 'name=^/' + plan.attempt + '$', '--format', '{{.ID}}').strip():
            raise Refused('name already exists')
        image_format = ('{"id":{{json .Id}},"volumes":{{len .Config.Volumes}},'
                        '"onbuild":{{len .Config.OnBuild}},"os":{{json .Os}},"arch":{{json .Architecture}}}')
        image = json.loads(ask(('image', 'inspect', '--format', image_format, plan.image)))
        if image != dict(id=plan.image, volumes=0, onbuild=0,
                         os='linux', arch=plan.platform.split('/')[1]):
            raise Refused('image identity/platform or implicit-volume/onbuild mismatch')
        validate(plan, grant)  # Recheck immediately before create intent/mutation.
        record(evidence, 'create-intent.json', dict(binding=plan.digest, name=plan.attempt, image=plan.image))
        intent = True  # Set before the request: timeout/empty ACK may still create.
        cid = ask(create_args(plan)).decode().strip()
        if not re.fullmatch('[0-9a-f]{64}', cid):
            cid = None
            raise Refused('invalid create acknowledgement')
        inspect(cid)  # Prove ownership before requesting public argv/mounts.
        data = inspect(cid, True)
        if data.get('status') != 'created' or not settled(data):
            raise Refused('not exclusively created')
        record(evidence, 'owned-id.json', dict(container_id=cid, binding=plan.digest))
        verify_inputs(plan, clock, deadline)
        validate(plan, grant)  # Expired approval cannot start an owned container.
        call('start', cid)
        data = inspect(cid, True)
        if not ((data.get('status') == 'running' and type(data.get('pid')) is int and data['pid'] > 0
                 and data.get('running') is True and data.get('restarting') is False)
                or (data.get('status') == 'exited' and settled(data))):
            raise Refused('start readback invalid')
        code = call('wait', cid).strip()
        data = inspect(cid, True)
        if not (code == b'0' and settled(data) and data.get('status') == 'exited'
                and data.get('oom') is False and type(data.get('exit')) is int and data['exit'] == 0):
            raise Refused('wait/readback unsuccessful')
        verify_inputs(plan, clock, deadline)
        status, closed = 'PASS', True
    except BaseException as error:
        if not isinstance(error, Exception):
            interruption = error
        deadline = clock() + 25  # Five distinct settlement operations; never a retry.
        # Never infer daemon settlement from client exit, stop ACK, or an error.
        # Each next mutation requires fresh exact identity. One stop, one kill.
        try:
            if not intent:
                raise Refused('no owned create intent; do not touch existing resource')
            data = inspect(cid or plan.attempt)
            cid = data['id']
            if not settled(data):
                try:
                    call('stop', '--time', '2', cid)
                except Exception:
                    pass
                data = inspect(cid)
            if not settled(data):
                try:
                    call('kill', '--signal', 'KILL', cid)
                except Exception:
                    pass
                data = inspect(cid)
            closed = settled(data)
        except Exception:
            closed = False
    result = dict(status=status, container_id=cid, settled=closed, binding=plan.digest)
    record(evidence, 'result.json', result)
    if interruption is not None:
        raise interruption
    return result
