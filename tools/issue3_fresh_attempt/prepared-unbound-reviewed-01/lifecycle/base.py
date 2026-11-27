#!/usr/bin/env python3
# Prepared successor; historical controller is immutable.
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import io
import selectors
import signal
import subprocess
import tarfile
import time
import uuid

GIB = 1024**3
PILL_SIZE = None
PILL_SHA = None
GUEST_SHA = None  # UNBOUND; legacy standalone entrypoints are disabled.
LABEL = 'org.dappnode.urbit.local-candidate-boot'
RESULT_PATH = '/urbit/control/official-lifecycle-result-bootstrap.json'

HEX = r'[0-9a-f]{64}'


class Refusal(Exception):
    pass


def require(ok):
    if not ok:
        raise Refusal('refused')


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def strict(data):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result)
            result[key] = value
        return result
    return json.loads(data, object_pairs_hook=pairs, parse_constant=lambda _: require(False))


def safe(path, directory=False):
    p = Path(path)
    require(p.is_absolute() and str(p) == str(path) and '..' not in p.parts)
    for item in [*reversed(p.parents), p]:
        s = item.lstat()
        require(not stat.S_ISLNK(s.st_mode) and s.st_uid in (0, os.getuid()) and not s.st_mode & 0o022)
    s = p.lstat()
    require(s.st_uid == os.getuid())
    require(stat.S_ISDIR(s.st_mode) if directory else stat.S_ISREG(s.st_mode) and s.st_nlink == 1)
    return s


def pinned(path, limit=256 * 1024**2, contents=False):
    before = safe(path)
    require(before.st_size <= limit)
    h, chunks = hashlib.sha256(), []
    def identity(s):
        return tuple(getattr(s, key) for key in ('st_dev', 'st_ino', 'st_uid', 'st_gid', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as f:
        require(identity(os.fstat(f.fileno())) == identity(before))
        while chunk := f.read(1024**2):
            h.update(chunk)
            if contents:
                chunks.append(chunk)
        require(identity(os.fstat(f.fileno())) == identity(before))
    require(identity(safe(path)) == identity(before))
    return b''.join(chunks) if contents else h.hexdigest()


def authorize(p, digest):
    try:
        path = p['task'] + '/authorization.json'
        require(not safe(path).st_mode & 0o077)
        a = strict(pinned(path, 16384, True))
        require(set(a) == {'schema', 'authorized', 'epoch', 'plan_sha256', 'owner_grant'})
        require(type(a['schema']) is int and a['schema'] == 1 and a['authorized'] is True)
        require(a['epoch'] == p['epoch'] and a['plan_sha256'] == digest)
        require(isinstance(a['owner_grant'], str) and 0 < len(a['owner_grant']) <= 8192)
    except (OSError, KeyError, ValueError, TypeError):
        raise Refusal('authorization missing or invalid') from None


def durable(path, value):
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), 'wb') as f:
        f.write(canonical(value))
        f.flush()
        os.fsync(f.fileno())
    fd = os.open(str(Path(path).parent), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def create_argv(p):
    return ['create', '--name=' + p['container'], '--label=' + LABEL + '=' + p['epoch'],
        '--platform=linux/amd64', '--pull=never', '--network=none', '--log-driver=none',
        '--read-only', '--user=10000:10000', '--cap-drop=ALL',
        '--security-opt=no-new-privileges:true', '--ipc=private', '--cgroupns=private',
        '--restart=no', '--ulimit=core=0', '--memory=5g', '--memory-swap=5g',
        '--cpus=2', '--pids-limit=128', '--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=128m,mode=1777',
        '--stop-timeout=150', '--workdir=/', '--entrypoint=python3',
        '--mount=type=volume,source=' + p['volume'] + ',target=/urbit',
        '--mount=type=bind,source=' + p['guest'] + ',target=/test/lifecycle_guest.py,readonly',
        '--mount=type=bind,source=' + p['pill'] + ',target=/bootstrap.pill,readonly',
        p['image'], '/test/lifecycle_guest.py', 'bootstrap']


def prepare(a):
    raise Refusal('legacy standalone controller disabled; use bound run_lifecycle.py')
    require(stat.S_IMODE(safe(a.task, True).st_mode) == 0o700)
    safe(a.scratch_root, True)
    require(Path(a.task).is_relative_to(a.scratch_root) and a.task != a.scratch_root)
    require(re.fullmatch('sha256:' + HEX, a.image))
    require(a.docker_host.startswith('unix:///') and '\n' not in a.docker_host)
    require(a.bind_prefix in ('', '/host_mnt'))
    require(isinstance(a.engine_id, str) and 0 < len(a.engine_id) <= 256)
    p = {'schema': 1, 'task': a.task, 'epoch': uuid.uuid4().hex, 'image': a.image,
        'pill': a.pill, 'guest': a.guest, 'scope': a.scope, 'baseline': a.baseline,
        'startup_receipt': a.startup_receipt, 'scratch_root': a.scratch_root,
        'docker_host': a.docker_host, 'bind_prefix': a.bind_prefix, 'engine_id': a.engine_id}
    for key in ('pill', 'guest'):
        require(',' not in p[key] and '\n' not in p[key])
    p['container'] = 'uvm-candidate-' + p['epoch']
    p['volume'] = p['container'] + '-state'
    sources = [str(Path(__file__).absolute()), str(Path(__file__).absolute().parents[2] / 'tests/test_candidate_boot.py')]
    sources += [a.pill, a.guest, a.scope, a.baseline, a.startup_receipt]
    require(len(set(sources)) == len(sources))
    p['sources'] = {path: pinned(path) for path in sources}
    require(safe(a.pill).st_size == PILL_SIZE and p['sources'][a.pill] == PILL_SHA)
    require(p['sources'][a.guest] == GUEST_SHA)
    scope = strict(pinned(a.scope, 65536, True))
    p['scratch_ceiling'] = scope['capacity']['scratch_root_limit_bytes']
    p['task_ceiling'] = scope['capacity']['scratch_task_limit_bytes']
    for key in ('scratch_ceiling', 'task_ceiling'):
        require(type(p[key]) is int and 0 < p[key] <= 6 * GIB)
    p['create_argv'] = create_argv(p)
    durable(a.task + '/plan.json', p)
    return verify_plan(a.task + '/plan.json')


def verify_plan(path):
    p = strict(pinned(path, 65536, True))
    keys = 'schema task epoch image pill guest scope baseline startup_receipt scratch_root docker_host bind_prefix engine_id container volume sources scratch_ceiling task_ceiling create_argv'.split()
    require(isinstance(p, dict) and set(p) == set(keys) and type(p['schema']) is int and p['schema'] == 1)
    require(path == p['task'] + '/plan.json' and stat.S_IMODE(safe(p['task'], True).st_mode) == 0o700)
    safe(p['scratch_root'], True)
    require(Path(p['task']).is_relative_to(p['scratch_root']) and p['task'] != p['scratch_root'])
    require(re.fullmatch('sha256:' + HEX, p['image']) and re.fullmatch(r'[0-9a-f]{32}', p['epoch']))
    require(p['container'] == 'uvm-candidate-' + p['epoch'] and p['volume'] == p['container'] + '-state')
    require(p['docker_host'].startswith('unix:///') and '\n' not in p['docker_host'])
    require(p['bind_prefix'] in ('', '/host_mnt') and 0 < len(p['engine_id']) <= 256)
    wanted = {str(Path(__file__).absolute()), str(Path(__file__).absolute().parents[2] / 'tests/test_candidate_boot.py')}
    wanted |= {p[k] for k in ('pill', 'guest', 'scope', 'baseline', 'startup_receipt')}
    require(isinstance(p['sources'], dict) and set(p['sources']) == wanted and len(wanted) == 7)
    for source, digest in p['sources'].items():
        require(re.fullmatch(HEX, digest) and pinned(source) == digest)
    require(safe(p['pill']).st_size == PILL_SIZE and p['sources'][p['pill']] == PILL_SHA)
    require(p['sources'][p['guest']] == GUEST_SHA)
    scope = strict(pinned(p['scope'], 65536, True))
    require(p['scratch_ceiling'] == scope['capacity']['scratch_root_limit_bytes'])
    require(p['task_ceiling'] == scope['capacity']['scratch_task_limit_bytes'])
    for key in ('scratch_ceiling', 'task_ceiling'):
        require(type(p[key]) is int and 0 < p[key] <= 6 * GIB)
    require(all(',' not in p[k] and '\n' not in p[k] for k in ('pill', 'guest')))
    require(p['create_argv'] == create_argv(p))
    return p, hashlib.sha256(canonical(p)).hexdigest()


# Fixed leaf-only Docker metadata projections. Never request secret-bearing
# Config, HostConfig, Mounts or LogConfig objects (even for later filtering).
def projection(fields):
    return '{' + ','.join('"' + k + '":{{json ' + v + '}}' for k, v in fields.items()) + '}'


ENGINE_FMT = projection({'id': '.ID', 'running': '.ContainersRunning'})
# Map range uses string keys, so commas need a boolean sentinel.
IMAGE_FMT = projection({'id': '.Id', 'arch': '.Architecture', 'os': '.Os', 'user': '.Config.User'})[:-1] + ',"volumes":[{{$first := true}}{{range $k,$v := .Config.Volumes}}{{if not $first}},{{end}}{{$first = false}}{{json $k}}{{end}}]}'
VOLUME_FMT = projection({'name': '.Name', 'driver': '.Driver', 'label': '(index .Labels "' + LABEL + '")', 'options_count': '(len .Options)'})
CONTAINER_FMT = projection({
    'id': '.Id', 'name': '.Name', 'image': '.Image', 'label': '(index .Config.Labels "' + LABEL + '")',
    'user': '.Config.User', 'workdir': '.Config.WorkingDir', 'entrypoint': '.Config.Entrypoint', 'cmd': '.Config.Cmd',
    'status': '.State.Status', 'pid': '.State.Pid', 'exit': '.State.ExitCode', 'oom': '.State.OOMKilled',
    'network': '.HostConfig.NetworkMode', 'log_driver': '.HostConfig.LogConfig.Type', 'log_path': '.LogPath',
    'readonly': '.HostConfig.ReadonlyRootfs', 'privileged': '.HostConfig.Privileged', 'auto_remove': '.HostConfig.AutoRemove',
    'port_count': '(len .HostConfig.PortBindings)', 'memory': '.HostConfig.Memory', 'swap': '.HostConfig.MemorySwap',
    'cpus': '.HostConfig.NanoCpus', 'pids': '.HostConfig.PidsLimit', 'cap_add': '.HostConfig.CapAdd',
    'cap_drop': '.HostConfig.CapDrop', 'security': '.HostConfig.SecurityOpt', 'ipc': '.HostConfig.IpcMode',
    'cgroupns': '.HostConfig.CgroupnsMode', 'restart': '.HostConfig.RestartPolicy.Name',
    'stop_timeout': '.Config.StopTimeout', 'tmp_count': '(len .HostConfig.Tmpfs)',
    'tmp': '(index .HostConfig.Tmpfs "/tmp")'})[:-1] + ',"ulimits":[{{range $i,$v := .HostConfig.Ulimits}}{{if $i}},{{end}}{"name":{{json $v.Name}},"soft":{{json $v.Soft}},"hard":{{json $v.Hard}}}{{end}}],"mounts":[{{range $i,$v := .Mounts}}{{if $i}},{{end}}{"type":{{json $v.Type}},"source":{{if eq $v.Type "bind"}}{{json $v.Source}}{{else}}null{{end}},"destination":{{json $v.Destination}},"rw":{{json $v.RW}},"name":{{if eq $v.Type "volume"}}{{json $v.Name}}{{else}}null{{end}}}{{end}}]}'


def expected_container(p):
    return {'name': '/' + p['container'], 'image': p['image'], 'label': p['epoch'],
        'user': '10000:10000', 'workdir': '/', 'entrypoint': ['python3'], 'cmd': ['/test/lifecycle_guest.py', 'bootstrap'],
        'network': 'none', 'log_driver': 'none', 'log_path': '', 'readonly': True, 'privileged': False,
        'auto_remove': False, 'port_count': 0, 'memory': 5*GIB, 'swap': 5*GIB, 'cpus': 2000000000,
        'pids': 128, 'cap_add': None, 'cap_drop': ['ALL'], 'security': ['no-new-privileges:true'],
        'ipc': 'private', 'cgroupns': 'private', 'restart': 'no', 'stop_timeout': 150,
        'tmp_count': 1, 'tmp': 'rw,noexec,nosuid,nodev,size=128m,mode=1777',
        'ulimits': [{'name': 'core', 'soft': 0, 'hard': 0}],
        'mounts': [
            {'type': 'bind', 'source': p['bind_prefix'] + p['pill'], 'destination': '/bootstrap.pill', 'rw': False, 'name': None},
            {'type': 'bind', 'source': p['bind_prefix'] + p['guest'], 'destination': '/test/lifecycle_guest.py', 'rw': False, 'name': None},
            {'type': 'volume', 'source': None, 'destination': '/urbit', 'rw': True, 'name': p['volume']}]}


class Docker:
    def __init__(self, p):
        from run_lifecycle import require_bound
        require_bound()
        config = p['task'] + '/boot-docker-config-' + p['epoch']
        os.mkdir(config, 0o700)
        self.base = ['docker', '--host=' + p['docker_host'], '--config=' + config]
        self.env = {'PATH': '/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin', 'HOME': p['task'], 'DOCKER_CONFIG': config}

    def call(self, argv, binary=False, timeout=35):
        proc = subprocess.Popen(self.base + argv, env=self.env, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, start_new_session=True)
        output = bytearray()
        sel = selectors.DefaultSelector()
        sel.register(proc.stdout, selectors.EVENT_READ)
        end = time.monotonic() + timeout
        try:
            while sel.get_map():
                require(time.monotonic() < end)
                for key, _ in sel.select(.2):
                    chunk = os.read(key.fileobj.fileno(), 8192)
                    if not chunk:
                        sel.unregister(key.fileobj)
                    else:
                        output.extend(chunk)
                        require(len(output) <= 65536)
            require(proc.wait(timeout=2) == 0)
            return bytes(output) if binary else strict(output)
        finally:
            sel.close()
            if proc.poll() is None:
                proc.kill()
                proc.wait()
            proc.stdout.close()


def usage(root):
    total = os.lstat(root).st_blocks * 512
    for base, dirs, files in os.walk(root, followlinks=False, onerror=lambda _: require(False)):
        for name in dirs + files:
            total += os.lstat(os.path.join(base, name)).st_blocks * 512
    return total


def capacity(p, initial=None):
    v = os.statvfs(p['task'])
    free = v.f_bavail * v.f_frsize
    require(usage(p['scratch_root']) <= p['scratch_ceiling'] and usage(p['task']) <= p['task_ceiling'])
    require(free >= ((16 + 7) if initial is None else 16) * GIB)  # admission = floor + growth
    if initial is not None:
        require(initial - free <= 7 * GIB)  # growth4 + VM3; not a quota
    return free


def inspect(d, p, cid):
    s = d.call(['container', 'inspect', '--format', CONTAINER_FMT, cid])
    require(isinstance(s, dict) and s.get('id') == cid and s.get('image') == p['image'])
    require(s.get('name') == '/' + p['container'] and s.get('label') == p['epoch'])
    require(type(s.get('pid')) is int and type(s.get('exit')) is int and type(s.get('oom')) is bool)
    require(isinstance(s.get('mounts'), list))
    s['mounts'].sort(key=lambda m: m['destination'])
    return s


DIAGNOSTICS = {
    'stage': (0, 9, False), 'failure': (0, 8, False), 'bootstrap_elapsed_ms': (0, 3600000, True),
    'readiness_elapsed_ms': (0, 3600000, True), 'http_attempts': (0, 1000, False),
    'last_root_status': (100, 599, True), 'last_login_status': (100, 599, True),
    'connection_failures': (0, 1000, False), 'last_errno': (0, 4095, True),
    'resume_poll_exit': (-255, 255, True), 'cleanup_exit': (-255, 255, True),
    'cleanup_failure': (0, 1, False), 'login_200_consecutive': (0, 2, False)}
CHECKS = ['exact_inputs_private_fresh_or_reopen_state', 'numeric_guest_admission_before_Vere',
    'actual_offline_fake_bootstrap_exit0_no_remaining_child', 'production_adapter_HTTP200_twice_while_alive',
    'sigterm_exit0_no_forced_kill_or_remaining_child']


def read_result(d, cid):
    data = d.call(['cp', cid + ':' + RESULT_PATH, '-'], binary=True)
    require(len(data) <= 32768)
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:') as tar:
        members = tar.getmembers()
        require(len(members) == 1)
        m = members[0]
        require(m.isreg() and 0 < m.size <= 16384 and m.name == RESULT_PATH.rsplit('/', 1)[1])
        r = strict(tar.extractfile(m).read(16385))
    require(isinstance(r, dict) and set(r) == set('schema phase success checks native_launches bootstrap_exit resume_exit http_status forced_kill guest diagnostics'.split()))
    require(type(r['schema']) is int and r['schema'] == 2 and r['phase'] == 'bootstrap' and r['success'] is True)
    require(r['checks'] == CHECKS and r['forced_kill'] is False)
    for k, v in {'native_launches': 2, 'bootstrap_exit': 0, 'resume_exit': 0, 'http_status': 200}.items():
        require(type(r[k]) is int and r[k] == v)
    diag = r['diagnostics']
    require(isinstance(diag, dict) and set(diag) == set(DIAGNOSTICS))
    for key, (low, high, nullable) in DIAGNOSTICS.items():
        value = diag[key]
        require((value is None and nullable) or (type(value) is int and low <= value <= high))
    require(diag['stage'] == 9 and diag['failure'] == 0 and diag['cleanup_failure'] == 0)
    require(diag['cleanup_exit'] == 0 and diag['resume_poll_exit'] is None)
    require(diag['last_login_status'] == 200 and diag['login_200_consecutive'] == 2)
    require(diag['http_attempts'] >= 4 and diag['http_attempts'] % 2 == 0)
    require(diag['connection_failures'] <= diag['http_attempts'] - 2)
    require(diag['readiness_elapsed_ms'] is not None and diag['bootstrap_elapsed_ms'] is not None)
    guest = r['guest']
    require(isinstance(guest, dict) and set(guest) == set('memory_available_bytes state_free_bytes root_free_bytes cgroup_memory_max_bytes cgroup_current_bytes'.split()))
    require(all(type(v) is int and 0 <= v <= 2**63-1 for v in guest.values()))
    require(guest['memory_available_bytes'] >= 5*GIB + GIB//2 and guest['cgroup_memory_max_bytes'] == 5*GIB)
    require(guest['cgroup_memory_max_bytes'] - guest['cgroup_current_bytes'] >= 4*GIB)
    require(guest['state_free_bytes'] >= 8*GIB and guest['root_free_bytes'] >= 8*GIB)
    # Output contains no guest-controlled strings, even after strict validation.
    return {'schema': 1, 'native_launches': r['native_launches'], 'bootstrap_exit': r['bootstrap_exit'],
        'resume_exit': r['resume_exit'], 'http_status': r['http_status'], 'guest': guest, 'diagnostics': diag}


def execute(p, digest, docker=None):
    raise Refusal('legacy standalone controller disabled; use bound run_lifecycle.py')
    frozen, actual = verify_plan(p['task'] + '/plan.json')
    require(frozen == p and actual == digest)
    authorize(p, digest)
    require(not os.path.lexists(p['task'] + '/attempt.json'))
    initial = capacity(p)
    d = docker if docker is not None else Docker(p)
    require(d.call(['info', '--format', ENGINE_FMT]) == {'id': p['engine_id'], 'running': 0})
    require(d.call(['image', 'inspect', '--format', IMAGE_FMT, p['image']]) ==
        {'id': p['image'], 'arch': 'amd64', 'os': 'linux', 'user': '10000:10000', 'volumes': ['/urbit']})
    for kind, name in (('container', p['container']), ('volume', p['volume'])):
        require(d.call([kind, 'ls'] + (['--all'] if kind == 'container' else []) +
            ['--filter=name=^' + name + '$', '--format={{.Name}}' if kind == 'volume' else '--format={{.Names}}'], binary=True) == b'')
        require(d.call([kind, 'ls'] + (['--all'] if kind == 'container' else []) +
            ['--filter=label=' + LABEL + '=' + p['epoch'], '--format={{.Name}}' if kind == 'volume' else '--format={{.Names}}'], binary=True) == b'')
    # Recheck the exact public bytes immediately before the exclusive mutation latch.
    require(verify_plan(p['task'] + '/plan.json') == (p, digest))
    authorize(p, digest)
    capacity(p)
    durable(p['task'] + '/attempt.json', {'plan_sha256': digest, 'epoch': p['epoch']})
    def journal(stage, **values):
        durable(p['task'] + '/' + stage + '.json', {'plan_sha256': digest, 'epoch': p['epoch'], **values})
    def attest(cid):
        require(strict(pinned(p['task'] + '/attempt.json', 16384, True)) == {'plan_sha256': digest, 'epoch': p['epoch']})
        require(strict(pinned(p['task'] + '/owned.json', 16384, True)) == {'plan_sha256': digest, 'epoch': p['epoch'], 'container_id': cid})
    cid = None
    try:
        journal('volume-create-uncertain', volume_name=p['volume'])
        reply = d.call(['volume', 'create', '--driver=local', '--label=' + LABEL + '=' + p['epoch'], p['volume']], binary=True)
        require(reply == (p['volume'] + '\n').encode())
        volume = d.call(['volume', 'inspect', '--format', VOLUME_FMT, p['volume']])
        require(volume == {'name': p['volume'], 'driver': 'local', 'label': p['epoch'], 'options_count': 0})
        journal('volume-owned', volume_name=p['volume'])
        capacity(p, initial)
        require(d.call(['image', 'inspect', '--format', IMAGE_FMT, p['image']]) ==
            {'id': p['image'], 'arch': 'amd64', 'os': 'linux', 'user': '10000:10000', 'volumes': ['/urbit']})
        require(verify_plan(p['task'] + '/plan.json') == (p, digest))
        journal('container-create-uncertain', container_name=p['container'])
        reply = d.call(p['create_argv'], binary=True).decode('ascii').strip()
        require(re.fullmatch(HEX, reply))
        cid = reply
        s = inspect(d, p, cid)
        require(s['status'] == 'created' and s['pid'] == 0)
        expected = expected_container(p)
        require(canonical({k: v for k, v in s.items() if k not in ('id', 'status', 'pid', 'exit', 'oom')}) == canonical(expected))
        journal('owned', container_id=cid)
        attest(cid)
        require(verify_plan(p['task'] + '/plan.json') == (p, digest))
        capacity(p, initial)
        journal('start-uncertain', container_id=cid)
        end = time.monotonic() + 1100
        d.call(['start', cid], binary=True)
        while True:
            s = inspect(d, p, cid)
            if s['status'] == 'exited':
                break
            require(s['status'] == 'running' and time.monotonic() < end)
            capacity(p, initial)
            time.sleep(3)
        attest(cid)
        require(s['pid'] == 0 and s['exit'] == 0 and s['oom'] is False)
        result = read_result(d, cid)
        s = inspect(d, p, cid)
        require(s['status'] == 'exited' and s['pid'] == 0 and s['exit'] == 0 and s['oom'] is False)
        require(d.call(['volume', 'inspect', '--format', VOLUME_FMT, p['volume']]) == volume)
        require(verify_plan(p['task'] + '/plan.json') == (p, digest))
        capacity(p, initial)
        final = {'success': True, 'container_id': cid, 'volume_name': p['volume'], 'report': result}
        journal('result', **final)
        return final
    except BaseException:
        # Never repeat an uncertain create/start. Exact owned state only; no logs,
        # no deletion, no replacement. A stop RPC may itself remain uncertain.
        if cid is not None and os.path.lexists(p['task'] + '/owned.json'):
            try:
                attest(cid)
                s = inspect(d, p, cid)
                if s['status'] not in ('created', 'exited') or s['pid'] != 0:
                    journal('stop-uncertain', container_id=cid)
                    d.call(['stop', '--time=150', cid], binary=True, timeout=175)
                    s = inspect(d, p, cid)
                require(s['status'] in ('created', 'exited') and s['pid'] == 0)
                journal('retained-stopped', container_id=cid)
            except BaseException:
                journal('manual-recovery-required', container_id=cid)
        else:
            journal('manual-recovery-required', container_name=p['container'], volume_name=p['volume'])
        journal('failed', success=False)
        raise Refusal('attempt consumed; retained resources require review') from None


def main():
    raise Refusal('legacy standalone controller disabled; use bound run_lifecycle.py')
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest='command', required=True)
    prep = sub.add_parser('prepare', help='freeze exact public inputs; no Docker and no authority created')
    for name in ('task', 'image', 'pill', 'guest', 'scope', 'baseline', 'startup-receipt', 'scratch-root', 'docker-host', 'engine-id'):
        prep.add_argument('--' + name, required=True)
    prep.add_argument('--bind-prefix', choices=('', '/host_mnt'), required=True,
        help='exact Docker Desktop observed bind Source prefix, not inferred')
    for command in ('verify', 'run'):
        p = sub.add_parser(command)
        p.add_argument('--plan', required=True)
    args = parser.parse_args()
    try:
        if args.command == 'prepare':
            p, digest = prepare(args)
            print(json.dumps({'plan_sha256': digest, 'epoch': p['epoch'], 'plan': p['task'] + '/plan.json'}))
        else:
            p, digest = verify_plan(args.plan)
            if args.command == 'verify':
                print(json.dumps({'plan_sha256': digest, 'epoch': p['epoch']}))
            else:
                def interrupted(signum, frame):
                    raise InterruptedError()
                signal.signal(signal.SIGTERM, interrupted)
                signal.signal(signal.SIGINT, interrupted)
                print(json.dumps(execute(p, digest), sort_keys=True))
    except (Exception, KeyboardInterrupt):
        print('REFUSED; no replay; inspect only task ledger and owned nonsecret metadata', file=__import__('sys').stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
