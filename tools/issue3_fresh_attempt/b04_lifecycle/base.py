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
PILL_SIZE = 217421172
PILL_SHA = 'f8b08c53dd6d0aa9c4f7654f0a7bcd11e94089222888a3c99c0a10eedcbb377b'
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


def prepare(*args):
    raise Refusal('legacy standalone controller disabled; use bound run_lifecycle.py')


def execute(*args):
    raise Refusal('legacy standalone controller disabled; use bound run_lifecycle.py')


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
    'status': '.State.Status', 'running': '.State.Running', 'pid': '.State.Pid', 'exit': '.State.ExitCode', 'oom': '.State.OOMKilled',
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
    deadline: float
    def __init__(self, p):
        from run_lifecycle import require_bound
        require_bound()
        config = p['task'] + '/boot-docker-config-' + p['epoch']
        os.mkdir(config, 0o700)
        self.base = ['docker', '--host=' + p['docker_host'], '--config=' + config]
        self.env = {'PATH': '/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin', 'HOME': p['task'], 'DOCKER_CONFIG': config,
                    'PYTHONDONTWRITEBYTECODE': '1'}
        self.folder = Path(p['task'])

    def arm_guard(self, plan, execution_start, execution_end):
        import sys
        import settlement
        self.context = dict(schema=1, plan_sha256=hashlib.sha256(canonical(plan)).hexdigest(),
                            epoch=plan['epoch'], controller_pid=os.getpid(),
                            execution_start=execution_start, execution_end=execution_end)
        settlement.context_hash(self.context)
        durable(str(self.folder/'lifecycle-control.json'), self.context)
        durable(str(self.folder/'lifecycle-slot-held.json'), dict(context_sha256=settlement.context_hash(self.context)))
        durable(str(self.folder/'lifecycle-watchdog-spent.json'), dict(automatic_retry=False))
        # Initial arming consumes execution time, including durable receipt I/O.
        # Already-armed recovery retains its separate immutable settlement endpoint.
        settlement.remaining(execution_end)
        self.guard = subprocess.Popen([sys.executable, '-B', str(self.folder/'lifecycle_watchdog.py')],
            env=self.env, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            start_new_session=True)
        durable(str(self.folder/'lifecycle-watchdog-pid.json'),dict(pid=self.guard.pid,pgid=self.guard.pid))
        end = min(execution_end,time.monotonic()+5)
        while time.monotonic() < end:
            if (self.folder/'lifecycle-watchdog-ready.json').exists():
                require(settlement.read_json(self.folder/'lifecycle-watchdog-ready.json',4096) ==
                        dict(pid=self.guard.pid, context_sha256=settlement.context_hash(self.context)))
                require(self.guard.poll() is None)
                return
            require(self.guard.poll() is None)
            time.sleep(min(.05,max(0,end-time.monotonic())))
        raise Refusal('watchdog not ready; no target permitted')

    def finish_guard(self, deadline):
        import settlement
        import settlement_verifier as verifier
        require(settlement.read(self.folder,self.context)['deadline'] == deadline)
        self.guard.wait(timeout=settlement.remaining(deadline))
        require(self.guard.returncode == 0 and verifier.process_absent('pid',self.guard.pid) and
                verifier.process_absent('pgid',self.guard.pid))
        row = settlement.read_json(self.folder/'lifecycle-watchdog-result.json',16384)
        require(row.get('context_sha256') == settlement.context_hash(self.context) and row.get('deadline') == deadline)
        settlement.remaining(deadline)
        require(row.get('settled') is True)
        return row

    def verify_settlement(self, deadline):
        import sys
        import settlement
        import settlement_verifier as verifier
        child = None
        try:
            require(settlement.read(self.folder,self.context)['deadline'] == deadline)
            settlement.remaining(deadline)
            durable(str(self.folder/'lifecycle-verifier-spent.json'),dict(automatic_retry=False))
            settlement.remaining(deadline)
            child = subprocess.Popen([sys.executable,'-B',str(self.folder/'settlement_verifier.py')],
                env=self.env,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,
                start_new_session=True)
            durable(str(self.folder/'lifecycle-verifier-pid.json'),dict(pid=child.pid,pgid=child.pid))
            child.wait(timeout=settlement.remaining(deadline))
            row = settlement.read_json(self.folder/'lifecycle-independent-verification.json',32768)
            require(child.returncode == 0 and row.get('verifier_pid') == child.pid and
                    row.get('context_sha256') == settlement.context_hash(self.context) and
                    row.get('deadline') == deadline and row.get('controller_self_excluded') == os.getpid())
            require(row.get('safety_verified') is True and row.get('release_allowed') is True and
                    row.get('checked_within_shared_deadline') is True)
            require(verifier.process_absent('pid',child.pid) and verifier.process_absent('pgid',child.pid))
            pids, groups = verifier.owned_processes(self.folder)
            for kind, ids in (('pid',pids),('pgid',groups)):
                for pid in ids:
                    settlement.remaining(deadline)
                    require(verifier.process_absent(kind,pid))
            settlement.remaining(deadline)
            return dict(row, verifier_reaped=True)
        except BaseException as exc:
            if child is not None:
                try:
                    os.killpg(child.pid,signal.SIGKILL)
                except ProcessLookupError:
                    pass
                try:
                    child.wait(timeout=max(0,deadline-time.monotonic()))
                except subprocess.TimeoutExpired:
                    pass
            return dict(safety_verified=False,release_allowed=False,error_type=type(exc).__name__)

    def call(self, argv, binary=False, timeout=35):
        now = time.monotonic()
        end = min(now + timeout, getattr(self, 'deadline', now + timeout))
        folder = getattr(self, 'folder', None)
        if folder is not None and (folder/'lifecycle-control.json').exists():
            import settlement
            context = settlement.read_json(folder/'lifecycle-control.json',4096)
            if (folder/settlement.NAME).exists():
                end = min(end,settlement.read(folder,context)['deadline'])
        require(now < end)
        receipt = None
        if folder is not None:
            receipt = folder/('lifecycle-rpc-'+uuid.uuid4().hex)
            os.mkdir(receipt,0o700)
            durable(str(receipt/'intent.json'),dict(isolated_group=True,deadline=end))
            require(time.monotonic() < end)
        proc = subprocess.Popen(self.base + argv, env=self.env, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, start_new_session=True)
        assert proc.stdout is not None
        output = bytearray()
        sel = selectors.DefaultSelector()
        try:
            if receipt is not None:
                durable(str(receipt/'pid.json'),dict(pid=proc.pid,pgid=proc.pid))
            sel.register(proc.stdout, selectors.EVENT_READ)
            while sel.get_map():
                require(time.monotonic() < end)
                for key, _ in sel.select(min(.2,max(0,end-time.monotonic()))):
                    chunk = os.read(key.fileobj.fileno(), 8192)
                    if not chunk:
                        sel.unregister(key.fileobj)
                    else:
                        output.extend(chunk)
                        require(len(output) <= 65536)
            require(proc.wait(timeout=max(0,end-time.monotonic())) == 0)
            require(time.monotonic() < end)
            return bytes(output) if binary else strict(output)
        finally:
            sel.close()
            # Same absolute endpoint covers capture, descendant kill and reaping.
            # Expiry is unresolved: never mint a fresh grace period.
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                proc.wait(timeout=max(0,end-time.monotonic()))
            finally:
                proc.stdout.close()


def usage(root):
    total = os.lstat(root).st_blocks * 512
    deadline, count = time.monotonic() + 5, 0
    for base, dirs, files in os.walk(root, followlinks=False, onerror=lambda _: require(False)):
        for name in dirs + files:
            count += 1
            require(count <= 10000 and time.monotonic() < deadline)
            total += os.lstat(os.path.join(base, name)).st_blocks * 512
    return total


def inspect(d, p, cid):
    s = d.call(['container', 'inspect', '--format', CONTAINER_FMT, cid])
    require(isinstance(s, dict) and s.get('id') == cid and s.get('image') == p['image'])
    require(s.get('name') == '/' + p['container'] and s.get('label') == p['epoch'])
    require(type(s.get('pid')) is int and type(s.get('exit')) is int and type(s.get('oom')) is bool and type(s.get('running')) is bool)
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
# Schema2 DIAGNOSTICS remains immutable; schema3 adds only this closed grammar.
SUCCESSOR_DIAGNOSTICS = dict(DIAGNOSTICS, failure_reason=(0, 5, False),
    failure_child_state=(0, 4, False), failure_child_exit=(-255, 255, True))
COUNTERS = ('memory_current_bytes', 'memory_peak_bytes', 'memory_oom',
    'memory_oom_kill', 'cpu_usage_usec', 'cpu_user_usec', 'cpu_system_usec',
    'cpu_nr_throttled', 'cpu_throttled_usec', 'arena_charged_bytes',
    'arena_peak_bytes', 'arena_failures')

CHECKS = ['exact_inputs_private_fresh_or_reopen_state', 'numeric_guest_admission_before_Vere',
    'actual_offline_fake_bootstrap_exit0_no_remaining_child', 'production_adapter_HTTP200_twice_while_alive',
    'sigterm_exit0_no_forced_kill_or_remaining_child']


def main():
    raise Refusal('legacy standalone controller disabled; use bound run_lifecycle.py')


if __name__ == '__main__':
    raise SystemExit(main())
