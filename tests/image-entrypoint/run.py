#!/usr/bin/env python3
"""Opt-in copied-image gate; retains all named resources, stopped.

Run with --image sha256:<local AMD64 image ID>. No Docker build/pull/logs/rm.
Only check.py and the existing guard TEST are mounted, never application source.
On interruption/uncertainty, stop attempts are bounded; daemon failure can require
manual recovery. No automatic retry of an uncertain create/start operation.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parents[2]
LABEL = 'org.dappnode.urbit.entrypoint-test'
DEFAULT_CMD = ['--pier-root', '/urbit/pier', '--uploads-root', '/urbit/uploads',
               '--control-root', '/urbit/control', '--password-hash-file', '/urbit/control/auth.json']


def docker(*args):
    # Never print command output/errors; no inherited stdin or attached starts.
    try:
        result = subprocess.run(['docker', *args], stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                timeout=40, check=False, text=True)
    except (OSError, subprocess.SubprocessError):
        raise RuntimeError('Docker operation uncertain') from None
    if result.returncode or len(result.stdout) > 65536:
        raise RuntimeError('Docker operation refused')
    return result.stdout.strip()


def public_result(raw, keys):
    try:
        value = json.loads(raw)
    except (ValueError, TypeError):
        raise ValueError('Invalid public result') from None
    if not isinstance(value, dict) or set(value) != keys:
        raise ValueError('Unexpected public result fields')
    return value


def sha(value):
    return isinstance(value, str) and re.fullmatch('[a-f0-9]{64}', value) is not None


def projection(fields):
    return '[' + ','.join('{{json ' + f + '}}' for f in fields) + ']'


class Harness:
    def __init__(self, image):
        if not re.fullmatch(r'sha256:[a-f0-9]{64}', image):
            raise ValueError('An immutable local sha256 image ID is required')
        self.image = image
        self.prefix = 'entrypoint-' + uuid.uuid4().hex
        self.containers = {}  # role -> exact ID; None means create is unsettled
        self.volumes = set()
        self.container_volumes = {}
        self.phase = 'preflight'
        self.failure_phase = None

    def name(self, role):
        if not re.fullmatch('[a-z-]+', role):
            raise ValueError('Invalid resource role')
        return self.prefix + '-' + role

    def validate_image(self, value):
        if value != [self.image, 'amd64', 'linux', '10000:10000',
                     ['sh', '/usr/local/bin/docker-entrypoint.sh'], DEFAULT_CMD, ['/urbit']]:
            raise ValueError('Image contract drift')

    def preflight(self):
        fields = ['.Id', '.Architecture', '.Os', '.Config.User', '.Config.Entrypoint', '.Config.Cmd']
        # Enumerate ONLY VOLUME destination names, never the Config object.
        fmt = projection(fields)[:-1] + ',[{{range $k,$v := .Config.Volumes}}{{json $k}}{{end}}]]'
        self.validate_image(json.loads(docker('image', 'inspect', '--format', fmt, self.image)))
        for resource, field in (('container', '{{.Names}}'), ('volume', '{{.Name}}')):
            args = ['container', 'ls', '-a'] if resource == 'container' else ['volume', 'ls']
            names = docker(*args, '--format', field).splitlines()
            if any(n.startswith(self.prefix) for n in names):
                raise ValueError('Resource prefix already exists')
            if docker(*args, '--filter', 'label=' + LABEL + '=' + self.prefix, '--format', field):
                raise ValueError('Task label already exists')

    def volume(self, role):
        self.volumes.add(role)  # Also retain an uncertain create identity.
        name = self.name(role)
        if docker('volume', 'create', '--label', LABEL + '=' + self.prefix, name) != name:
            raise ValueError('Volume creation uncertain')
        self.verify_volume(role)

    def verify_volume(self, role):
        fields = ['.Name', '(index .Labels "' + LABEL + '")', '.Driver']
        value = json.loads(docker('volume', 'inspect', '--format', projection(fields), self.name(role)))
        if value != [self.name(role), self.prefix, 'local']:
            raise ValueError('Volume identity mismatch')

    def create_command(self, role, volume, helper=False):
        command = ['container', 'create', '--name', self.name(role),
                   '--label', LABEL + '=' + self.prefix,
                   '--platform=linux/amd64', '--pull=never', '--network=none', '--log-driver=none',
                   '--cap-drop=ALL', '--security-opt=no-new-privileges', '--read-only',
                   '--memory=256m', '--memory-swap=256m', '--pids-limit=32', '--cpus=1',
                   '--restart=no', '--stop-timeout=15',
                   '--tmpfs', '/tmp:rw,noexec,nosuid,nodev,size=32m,mode=1777',
                   '--mount', 'type=volume,source=' + self.name(volume) + ',target=/urbit',
                   '--mount', 'type=bind,source=' + str(ROOT / 'tests/image-entrypoint/check.py') + ',target=/check.py,readonly',
                   '--mount', 'type=bind,source=' + str(ROOT / 'tests/test_volume_guard.py') + ',target=/tests/test_volume_guard.py,readonly',
                   '--env', 'OWNER_CA_SHA256=' + '0' * 64,
                   '--env', 'IMPORTER_BOOTSTRAP_SHA256=' + '1' * 64,
                   '--env', 'IMPORTER_ORIGIN=https://uvm.public.dappnode.private:8443',
                   '--env', 'URBIT_SHIP_ORIGIN=https://ship.uvm.public.dappnode.private:8443']
        # Fixed digests above are public nonsecret placeholders, not credentials.
        if helper:
            command += ['--entrypoint', 'python3', self.image, '/check.py', 'hold']
        else:
            command += [self.image, *DEFAULT_CMD, '--bind', '0.0.0.0']
        return command

    def create(self, role, volume, helper=False):
        self.phase = 'create-' + role
        self.verify_volume(volume)
        self.container_volumes[role] = volume
        self.containers[role] = None
        identity = docker(*self.create_command(role, volume, helper))
        if not sha(identity):
            raise ValueError('Container creation uncertain')
        self.containers[role] = identity
        self.state(role)
        return role

    def state(self, role):
        fields = ['.Id', '.Name', '.Image', '(index .Config.Labels "' + LABEL + '")',
                  '.State.Status', '.State.ExitCode', '.State.Pid', '.State.OOMKilled',
                  '.HostConfig.NetworkMode', '.HostConfig.LogConfig.Type', '.HostConfig.CapDrop',
                  '.HostConfig.SecurityOpt', '.HostConfig.PortBindings', '.HostConfig.Memory',
                  '.HostConfig.PidsLimit', '.HostConfig.ReadonlyRootfs', '.HostConfig.MemorySwap',
                  '.HostConfig.RestartPolicy.Name', '(index .HostConfig.Tmpfs "/tmp")']
        value = json.loads(docker('container', 'inspect', '--format', projection(fields),
                                 self.containers[role] or self.name(role)))
        identity, name, image, label, status, code, pid, oom, *restrictions = value
        if (not sha(identity) or name != '/' + self.name(role) or image != self.image or
                label != self.prefix or (self.containers[role] not in (None, identity))):
            raise ValueError('Container identity mismatch')
        self.containers[role] = identity
        if (restrictions[:3] != ['none', 'none', ['ALL']] or
                restrictions[3] not in (['no-new-privileges'], ['no-new-privileges:true']) or
                restrictions[4] not in ({}, None) or
                restrictions[5:] != [268435456, 32, True, 268435456, 'no',
                                     'rw,noexec,nosuid,nodev,size=32m,mode=1777'] or oom):
            raise ValueError('Container containment mismatch')
        # Project individual mount leaf fields, not the Mounts object.
        mount_format = '{{range .Mounts}}{{.Type}}|{{.Name}}|{{if eq .Type "bind"}}{{.Source}}{{end}}|{{.Destination}}|{{.RW}}\n{{end}}'
        mounts = docker('container', 'inspect', '--format', mount_format, identity).splitlines()
        parsed = [line.split('|') for line in mounts]
        expected_binds = {(str(ROOT / 'tests/image-entrypoint/check.py'), '/check.py'),
                          (str(ROOT / 'tests/test_volume_guard.py'), '/tests/test_volume_guard.py')}
        # Docker Desktop projects these exact requested host paths through its VM.
        desktop_binds = {('/host_mnt' + source, target) for source, target in expected_binds}
        if len(parsed) != 3 or any(len(m) != 5 for m in parsed):
            raise ValueError('Unexpected mounts')
        volumes = [m for m in parsed if m[0] == 'volume']
        binds = [m for m in parsed if m[0] == 'bind']
        if (len(volumes) != 1 or volumes[0][1] != self.name(self.container_volumes[role]) or
                volumes[0][3:] != ['/urbit', 'true'] or len(binds) != 2 or
                {(m[2], m[3]) for m in binds} not in (expected_binds, desktop_binds) or
                any(m[4] != 'false' for m in binds)):
            raise ValueError('Mount identity mismatch')
        if status not in ('created', 'running', 'exited') or type(pid) is not int or type(code) is not int:
            raise ValueError('Container state uncertain')
        if (status == 'running') != (pid > 0):
            raise ValueError('Container PID uncertain')
        return status, code

    def start(self, role):
        self.phase = 'start-' + role
        self.state(role)
        docker('container', 'start', self.containers[role])

    def stop(self, role):
        # Exact owned ID when known; discover an uncertain creation by unique name.
        if self.containers[role] is None:
            self.state(role)
        try:
            docker('container', 'stop', '--time=15', self.containers[role])
        finally:
            status, code = self.state(role)
            if status not in ('exited', 'created'):
                raise RuntimeError('Container stop uncertain')
        return code

    def finish(self):
        failed = False
        for role in self.containers:
            try:
                self.stop(role)
            except Exception:
                failed = True
        if failed:
            raise RuntimeError('Stop/readback uncertain; preserve resources and reconcile manually')

    def check(self, role, action, *args):
        self.phase = 'check-' + role + '-' + action
        if self.state(role)[0] != 'running':
            raise ValueError('Check container not running')
        return docker('container', 'exec', self.containers[role], 'python3', '/check.py', action, *args)

    def helper(self, role, volume):
        self.create(role, volume, helper=True)
        self.start(role)
        return role

    def await_exit(self, role, expected):
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            status, code = self.state(role)
            if status == 'exited':
                if code != expected:
                    raise ValueError('Unexpected exit status')
                return
            time.sleep(.25)
        raise ValueError('Exit deadline exceeded')

    def await_pending(self, role):
        deadline = time.monotonic() + 90
        previous = None
        since = None
        while time.monotonic() < deadline:
            raw = self.check(role, 'pending')
            if raw == '{"state":"not-ready"}':
                previous = since = None
            else:
                value = public_result(raw, {'state', 'csr_sha256', 'no_listener', 'no_ship'})
                if (value['state'] != 'pending' or not sha(value['csr_sha256']) or
                        value['no_listener'] is not True or value['no_ship'] is not True):
                    raise ValueError('Invalid readiness result')
                if previous is not None and previous != value:
                    raise ValueError('Public CSR changed')
                previous = value
                if since is None:
                    since = time.monotonic()
                # Past a complete service poll (3s): CSR existence alone is NOT readiness.
                if time.monotonic() - since >= 4:
                    return value['csr_sha256']
            time.sleep(.5)
        raise ValueError('Pending readiness deadline exceeded')

    def run(self):
        self.preflight()
        try:
            for role in ('unit-volume', 'empty-volume', 'legacy-volume', 'unknown-volume'):
                self.volume(role)
            unit = self.helper('unit', 'unit-volume')
            result = public_result(self.check(unit, 'unit'), {'tests', 'guard_sha256', 'vere_sha256'})
            manifest = json.loads((ROOT / 'build/vere-release.json').read_text())
            if result != {'tests': 4,
                          'guard_sha256': hashlib.sha256((ROOT / 'build/volume_guard.py').read_bytes()).hexdigest(),
                          'vere_sha256': manifest['executable_sha256']}:
                raise ValueError('Copied guard/executable qualification failed')
            if self.stop(unit) != 0:
                raise ValueError('Helper stop failed')
            for kind in ('legacy', 'unknown', 'empty'):
                volume = kind + '-volume'
                setup = self.helper(kind + '-setup', volume)
                before = public_result(self.check(setup, 'setup', kind), {'metadata_sha256'})
                if not sha(before['metadata_sha256']) or self.stop(setup) != 0:
                    raise ValueError('Synthetic setup failed')
                if kind != 'empty':
                    service = self.create(kind, volume)
                    self.start(service)
                    self.await_exit(service, 78)
                    self.start(setup)
                    after = public_result(self.check(setup, 'snapshot'), {'metadata_sha256'})
                    if before != after or self.stop(setup) != 0:
                        raise ValueError('Refused volume mutated')
            fingerprints = []
            for role in ('pending', 'replacement'):
                self.create(role, 'empty-volume')
                self.start(role)
                fingerprints.append(self.await_pending(role))
                if self.stop(role) != 0:
                    raise ValueError('Pending service did not stop cleanly')
            if (fingerprints[0] != fingerprints[1] or
                    self.containers['pending'] == self.containers['replacement']):
                raise ValueError('Replacement persistence failed')
        except BaseException:
            self.failure_phase = self.phase
            raise
        finally:
            self.finish()
        # Reconcile exact task-label identities, including stopped resources.
        for volume in self.volumes:
            self.verify_volume(volume)
        ids = set(docker('container', 'ls', '-a', '--no-trunc', '--filter',
                         'label=' + LABEL + '=' + self.prefix, '--format', '{{.ID}}').splitlines())
        volumes = set(docker('volume', 'ls', '--filter', 'label=' + LABEL + '=' + self.prefix,
                             '--format', '{{.Name}}').splitlines())
        if ids != set(self.containers.values()) or volumes != {self.name(v) for v in self.volumes}:
            raise ValueError('Task resource inventory uncertain')
        return {'result': 'PASS', 'image': self.image, 'task_label': LABEL + '=' + self.prefix,
                'csr_sha256': fingerprints[0], 'copied_guard_tests': result['tests'],
                'guard_sha256': result['guard_sha256'], 'vere_sha256': result['vere_sha256'],
                'containers': [{'name': self.name(r), 'id': identity, 'state': self.state(r)[0]}
                               for r, identity in self.containers.items()], 'volumes': sorted(volumes)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', required=True)
    args = parser.parse_args()
    harness = None
    try:
        harness = Harness(args.image)
        # Public recovery handle is printed before any resource creation.
        print(json.dumps({'task_label': LABEL + '=' + harness.prefix}), flush=True)
        print(json.dumps(harness.run(), sort_keys=True))
        return 0
    except (Exception, KeyboardInterrupt):
        print(json.dumps({'result': 'FAIL', 'task_label': LABEL + '=' + harness.prefix if harness else None,
                          'phase': (harness.failure_phase or harness.phase) if harness else 'argument-validation',
                          'resources': 'preserved; inspect exact task labels for stop uncertainty'}))
        return 1


if __name__ == '__main__':
    sys.exit(main())
