"""Host-only Unix-socket broker for the opt-in patched Dappmanager.

No network listener, manager-provided host paths, shell, automatic rollback,
installation or default Compose compatibility. See docs/dappmanager-integration.md.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import socketserver
import stat
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from dappmanager_lifecycle import (Admission, Blocked, CANONICAL_AUTHORITY,
                                  ComposeBackend, Lifecycle, Provider,
                                  StartAcknowledgementDocker, private_root, PreimportUpdateRefused)

PACKAGE = 'uvm.public.dappnode.eth'
SOCKET = '/run/uvm-maintenance/dappmanager.sock'
LIMIT = 1024 * 1024


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
                                     ensure_ascii=False, allow_nan=False).encode()).hexdigest()


def dispatch(request, plan, lifecycle, receipt=None):
    if (isinstance(request, dict) and request.get('package') == PACKAGE and
            request.get('operation') == 'certificate' and
            set(request) == {'package', 'operation', 'container', 'filename', 'content'}):
        return lifecycle.upload_certificate(request['container'], request['filename'], request['content'])
    if (not isinstance(request, dict) or set(request) != {'package', 'operation', 'compose'} or
            request['package'] != PACKAGE or request['operation'] not in ('activate', 'recover') or
            digest(request['compose']) != plan['manager_compose_sha256']):
        raise Blocked('REQUEST_NOT_HOST_APPROVED')
    try:
        return lifecycle.activate() if request['operation'] == 'activate' else lifecycle.recover()
    except PreimportUpdateRefused:
        if request['operation'] == 'activate' and receipt is not None:
            receipt({'schema': 1, 'request_sha256': digest(request),
                     'plan_sha256': digest(plan), 'branch': 'PREIMPORT_UPDATE_REFUSED'})
        raise


def persist_receipt(value):
    # Existing root-private socket parent; exact request digest, exclusive leaf.
    # No client paths, descriptor contents, engine output or secrets are retained.
    root = private_root(Path(SOCKET).parent)
    try:
        fd = os.open('preimport-' + value['request_sha256'] + '.json',
                     os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=root)
        with os.fdopen(fd, 'wb') as out:
            data = json.dumps(value, sort_keys=True, separators=(',', ':')).encode()
            if out.write(data) != len(data): raise Blocked('RECEIPT_WRITE_UNCERTAIN')
            out.flush(); os.fsync(out.fileno())
        os.fsync(root)
    finally:
        os.close(root)


def trusted_bytes(path):
    """No symlink ancestors; immutable root-only regular leaf, bounded read."""
    path = Path(path)
    if not path.is_absolute() or '..' in path.parts:
        raise Blocked('TRUSTED_RELEASE_REQUIRED')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parts[1:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
            info = os.fstat(fd)
            if info.st_uid != 0 or info.st_mode & 0o022:
                raise Blocked('TRUSTED_RELEASE_REQUIRED')
        leaf = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
        try:
            info = os.fstat(leaf)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or
                    stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
                raise Blocked('TRUSTED_RELEASE_REQUIRED')
            data = os.read(leaf, LIMIT + 1)
            if len(data) > LIMIT:
                raise Blocked('INPUT_TOO_LARGE')
            return data
        finally:
            os.close(leaf)
    finally:
        os.close(fd)


def unique_json(data):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise Blocked('DUPLICATE_JSON_KEY')
            result[key] = value
        return result
    return json.loads(data, object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(Blocked('NONFINITE_JSON')))


def validate_plan(plan, raw):
    """Host JSON descriptor, not an SDK descriptor; never validate arbitrary YAML."""
    if (set(plan) != {'volume', 'compose_path', 'compose_file_sha256', 'manager_compose_sha256'} or
            not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_.-]*', plan['volume']) or
            'uvmpublicdappnodeeth' not in re.sub('[^a-z0-9]', '', plan['volume'].lower()) or
            not all(re.fullmatch('[a-f0-9]{64}', plan[key]) for key in
                    ('compose_file_sha256', 'manager_compose_sha256')) or
            hashlib.sha256(raw).hexdigest() != plan['compose_file_sha256']):
        raise Blocked('PLAN_REFUSED')
    compose = unique_json(raw)
    if (not isinstance(compose, dict) or '$' in raw.decode() or
            not set(compose) <= {'name', 'services', 'networks', 'volumes'} or
            set(compose.get('services', {})) != {'ship'} or
            compose.get('volumes') != {'ship_data': {'external': True, 'name': plan['volume']}}):
        raise Blocked('HOST_DESCRIPTOR_REFUSED')
    service = compose['services']['ship']
    # Host plan is reviewed source. Prevent Compose hidden writers and file inputs
    # even before the provider independently checks the created scope.
    allowed = {'image', 'container_name', 'user', 'restart', 'volumes', 'networks',
               'environment', 'ports', 'labels', 'cap_drop', 'security_opt',
               'stop_grace_period', 'init', 'read_only', 'mem_limit', 'cpus', 'pids_limit'}
    if (not set(service) <= allowed or
            not re.fullmatch(r'[^\s]+@sha256:[a-f0-9]{64}', service.get('image', '')) or
            service.get('container_name') != 'DAppNodePackage-ship.' + PACKAGE or
            not isinstance(service.get('labels'), dict) or
            service['labels'].get('dappnode.dnp.dnpName') != PACKAGE or
            service.get('user') != '10000:10000' or service.get('restart') != 'unless-stopped' or
            service.get('cap_drop') != ['ALL'] or
            service.get('security_opt') != ['no-new-privileges:true'] or
            service.get('volumes') != [{'type': 'volume', 'source': 'ship_data', 'target': '/urbit',
                                       'volume': {'nocopy': True}}] or
            any(not isinstance(value, dict) or value.get('external') is not True or
                not set(value) <= {'external', 'name'} for value in compose.get('networks', {}).values())):
        raise Blocked('HOST_DESCRIPTOR_REFUSED')
    return plan


class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        self.connection.settimeout(5)
        try:
            data = self.rfile.readline(LIMIT + 1)
            if len(data) > LIMIT or not data.endswith(b'\n'):
                raise Blocked('REQUEST_FRAME_REFUSED')
            request = unique_json(data)
            result = self.server.dispatch_request(request)
            response = dict(result, ok=True)
        except Exception:
            # Never reflect descriptor/environment/path/engine output to logs.
            response = {'ok': False, 'error': 'HOST_LIFECYCLE_REFUSED_PRESERVE_STATE'}
        self.wfile.write(json.dumps(response, separators=(',', ':')).encode() + b'\n')


class Server(socketserver.UnixStreamServer):
    allow_reuse_address = False


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--plan', required=True, help='root-owned immutable release plan JSON')
    parser.add_argument('--endpoint', required=True, type=float)
    parser.add_argument('--compose-sha256', required=True)
    args = parser.parse_args()
    if not sys.platform.startswith('linux') or os.geteuid() != 0:
        raise Blocked('ROOT_LINUX_HOST_REQUIRED')
    def request(request):
        plan = unique_json(trusted_bytes(args.plan))
        validate_plan(plan, trusted_bytes(plan['compose_path']))
        docker = StartAcknowledgementDocker(endpoint=args.endpoint,
            compose={'path':'/usr/libexec/docker/cli-plugins/docker-compose','sha256':args.compose_sha256})
        operation = Lifecycle(ComposeBackend(plan, docker), Admission(),
                              lambda storage: Provider(CANONICAL_AUTHORITY, storage, docker=docker))
        return dispatch(request, plan, operation, persist_receipt)
    # No stale socket deletion or second-authority fallback. systemd owns this
    # root-only runtime directory; mounting it into the patched manager is opt-in.
    root = private_root(Path(SOCKET).parent)
    os.close(root)
    old = os.umask(0o077)
    try:
        with Server(SOCKET, Handler) as server:
            os.chmod(SOCKET, 0o600, follow_symlinks=False)
            server.dispatch_request = request
            server.serve_forever()
    finally:
        os.umask(old)


if __name__ == '__main__':
    main()
