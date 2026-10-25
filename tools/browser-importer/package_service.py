"""Package-owned private HTTPS boundary; never automatically starts a ship."""
from dataclasses import dataclass
import ipaddress
import re
import os
import signal
import subprocess
import time
import argparse
from contextlib import contextmanager
import fcntl
from pathlib import Path
import shutil
import stat
import sys
import tempfile
import threading


@dataclass(frozen=True)
class Origin:
    value: str
    host: str
    authority: str


def parse_origin(value, port):
    """Accept only a literal, canonical HTTPS DNS origin (no URL normalization)."""
    match = re.fullmatch(r'https://([a-z0-9.-]+)(?::([1-9][0-9]{0,4}))?', value or '')
    if not match:
        raise ValueError('Invalid private origin.')
    host, explicit_port = match.groups()
    labels = host.split('.')
    if (len(host) > 253 or len(labels) < 2 or
            any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label)
                for label in labels)):
        raise ValueError('Invalid private hostname.')
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise ValueError('A DNS hostname is required.')
    effective = int(explicit_port) if explicit_port else 443
    if not 1 <= effective <= 65535 or effective != port:
        raise ValueError('Origin and listener ports must match.')
    return Origin(value, host, host + (':' + explicit_port if explicit_port else ''))


def nginx_path(path):
    """Quote a restricted absolute path; never interpolate Nginx variables."""
    path = str(path)
    if not re.fullmatch(r'/[a-zA-Z0-9_./ -]+', path) or '..' in path.split('/'):
        raise ValueError('Unsafe configuration path.')
    return '"' + path + '"'


def validate_routes(admin_origin, ship_origin, bind, port, importer_port, ship_port):
    if any(type(p) is not int or not 1 <= p <= 65535 for p in (port, importer_port, ship_port)):
        raise ValueError('Invalid listener port.')
    if len({port, importer_port, ship_port}) != 3:
        raise ValueError('Listener ports must be distinct.')
    if ship_port == 12321:
        raise ValueError('The special local-control listener must never be proxied.')
    address = ipaddress.IPv4Address(bind)
    if str(address) != bind:
        raise ValueError('A canonical IPv4 listener is required.')
    admin, ship = parse_origin(admin_origin, port), parse_origin(ship_origin, port)
    if admin.host == ship.host:
        raise ValueError('Separate administration and ship hostnames are required.')
    return admin, ship


def render_nginx(*, admin_origin, ship_origin, bind, port, importer_port, ship_port,
                 certificate, key, ca, runtime_dir):
    """Render a complete standalone config, without external includes or file serving."""
    admin, ship = validate_routes(admin_origin, ship_origin, bind, port, importer_port, ship_port)
    cert, private_key, trust = map(nginx_path, (certificate, key, ca))
    runtime_dir = str(runtime_dir)
    pid = nginx_path(runtime_dir + '/nginx.pid')
    body_temp = nginx_path(runtime_dir + '/body')
    proxy_temp = nginx_path(runtime_dir + '/proxy')
    result = f'''daemon off;
worker_processes 1;
pid {pid};
error_log /dev/null crit;
events {{ worker_connections 128; }}
http {{
    access_log off;
    server_tokens off;
    client_body_temp_path {body_temp};
    proxy_temp_path {proxy_temp};
    fastcgi_temp_path {nginx_path(runtime_dir + '/fastcgi')};
    uwsgi_temp_path {nginx_path(runtime_dir + '/uwsgi')};
    scgi_temp_path {nginx_path(runtime_dir + '/scgi')};
    client_header_timeout 15s;
    client_body_timeout 30s;
    send_timeout 30s;
    keepalive_timeout 30s;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_session_tickets off;
    map $http_upgrade $connection_upgrade {{
        default upgrade;
        "" close;
    }}
    server {{
        listen {bind}:{port} ssl default_server;
        server_name _;
        ssl_reject_handshake on;
        return 421;
    }}
'''
    for origin, upstream, admin_route in ((admin, importer_port, True), (ship, ship_port, False)):
        tls = (f'''proxy_ssl_verify on;
            proxy_ssl_verify_depth 1;
            proxy_ssl_trusted_certificate {trust};
            proxy_ssl_server_name on;
            proxy_ssl_name {admin.host};
            proxy_ssl_protocols TLSv1.2 TLSv1.3;''' if admin_route else
               f'proxy_cookie_domain ~.* {ship.host};')
        result += f'''    server {{
        listen {bind}:{port} ssl;
        server_name {origin.host};
        ssl_certificate {cert};
        ssl_certificate_key {private_key};
        if ($ssl_server_name != "{origin.host}") {{ return 421; }}
        if ($http_host != "{origin.authority}") {{ return 421; }}
        if ($host != "{origin.host}") {{ return 421; }}
        client_max_body_size 2m;
        location / {{
            proxy_pass {'https' if admin_route else 'http'}://127.0.0.1:{upstream};
            {tls}
            proxy_http_version 1.1;
            proxy_request_buffering off;
            proxy_buffering off;
            proxy_max_temp_file_size 0;
            proxy_connect_timeout 5s;
            proxy_read_timeout 3600s;
            proxy_send_timeout 60s;
            proxy_next_upstream off;
            proxy_set_header Host $http_host;
            proxy_set_header Origin $http_origin;
            proxy_set_header Forwarded "";
            proxy_set_header X-Forwarded-For $remote_addr;
            proxy_set_header X-Forwarded-Host $http_host;
            proxy_set_header X-Forwarded-Proto https;
            proxy_set_header X-Forwarded-Port {port};
            proxy_set_header X-Forwarded-Server "";
            proxy_set_header X-Forwarded-Prefix "";
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection $connection_upgrade;
        }}
    }}
'''
    return result + '}\n'


def child_environment(environment=None):
    environment = dict(os.environ if environment is None else environment)
    for name in ('SSLKEYLOGFILE', 'IMPORTER_BACKEND_TLS_NAME'):
        environment.pop(name, None)
    return environment


def stop_children(children, timeout):
    """Stop owned sessions, including workers whose master has already exited."""
    for child in reversed(children):
        try:
            os.killpg(child.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
    deadline = time.monotonic() + timeout
    for child in reversed(children):
        try:
            child.wait(timeout=max(0, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            # Each child was started in its own session; never signal our group.
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            child.wait(timeout=5)
    for child in reversed(children):
        # A dead master can leave an ignoring worker in its owned process group.
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        # As container PID1 we may adopt orphan workers. Never reap other groups.
        deadline = time.monotonic() + 1
        while time.monotonic() < deadline:
            try:
                pid, _ = os.waitpid(-child.pid, os.WNOHANG)
            except ChildProcessError:
                break
            if pid == 0:
                time.sleep(.01)


def supervise(importer_command, nginx_command, environment, stop, *,
              popen=subprocess.Popen, shutdown_timeout=150):
    """Both services live or neither does. Importer exit0 permits enrollment restart."""
    children = []
    try:
        for command in (importer_command, nginx_command):
            if stop.is_set():
                return 0
            children.append(popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                  stderr=subprocess.DEVNULL, env=child_environment(environment),
                                  close_fds=True, start_new_session=True))
        importer, nginx = children
        while not stop.is_set():
            # A frontend exit is always a fault, including exit0.
            if nginx.poll() is not None:
                return 78
            result = importer.poll()
            if result is not None:
                return 0 if result == 0 else 78
            stop.wait(.1)
        return 0
    finally:
        stop_children(children, shutdown_timeout)


@contextmanager
def lifetime_lock(control_root):
    """Private persistent lock, held across enrollment and both child lifetimes."""
    from importer import private_root
    root = private_root(control_root)
    fd = None
    try:
        fd = os.open('package-service.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK,
                     0o600, dir_fd=root)
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or
                stat.S_IMODE(info.st_mode) & 0o077 or info.st_nlink != 1):
            raise ValueError('Unsafe package controller lock.')
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        current = os.stat('package-service.lock', dir_fd=root, follow_symlinks=False)
        if (current.st_dev, current.st_ino) != (info.st_dev, info.st_ino):
            raise ValueError('Package controller lock changed.')
        yield
    finally:
        if fd is not None:
            os.close(fd)
        os.close(root)


class SafeArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        raise ValueError('Invalid package service arguments.')


def make_parser(environment=None):
    environment = os.environ if environment is None else environment
    parser = SafeArgumentParser(description='Private package HTTPS; no automatic ship start.')
    for name in ('pier-root', 'uploads-root', 'control-root', 'password-hash-file'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--bind', default='0.0.0.0')
    parser.add_argument('--port', type=int, default=8443)
    parser.add_argument('--importer-port', type=int, default=8080,
                        help='Loopback importer port; override only for isolated synthetic tests')
    parser.add_argument('--ship-port', type=int, default=8081,
                        help='Normal authenticated loopback web port, never the local-control listener')
    parser.add_argument('--origin', default=environment.get(
        'IMPORTER_ORIGIN', 'https://uvm.public.dappnode.private:8443'))
    parser.add_argument('--ship-origin', default=environment.get(
        'URBIT_SHIP_ORIGIN', 'https://ship.uvm.public.dappnode.private:8443'))
    parser.add_argument('--owner-ca-sha256', default=environment.get('OWNER_CA_SHA256'))
    parser.add_argument('--bootstrap-authority-sha256', default=environment.get('IMPORTER_BOOTSTRAP_SHA256'))
    parser.add_argument('--nginx', help='Explicit Nginx executable (normally discovered on PATH)')
    parser.add_argument('--reserve-bytes', type=int, default=1024**3)
    parser.add_argument('--max-upload-bytes', type=int, default=8 * 1024**3)
    parser.add_argument('--max-expanded-bytes', type=int, default=64 * 1024**3)
    return parser


def importer_command(args, identity):
    command = [sys.executable, str(Path(__file__).with_name('managed_service.py'))]
    for flag in ('pier-root', 'uploads-root', 'control-root', 'password-hash-file',
                 'reserve-bytes', 'max-upload-bytes', 'max-expanded-bytes'):
        command.extend(['--' + flag, str(getattr(args, flag.replace('-', '_')))])
    command.extend(['--bind', '127.0.0.1', '--port', str(args.importer_port),
                    '--origin', args.origin, '--tls-cert', str(identity['certificate']),
                    '--tls-key', str(identity['key'])])
    if args.bootstrap_authority_sha256 is not None:
        command.extend(['--bootstrap-authority-sha256', args.bootstrap_authority_sha256])
    return command


def run_service(args, stop, *, ensure_tls=None, environment=None, supervisor=supervise,
                syntax_test=subprocess.run, temp_dir=None, poll_seconds=3):
    admin, ship = validate_routes(args.origin, args.ship_origin, args.bind, args.port,
                                  args.importer_port, args.ship_port)
    if not re.fullmatch(r'[a-f0-9]{64}', args.owner_ca_sha256 or ''):
        raise ValueError('An independently configured owner CA digest is required.')
    if args.reserve_bytes < 0 or args.max_upload_bytes <= 0 or args.max_expanded_bytes <= 0:
        raise ValueError('Invalid importer resource bounds.')
    if not 0 < poll_seconds <= 60:
        raise ValueError('Invalid certificate polling interval.')
    environment = child_environment(environment)
    with lifetime_lock(args.control_root):
        if ensure_tls is None:
            # Import only after local configuration and exclusive ownership are checked.
            from owner_tls import ensure_owner_tls
            ensure_tls = ensure_owner_tls
        announced = False
        while not stop.is_set():
            identity = ensure_tls(args.control_root, (admin.host, ship.host), args.owner_ca_sha256)
            if identity['state'] == 'READY':
                break
            if identity['state'] != 'AWAITING_CERTIFICATE':
                raise ValueError('Owner TLS is not ready.')
            if not announced:
                sys.stderr.write('AWAITING_CERTIFICATE; no network listener or ship started.\n')
                announced = True
            stop.wait(poll_seconds)
        else:
            return 0
        if stop.is_set():
            return 0
        nginx = args.nginx or shutil.which('nginx')
        if not nginx or not os.path.isabs(nginx) or not os.access(nginx, os.X_OK):
            raise ValueError('Nginx executable unavailable.')
        # Only this newly-created service-owned temporary directory is removed.
        with tempfile.TemporaryDirectory(prefix='urbit-frontend-', dir=temp_dir) as runtime_dir:
            config = render_nginx(admin_origin=args.origin, ship_origin=args.ship_origin,
                                  bind=args.bind, port=args.port, importer_port=args.importer_port,
                                  ship_port=args.ship_port, certificate=identity['certificate'],
                                  key=identity['key'], ca=identity['ca'], runtime_dir=runtime_dir)
            config_path = Path(runtime_dir) / 'nginx.conf'
            fd = os.open(config_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, 'w') as target:
                target.write(config)
            command = [nginx, '-p', runtime_dir + '/', '-c', str(config_path), '-e', '/dev/null']
            result = syntax_test(command + ['-t'], stdin=subprocess.DEVNULL,
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                 timeout=30, env=environment, close_fds=True)
            if result.returncode != 0:
                raise ValueError('Frontend configuration refused.')
            if stop.is_set():
                return 0
            sys.stderr.write('READY; private frontend starting, no automatic ship start.\n')
            return supervisor(importer_command(args, identity), command, environment, stop)


def main(argv=None):
    stop = threading.Event()
    previous = {}
    try:
        for signum in (signal.SIGTERM, signal.SIGINT):
            previous[signum] = signal.signal(signum, lambda *_: stop.set())
        args = make_parser().parse_args(argv)
        return run_service(args, stop)
    except Exception:
        # Never disclose certificate/key paths, command output, URLs or private errors.
        sys.stderr.write('Private package service refused startup or stopped after a fault.\n')
        return 78
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)


if __name__ == '__main__':
    raise SystemExit(main())
