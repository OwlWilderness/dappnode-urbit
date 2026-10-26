"""Authenticated private import HTTP boundary. No ship runtime or secret logging."""
import hashlib
import hmac
import json
import secrets
import sys
import threading
import time
import re
import os
import stat
import argparse
import signal
import ssl
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).parent))
from importer import Importer, ImportError, private_root
from enrollment import CredentialEnrollment, EnrollmentRefused
from backend_tls import ensure_backend_tls


class PrivateServer(ThreadingHTTPServer):
    slots: threading.BoundedSemaphore
    origin: str
    engine: Importer
    auth_lock: threading.Lock
    sessions: dict
    attempts: list
    salt: bytes
    password_hash: bytes
    daemon_threads = False
    # Restarting after first enrollment must reclaim the same port even while
    # closed connections remain in TIME_WAIT. This is not SO_REUSEPORT.
    allow_reuse_address = True

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()

    def handle_error(self, request, client_address):
        # Do not print exception details, paths, request headers or payloads.
        sys.stderr.write('Import HTTP request failed.\n')


class Handler(BaseHTTPRequestHandler):
    server: PrivateServer  # pyright: ignore[reportIncompatibleVariableOverride]
    server_version = 'PrivateImport'

    def setup(self):
        self.request.settimeout(30)
        super().setup()

    def log_message(self, *args):
        pass

    def send_error(self, code, message=None, explain=None):
        self.reply(code, {'error': 'Request rejected.'})

    def reply(self, status, data, *, cookie=None):
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
        if cookie:
            self.send_header('Set-Cookie', cookie)
        self.end_headers()
        self.wfile.write(body)

    def host_allowed(self):
        hosts = self.headers.get_all('Host', [])
        return len(hosts) == 1 and hosts[0] == urlsplit(self.server.origin).netloc

    def body(self, limit=16384):
        lengths = self.headers.get_all('Content-Length', [])
        if self.headers.get('Transfer-Encoding') or len(lengths) != 1 or not lengths[0].isdecimal():
            raise ValueError('Invalid framing')
        length = int(lengths[0])
        if not 0 < length <= limit:
            raise ValueError('Invalid request size')
        data = self.rfile.read(length)
        if len(data) != length:
            raise ValueError('Incomplete request')
        return data

    def session_cookie_name(self):
        return '__Host-import_session' if self.server.origin.startswith('https://') else 'import_session'

    def session(self):
        cookies = SimpleCookie()
        try:
            name = self.session_cookie_name()
            headers = self.headers.get_all('Cookie', []) if hasattr(self.headers, 'get_all') else [self.headers.get('Cookie', '')]
            if len(headers) != 1 or sum(part.strip().partition('=')[0] == name for part in headers[0].split(';')) != 1:
                return None
            cookies.load(headers[0])
            sid = cookies[name].value if name in cookies else ''
        except Exception:
            return None
        with self.server.auth_lock:
            now = time.monotonic()
            self.server.sessions = {key: value for key, value in self.server.sessions.items()
                                    if value['expires'] > now}
            return self.server.sessions.get(sid)

    def do_GET(self):
        if not self.host_allowed():
            return self.reply(403, {'error': 'Host rejected.'})
        assets = {'/': ('index.html', 'text/html'), '/index.html': ('index.html', 'text/html'),
                  '/style.css': ('style.css', 'text/css'), '/app.mjs': ('app.mjs', 'text/javascript')}
        if self.path in assets:
            filename, content_type = assets[self.path]
            body = (Path(__file__).parent / 'web' / filename).read_bytes()
            self.send_response(200)
            self.send_header('Content-Type', content_type + '; charset=utf-8')
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Cache-Control', 'no-store')
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.send_header('Referrer-Policy', 'no-referrer')
            self.send_header('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
            self.end_headers()
            self.wfile.write(body)
            return
        session = self.session()
        if not session:
            return self.reply(401, {'error': 'Authentication required.'})
        if self.path != '/api/status':
            return self.reply(404, {'error': 'Not found.'})
        data = self.server.engine.status()
        data['csrf'] = session['csrf']
        data['capacity'] = self.server.engine.capacity()
        self.reply(200, data)

    def do_POST(self):
        if not self.host_allowed() or self.headers.get_all('Origin', []) != [self.server.origin]:
            return self.reply(403, {'error': 'Origin or Host rejected.'})
        try:
            if self.path == '/api/login' and self.command == 'POST':
                return self.login()
            session = self.session()
            if not session:
                return self.reply(401, {'error': 'Authentication required.'})
            csrf = self.headers.get('X-CSRF-Token', '')
            if not hmac.compare_digest(csrf, session['csrf']):
                return self.reply(403, {'error': 'CSRF token rejected.'})
            if self.path == '/api/access-code' and self.command == 'POST':
                return self.reveal_access_code(session)
            if self.path == '/api/jobs' and self.command == 'POST':
                if self.headers.get('Content-Type') != 'application/json':
                    raise ValueError('JSON required')
                params = json.loads(self.body())
                return self.reply(201, self.server.engine.create(**params))
            parsed = urlsplit(self.path)
            route = re.fullmatch(r'/api/jobs/([a-f0-9]{32})(?:/(chunk|verify|validate))?', parsed.path)
            if route:
                job_id, action = route.groups()
                if self.command == 'POST' and action == 'validate' and not parsed.query:
                    if self.headers.get('Content-Type') != 'application/json' or json.loads(self.body()) != {}:
                        raise ValueError('Empty JSON object required')
                    return self.reply(202, self.server.engine.begin_validate(job_id))
                if self.command == 'DELETE' and action is None and not parsed.query:
                    self.server.engine.cancel(job_id)
                    return self.reply(200, {'cancelled': True})
                if ((self.command == 'PUT' and action == 'chunk') or
                        (self.command == 'POST' and action == 'verify')):
                    if not re.fullmatch(r'offset=(0|[1-9][0-9]{0,20})', parsed.query):
                        raise ValueError('Invalid offset')
                    if self.headers.get('Content-Type') != 'application/octet-stream':
                        raise ValueError('Binary chunk required')
                    offset = int(parsed.query.split('=')[1])
                    data = self.body(1024**2)
                    operation = self.server.engine.append if action == 'chunk' else self.server.engine.verify
                    return self.reply(200, operation(job_id, offset, data))
            if self.path == '/api/start' and self.command == 'POST':
                if type(self.server.engine).start is Importer.start:
                    # Preserve the standalone importer's unconditional refusal.
                    self.server.engine.start()
                if self.headers.get('Content-Type') != 'application/json':
                    raise ValueError('JSON required')
                params = json.loads(self.body())
                if (not isinstance(params, dict) or set(params) != {'confirmed_stopped'} or
                        params['confirmed_stopped'] is not True):
                    raise ValueError('Explicit stopped confirmation required')
                return self.reply(200, self.server.engine.start(confirmed_stopped=True))
            if self.path == '/api/stop' and self.command == 'POST':
                if self.headers.get('Content-Type') != 'application/json' or json.loads(self.body()) != {}:
                    raise ValueError('Empty JSON object required')
                stop = getattr(self.server.engine, 'stop', None)
                if stop is None:
                    raise ImportError('No runtime is managed by this importer.')
                return self.reply(200, stop())
            if self.path == '/api/logout' and self.command == 'POST':
                with self.server.auth_lock:
                    self.server.sessions = {key: value for key, value in self.server.sessions.items()
                                            if value is not session}
                secure = '; Secure' if self.server.origin.startswith('https://') else ''
                return self.reply(200, {'logged_out': True},
                                  cookie=f'{self.session_cookie_name()}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0{secure}')
            return self.reply(404, {'error': 'Not found.'})
        except ImportError as error:
            self.reply(409, {'error': str(error)})
        except (ValueError, TypeError, KeyError):
            self.reply(400, {'error': 'Invalid request.'})
        except (OSError, TimeoutError):
            self.reply(503, {'error': 'Storage or transfer unavailable. Import remains locked.'})

    do_PUT = do_POST
    do_DELETE = do_POST

    def reveal_access_code(self, session):
        # This route has no expression, path, port or alternate-operation input.
        if (self.headers.get_all('Content-Type', []) != ['application/json'] or
                self.headers.get_all('X-CSRF-Token', []) != [session['csrf']]):
            raise ValueError('Invalid request')
        pairs = json.loads(self.body(4096), object_pairs_hook=list)
        if (not isinstance(pairs, list) or len(pairs) != 1 or
                not isinstance(pairs[0], tuple) or pairs[0][0] != 'password'):
            raise ValueError('Invalid request')
        password = pairs[0][1]
        if not isinstance(password, str) or not 1 <= len(password) <= 1024:
            return self.reply(401, {'error': 'Authentication failed.'})
        with self.server.auth_lock:
            now = time.monotonic()
            self.server.attempts = [when for when in self.server.attempts if when > now - 60]
            if len(self.server.attempts) >= 5:
                return self.reply(429, {'error': 'Authentication rate limit reached; retry later.'})
            self.server.attempts.append(now)
        digest = hashlib.scrypt(password.encode(), salt=self.server.salt, n=16384, r=8, p=1)
        password = pairs = None
        if not hmac.compare_digest(digest, self.server.password_hash):
            return self.reply(401, {'error': 'Authentication failed.'})
        reveal = getattr(self.server.engine, 'reveal_access_code', None)
        if reveal is None:
            return self.reply(409, {'error': 'Access code unavailable.'})
        if self.session() is not session:
            return self.reply(401, {'error': 'Authentication required.'})
        try:
            code = reveal()
        except Exception:
            # Never reflect runtime/protocol exceptions or stack traces.
            return self.reply(409, {'error': 'Access code unavailable.'})
        if self.session() is not session:
            return self.reply(401, {'error': 'Authentication required.'})
        return self.reply(200, {'code': code})

    def login(self):
        if self.headers.get('Content-Type') != 'application/json':
            raise ValueError('JSON required')
        params = json.loads(self.body())
        if not isinstance(params, dict):
            raise ValueError('JSON object required')
        password = params.get('password', '')
        if not isinstance(password, str) or len(password) > 1024:
            return self.reply(401, {'error': 'Authentication failed.'})
        with self.server.auth_lock:
            now = time.monotonic()
            self.server.attempts = [when for when in self.server.attempts if when > now - 60]
            if len(self.server.attempts) >= 5:
                return self.reply(429, {'error': 'Login rate limit reached; retry later.'})
            self.server.attempts.append(now)
        digest = hashlib.scrypt(password.encode(), salt=self.server.salt, n=16384, r=8, p=1)
        if not hmac.compare_digest(digest, self.server.password_hash):
            return self.reply(401, {'error': 'Authentication failed.'})
        sid = secrets.token_urlsafe(32)
        csrf = secrets.token_urlsafe(32)
        with self.server.auth_lock:
            self.server.sessions = {key: value for key, value in self.server.sessions.items()
                                    if value['expires'] > now}
            if len(self.server.sessions) >= 8:
                return self.reply(429, {'error': 'Active session limit reached.'})
            self.server.sessions[sid] = {'csrf': csrf, 'expires': now + 900}
        secure = '; Secure' if self.server.origin.startswith('https://') else ''
        self.reply(200, {'csrf': csrf}, cookie=f'{self.session_cookie_name()}={sid}; Path=/; HttpOnly; SameSite=Strict; Max-Age=900{secure}')


class EnrollmentHandler(Handler):
    """No importer engine, session or runtime is reachable before enrollment."""
    def do_PUT(self):
        self.reply(405, {'error': 'Method rejected.'})

    do_DELETE = do_PUT

    def do_GET(self):
        if not self.host_allowed():
            return self.reply(403, {'error': 'Host rejected.'})
        assets = {'/': ('enroll.html', 'text/html'),
                  '/enroll.mjs': ('enroll.mjs', 'text/javascript'),
                  '/style.css': ('style.css', 'text/css')}
        if self.path not in assets:
            return self.reply(404, {'error': 'Not found.'})
        filename, content_type = assets[self.path]
        data = (Path(__file__).parent / 'web' / filename).read_bytes()
        self.send_response(200)
        self.send_header('Content-Type', content_type + '; charset=utf-8')
        self.send_header('Content-Length', str(len(data)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        if not self.host_allowed() or self.headers.get_all('Origin', []) != [self.server.origin]:
            return self.reply(403, {'error': 'Origin or Host rejected.'})
        if self.path != '/api/enroll':
            return self.reply(404, {'error': 'Not found.'})
        with self.server.auth_lock:
            now = time.monotonic()
            self.server.attempts = [when for when in self.server.attempts if when > now - 60]
            if len(self.server.attempts) >= 5:
                return self.reply(429, {'error': 'Enrollment rate limit reached.'})
            self.server.attempts.append(now)
        try:
            if self.headers.get_all('Content-Type', []) != ['application/json']:
                raise ValueError('JSON required')
            params = json.loads(self.body(4096))
            if not isinstance(params, dict) or set(params) != {'authority', 'password'}:
                raise ValueError('Invalid enrollment request')
            self.server.enrollment.enroll(params['authority'], params['password'])
        except (EnrollmentRefused, ValueError, TypeError, KeyError):
            return self.reply(403, {'error': 'Enrollment refused.'})
        self.reply(201, {'enrolled': True, 'login_required': True})
        if self.server.stop_on_enroll:
            threading.Thread(target=self.server.shutdown, daemon=True).start()


def make_enrollment_server(control_root, authority_digest, bind, *, origin=None,
                           tls_context=None, stop_on_enroll=False):
    """Serve only first-owner enrollment; external access requires direct TLS."""
    if not isinstance(authority_digest, str) or not re.fullmatch('[a-f0-9]{64}', authority_digest):
        raise ValueError('A configured bootstrap authority digest is required.')
    loopback = bind[0] in ('127.0.0.1', '::1')
    if not loopback and (tls_context is None or not origin or not origin.startswith('https://')):
        raise ValueError('Non-loopback enrollment requires configured TLS and an exact HTTPS origin.')
    scheme = 'https' if tls_context is not None else 'http'
    if origin is not None:
        parsed = urlsplit(origin)
        if (parsed.scheme != scheme or parsed.path or parsed.query or parsed.fragment or
                parsed.username or not parsed.hostname):
            raise ValueError('An exact enrollment origin is required.')
        _ = parsed.port
    enrollment = CredentialEnrollment(control_root, authority_digest)
    if enrollment.state() != 'UNENROLLED':
        raise ValueError('Enrollment is already consumed or storage is unsafe.')
    server = PrivateServer(bind, EnrollmentHandler)
    server.origin = origin or f'{scheme}://127.0.0.1:{server.server_port}'
    server.enrollment = enrollment
    server.stop_on_enroll = stop_on_enroll
    server.auth_lock = threading.Lock()
    server.attempts = []
    server.slots = threading.BoundedSemaphore(8)
    if tls_context is not None:
        server.socket = tls_context.wrap_socket(server.socket, server_side=True)
    return server


def make_server(engine, bind, credential, *, origin=None, tls_context=None):
    """Plain HTTP is allowed only on a literal loopback bind for local tests."""
    loopback = bind[0] in ('127.0.0.1', '::1')
    if not loopback and (tls_context is None or not origin or not origin.startswith('https://')):
        raise ValueError('Non-loopback import access requires configured TLS and an exact HTTPS origin.')
    expected_scheme = 'https' if tls_context is not None else 'http'
    if origin is not None:
        parsed = urlsplit(origin)
        if (parsed.scheme != expected_scheme or parsed.path or parsed.query or parsed.fragment or
                parsed.username or not parsed.hostname):
            raise ValueError('An exact origin matching the configured transport is required.')
        # Accessing port also rejects malformed/non-numeric/out-of-range ports.
        _ = parsed.port
    salt = bytes.fromhex(credential['salt'])
    password_hash = bytes.fromhex(credential['hash'])
    if len(salt) != 16 or len(password_hash) != 64:
        raise ValueError('A configured scrypt password hash is required.')
    server = PrivateServer(bind, Handler)
    server.engine = engine
    server.origin = origin or f'{expected_scheme}://127.0.0.1:{server.server_port}'
    server.salt = salt
    server.password_hash = password_hash
    server.sessions = {}
    server.attempts = []
    server.auth_lock = threading.Lock()
    server.slots = threading.BoundedSemaphore(8)
    if tls_context is not None:
        server.socket = tls_context.wrap_socket(server.socket, server_side=True)
    return server


def load_credential(path):
    """Read only an explicitly configured service verifier, never pier/key data."""
    path = Path(path)
    parent_fd = private_root(path.parent)
    try:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent_fd)
    finally:
        os.close(parent_fd)
    with os.fdopen(fd, 'rb') as source:
        info = os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o077:
            raise ValueError('A private service-owned password verifier is required.')
        data = source.read(4097)
    if len(data) > 4096:
        raise ValueError('Invalid credential configuration.')
    return json.loads(data)


def main(*, engine_class=Importer):
    managed = engine_class is not Importer
    parser = argparse.ArgumentParser(description=('Private importer with explicit official-runtime Start; no automatic boot.'
                                                  if managed else 'Private stopped-pier ZIP importer. Ship start is always unavailable.'))
    parser.add_argument('--pier-root', required=True)
    parser.add_argument('--uploads-root', required=True)
    parser.add_argument('--control-root', required=True)
    parser.add_argument('--password-hash-file', required=True, help='Private preconfigured scrypt verifier; not a ship key')
    parser.add_argument('--bootstrap-authority-sha256', default=os.environ.get('IMPORTER_BOOTSTRAP_SHA256'),
                        help='Optional SHA-256 of a separate high-entropy owner authority, for first enrollment only')
    parser.add_argument('--bind', default='127.0.0.1')
    parser.add_argument('--port', type=int, default=8080)
    parser.add_argument('--origin', default=os.environ.get('IMPORTER_ORIGIN'),
                        help='Exact configured origin; non-loopback requires HTTPS and TLS')
    parser.add_argument('--tls-cert')
    parser.add_argument('--tls-key')
    parser.add_argument('--backend-tls-name', default=os.environ.get('IMPORTER_BACKEND_TLS_NAME'),
                        help='Exact internal DNS name for a service-owned persistent backend TLS identity')
    parser.add_argument('--reserve-bytes', type=int, default=1024**3)
    parser.add_argument('--max-upload-bytes', type=int, default=8 * 1024**3)
    parser.add_argument('--max-expanded-bytes', type=int, default=64 * 1024**3)
    args = parser.parse_args()
    try:
        if args.reserve_bytes < 0 or args.max_upload_bytes <= 0 or args.max_expanded_bytes <= 0:
            raise ValueError('Invalid resource limits.')
        if args.backend_tls_name:
            if args.tls_cert or args.tls_key:
                raise ValueError('A service-owned TLS identity cannot be combined with supplied key paths.')
            _, certificate, key = ensure_backend_tls(args.control_root, args.backend_tls_name)
            args.tls_cert, args.tls_key = str(certificate), str(key)
        context = None
        if args.tls_cert or args.tls_key:
            if not args.tls_cert or not args.tls_key:
                raise ValueError('Both TLS certificate and key are required.')
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.load_cert_chain(args.tls_cert, args.tls_key)
        try:
            credential = load_credential(args.password_hash_file)
        except FileNotFoundError:
            # Only the dedicated control record can be provisioned. Never
            # interpret an invalid or unsafe existing record as unenrolled.
            if os.path.abspath(args.password_hash_file) != os.path.join(os.path.abspath(args.control_root), 'auth.json'):
                raise ValueError('Enrollment path must be the dedicated control record.')
            server = make_enrollment_server(args.control_root, args.bootstrap_authority_sha256,
                                            (args.bind, args.port), origin=args.origin,
                                            tls_context=context, stop_on_enroll=True)
            def stop_enrollment(_signum, _frame):
                raise KeyboardInterrupt
            signal.signal(signal.SIGTERM, stop_enrollment)
            sys.stderr.write('Private enrollment listening; no importer or ship was started.\n')
            try:
                server.serve_forever()
            except KeyboardInterrupt:
                pass
            finally:
                server.server_close()
            # Restart under the normal package policy, loading the durable
            # verifier. Never move directly into a live importer in a request.
            return 0 if CredentialEnrollment(args.control_root, args.bootstrap_authority_sha256).state() == 'ENROLLED' else 78
        with engine_class(args.pier_root, args.uploads_root, args.control_root,
                      reserve_bytes=args.reserve_bytes, max_upload_bytes=args.max_upload_bytes,
                      max_expanded_bytes=args.max_expanded_bytes) as engine:
            server = make_server(engine, (args.bind, args.port), credential,
                                 origin=args.origin, tls_context=context)

            def stop(_signum, _frame):
                raise KeyboardInterrupt

            signal.signal(signal.SIGTERM, stop)
            sys.stderr.write('Private importer listening; no ship was automatically started.\n')
            try:
                server.serve_forever()
            except KeyboardInterrupt:
                pass
            finally:
                server.server_close()
    except (OSError, ValueError, TypeError, KeyError, ImportError):
        sys.stderr.write('Private importer refused startup or storage/lifecycle configuration; review locked state before recovery.\n')
        return 78
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
