"""Initial owner-signed TLS provisioning. No CA private key or listener.

The CA DER SHA256 pin is trusted management configuration, never upload data.
Public exchange: owner-tls-public/{request.pem,root-ca.pem,server.pem}.
A READY identity is immutable; renewal/recovery is deliberately not implemented.
"""
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import re
import fcntl
import json
import stat
from datetime import datetime, timezone

from importer import private_root, rename_without_replace, ImportError as StorageError

_LABEL = re.compile(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?')
_CERT = re.compile(rb'-----BEGIN CERTIFICATE-----\r?\n[A-Za-z0-9+/=\r\n]+-----END CERTIFICATE-----\s*')
_LIMIT = 65536
_MONTHS: tuple[str, ...] = tuple('Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec'.split())


def _openssl(*args, data=None):
    executable = next((p for p in ('/opt/homebrew/opt/openssl@3/bin/openssl',
                                  '/usr/local/opt/openssl@3/bin/openssl',
                                  shutil.which('openssl')) if p and Path(p).is_file()), None)
    env = {k: v for k, v in os.environ.items()
           if not k.startswith(('OPENSSL_', 'SSL_CERT_', 'SSLKEYLOG'))}
    env.update(OPENSSL_CONF='/dev/null', LC_ALL='C')
    try:
        if executable is None:
            raise ValueError('OpenSSL 3 is required.')
        result = subprocess.run([executable, *map(str, args)], env=env,
                                input=data, stdin=subprocess.DEVNULL if data is None else None, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, timeout=30, check=True)
        return result.stdout
    except (OSError, subprocess.SubprocessError, TypeError):
        raise ValueError('Owner TLS operation refused.') from None


def _validate(directory, key, names, pin):
    ca, leaf = directory / 'root-ca.pem', directory / 'server.pem'
    common = ('-x509_strict', '-auth_level', '2', '-check_ss_sig', '-no-CApath', '-no-CAstore', '-CAfile', ca)
    if ca.exists():
        if hashlib.sha256(_openssl('x509', '-in', ca, '-outform', 'DER')).hexdigest() != pin:
            raise ValueError('Owner TLS CA pin mismatch.')
        root_bc = _openssl('x509', '-in', ca, '-noout', '-ext', 'basicConstraints')
        if b'CA:TRUE' not in root_bc:
            raise ValueError('Owner TLS root CA constraints refused.')
        subject = _openssl('x509', '-in', ca, '-noout', '-subject', '-nameopt', 'RFC2253').split(b'=', 1)[1]
        issuer = _openssl('x509', '-in', ca, '-noout', '-issuer', '-nameopt', 'RFC2253').split(b'=', 1)[1]
        if subject != issuer:
            raise ValueError('Owner TLS requires a self-signed root.')
        _openssl('verify', *common, ca)
    if not leaf.exists():
        return
    if ca.exists():
        for name in names:
            _openssl('verify', *common, '-purpose', 'sslserver', '-verify_depth', '0', '-verify_hostname', name, leaf)
    leaf_bc = _openssl('x509', '-in', leaf, '-noout', '-ext', 'basicConstraints')
    if b'CA:FALSE' not in leaf_bc or b'CA:TRUE' in leaf_bc:
        raise ValueError('Owner TLS leaf constraints refused.')
    # Validate standalone leaf validity too: incomplete uploads must not mask
    # locally detectable invalid input. Full chain verification remains required.
    dates = _openssl('x509', '-in', leaf, '-noout', '-dates').decode('ascii').splitlines()
    bounds = []
    for line in dates:
        month, day, clock, year, zone = line.split('=', 1)[1].split()
        if zone != 'GMT':
            raise ValueError('Owner TLS validity format refused.')
        bounds.append(datetime(int(year), _MONTHS.index(month) + 1,
                               int(day), *map(int, clock.split(':')), tzinfo=timezone.utc))
    if len(bounds) != 2 or not bounds[0] <= datetime.now(timezone.utc) < bounds[1]:
        raise ValueError('Owner TLS leaf validity refused.')
    san = _openssl('x509', '-in', leaf, '-noout', '-ext', 'subjectAltName').decode('ascii')
    entries = [x.strip() for x in ''.join(san.splitlines()[1:]).split(',')]
    if sorted(entries) != sorted('DNS:' + n for n in names):
        raise ValueError('Owner TLS SAN set mismatch.')
    eku = _openssl('x509', '-in', leaf, '-noout', '-ext', 'extendedKeyUsage')
    if b'TLS Web Server Authentication' not in eku:
        raise ValueError('Owner TLS server purpose is required.')
    if _openssl('x509', '-in', leaf, '-pubkey', '-noout') != _openssl('pkey', '-in', key, '-pubout'):
        raise ValueError('Owner TLS key mismatch.')


def _directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    info = os.fstat(fd)
    if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
        os.close(fd)
        raise ValueError('Owner TLS directory is unsafe.')
    return fd


def _read(path, mode=None, public=False):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as source:
        info = os.fstat(source.fileno())
        owners = {0, os.geteuid()} if public else {os.geteuid()}
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or
                info.st_uid not in owners or info.st_size > _LIMIT or
                stat.S_IMODE(info.st_mode) & 0o022 or
                (mode is not None and stat.S_IMODE(info.st_mode) != mode)):
            raise ValueError('Owner TLS file is unsafe.')
        data = source.read(_LIMIT + 1)
        if len(data) > _LIMIT or len(data) != info.st_size:
            raise ValueError('Owner TLS file changed or exceeds limits.')
        return data


def _write(path, data, mode):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as output:
        output.write(data)
        output.flush()
        os.fchmod(output.fileno(), mode)
        os.fsync(output.fileno())


def _sync(path):
    fd = _directory(path)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _commit(parent, source, target):
    fd = _directory(parent)
    try:
        rename_without_replace(fd, source, fd, target)
        os.fsync(fd)
    finally:
        os.close(fd)


def _certificate(data):
    if not _CERT.fullmatch(data):
        raise ValueError('Exactly one public PEM certificate is required.')
    return _openssl('x509', '-inform', 'PEM', '-outform', 'DER', data=data)


def _ensure(root, names, pin):
    identity, public = root / 'owner-tls', root / 'owner-tls-public'
    settings = json.dumps({'names': list(names), 'ca_sha256': pin}, sort_keys=True).encode() + b'\n'
    if '.owner-tls-init' in os.listdir(root):
        raise ValueError('Incomplete owner TLS creation requires owner recovery.')
    if 'owner-tls' not in os.listdir(root):
        if 'owner-tls-public' in os.listdir(root):
            raise ValueError('Conflicting owner TLS exchange requires owner recovery.')
        stage = root / '.owner-tls-init'
        stage.mkdir(mode=0o700)
        # The enclosing 0700 directory protects all creation, even with a broad umask.
        _openssl('req', '-new', '-newkey', 'rsa:2048', '-nodes', '-subj', '/CN=Urbit package service',
                 '-addext', 'subjectAltName=' + ','.join('DNS:' + n for n in names),
                 '-keyout', stage / 'server.key', '-out', stage / 'request.pem')
        (stage / 'server.key').chmod(0o600)
        (stage / 'request.pem').chmod(0o444)
        for filename in ('server.key', 'request.pem'):
            fd = os.open(stage / filename, os.O_RDONLY | os.O_NOFOLLOW)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
        _write(stage / 'settings.json', settings, 0o444)
        _sync(stage)
        _commit(root, stage.name, identity.name)
        public.mkdir(mode=0o700)
        _write(public / 'request.pem', _read(identity / 'request.pem', 0o444), 0o444)
        _sync(public)
        _sync(root)
    for directory in (identity, public):
        fd = _directory(directory)
        os.close(fd)
    contents = set(os.listdir(identity))
    if not contents <= {'settings.json', 'server.key', 'request.pem', 'validated', 'activation.json'}:
        raise ValueError('Incomplete or unexpected owner TLS private state.')
    if ('activation.json' in contents) != ('validated' in contents):
        raise ValueError('Incomplete owner TLS activation requires owner recovery.')
    if not set(os.listdir(public)) <= {'request.pem', 'root-ca.pem', 'server.pem'}:
        raise ValueError('Unexpected owner TLS exchange file; private keys are forbidden.')
    if _read(identity / 'settings.json', 0o444) != settings:
        raise ValueError('Owner TLS identity settings changed.')
    _read(identity / 'server.key', 0o600)
    request = _read(identity / 'request.pem', 0o444)
    if _read(public / 'request.pem', 0o444) != request:
        raise ValueError('Owner TLS request changed.')
    _openssl('req', '-in', identity / 'request.pem', '-verify', '-noout')
    if _openssl('req', '-in', identity / 'request.pem', '-pubkey', '-noout') != _openssl('pkey', '-in', identity / 'server.key', '-pubout'):
        raise ValueError('Owner TLS request key mismatch.')
    uploads = {}
    for filename in ('root-ca.pem', 'server.pem'):
        try:
            data = _read(public / filename, public=True)
        except FileNotFoundError:
            continue
        der = _certificate(data)
        if filename == 'root-ca.pem' and hashlib.sha256(der).hexdigest() != pin:
            raise ValueError('Owner TLS CA pin mismatch.')
        uploads[filename] = data
    result = dict(state='AWAITING_CERTIFICATE', request=str(public / 'request.pem'),
                  key=str(identity / 'server.key'), certificate=None, ca=None)
    if 'validated' not in os.listdir(identity):
        if not uploads:
            return result
        stage = identity / '.validate'
        stage.mkdir(mode=0o700)
        try:
            for filename, data in uploads.items():
                _write(stage / filename, data, 0o444)
            _validate(stage, identity / 'server.key', names, pin)
        except ValueError:
            # Only this invocation's public validation copies; never private key/state.
            for filename in uploads:
                (stage / filename).unlink()
            stage.rmdir()
            raise
        if len(uploads) != 2:
            for filename in uploads:
                (stage / filename).unlink()
            stage.rmdir()
            return result
        manifest = json.dumps({n: hashlib.sha256(d).hexdigest() for n, d in uploads.items()}, sort_keys=True).encode()
        _write(stage / 'manifest.json', manifest, 0o444)
        _sync(stage)
        # Journal before publication: a deleted/uncertain snapshot cannot silently
        # return an activated identity to initial enrollment.
        _write(identity / 'activation.json', manifest, 0o444)
        _sync(identity)
        _commit(identity, stage.name, 'validated')
    validated = identity / 'validated'
    fd = _directory(validated)
    os.close(fd)
    if set(os.listdir(validated)) != {'server.pem', 'root-ca.pem', 'manifest.json'}:
        raise ValueError('Incomplete owner TLS certificate snapshot.')
    snapshot = {n: _read(validated / n, 0o444) for n in ('server.pem', 'root-ca.pem')}
    expected_manifest = json.dumps({n: hashlib.sha256(d).hexdigest() for n, d in snapshot.items()}, sort_keys=True).encode()
    if (_read(validated / 'manifest.json', 0o444) != expected_manifest or
            _read(identity / 'activation.json', 0o444) != expected_manifest):
        raise ValueError('Owner TLS snapshot changed.')
    for filename, data in snapshot.items():
        _certificate(data)
        if filename in uploads and uploads[filename] != data:
            raise ValueError('Owner TLS upload replacement is not supported.')
    _validate(validated, identity / 'server.key', names, pin)
    result.update(state='READY', certificate=str(validated / 'server.pem'), ca=str(validated / 'root-ca.pem'))
    return result


def ensure_owner_tls(control_root, names, ca_sha256):
    """Create a CSR once, await owner uploads, or return revalidated READY paths.

    Names are ordered (administration, ship) and immutable. A trusted management
    caller must supply the lowercase root DER SHA256 fingerprint. Missing uploads
    do not start TLS; corrupt/partial private state requires explicit recovery.
    Files uploaded by root are accepted without chown or private-key relaxation.
    """
    if (not isinstance(names, (tuple, list)) or len(names) != 2 or
            any(not isinstance(n, str) or len(n) > 253 or '.' not in n or
                not all(_LABEL.fullmatch(p) for p in n.split('.')) or
                all(p.isdigit() for p in n.split('.')) for n in names) or names[0] == names[1] or
            not isinstance(ca_sha256, str) or not re.fullmatch('[0-9a-f]{64}', ca_sha256)):
        raise ValueError('Two distinct canonical DNS names and a lowercase CA SHA256 pin are required.')
    if not _openssl('version').startswith(b'OpenSSL 3.'):
        raise ValueError('Owner TLS requires OpenSSL 3.')
    root = Path(control_root).absolute()
    if '..' in root.parts:
        raise ValueError('Owner TLS control path must not contain parent traversal.')
    fd = lock = None
    try:
        fd = private_root(root)
        flags = os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK
        try:
            lock = os.open('.owner-tls.lock', flags | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=fd)
        except FileExistsError:
            lock = os.open('.owner-tls.lock', flags, dir_fd=fd)
        info = os.fstat(lock)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.geteuid() or
                stat.S_IMODE(info.st_mode) != 0o600):
            raise ValueError('Owner TLS lock is unsafe.')
        fcntl.flock(lock, fcntl.LOCK_EX)
        return _ensure(root, names, ca_sha256)
    except (OSError, StorageError, UnicodeError):
        raise ValueError('Owner TLS storage or validation refused; owner recovery may be required.') from None
    finally:
        if lock is not None:
            os.close(lock)
        if fd is not None:
            os.close(fd)
