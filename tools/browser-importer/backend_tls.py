"""Service-owned backend TLS identity for a separately trusted private proxy.

Only the public CA certificate may be transferred to the proxy. No owner
credential, Urbit key, pier file, or frontend portal key is used here.
"""
import fcntl
import os
from pathlib import Path
import re
import secrets
import ssl
import stat
import subprocess
import sys
import uuid

sys.path.insert(0, str(Path(__file__).parent))
from importer import private_root

_LABEL = re.compile(r'^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$')
_FILES = {'backend-ca.pem': 0o444, 'backend.pem': 0o444,
          'backend.key': 0o600, 'hostname': 0o444}


def _openssl(*args):
    try:
        subprocess.run(['openssl', *map(str, args)], check=True,
                       stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, timeout=30)
    except (OSError, subprocess.SubprocessError):
        raise ValueError('Backend TLS identity validation or creation was refused.') from None


def _verify(directory, name):
    directory = Path(directory)
    if set(os.listdir(directory)) != set(_FILES):
        raise ValueError('Backend TLS identity has unexpected files.')
    for filename, mode in _FILES.items():
        info = os.lstat(directory / filename)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != mode:
            raise ValueError('Backend TLS identity ownership or permissions are unsafe.')
    if (directory / 'hostname').read_text() != name + '\n':
        raise ValueError('Backend TLS identity hostname changed.')
    ca, leaf, key = (directory / filename for filename in ('backend-ca.pem', 'backend.pem', 'backend.key'))
    _openssl('verify', '-x509_strict', '-purpose', 'sslserver',
             '-verify_hostname', name, '-CAfile', ca, leaf)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(str(leaf), str(key))
    return ca, leaf, key


def ensure_backend_tls(control_root, name):
    """Create once on the private volume, then reuse without silent rotation.

    A failed/partial creation leaves a private stage and refuses subsequent
    startup rather than replacing an identity the proxy might already trust.
    """
    if (not isinstance(name, str) or len(name) > 253 or
            not all(_LABEL.fullmatch(part) for part in name.split('.'))):
        raise ValueError('An exact canonical backend DNS name is required.')
    root = Path(control_root)
    fd = private_root(root)
    lock_fd = None
    try:
        lock_fd = os.open('.backend-tls.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW,
                          0o600, dir_fd=fd)
        info = os.fstat(lock_fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600:
            raise ValueError('Backend TLS lock is unsafe.')
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        names = set(os.listdir(fd))
        if any(n.startswith('.backend-tls-stage-') for n in names):
            raise ValueError('Uncertain backend TLS creation requires owner recovery.')
        final = root / 'backend-tls'
        if 'backend-tls' in names:
            info = os.lstat(final)
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
                raise ValueError('Backend TLS directory is unsafe.')
            return _verify(final, name)
        stage_name = '.backend-tls-stage-' + uuid.uuid4().hex
        os.mkdir(stage_name, 0o700, dir_fd=fd)
        stage = root / stage_name
        previous_umask = os.umask(0o077)
        try:
            ca_config = stage / 'ca.cnf'
            ca_config.write_text('[req]\ndistinguished_name=dn\nx509_extensions=ca\n[dn]\n[ca]\n'
                                 'basicConstraints=critical,CA:TRUE,pathlen:0\n'
                                 'keyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\n')
            _openssl('req', '-config', ca_config, '-x509', '-newkey', 'rsa:2048', '-nodes',
                     '-days', '365', '-subj', '/CN=Private importer backend CA',
                     '-keyout', stage / 'ca.key', '-out', stage / 'backend-ca.pem')
            _openssl('req', '-new', '-newkey', 'rsa:2048', '-nodes', '-subj', '/CN=' + name,
                     '-keyout', stage / 'backend.key', '-out', stage / 'backend.csr')
            extensions = stage / 'leaf.ext'
            extensions.write_text('basicConstraints=critical,CA:FALSE\n'
                                  'keyUsage=critical,digitalSignature,keyEncipherment\n'
                                  'subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n'
                                  'extendedKeyUsage=serverAuth\nsubjectAltName=DNS:' + name + '\n')
            _openssl('x509', '-req', '-in', stage / 'backend.csr', '-CA', stage / 'backend-ca.pem',
                     '-CAkey', stage / 'ca.key', '-set_serial', '0x' + secrets.token_hex(16), '-days', '365',
                     '-extfile', extensions, '-out', stage / 'backend.pem')
            (stage / 'hostname').write_text(name + '\n')
            for temporary in ('ca.key', 'backend.csr', 'ca.cnf', 'leaf.ext'):
                (stage / temporary).unlink()
            for filename, mode in _FILES.items():
                os.chmod(stage / filename, mode)
                with open(stage / filename, 'rb') as source:
                    os.fsync(source.fileno())
            stage_fd = os.open(stage_name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            try: os.fsync(stage_fd)
            finally: os.close(stage_fd)
            _verify(stage, name)
            if 'backend-tls' in os.listdir(fd):
                raise ValueError('Backend TLS identity already exists.')
            os.rename(stage_name, 'backend-tls', src_dir_fd=fd, dst_dir_fd=fd)
            os.fsync(fd)
            return _verify(final, name)
        finally:
            os.umask(previous_umask)
    finally:
        if lock_fd is not None:
            os.close(lock_fd)
        os.close(fd)
