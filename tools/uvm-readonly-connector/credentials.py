"""Dedicated session input only. Does not log in, scrape cookies or read auth.json."""
import hashlib
import os
from pathlib import Path
import re
import ssl
import stat
from connector import Refused

# Portable fail-closed template. A separately reviewed installation must bind
# its own authenticated public-root DER SHA-256 here before activation.
# No tool argument or environment override can change this trust binding.
PUBLIC_CA_SHA256 = ''


def _read(path, limit, private=False):
    parent_fd = None
    fd = None
    try:
        if type(path) is not str or not os.path.isabs(path):
            raise ValueError()
        parent, leaf = os.path.split(path)
        if not leaf or str(Path(parent).resolve()) != parent:
            raise ValueError()
        parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        info = os.fstat(parent_fd)
        if private and (info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700):
            raise ValueError()
        fd = os.open(leaf, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent_fd)
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or
                info.st_size > limit or info.st_size < 1):
            raise ValueError()
        if private and (info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600):
            raise ValueError()
        with os.fdopen(fd, 'rb') as stream:
            fd = None
            result = stream.read(limit + 1)
        if len(result) > limit:
            raise ValueError()
        return result
    except Exception:
        raise Refused('Connector local credential or trust input unavailable.') from None
    finally:
        if fd is not None:
            os.close(fd)
        if parent_fd is not None:
            os.close(parent_fd)


def read_session(path):
    raw = _read(path, 43, private=True)
    if not re.fullmatch(rb'[A-Za-z0-9_-]{43}', raw):
        raise Refused('Dedicated owner session required.')
    return raw.decode('ascii')


def load_context(path):
    try:
        pem = _read(path, 16384).decode('ascii')
        # Do not accept a CA bundle, private keys, or unpinned alternative roots.
        if (pem.count('-----BEGIN CERTIFICATE-----') != 1 or
                not re.fullmatch(r'\s*-----BEGIN CERTIFICATE-----[A-Za-z0-9+/=\s]+-----END CERTIFICATE-----\s*', pem)):
            raise ValueError()
        der = ssl.PEM_cert_to_DER_cert(pem.strip())
        if (not re.fullmatch(r'[0-9a-f]{64}', PUBLIC_CA_SHA256) or
                hashlib.sha256(der).hexdigest() != PUBLIC_CA_SHA256):
            raise ValueError()
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_verify_locations(cadata=pem)
        return context
    except Exception:
        raise Refused('Pinned public CA unavailable.') from None
