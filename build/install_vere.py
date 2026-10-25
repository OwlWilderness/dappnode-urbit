"""Install a pinned public Vere release without ever executing it."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import tarfile
import urllib.request

MAX_ARCHIVE_BYTES = 16 * 1024**2
MAX_EXECUTABLE_BYTES = 64 * 1024**2


def verify_archive(data, contract):
    if (len(data) != contract['archive_bytes'] or
            hashlib.sha256(data).hexdigest() != contract['archive_sha256']):
        raise ValueError('Official release archive checksum or size mismatch.')
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as archive:
        member = archive.next()
        if (member is None or not member.isfile() or member.name != contract['member'] or
                member.size != contract['executable_bytes'] or
                not 64 <= member.size <= MAX_EXECUTABLE_BYTES):
            raise ValueError('Official release archive member rejected.')
        source = archive.extractfile(member)
        if source is None:
            raise ValueError('Official release executable missing.')
        with source:
            executable = source.read(MAX_EXECUTABLE_BYTES + 1)
        if archive.next() is not None:
            raise ValueError('Unexpected official release archive members.')
    if (len(executable) != contract['executable_bytes'] or
            hashlib.sha256(executable).hexdigest() != contract['executable_sha256'] or
            executable[:6] != b'\x7fELF\x02\x01' or
            int.from_bytes(executable[18:20], 'little') != 62):
        raise ValueError('Official release executable checksum or architecture mismatch.')
    return executable


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument('--download', action='store_true')
    source.add_argument('--archive', type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    contract = json.loads(Path(__file__).with_name('vere-release.json').read_text())
    if not 0 < contract['archive_bytes'] <= MAX_ARCHIVE_BYTES:
        raise ValueError('Release archive budget rejected.')
    if args.download:
        # The reviewed source-controlled lock is the only network authority.
        expected = ('https://github.com/urbit/vere/releases/download/'
                    + contract['tag'] + '/linux-x86_64.tgz')
        if contract['url'] != expected or contract['architecture'] != 'linux/amd64':
            raise ValueError('Release origin or architecture rejected.')
        with urllib.request.urlopen(contract['url'], timeout=60) as response:
            if not response.geturl().startswith('https://'):
                raise ValueError('Insecure release redirect rejected.')
            data = response.read(contract['archive_bytes'] + 1)
    else:
        with args.archive.open('rb') as archive:
            data = archive.read(contract['archive_bytes'] + 1)
    executable = verify_archive(data, contract)
    # Verify everything before creating output. Never replace an existing artifact.
    fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o500)
    with os.fdopen(fd, 'wb') as output:
        output.write(executable)
        output.flush()
        os.fsync(output.fileno())
        os.fchmod(output.fileno(), 0o555)
    print('PASS: verified official stable AMD64 executable installed; not executed.')


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, tarfile.TarError):
        sys.stderr.write('Official Vere release installation refused.\n')
        raise SystemExit(78)
