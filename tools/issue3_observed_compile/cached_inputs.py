"""Read only exact retained public compiler archive and installed client bytes.

No Docker/API invocation, cache scan, extraction, install, or executable launch.
The historical BuildKit image is NOT an ordinary compiler execution base.
"""
import hashlib
from pathlib import Path
import tarfile
import time

from . import bind_b04 as binder
from . import prepare
from .stage import open_regular, checked_read, relative
from .supervisor import digest

ARCHIVE = Path('/tmp/issue3-source-check-01/materials/zig-x86_64-linux-0.15.2.tar.xz')
PIN = dict(bytes=53733924, sha256='02aa270f183da276e5b5920b1dac44a63f1a49e55050ebde3aecc9eb82f93239')
ROOT = 'zig-x86_64-linux-0.15.2'
CLIENT = Path('/Applications/Docker.app/Contents/Resources/bin/docker')


def compiler_inventory(archive, pin, root=ROOT, seconds=90):
    """Hash binary+whole bundled lib tree in place, with metadata/count bounds."""
    deadline = time.monotonic()+seconds
    files, total, seen = {}, 0, set()
    with open_regular(archive) as raw:
        checked_read(raw,pin,deadline)
        raw.seek(0)
        with tarfile.open(fileobj=raw,mode='r|xz') as tar:
            for count, member in enumerate(tar,1):
                prepare.require(count <= 100000 and time.monotonic() < deadline, 'compiler inventory bound')
                name = relative(member.name.rstrip('/') if member.isdir() else member.name)
                prepare.require(name.casefold() not in seen, 'duplicate compiler archive member')
                seen.add(name.casefold())
                total += member.size
                prepare.require(0 <= member.size <= 256*1024**2 and total <= 2*1024**3,
                                'compiler expanded bound')
                if name == root+'/zig' or name.startswith(root+'/lib/') and not member.isdir():
                    prepare.require(member.isfile(), 'nonregular compiler/sysroot member')
                    stream = tar.extractfile(member)
                    if stream is None:
                        raise ValueError('missing compiler member')
                    h, length = hashlib.sha256(), 0
                    with stream:
                        while True:
                            prepare.require(time.monotonic() < deadline,'compiler inventory deadline')
                            data = stream.read(1048576)
                            if not data:
                                break
                            length += len(data)
                            prepare.require(length <= member.size, 'compiler member grew')
                            h.update(data)
                    prepare.require(length == member.size, 'short compiler member')
                    files[name] = dict(bytes=length,sha256=h.hexdigest(),mode=member.mode)
        raw.seek(0)
        checked_read(raw,pin,deadline)
    prepare.require(root+'/zig' in files and any(n.startswith(root+'/lib/libc/') for n in files),
                    'compiler and bundled libc sysroot required')
    return dict(archive=dict(path=str(archive),**pin), compiler=files[root+'/zig'],
                compiler_member=root+'/zig', sysroot_prefix=root+'/lib/',
                sysroot_inventory_sha256=hashlib.sha256(binder.encoded(files)).hexdigest(),
                files=files, extracted=False, compiler_executed=False)


def inspect_cached():
    compiler = compiler_inventory(ARCHIVE,PIN)
    return dict(schema='issue3-b04-cached-inputs-v1', status='BLOCKED_NO_EXECUTION_BASE',
        compiler=compiler,
        transport=dict(path=str(CLIENT), **digest(CLIENT,128*1024**2), executed=False,
                       daemon_endpoint=None, effective_transport_verified=False),
        base=None, emulation=None, target_executed=False, final_elf_acceptance=False,
        blockers=[
          'No freshly inspected cached non-volume linux/amd64 execution image ID and member hashes '
          'for Python controller, Zig compiler+lib tree, libc loader and emulator (if required).',
          'No selected engine/context/endpoint identity or effective container/cgroup readback. '
          'No Docker/API operation is permitted in this source-only scope.',
          'Compiler+bundled sysroot are authenticated only IN the retained tar.xz; previously '
          'extracted source-check trees were retired. No new toolchain extraction is authorized.',
        ])


def main():
    print(binder.encoded(inspect_cached()).decode(),end='')


if __name__ == '__main__':
    main()
