"""Verify explicitly selected public notices; never invoke Docker or write files.

--image-root is an already prepared PUBLIC image filesystem, not a container
volume or owner state. Source-only success is not copied-image acceptance.
"""
import argparse
import hashlib
import json
import re
import stat
from pathlib import Path, PurePosixPath

BEGIN = '# BEGIN UVM PUBLIC NOTICE FILES\n'
END = '# END UVM PUBLIC NOTICE FILES\n'
MANIFEST = 'build/notice-files.json'
DESTINATION = '/usr/share/doc/uvm'


def public_path(name):
    if (not isinstance(name, str) or not name or
            name != PurePosixPath(name).as_posix() or
            PurePosixPath(name).is_absolute() or
            any(part in ('.', '..') for part in name.split('/')) or
            not re.fullmatch(r'[A-Za-z0-9_./+@-]+', name)):
        raise ValueError('Invalid public notice path')
    return name


def read_regular(root, name):
    root = Path(root).absolute()
    for ancestor in [*reversed(root.parents), root]:
        mode = ancestor.lstat().st_mode
        if stat.S_ISLNK(mode):
            raise ValueError('Refusing symlink notice root or ancestor')
        if not stat.S_ISDIR(mode):
            raise ValueError('Notice root ancestor is not a directory')
    path = root
    for part in PurePosixPath(public_path(name)).parts:
        path = path / part
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode):
            raise ValueError('Refusing symlink notice path')
        if path != root / name and not stat.S_ISDIR(info.st_mode):
            raise ValueError('Notice ancestor is not a directory')
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise ValueError('Notice must be a regular single-link file')
    # The prepared, exact Vere source archive is approximately 5 MiB. Bound
    # individual public inputs without excluding this actual delivery material.
    if info.st_size > 8 * 1024 * 1024:
        raise ValueError('Notice file exceeds size bound')
    return path.read_bytes()


def context_block(files):
    paths = sorted({public_path(name) for name in files} | {MANIFEST})
    parents = {parent.as_posix() for name in paths
               for parent in PurePosixPath(name).parents if parent.as_posix() != '.'}
    lines = []
    # The existing application context already opens build/ and excludes its
    # children. Repeating build/** here would erase its earlier file exceptions.
    for parent in sorted(parents - {'build'}, key=lambda value: (value.count('/'), value)):
        lines.extend([f'!{parent}/', f'{parent}/**'])
    lines.extend(f'!{name}' for name in paths)
    return BEGIN + '\n'.join(lines) + '\n' + END


def verify(root, image_root=None):
    root = Path(root).absolute()
    raw = read_regular(root, MANIFEST)
    manifest = json.loads(raw)
    if (set(manifest) != {'schema_version', 'destination', 'files'} or
            manifest['schema_version'] != 1 or
            manifest['destination'] != DESTINATION or
            not isinstance(manifest['files'], dict) or
            not 1 <= len(manifest['files']) <= 2000):
        raise ValueError('Invalid notice manifest')
    files = manifest['files']
    for name, digest in files.items():
        public_path(name)
        if not isinstance(digest, str) or not re.fullmatch(r'[0-9a-f]{64}', digest):
            raise ValueError('Invalid notice digest')
        if hashlib.sha256(read_regular(root, name)).hexdigest() != digest:
            raise ValueError(f'Notice digest mismatch: {name}')
    ignore = read_regular(root, '.dockerignore').decode()
    if ignore.count(BEGIN) != 1 or ignore.count(END) != 1:
        raise ValueError('Missing unique notice context block')
    if not ignore.startswith('**\n') or not ignore.endswith(END):
        raise ValueError('Notice context must retain default exclusion and end with its fixed block')
    before = ignore[:ignore.index(BEGIN)]
    if any(line.startswith('!') and ('*' in line or '?' in line or '[' in line or
           line[1:].startswith(('THIRD_PARTY', 'LICENSE', 'docs/')))
           for line in before.splitlines()):
        raise ValueError('Unreviewed notice context exception outside fixed block')
    block = ignore[ignore.index(BEGIN):ignore.index(END) + len(END)]
    if block != context_block(files):
        raise ValueError('Notice context allowlist differs from manifest')
    copied = 0
    if image_root is not None:
        image_root = Path(image_root).absolute()
        prefix = DESTINATION.lstrip('/')
        for name, digest in files.items():
            if hashlib.sha256(read_regular(image_root, f'{prefix}/{name}')).hexdigest() != digest:
                raise ValueError(f'Copied notice digest mismatch: {name}')
            copied += 1
        if read_regular(image_root, f'{prefix}/notice-files.json') != raw:
            raise ValueError('Copied notice manifest differs from source')
    return {'status': 'PUBLIC_IMAGE_NOTICE_BYTES_VERIFIED' if image_root is not None
            else 'SOURCE_NOTICE_INPUTS_VERIFIED_IMAGE_UNBUILT',
            'files_verified': len(files), 'image_files_verified': copied,
            'manifest_sha256': hashlib.sha256(raw).hexdigest(),
            'runtime_tested': False, 'distribution_clearance': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument('--image-root', type=Path)
    parser.add_argument('--print-context-block', action='store_true')
    args = parser.parse_args()
    if args.print_context_block:
        manifest = json.loads(read_regular(args.root, MANIFEST))
        print(context_block(manifest['files']), end='')
    else:
        print(json.dumps(verify(args.root, args.image_root), sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, TypeError, KeyError) as error:
        raise SystemExit(f'NOTICE_VERIFICATION_REFUSED: {error}')
