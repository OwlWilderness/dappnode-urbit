#!/usr/bin/env python3
"""File-only exact-b04 plan/stage/independent readback. Never uses an engine.

A plan is an external trust anchor: retain its digest separately from the stage.
Stage is a future explicitly authorized large-copy operation, not plan's side effect.
"""
import argparse
import hashlib
import importlib.util
import importlib.abc
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
from types import SimpleNamespace
from typing import Any

ROOT = Path(__file__).absolute().parents[2]
ELF = 'build/owned-b04/urbit'
DOCKERFILE = 'build/Dockerfile.b04'
IGNORE = 'build/Dockerfile.b04.dockerignore'
RETAINED = Path('/tmp/issue3-owned-trial-20261030-b04-observed/artifact/urbit')
REPORT = 'docs/openssl-candidate-evidence/owned-b04-report-20261030.json'
DEPENDENCIES = {
    'tools/local-candidate/verify_image.py': '3d08a76912b8e76da123cf659d9ef0a647ee9dc5101ab1c7eb9ee4190dee7667',
    'scripts/inventory-public-image.py': '486525665591f4a24bb45ee2e8e86a7c969d5f3cedb614eafe4fcef64a5d4bc0',
    'scripts/verify-notice-packaging.py': '407611d01647f308bbf38fdd445036ceb1ee7db3254cdbcaec70be2c8b7dd0d0',
}
COUNTS = (409, 429, 431)
B04_BYTES = 42467624
B04_SHA256 = 'f2eba68682650ab6d9712017781612f4dbc3c01411c1ba5c7c4ecbb0f186b6b5'
REPORT_BYTES = 19480
REPORT_SHA256 = '6c8650dec16390f800ace04414c750e213055fd81950addb2465ee07e8a94d4d'
MAX_FILE = 48 * 1024**2
MAX_TOTAL = 128 * 1024**2
RESERVE = 64 * 1024**2
MAX_ENTRIES = 512
SCHEMA = 'issue3-b04-package-stage-plan-v1'


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def public(name):
    if (not isinstance(name, str) or not name or
            PurePosixPath(name).as_posix() != name or name.startswith('/') or
            any(p in ('', '.', '..') for p in name.split('/')) or
            not re.fullmatch(r'[A-Za-z0-9_./+@-]+', name)):
        raise ValueError('noncanonical public path')
    return name


def absolute(path):
    path = Path(path)
    if '..' in path.parts:
        raise ValueError('traversal in root')
    return Path(os.path.abspath(path))


def directory(path):
    """Open every ancestor without following links, including the root itself."""
    path = absolute(path)
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def fingerprint(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _consume(root, name, sink=None, retain=False):
    public(name)
    parts = name.split('/')
    fd = directory(root)
    try:
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        leaf = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
        with os.fdopen(leaf, 'rb') as stream:
            before = os.fstat(stream.fileno())
            if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or
                    not 0 <= before.st_size <= MAX_FILE or
                    stat.S_IMODE(before.st_mode) & 0o7022 or
                    not stat.S_IMODE(before.st_mode) & 0o004):
                raise ValueError('regular single-link public file size/mode required')
            digest, count, chunks = hashlib.sha256(), 0, []
            while True:
                block = stream.read(min(1024**2, before.st_size - count + 1))
                if not block:
                    break
                count += len(block)
                if count > before.st_size:
                    raise ValueError('file grew during read')
                digest.update(block)
                if sink is not None:
                    sink.write(block)
                if retain:
                    chunks.append(block)
            after = os.fstat(stream.fileno())
            linked = os.stat(parts[-1], dir_fd=fd, follow_symlinks=False)
            if (count != before.st_size or fingerprint(before) != fingerprint(after) or
                    fingerprint(before) != fingerprint(linked)):
                raise ValueError('file identity changed during read')
            seal = dict(bytes=count, mode=f'{stat.S_IMODE(before.st_mode):04o}', sha256=digest.hexdigest())
            # Reopen the entire name: detect ancestor replacement, not just leaf changes.
            check = directory(absolute(root) / Path(name).parent)
            try:
                if fingerprint(os.stat(parts[-1], dir_fd=check, follow_symlinks=False)) != fingerprint(before):
                    raise ValueError('path changed during read')
            finally:
                os.close(check)
            return seal, b''.join(chunks) if retain else None
    finally:
        os.close(fd)


def read(root, name):
    data = _consume(root, name, retain=True)[1]
    assert data is not None
    return data


def seal(root, name):
    return _consume(root, name)[0]


def _verifier(root):
    # Pin all executable dependencies before importing any of them.
    frozen = {}
    for name, digest in DEPENDENCIES.items():
        data = read(root, name)
        if sha(data) != digest:
            raise ValueError('frozen verifier/parser/noticechecker dependency drift: ' + name)
        frozen[str(absolute(root) / name)] = data
    class FrozenLoader(importlib.abc.Loader):
        def __init__(self, filename):
            self.filename = filename
        def create_module(self, spec):
            return None
        def exec_module(self, module):
            module.__file__ = self.filename
            exec(compile(frozen[self.filename], self.filename, 'exec'), module.__dict__)
    def frozen_spec(name, path):
        filename = str(absolute(path))
        if filename not in frozen:
            raise ValueError('unfrozen verifier dependency')
        return importlib.util.spec_from_loader(name, FrozenLoader(filename), origin=filename)
    name = 'tools/local-candidate/verify_image.py'
    spec = frozen_spec('b04_frozen_stage_verifier', Path(root) / name)
    assert spec is not None and spec.loader is not None
    module: Any = importlib.util.module_from_spec(spec)
    # Execute exactly the already authenticated bytes, not a subsequently reopened file.
    spec.loader.exec_module(module)
    module.ROOT = Path(root)
    module.importlib = SimpleNamespace(util=SimpleNamespace(
        spec_from_file_location=frozen_spec, module_from_spec=importlib.util.module_from_spec))
    return module


def contract(root, support, captured=None):
    verifier = _verifier(support)
    def reader(_root, name):
        data = read(support if name == REPORT else root, name)
        if captured is not None:
            identity = (len(data), sha(data))
            if name in captured and captured[name] != identity:
                raise ValueError('source mutation during contract')
            captured[name] = identity
        return data
    return verifier, verifier.build_contract(root, read_regular=reader)


def plan(source=ROOT, retained=RETAINED):
    source, retained = absolute(source), absolute(retained)
    captured = {}
    verifier, binding = contract(source, source, captured)
    names = {item['source'] for item in binding['files'].values() if item['role'] != 'elf'}
    names |= {IGNORE, DOCKERFILE, ELF}
    if (binding['notice_count'], len(binding['files']), len(names)) != COUNTS:
        raise ValueError('exact 409 notices / 429 selected / 431 context paths required')
    identity = seal(retained.parent, retained.name)
    if identity != dict(bytes=verifier.B04_BYTES, mode='0555', sha256=verifier.B04_SHA256):
        raise ValueError('retained b04 identity/mode mismatch')
    entries = {}
    for name in sorted(names):
        original = retained if name == ELF else source / name
        info = seal(original.parent, original.name)
        if name != ELF and captured.get(name) != (info['bytes'], info['sha256']):
            raise ValueError('source mutation between contract and seal')
        entries['context/' + name] = dict(source=str(original), **info)
    for name in sorted({REPORT, *DEPENDENCIES}):
        entries['support/' + name] = dict(source=str(source / name), **seal(source, name))
    result = dict(schema=SCHEMA, notice_count=COUNTS[0], selected_paths=COUNTS[1],
                  context_paths=COUNTS[2], entries=entries,
                  engine_transport=False, image_built=False, distribution_clearance=False)
    validate_plan(result)
    # A second complete read closes discovery-vs-seal mutation windows.
    for item in entries.values():
        path = Path(item['source'])
        if seal(path.parent, path.name) != {k: item[k] for k in ('bytes', 'mode', 'sha256')}:
            raise ValueError('source mutation during planning')
    return result


def validate_plan(value):
    keys = {'schema', 'notice_count', 'selected_paths', 'context_paths', 'entries',
            'engine_transport', 'image_built', 'distribution_clearance'}
    if (not isinstance(value, dict) or set(value) != keys or value['schema'] != SCHEMA or
            any(value[k] is not False for k in ('engine_transport', 'image_built', 'distribution_clearance')) or
            (value['notice_count'], value['selected_paths'], value['context_paths']) != COUNTS or
            not isinstance(value['entries'], dict) or not 1 <= len(value['entries']) <= MAX_ENTRIES):
        raise ValueError('stage plan schema/counts')
    total = 0
    for name, item in value['entries'].items():
        public(name)
        if (not name.startswith(('context/', 'support/')) or not isinstance(item, dict) or
                set(item) != {'source', 'bytes', 'mode', 'sha256'} or
                not isinstance(item['source'], str) or not Path(item['source']).is_absolute() or
                '..' in Path(item['source']).parts or type(item['bytes']) is not int or
                not 0 <= item['bytes'] <= MAX_FILE or not re.fullmatch(r'0[0-7]{3}', item['mode']) or
                int(item['mode'], 8) & 0o7022 or not int(item['mode'], 8) & 0o004 or
                not re.fullmatch(r'[0-9a-f]{64}', item['sha256'])):
            raise ValueError('invalid stage entry seal')
        total += item['bytes']
    if total > MAX_TOTAL:
        raise ValueError('aggregate stage capacity bound')
    if sum(n.startswith('context/') for n in value['entries']) != COUNTS[2]:
        raise ValueError('context count mismatch')
    if {n for n in value['entries'] if n.startswith('support/')} != {'support/' + n for n in {REPORT, *DEPENDENCIES}}:
        raise ValueError('exact excluded support required')
    entries = value['entries']
    for name, size, digest, mode in (
            ('context/' + ELF, B04_BYTES, B04_SHA256, '0555'),
            ('support/' + REPORT, REPORT_BYTES, REPORT_SHA256, None)):
        item = entries.get(name, {})
        if (item.get('bytes') != size or item.get('sha256') != digest or
                (mode is not None and item.get('mode') != mode)):
            raise ValueError('exact b04 ELF/report identity seal')
    for name, digest in DEPENDENCIES.items():
        if entries['support/' + name]['sha256'] != digest:
            raise ValueError('frozen dependency plan seal')
    origin = Path(entries['context/' + IGNORE]['source']).parents[1]
    for name, item in entries.items():
        if name != 'context/' + ELF and Path(item['source']) != origin / name.split('/', 1)[1]:
            raise ValueError('source mapping outside exact public selection')
    return total


def receipt(value):
    return canonical(dict(schema='issue3-b04-package-stage-receipt-v1',
                          plan_sha256=sha(canonical(value)), engine_transport=False,
                          image_built=False, distribution_clearance=False))


def inventory(root, allowed=None):
    """Descriptor-relative closed-world walk; no symlink traversal or special files."""
    result = {}
    def walk(fd, prefix):
        before = os.fstat(fd)
        for name in sorted(os.listdir(fd)):
            path = public(prefix + name)
            if ((allowed is not None and path not in allowed) or len(result) >= 4096 or
                    path.count('/') > 32):
                raise ValueError('closed-world unexpected entry or traversal bound')
            info = os.stat(name, dir_fd=fd, follow_symlinks=False)
            if stat.S_ISDIR(info.st_mode):
                if stat.S_IMODE(info.st_mode) != 0o755:
                    raise ValueError('stage directory mode')
                result[path] = 'directory'
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                try:
                    if (info.st_dev, info.st_ino) != (os.fstat(child).st_dev, os.fstat(child).st_ino):
                        raise ValueError('directory identity race')
                    walk(child, path + '/')
                finally:
                    os.close(child)
            elif stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
                result[path] = 'file'
            else:
                raise ValueError('stage link or special entry')
        if fingerprint(before) != fingerprint(os.fstat(fd)):
            raise ValueError('directory changed during walk')
    fd = directory(root)
    try:
        if stat.S_IMODE(os.fstat(fd).st_mode) != 0o755:
            raise ValueError('stage root mode')
        walk(fd, '')
    finally:
        os.close(fd)
    return result


def directory_token(path):
    fd = directory(path)
    try:
        info = os.fstat(fd)
        return info.st_dev, info.st_ino
    finally:
        os.close(fd)


def verify(value, output):
    """Independent readback: original source tree and retained ELF are not needed."""
    validate_plan(value)
    output = absolute(output)
    token = directory_token(output)
    expected = {name: 'file' for name in value['entries']}
    expected['receipt.json'] = 'file'
    for name in list(expected):
        for parent in PurePosixPath(name).parents:
            if str(parent) != '.':
                expected[str(parent)] = 'directory'
    if inventory(output, expected) != expected:
        raise ValueError('closed-world stage entry mismatch')
    if read(output, 'receipt.json') != receipt(value) or seal(output, 'receipt.json')['mode'] != '0444':
        raise ValueError('stage receipt altered')
    for name, item in value['entries'].items():
        if seal(output, name) != {k: item[k] for k in ('bytes', 'mode', 'sha256')}:
            raise ValueError('stage file seal mismatch: ' + name)
    verifier, binding = contract(output / 'context', output / 'support')
    selected = {x['source'] for x in binding['files'].values() if x['role'] != 'elf'}
    selected |= {IGNORE, DOCKERFILE, ELF}
    if (binding['notice_count'], len(binding['files']), len(selected)) != COUNTS or selected != {
            n.removeprefix('context/') for n in value['entries'] if n.startswith('context/')}:
        raise ValueError('readback contract allowlist mismatch')
    verifier.validate_context(output / 'context')
    # Re-read after independent semantic validation, including the report and dependencies.
    for name, item in value['entries'].items():
        if seal(output, name) != {k: item[k] for k in ('bytes', 'mode', 'sha256')}:
            raise ValueError('mutation during readback')
    if (inventory(output, expected) != expected or read(output, 'receipt.json') != receipt(value) or
            directory_token(output) != token):
        raise ValueError('stage changed during readback')
    return dict(status='EXACT_B04_FILE_STAGE_VERIFIED_IMAGE_UNBUILT',
                plan_sha256=sha(canonical(value)), notice_count=COUNTS[0],
                selected_paths=COUNTS[1], context_paths=COUNTS[2],
                engine_transport=False, image_built=False, distribution_clearance=False)


def stage(value, output, reserve=RESERVE):
    """Fresh output only. Failed stages remain for inspection; never resume/clean."""
    total = validate_plan(value)
    if type(reserve) is not int or reserve < 0:
        raise ValueError('capacity reserve')
    output = absolute(output)
    parent = directory(output.parent)
    try:
        # Check capacity before creating anything. This is host admission, not an OS quota.
        if shutil.disk_usage(output.parent).free < total + reserve + 1024**2:
            raise ValueError('insufficient host stage capacity')
        for item in value['entries'].values():
            src = absolute(item['source'])
            if output == src or output in src.parents:
                raise ValueError('output overlaps input')
            if seal(src.parent, src.name) != {k: item[k] for k in ('bytes', 'mode', 'sha256')}:
                raise ValueError('source seal drift before stage')
        os.mkdir(output.name, mode=0o755, dir_fd=parent)
        created = os.open(output.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        try:
            os.fchmod(created, 0o755)
            info = os.fstat(created)
            token = info.st_dev, info.st_ino
        finally:
            os.close(created)
    finally:
        os.close(parent)
    # All writes use no-follow directory descriptors. Never replace existing leaves.
    for name, item in value['entries'].items():
        fd = directory(output)
        try:
            info = os.fstat(fd)
            if (info.st_dev, info.st_ino) != token:
                raise ValueError('stage output identity changed')
            parts = name.split('/')
            for part in parts[:-1]:
                try:
                    os.mkdir(part, mode=0o755, dir_fd=fd)
                except FileExistsError:
                    pass
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.fchmod(child, 0o755)
                os.close(fd)
                fd = child
            leaf = os.open(parts[-1], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                           0o600, dir_fd=fd)
            with os.fdopen(leaf, 'wb') as stream:
                src = Path(item['source'])
                actual, _ = _consume(src.parent, src.name, sink=stream)
                if actual != {k: item[k] for k in ('bytes', 'mode', 'sha256')}:
                    raise ValueError('source mutation during copy')
                stream.flush()
                os.fchmod(stream.fileno(), int(item['mode'], 8))
                os.fsync(stream.fileno())
        finally:
            os.close(fd)
    # Source readback again before sealing completion; no success receipt on drift.
    for item in value['entries'].values():
        src = Path(item['source'])
        if seal(src.parent, src.name) != {k: item[k] for k in ('bytes', 'mode', 'sha256')}:
            raise ValueError('source mutation after copy')
    fd = directory(output)
    try:
        info = os.fstat(fd)
        if (info.st_dev, info.st_ino) != token:
            raise ValueError('stage output identity changed')
        leaf = os.open('receipt.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
        with os.fdopen(leaf, 'wb') as stream:
            stream.write(receipt(value))
            stream.flush()
            os.fchmod(stream.fileno(), 0o444)
            os.fsync(stream.fileno())
    finally:
        os.close(fd)
    result = verify(value, output)
    if directory_token(output) != token:
        raise ValueError('stage output identity changed after readback')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('plan', 'stage', 'verify'))
    parser.add_argument('--source', type=Path, default=ROOT)
    parser.add_argument('--elf', type=Path, default=RETAINED)
    parser.add_argument('--plan', type=Path)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    if args.action == 'plan':
        result = plan(args.source, args.elf)
    else:
        if args.plan is None or args.output is None:
            parser.error('stage/verify require --plan and --output')
        value = json.loads(read(absolute(args.plan).parent, args.plan.name))
        result = stage(value, args.output) if args.action == 'stage' else verify(value, args.output)
    print(canonical(result).decode(), end='')


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, TypeError, KeyError) as error:
        raise SystemExit('B04_PACKAGE_STAGE_REFUSED: ' + str(error))
