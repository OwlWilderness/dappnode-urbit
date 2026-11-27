"""Bounded allowlist staging. Import/plan never stages or launches processes.

stage_public is the authenticated boundary. stage_selection is intentionally an
unauthenticated fixture/mechanism API. No tar extract/extractall, shell or cleanup.
A failed fresh attempt is retained permanently and may not be resumed/replayed.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tarfile
import time

from . import wire as binder
from . import prepare


def relative(name):
    prepare.require(type(name) is str and re.fullmatch(r'[A-Za-z0-9_./+-]{1,512}', name)
                    and not name.startswith('/') and
                    all(p not in ('', '.', '..') for p in name.split('/')), 'noncanonical path')
    return name


def archive_name(member):
    name = member.name[:-1] if member.isdir() and member.name.endswith('/') else member.name
    prepare.require(type(name) is str and 0 < len(name) <= 1024 and
                    all(32 <= ord(c) <= 126 for c in name) and '\\' not in name and
                    ':' not in name and not name.startswith('/') and
                    all(p not in ('','.','..') for p in name.split('/')), 'noncanonical archive path')
    return name


def open_regular(path):
    """Walk every component using dirfds/O_NOFOLLOW, including parent directories."""
    path = Path(path)
    prepare.require(path.is_absolute(), 'absolute input path')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parts[1:-1]:
            relative(part)
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        result = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
        info = os.fstat(result)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            os.close(result)
            raise ValueError('regular single-link input required')
        return os.fdopen(result, 'rb')
    finally:
        os.close(fd)


def checked_read(stream, pin, deadline, sink=None):
    prepare.require(type(pin) is dict and type(pin.get('bytes')) is int and
                    0 <= pin['bytes'] <= 256 * 1024**2 and
                    re.fullmatch('[0-9a-f]{64}', pin.get('sha256', '')) is not None, 'size/hash pin')
    h, size = hashlib.sha256(), 0
    while True:
        prepare.require(time.monotonic() < deadline, 'staging deadline')
        data = stream.read(min(1048576, pin['bytes'] - size + 1))
        if not data:
            break
        size += len(data)
        prepare.require(size <= pin['bytes'], 'input exceeded declared size')
        h.update(data)
        if sink is not None:
            sink.write(data)
    prepare.require(dict(bytes=size, sha256=h.hexdigest()) == pin, 'input hash/size drift')
    return pin


def save_new(path, data):
    with path.open('xb') as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    fd = os.open(path.parent,os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def stage_selection(attempt, archive, archive_pin, files, origins, retained_root,
                    generated, seconds=90):
    """Stage an explicit already-selected allowlist; NOT provenance authentication.

    New owned 0700 directory required; ancestors must be canonical, privately
    controlled. Readonly modes deter accidents, not hostile same-UID writers.
    No real library copying occurs until this function is explicitly invoked.
    """
    attempt, retained_root = Path(attempt), Path(retained_root)
    prepare.require(attempt.is_absolute() and attempt.parent == attempt.parent.resolve(),
                    'canonical owned parent')
    prepare.require(type(seconds) in (int, float) and 0 < seconds <= 90, 'staging time bound')
    prepare.require(type(files) is list and 0 < len(files) <= prepare.MAX_FILES, 'selection count')
    names, total = set(), 0
    for row in files:
        name = relative(row['path'])
        prepare.require(name.casefold() not in names, 'duplicate portable destination')
        names.add(name.casefold())
        prepare.require(type(row['bytes']) is int and 0 < row['bytes'] <= prepare.MAX_FILE,
                        'selected file bound')
        total += row['bytes']
    prepare.require(total <= prepare.MAX_TOTAL and set(origins) == {r['path'] for r in files},
                    'selection bytes/origins')
    deadline = time.monotonic() + seconds
    attempt.mkdir(mode=0o700)  # Exclusive attempt; preserve any historical/partial tree.
    save_new(attempt/'intent.json', binder.encoded(dict(files=files, origins=origins,
        archive=dict(path=str(archive), **archive_pin), target_executed=False)))
    root = attempt/'inputs'
    root.mkdir(mode=0o700)
    try:
        selected = {}
        for row in files:
            origin = origins[row['path']]
            if origin['kind'] == 'archive-member':
                key = relative(origin['path'])
                prepare.require(key not in selected, 'duplicate selected archive origin')
                selected[key] = row
        selected_folded = {k.casefold() for k in selected}
        written = set()

        def put(row, stream):
            name = row['path']
            prepare.require(name not in written, 'duplicate output')
            dest = root/name
            dest.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            with dest.open('xb') as out:
                checked_read(stream, {k: row[k] for k in ('bytes', 'sha256')}, deadline, out)
                out.flush()
                os.fsync(out.fileno())
            dest.chmod(0o444)
            written.add(name)

        with open_regular(archive) as raw:
            before = os.fstat(raw.fileno())
            checked_read(raw, archive_pin, deadline)
            raw.seek(0)
            seen, expanded = set(), 0
            with tarfile.open(fileobj=raw, mode='r|gz') as tar:
                for count, member in enumerate(tar, 1):
                    prepare.require(time.monotonic() < deadline and count <= 100000,
                                    'archive count/deadline')
                    expanded += member.size
                    prepare.require(0 <= member.size and expanded <= 4 * 1024**3, 'archive expanded bound')
                    # Directory trailing slash is tar syntax only, never normalized for files.
                    name = archive_name(member)
                    prepare.require(name.casefold() not in seen, 'duplicate portable archive member')
                    seen.add(name.casefold())
                    if name not in selected:
                        # Reject aliases that could impersonate a selected identity.
                        prepare.require(name.casefold() not in selected_folded,
                                        'portable selected alias')
                        continue
                    row = selected[name]
                    prepare.require(member.isfile() and member.size == row['bytes'],
                                    'selected member type/size')
                    stream = tar.extractfile(member)
                    if stream is None:
                        raise ValueError('unreadable member')
                    with stream:
                        put(row, stream)
            raw.seek(0)
            checked_read(raw, archive_pin, deadline)
            after = os.fstat(raw.fileno())
            prepare.require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) ==
                            (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns), 'archive changed')
        for row in files:
            origin = origins[row['path']]
            if origin['kind'] == 'retained-file':
                relative(origin['path'])
                with open_regular(retained_root/origin['path']) as stream:
                    put(row, stream)
            elif origin['kind'] == 'canonical-generated-json':
                import io
                with io.BytesIO(generated[row['path']]) as stream:
                    put(row, stream)
            else:
                prepare.require(origin['kind'] == 'archive-member', 'unknown origin kind')
        prepare.require(written == {r['path'] for r in files}, 'missing selected member')
        for directory in sorted((p for p in root.rglob('*') if p.is_dir()),
                                key=lambda p: len(p.parts), reverse=True):
            directory.chmod(0o555)
        root.chmod(0o555)
        result = dict(schema='issue3-b04-stage-v1', status='STAGED_UNAUTHENTICATED_NOT_EXECUTED',
                      target_executed=False, final_elf_acceptance=False,
                      files=len(written), bytes=total)
        save_new(attempt/'stage.json', binder.encoded(result))
        return result
    except BaseException as exc:
        save_new(attempt/'stage-failed.json', binder.encoded(dict(status='FAILED_PRESERVED_NO_RETRY',
                 error=type(exc).__name__, detail=str(exc)[:1000], target_executed=False)))
        raise


def stage_public(attempt):
    """Freshly authenticate original pair, stage only its exact 352 files, rehash."""
    from . import bind_b04
    binding = bind_b04.bind_public('original')
    prepare.require(len(binding['manifest']['files']) == 352, 'exact b04 352 selection')
    contract = binding['dependency_contract']
    result = stage_selection(attempt, contract['source']['archive']['path'],
        {k: contract['source']['archive'][k] for k in ('bytes','sha256')},
        binding['manifest']['files'], binding['origins'], contract['artifact_root'],
        {'contract.json': binder.encoded(contract)})
    plan = prepare.prepare(Path(attempt)/'inputs', binding['manifest'])
    result.update(status='AUTHENTICATED_ORIGINAL_STAGED_NOT_AUTHORIZED',
                  binding_sha256=hashlib.sha256(binder.encoded(binding)).hexdigest(), plan=plan)
    save_new(Path(attempt)/'authenticated-stage.json', binder.encoded(result))
    save_new(Path(attempt)/'binding.json', binder.encoded(binding))
    return result


def main():
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--stage', type=Path, help='explicit new owned absolute attempt; never executes')
    args = parser.parse_args()
    from . import bind_b04
    result = stage_public(args.stage) if args.stage else bind_b04.bind_public('original')
    print(binder.encoded(result).decode(), end='')


if __name__ == '__main__':
    main()
