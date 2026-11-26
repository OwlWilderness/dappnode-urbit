"""Retain selected actual final-link bytes; no search, compilation or execution.

Caller supplies the exact successful final linker argv and its working directory.
This is provenance evidence, not a cryptographic proof that a compiler used it.
"""
import hashlib
import json
from pathlib import Path
import shutil
import unicodedata

LIBRARIES = ('libssl.a', 'libcrypto.a', 'libcurl.a')


def digest(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def retain(cwd, argv, binary, headers, output, guard=None):
    cwd, binary, output = Path(cwd), Path(binary), Path(output)
    if not isinstance(argv, list) or not argv or any(not isinstance(a, str) or a.startswith('@') for a in argv):
        raise ValueError('explicit argv required; response files unsupported')
    def regular(path):
        path = Path(path).absolute()
        if '..' in path.parts or any(p.is_symlink() for p in [path, *path.parents]) or not path.is_file():
            raise ValueError('nonregular, linked or traversing input')
        return path
    selected = {}
    for name in LIBRARIES:
        matches = [cwd / arg for arg in argv if Path(arg).name == name]
        if len(matches) != 1:
            raise ValueError('exactly one explicit link input required: ' + name)
        selected[name] = regular(matches[0])
    if argv.count('-o') != 1 or argv.index('-o') + 1 == len(argv):
        raise ValueError('one explicit linker output required')
    link_output = regular(cwd / argv[argv.index('-o') + 1])
    if digest(link_output) != digest(regular(binary)):
        raise ValueError('linked output does not match delivered binary')
    if not headers or {n.split('/')[0] for n in headers} != {'openssl', 'curl'}:
        raise ValueError('explicit openssl/curl header labels required')
    destinations = set()
    for name, path in headers.items():
        parts = name.split('/')
        if (len(parts) < 2 or any(p in ('', '.', '..') for p in parts)
                or '\\' in name or '\x00' in name):
            raise ValueError('unsafe header label')
        key = unicodedata.normalize('NFD', name).casefold()
        if key in destinations:
            raise ValueError('aliased header destination')
        destinations.add(key)
        regular(path)
    if any(p.is_symlink() for p in [output, *output.parents]) or output.exists():
        raise ValueError('output must be fresh and not linked')
    before = {str(p): digest(p) for p in [*selected.values(), *map(Path, headers.values()), binary]}
    output.mkdir()
    records = {}
    for label, source in [(f'libraries/{n}', p) for n, p in selected.items()] + [
            (f'headers/{n}', Path(p)) for n, p in headers.items()]:
        target = output / label
        target.parent.mkdir(parents=True, exist_ok=True)
        if guard:
            guard.copy_file(source, target)
        else:
            shutil.copyfile(source, target)
        if digest(target) != before[str(source)] or digest(source) != before[str(source)]:
            raise ValueError('input changed or copy differs')
        records[label] = {'sha256': digest(target), 'bytes': target.stat().st_size,
                          'source': str(source)}
    if any(digest(Path(p)) != h for p, h in before.items()):
        raise ValueError('input changed during retention')
    if guard:
        guard.check(force=True)
    if any(digest(output / label) != record['sha256'] for label, record in records.items()):
        raise ValueError('retained destination changed before receipt')
    receipt = dict(schema_version=1, status='RETAINED_NOT_TLS_TESTED',
                   cwd=str(cwd), argv=argv, binary_sha256=digest(binary), files=records)
    (output/'link-inputs.json').write_text(json.dumps(receipt, indent=2)+'\n')
    return receipt
