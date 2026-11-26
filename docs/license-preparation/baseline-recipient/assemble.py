"""Hash-check / assemble sealed public baseline files; never execute recipes."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import tarfile
import unicodedata


def safe_relative(value):
    if not isinstance(value, str) or not value or '\\' in value or '\x00' in value:
        raise ValueError('invalid relative path')
    p = PurePosixPath(value)
    if p.is_absolute() or value != p.as_posix() or any(x in ('', '.', '..') for x in value.split('/')):
        raise ValueError('noncanonical relative path')
    return p


def no_links(path):
    path = Path(os.path.abspath(path))
    for p in [path, *path.parents]:
        if p.is_symlink():
            raise ValueError('symlink refused')
    return path


def digest_file(path):
    h = hashlib.sha256()
    size = 0
    with path.open('rb') as f:
        for data in iter(lambda: f.read(1024 * 1024), b''):
            h.update(data)
            size += len(data)
    return {'bytes': size, 'sha256': h.hexdigest()}


def validate_manifest(m):
    if type(m.get('schema_version')) is not int or m['schema_version'] != 1 or m.get('status') != 'SEALED_RETAINED_BASELINE_COMPANION_WITH_EXPLICIT_GAPS':
        raise ValueError('unsupported manifest')
    if type(m.get('entry_count', len(m['entries']))) is not int or m.get('entry_count', len(m['entries'])) != len(m['entries']):
        raise ValueError('entry count mismatch')
    paths = set()
    archive_member_refs = set()
    for e in m['entries']:
        path = safe_relative(e['recipient_path'])
        portable = unicodedata.normalize('NFC', str(path)).casefold()
        if portable in paths or portable == 'companion-manifest.json':
            raise ValueError('recipient collision or reserved manifest name')
        paths.add(portable)
        if type(e['bytes']) is not int or e['bytes'] < 0 or not re.fullmatch('[0-9a-f]{64}', e['sha256']):
            raise ValueError('invalid file identity')
        s = e['source']
        if s['kind'] not in ('repository_file', 'archive_member'):
            raise ValueError('unsupported source')
        safe_relative(s['path'])
        if s['kind'] == 'archive_member':
            safe_relative(s['member'])
            ref = (s['path'], s['member'])
            if ref in archive_member_refs:
                raise ValueError('duplicate archive member reference')
            archive_member_refs.add(ref)
    for p in paths:
        if any('/'.join(p.split('/')[:i]) in paths for i in range(1, len(p.split('/')))):
            raise ValueError('recipient file/directory conflict')
    archive = m['selected_baseline']['source_archive']
    if not any(e['source'] == {'kind': 'repository_file', 'path': archive['path']} and
               all(e[k] == archive[k] for k in ('bytes', 'sha256')) for e in m['entries']):
        raise ValueError('required archive binding missing')


def verify(repo, m):
    validate_manifest(m)
    repo = no_links(repo)
    archive_refs = {}
    files_checked = 0
    # Authenticate opaque archives before inspecting any member.
    for e in m['entries']:
        if e['source']['kind'] != 'repository_file':
            continue
        p = no_links(repo / e['source']['path'])
        if not p.is_file() or digest_file(p) != {k: e[k] for k in ('bytes', 'sha256')}:
            raise ValueError('source file identity mismatch: ' + e['recipient_path'])
        files_checked += 1
    archive = m['selected_baseline']['source_archive']
    ap = no_links(repo / archive['path'])
    if digest_file(ap) != {k: archive[k] for k in ('bytes', 'sha256')}:
        raise ValueError('archive identity mismatch')
    for e in m['entries']:
        if e['source']['kind'] == 'archive_member':
            if e['source']['path'] != archive['path']:
                raise ValueError('unbound archive reference')
            archive_refs[e['source']['member']] = e
    found = set()
    with tarfile.open(ap) as t:
        names = set()
        for member in t:
            if member.name in names:
                raise ValueError('duplicate archive name')
            names.add(member.name)
            if member.name not in archive_refs:
                continue
            e = archive_refs[member.name]
            if not member.isfile() or member.size != e['bytes']:
                raise ValueError('archive member type/size mismatch')
            stream = t.extractfile(member)
            if stream is None:
                raise ValueError('missing archive content')
            data = stream.read()
            if hashlib.sha256(data).hexdigest() != e['sha256']:
                raise ValueError('archive member hash mismatch')
            found.add(member.name)
    if found != set(archive_refs):
        raise ValueError('missing archive members')
    return {'repository_files_verified': files_checked, 'archive_members_verified': len(found),
            'entries_verified': len(m['entries']), 'build_executed': False, 'network_used': False}


def assemble(repo, m, destination):
    result = verify(repo, m)
    destination = no_links(destination)
    if destination.exists() or not destination.parent.is_dir():
        raise ValueError('destination must be new with existing parent')
    destination.mkdir(mode=0o755)
    # Only new destination files are written; failures retain a partial directory.
    archives = {}
    try:
        for e in m['entries']:
            out = destination / e['recipient_path']
            out.parent.mkdir(parents=True, exist_ok=True)
            s = e['source']
            if s['kind'] == 'repository_file':
                with no_links(repo / s['path']).open('rb') as src, out.open('xb') as dst:
                    shutil.copyfileobj(src, dst, length=1024 * 1024)
            else:
                if s['path'] not in archives:
                    archives[s['path']] = tarfile.open(no_links(repo / s['path']))
                t = archives[s['path']]
                with t.extractfile(s['member']) as src, out.open('xb') as dst:
                    shutil.copyfileobj(src, dst, length=1024 * 1024)
            out.chmod(0o644)
        # Rehash all destinations after all copies, before success receipt.
        for e in m['entries']:
            if digest_file(no_links(destination / e['recipient_path'])) != {k: e[k] for k in ('bytes', 'sha256')}:
                raise ValueError('assembled destination mismatch')
        canonical_manifest = (json.dumps(m, sort_keys=True, indent=2) + '\n').encode()
        with (destination / 'companion-manifest.json').open('xb') as f:
            f.write(canonical_manifest)
        if (destination / 'companion-manifest.json').read_bytes() != canonical_manifest:
            raise ValueError('recipient manifest write mismatch')
        return result
    finally:
        for t in archives.values():
            t.close()


def verify_recipient(root, m):
    validate_manifest(m)
    root = no_links(root)
    for e in m['entries']:
        p = no_links(root / e['recipient_path'])
        if not p.is_file() or digest_file(p) != {k: e[k] for k in ('bytes', 'sha256')}:
            raise ValueError('recipient identity mismatch: ' + e['recipient_path'])
    return {'recipient_files_verified': len(m['entries']), 'build_executed': False, 'network_used': False}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    roots = p.add_mutually_exclusive_group(required=True)
    roots.add_argument('--repo-root', type=Path)
    roots.add_argument('--recipient-root', type=Path)
    p.add_argument('--manifest', type=Path, required=True)
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument('--verify-only', action='store_true')
    g.add_argument('--output', type=Path)
    a = p.parse_args()
    m = json.loads(no_links(a.manifest).read_text())
    if a.recipient_root is not None:
        if not a.verify_only:
            p.error('--recipient-root requires --verify-only')
        result = verify_recipient(a.recipient_root, m)
    else:
        result = verify(a.repo_root, m) if a.verify_only else assemble(a.repo_root, m, a.output)
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
