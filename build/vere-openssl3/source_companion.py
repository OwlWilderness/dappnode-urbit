"""File-only recipient source staging. Never extracts, builds or clears licences.

An explicit independently reviewed plan binds each public file. Archive remains
byte-for-byte intact, including notices and the 24 retained package-cache trees.
"""
import argparse
import hashlib
import json
import re
from pathlib import Path, PurePosixPath
import shutil
import tarfile


def digest(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as f:
        for chunk in iter(lambda: f.read(1024**2), b''):
            h.update(chunk)
    return h.hexdigest()


def inspect_archive(path):
    trees, seen, total = set(), set(), 0
    with tarfile.open(path, 'r:gz') as archive:
        for member in archive:
            name = PurePosixPath(member.name)
            parts = name.parts
            total += member.size
            # Opaque preservation only, never filesystem extraction. Permit
            # relative upstream symlinks confined lexically to their source tree.
            import posixpath
            link_ok = False
            if member.issym() and not PurePosixPath(member.linkname).is_absolute():
                target = PurePosixPath(posixpath.normpath(str(name.parent / member.linkname)))
                prefix = parts[:2] if parts and parts[0] == 'p' else parts[:1]
                link_ok = target.parts[:len(prefix)] == prefix and '..' not in target.parts
            if (name.is_absolute() or '..' in parts or not parts or
                    member.name in seen or not (member.isfile() or member.isdir() or link_ok) or
                    len(seen) >= 100000 or total > 4 * 1024**3):
                raise ValueError('unsafe, duplicate or oversized archive')
            seen.add(member.name)
            if len(parts) >= 3 and parts[0] == 'p' and member.isfile():
                trees.add(parts[1])
    if len(trees) != 24:
        raise ValueError('expected the 24 existing package-cache trees')
    return sorted(trees)


ALLOWED = {'candidate.py', 'candidate.json', 'Dockerfile', 'inputs.json',
           'builder-apks.json', 'curl-build.zig', 'curl-build.zig.zon',
           'sha-stack.c', 'h2o-socket.c', 'h2o-overlay.json',
           'dependency-manifests.json', 'openssl-archives.json',
           'retain_link_inputs.py', 'source_companion.py', 'BUILD-RELINK.md',
           'source-materials.tar.gz'}


def check_files(directory, hashes):
    if (not isinstance(hashes, dict) or 'source-materials.tar.gz' not in hashes
            or not set(hashes) <= ALLOWED):
        raise ValueError('only explicitly allowlisted public inputs may be copied')
    for name, expected in hashes.items():
        if not isinstance(expected, str) or re.fullmatch(r'[0-9a-f]{64}', expected) is None:
            raise ValueError('invalid source hash: ' + name)
        path = directory/name
        if any(p.is_symlink() for p in [path, *path.parents]) or not path.is_file():
            raise ValueError('nonregular or linked source')
        if digest(path) != expected:
            raise ValueError('source hash mismatch: ' + name)


def assemble(artifact, plan, output):
    artifact, output = Path(artifact), Path(output)
    hashes = dict(plan['files'], **{'source-materials.tar.gz': plan['source_archive_sha256']})
    check_files(artifact, hashes)
    trees = inspect_archive(artifact/'source-materials.tar.gz')
    if output.exists() or any(p.is_symlink() for p in [output, *output.parents]):
        raise ValueError('output must be new, with no linked ancestors')
    if shutil.disk_usage(output.parent).free < sum((artifact/n).stat().st_size for n in hashes) + 1024**3:
        raise ValueError('insufficient staging capacity plus 1 GiB reserve')
    output.mkdir()
    for name in hashes:
        with (artifact/name).open('rb') as reader, (output/name).open('xb') as writer:
            shutil.copyfileobj(reader, writer, 1024**2)
    check_files(output, hashes)
    check_files(artifact, hashes)
    receipt = dict(schema_version=1, status='SOURCE_STAGED_NOT_RELEASE_COMPLETE',
                   files=hashes, package_trees=trees, package_tree_count=len(trees),
                   distribution_cleared=False, license_choices_enacted=False,
                   rebuild_relink_tested=False,
                   dbus_discrepancy='Source 1.14.8; frozen adapter DBUS_VERSION 1.14.10; not normalized',
                   avahi_notice='Preserved byte-for-byte in archive; literal version 2 or any later version, not normalized to 2.1')
    (output/'companion.json').write_text(json.dumps(receipt, indent=2)+'\n')
    return receipt


def validate(output):
    output = Path(output)
    receipt = json.loads((output/'companion.json').read_text())
    if (not isinstance(receipt, dict) or type(receipt.get('schema_version')) is not int
            or receipt.get('schema_version') != 1
            or receipt.get('status') != 'SOURCE_STAGED_NOT_RELEASE_COMPLETE'):
        raise ValueError('unsupported companion schema or status')
    check_files(output, receipt['files'])
    trees = inspect_archive(output/'source-materials.tar.gz')
    if (receipt.get('package_trees') != trees or receipt.get('package_tree_count') != 24 or
            receipt.get('distribution_cleared') is not False or
            receipt.get('license_choices_enacted') is not False or
            receipt.get('rebuild_relink_tested') is not False):
        raise ValueError('companion inventory or scope mismatch')
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--validate', type=Path)
    parser.add_argument('--artifact', type=Path)
    parser.add_argument('--plan', type=Path)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    if args.validate:
        result = validate(args.validate)
    else:
        if not all((args.artifact, args.plan, args.output)):
            parser.error('assembly requires --artifact --plan --output')
        result = assemble(args.artifact, json.loads(args.plan.read_text()), args.output)
    print(json.dumps(result, indent=2))

if __name__ == '__main__':
    main()
