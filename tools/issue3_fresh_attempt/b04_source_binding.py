"""Read-only exact b04 source/notices binding; never assembles or clears release."""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import posixpath
import re
import tarfile
import time
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / 'docs/license-preparation/b04-source-notices-binding.json'
MANIFEST_SHA256 = '715108b2cecbce58dd4c88a53659862f850b65c2ff4246915ba42beb9617d487'
ELF = {'bytes': 42467624, 'sha256': 'f2eba68682650ab6d9712017781612f4dbc3c01411c1ba5c7c4ecbb0f186b6b5'}
SOURCE = {'bytes': 220848835, 'sha256': 'a5f35232abe2aa4d03ff82e06665a465ecf1d6ee0f5399d22b8c7fd6bfcfea54'}


def regular(path):
    path = Path(path).absolute()
    if any(p.is_symlink() for p in (path, *path.parents)) or not path.is_file():
        raise ValueError('nonregular or linked input: ' + str(path))
    return path


def digest(path):
    h = hashlib.sha256()
    with regular(path).open('rb') as reader:
        for chunk in iter(lambda: reader.read(1024**2), b''):
            h.update(chunk)
    return h.hexdigest()


def relative(name):
    if (not isinstance(name, str) or not name or name.startswith('/') or
            '\\' in name or any(p in ('', '.', '..') for p in name.split('/'))):
        raise ValueError('noncanonical relative path')
    return name


def hash_value(value):
    if not isinstance(value, str) or re.fullmatch('[0-9a-f]{64}', value) is None:
        raise ValueError('invalid hash')


def load_json(path):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError('duplicate JSON key: ' + key)
            result[key] = value
        return result
    if regular(path).stat().st_size > 2 * 1024**2:
        raise ValueError('JSON size bound exceeded')
    return json.loads(Path(path).read_text(), object_pairs_hook=pairs)


def check_file(path, expected):
    hash_value(expected.get('sha256'))
    if type(expected.get('bytes')) is not int or expected['bytes'] < 0:
        raise ValueError('invalid byte count')
    if regular(path).stat().st_size != expected['bytes']:
        raise ValueError('byte count mismatch: ' + str(path))
    if digest(path) != expected['sha256']:
        raise ValueError('hash mismatch: ' + str(path))


def check_notice_selection(root, selection, required):
    if (type(selection.get('schema_version')) is not int or selection['schema_version'] != 1
            or selection.get('destination') != '/usr/share/doc/uvm'
            or not isinstance(selection.get('files'), dict)):
        raise ValueError('unsupported notice selection schema or destination')
    files = selection['files']
    missing = sorted(set(required) - set(files))
    if missing:
        raise ValueError('missing required notices: ' + str(missing))
    for name, expected in files.items():
        relative(name)
        hash_value(expected)
        if name in required and required[name] != expected:
            raise ValueError('required notice selection hash mismatch: ' + name)
        if digest(Path(root) / name) != expected:
            raise ValueError('notice file hash mismatch: ' + name)


def check_scope(plan):
    if plan.get('image_evidence', 'absent') is not None:
        raise ValueError('no b04 package image evidence is established here')
    if (type(plan.get('schema_version')) is not int or plan['schema_version'] != 1
            or plan.get('status') != 'B04_SOURCE_NOTICES_PREPARATION_ONLY'
            or plan.get('attempt') != 'issue3-owned-20261030-b04'):
        raise ValueError('unsupported b04 binding schema/status/attempt')
    for key in ('distribution_cleared', 'license_choices_enacted', 'rebuild_relink_tested'):
        if plan.get(key) is not False:
            raise ValueError('scope escalation: ' + key)
    if plan.get('elf') != ELF or plan.get('source_archive') != SOURCE:
        raise ValueError('historical ELF/source substitution')


def inspect_archive(path, required, *, max_members=100000,
                    max_bytes=4 * 1024**3, max_seconds=90) -> dict[str, Any]:
    """Stream an opaque archive; bounded small reads, no extraction/writes."""
    seen, trees, found, roots = set(), {}, {}, {}
    total = count = 0
    deadline = time.monotonic() + max_seconds
    with tarfile.open(path, 'r|gz') as archive:
        for member in archive:
            count += 1
            total += member.size
            if count > max_members or total > max_bytes or time.monotonic() > deadline:
                raise ValueError('archive inspection bound exceeded')
            name = member.name
            parts = PurePosixPath(name).parts
            canonical = name.rstrip('/') if member.isdir() else name
            if (not parts or name.startswith('/') or '\\' in name or
                    any(p in ('', '.', '..') for p in canonical.split('/'))):
                raise ValueError('noncanonical archive member')
            if canonical in seen:
                raise ValueError('duplicate archive member')
            seen.add(canonical)
            link_ok = False
            if member.issym() and not member.linkname.startswith('/'):
                target = PurePosixPath(posixpath.normpath(str(PurePosixPath(name).parent / member.linkname)))
                prefix = parts[:2] if parts[0] == 'p' else parts[:1]
                link_ok = target.parts[:len(prefix)] == prefix and '..' not in target.parts
            if not (member.isfile() or member.isdir() or link_ok):
                raise ValueError('unsupported archive member type or escaping link')
            roots[parts[0]] = roots.get(parts[0], 0) + 1
            if len(parts) >= 3 and parts[0] == 'p' and member.isfile():
                trees[parts[1]] = trees.get(parts[1], 0) + 1
            if name in required:
                if not member.isfile() or member.size > 250000:
                    raise ValueError('required member nonregular or oversized: ' + name)
                reader = archive.extractfile(member)
                if reader is None:
                    raise ValueError('unreadable required member')
                data = reader.read(250001)
                if len(data) != member.size or hashlib.sha256(data).hexdigest() != required[name]:
                    raise ValueError('required member hash mismatch: ' + name)
                found[name] = required[name]
    if set(found) != set(required):
        raise ValueError('missing required archive members: ' + str(sorted(set(required) - set(found))))
    return dict(members=count, declared_bytes=total, roots=roots,
                package_trees=dict(sorted(trees.items())), required_members=found)


def validate(artifact, *, manifest=MANIFEST, repo=ROOT, notice_manifest=None):
    """Audit existing exact public inputs; return preparation facts, not clearance.

    The reviewed manifest is pinned out of band in this successor. Changing it
    requires explicit source review and pin update, not user-supplied hash plans.
    """
    artifact, repo = Path(artifact), Path(repo)
    if digest(manifest) != MANIFEST_SHA256:
        raise ValueError('reviewed manifest hash mismatch')
    plan = load_json(manifest)
    check_scope(plan)
    check_file(artifact / 'urbit', ELF)
    check_file(artifact / 'source-materials.tar.gz', SOURCE)
    for name, expected in plan['artifact_files'].items():
        check_file(artifact / relative(name), expected)
    for name, expected in plan['evidence_files'].items():
        check_file(repo / relative(name), expected)
    frozen = artifact.parent / 'frozen-recipe'
    for name, expected in plan['frozen_recipe_files'].items():
        if digest(frozen / relative(name)) != expected:
            raise ValueError('frozen recipe hash mismatch: ' + name)
    inventory = inspect_archive(artifact / 'source-materials.tar.gz', plan['required_archive_members'])
    actual = {k: inventory[k] for k in ('members', 'declared_bytes', 'roots', 'package_trees')}
    if actual != plan['archive_inventory']:
        raise ValueError('exact b04 archive inventory mismatch')
    for name, expected in plan['required_repo_notices'].items():
        if digest(repo / relative(name)) != expected:
            raise ValueError('required repository notice hash mismatch: ' + name)
    selected = load_json(notice_manifest or repo / 'build/notice-files.json')
    check_notice_selection(repo, selected, {})
    missing = sorted(set(plan['required_repo_notices']) - set(selected.get('files', {})))
    if notice_manifest is not None:
        check_notice_selection(repo, selected, plan['required_repo_notices'])
    # Read-only audit is useful before package worker includes the delta. It
    # deliberately cannot report notice selection PASS when required files miss.
    elif not missing:
        check_notice_selection(repo, selected, plan['required_repo_notices'])
    check_file(artifact / 'urbit', ELF)
    check_file(artifact / 'source-materials.tar.gz', SOURCE)
    return dict(schema_version=1, attempt=plan['attempt'],
                status='SOURCE_BOUND_NOTICE_SELECTION_INCOMPLETE' if missing else 'SOURCE_NOTICES_BOUND_NOT_RELEASE_COMPLETE',
                elf=ELF, source_archive=SOURCE, archive_members=inventory['members'],
                package_tree_count=len(inventory['package_trees']),
                required_archive_members=len(inventory['required_members']),
                required_notices=len(plan['required_repo_notices']),
                missing_selected_notices=missing, image_evidence=None,
                distribution_cleared=False, license_choices_enacted=False,
                rebuild_relink_tested=False, source_companion_assembled=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--artifact', required=True, type=Path)
    parser.add_argument('--manifest', default=MANIFEST, type=Path)
    parser.add_argument('--repo', default=ROOT, type=Path)
    parser.add_argument('--notice-manifest', type=Path,
                        help='strict selection validation; missing required notices fail')
    args = parser.parse_args()
    try:
        result = validate(args.artifact, manifest=args.manifest, repo=args.repo,
                          notice_manifest=args.notice_manifest)
    except (ValueError, OSError, tarfile.TarError) as exc:
        parser.exit(1, str(exc) + '\n')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
