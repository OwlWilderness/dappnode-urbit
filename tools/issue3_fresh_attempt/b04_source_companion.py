"""Bounded b04 recipient companion: plan/copy/validate, never extract or build.

Trust starts at the reviewed b04_source_binding manifest pin. Validation also
requires an independently retained plan; a self-edited receipt is not authority.
Failed assemblies are retained incomplete, without a completion receipt.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import sys
import time
from typing import Any
import unicodedata

# Delivered validation must not create unplanned __pycache__ inside its own tree.
sys.dont_write_bytecode = True

try:
    from . import b04_source_binding as binding
except ImportError:
    import b04_source_binding as binding

ROOT = Path(__file__).resolve().parents[2]
GUIDE = 'docs/license-preparation/b04-recipient/BUILD-RELINK.md'
LAYOUT = 'docs/license-preparation/b04-recipient/layout.json'
# The guide/layout are separately reviewed successor inputs, not frozen history.
DOCUMENT_PINS = {
    GUIDE: '4bc1570eed2fa97591d4fed44d760b84b0a6013cff291fbb489a9e9f1ba8787e',
    LAYOUT: '655f8d706af79e9ca8059c0f9e20a2669580554834bc809c02be0f8d3c7ef8a6',
}
MAX_FILES = 512
MAX_BYTES = 256 * 1024**2
MAX_FILE_BYTES = 224 * 1024**2
RESERVE = 64 * 1024**2
CLAIMS = dict(distribution_cleared=False, license_choices_enacted=False,
              rebuild_relink_tested=False, authenticated_final_link_inputs=False,
              authenticated_compile_headers=False)


def regular(path):
    path = binding.regular(path)
    if path.stat().st_nlink != 1:
        raise ValueError('hardlinked input: ' + str(path))
    return path


def canonical(name):
    binding.relative(name)
    if any(':' in part or any(ord(c) < 32 for c in part) or
           part.endswith((' ', '.')) for part in name.split('/')):
        raise ValueError('nonportable recipient path')
    return unicodedata.normalize('NFC', name).casefold()


def inventory(plan):
    if (type(plan.get('schema_version')) is not int or plan['schema_version'] != 1 or
            plan.get('status') != 'B04_COMPANION_PLAN_NOT_BUILD_VERIFIED' or
            any(plan.get(k) is not False for k in CLAIMS)):
        raise ValueError('unsupported plan or false rebuild/release claim')
    files = plan.get('files')
    if not isinstance(files, dict) or not files or len(files) > MAX_FILES:
        raise ValueError('file count bound')
    seen = set()
    total = 0
    for name, entry in files.items():
        key = canonical(name)
        parts = key.split('/')
        if key in seen:
            raise ValueError('recipient path collision')
        seen.add(key)
        binding.hash_value(entry.get('sha256'))
        size = entry.get('bytes')
        if type(size) is not int or not 0 <= size <= MAX_FILE_BYTES:
            raise ValueError('file byte bound')
        total += size
    for name in seen:
        parts = name.split('/')
        if any('/'.join(parts[:i]) in seen for i in range(1, len(parts))):
            raise ValueError('recipient file/directory collision')
    if 'companion.json' in seen or total > MAX_BYTES or plan.get('total_bytes') != total:
        raise ValueError('total byte bound or reserved receipt collision')
    if plan.get('source_archive') != files.get('source-materials.tar.gz'):
        raise ValueError('source archive binding missing')
    return files


def _sources(artifact, repo, reviewed):
    artifact, repo = Path(artifact), Path(repo)
    result = {'source-materials.tar.gz': artifact / 'source-materials.tar.gz'}
    for name in reviewed['frozen_recipe_files']:
        result['recipe/' + binding.relative(name)] = artifact.parent / 'frozen-recipe' / name
    for name in reviewed['artifact_files']:
        result['support/' + binding.relative(name)] = artifact / name
    for group in ('evidence_files', 'required_repo_notices'):
        for name in reviewed[group]:
            result[binding.relative(name)] = repo / name
    for name in (str(binding.MANIFEST.relative_to(binding.ROOT)),
                 'tools/issue3_fresh_attempt/b04_source_binding.py',
                 'tools/issue3_fresh_attempt/b04_source_companion.py', GUIDE, LAYOUT):
        result[binding.relative(name)] = repo / name
    layout = binding.load_json(repo / LAYOUT)
    for name, expected in layout['reviewed_evidence'].items():
        binding.check_file(repo / binding.relative(name), expected)
        result[name] = repo / name
    return result


def plan(artifact, *, repo=ROOT) -> dict[str, Any]:
    """Authenticate exact retained inputs, then map every explicit inventory leaf."""
    binding.validate(artifact, repo=repo, notice_manifest=Path(repo) / 'build/notice-files.json')
    reviewed = binding.load_json(binding.MANIFEST)
    if set(DOCUMENT_PINS) != {GUIDE, LAYOUT}:
        raise ValueError('reviewed recipient document pins missing')
    for name, expected in DOCUMENT_PINS.items():
        if binding.digest(Path(repo) / name) != expected:
            raise ValueError('reviewed recipient document hash mismatch: ' + name)
    # Completeness comes from the recipe's explicit inventory, not a tree count.
    owned = binding.load_json(Path(artifact).parent / 'frozen-recipe/owned-recipe.json')
    if set(owned['files']) | {'owned-recipe.json'} != set(reviewed['frozen_recipe_files']):
        raise ValueError('frozen recipe inventory incomplete')
    sources = _sources(artifact, repo, reviewed)
    files: dict[str, Any] = {name: dict(bytes=regular(path).stat().st_size, sha256=binding.digest(path))
                             for name, path in sources.items()}
    exact = {'source-materials.tar.gz': reviewed['source_archive']}
    exact.update({'support/' + n: e for n, e in reviewed['artifact_files'].items()})
    exact.update(reviewed['evidence_files'])
    hashes = {'recipe/' + n: h for n, h in reviewed['frozen_recipe_files'].items()}
    hashes.update(reviewed['required_repo_notices'])
    hashes.update(DOCUMENT_PINS)
    hashes[str(binding.MANIFEST.relative_to(binding.ROOT))] = binding.MANIFEST_SHA256
    if (any(files[n] != e for n, e in exact.items()) or
            any(files[n]['sha256'] != h for n, h in hashes.items())):
        raise ValueError('authenticated inventory changed during planning')
    result = dict(schema_version=1, status='B04_COMPANION_PLAN_NOT_BUILD_VERIFIED',
                  attempt=reviewed['attempt'], binding_sha256=binding.MANIFEST_SHA256,
                  files=dict(sorted(files.items())), total_bytes=sum(e['bytes'] for e in files.values()),
                  source_archive=files['source-materials.tar.gz'], **CLAIMS)
    inventory(result)
    return result


def capacity(parent, remaining, reserve=RESERVE):
    if shutil.disk_usage(parent).free < remaining + reserve:
        raise ValueError('companion capacity: remaining bytes plus reserve unavailable')


def directory(path):
    path = Path(path).absolute()
    if any(p.is_symlink() for p in (path, *path.parents)) or not path.is_dir():
        raise ValueError('nonregular or linked directory')
    return path


def _copy(source, destination, expected, deadline):
    """Exclusive, nofollow regular-file copy, bounded by the authenticated size."""
    regular(source)
    flags = os.O_RDONLY | os.O_NOFOLLOW
    with os.fdopen(os.open(source, flags), 'rb') as reader:
        before = os.fstat(reader.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size != expected['bytes']:
            raise ValueError('copy source identity mismatch')
        h, count = hashlib.sha256(), 0
        with destination.open('xb') as writer:
            while True:
                if time.monotonic() > deadline:
                    raise ValueError('copy deadline bound')
                data = reader.read(min(1024**2, expected['bytes'] - count + 1))
                if not data:
                    break
                count += len(data)
                if count > expected['bytes']:
                    raise ValueError('copy byte bound')
                h.update(data)
                writer.write(data)
            writer.flush()
            os.fsync(writer.fileno())
        after = os.fstat(reader.fileno())
        if (count != expected['bytes'] or h.hexdigest() != expected['sha256'] or
                (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) !=
                (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)):
            raise ValueError('copy source changed or hash mismatch')
    binding.check_file(destination, expected)


def _check_tree(output, expected, *, receipt):
    directory(output)
    actual, dirs = set(), set()
    for root, folders, leaves in os.walk(output, followlinks=False):
        for name in folders:
            directory(Path(root) / name)
            dirs.add((Path(root) / name).relative_to(output).as_posix())
        for name in leaves:
            p = regular(Path(root) / name)
            actual.add(p.relative_to(output).as_posix())
        if len(actual) > MAX_FILES + 1 or len(dirs) > MAX_FILES * 8:
            raise ValueError('output tree bound')
    wanted = set(inventory(expected)) | ({'companion.json'} if receipt else set())
    expected_dirs = {str(Path(n).parent) for n in wanted}
    expected_dirs = {str(p) for n in wanted for p in Path(n).parents if str(p) != '.'}
    if actual != wanted or dirs != expected_dirs:
        raise ValueError('output inventory mismatch')
    for name, entry in expected['files'].items():
        regular(Path(output) / name)
        binding.check_file(Path(output) / name, entry)


def validate(output, expected):
    """Offline readback against an independently authenticated/retained plan."""
    output = Path(output).absolute()
    inventory(expected)
    receipt = binding.load_json(output / 'companion.json')
    if receipt != dict(status='ASSEMBLED_NOT_REBUILD_RELINK_VERIFIED', plan=expected):
        raise ValueError('completion receipt/expected plan mismatch')
    _check_tree(output, expected, receipt=True)
    return dict(status=receipt['status'], files=len(expected['files']),
                bytes=expected['total_bytes'], **CLAIMS)


def assemble(artifact, output, *, repo=ROOT, expected=None, seconds=120):
    """Never overwrite or remove output, including any partial failed copy."""
    output = Path(output).absolute()
    directory(output.parent)
    if output.exists() or output.is_symlink():
        raise ValueError('existing output refused')
    current = plan(artifact, repo=repo)
    inventory(current)  # Recheck at the side-effect boundary, even for API callers.
    if expected is not None and current != expected:
        raise ValueError('plan changed before assembly')
    expected = current
    capacity(output.parent, expected['total_bytes'] + 2 * 1024**2)
    sources = _sources(artifact, repo, binding.load_json(binding.MANIFEST))
    deadline = time.monotonic() + seconds
    output.mkdir()  # Exclusive creation; failed results are retained, not cleaned.
    remaining = expected['total_bytes']
    for name, entry in expected['files'].items():
        capacity(output, remaining + 2 * 1024**2)
        destination = output / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        directory(destination.parent)
        _copy(sources[name], destination, entry, deadline)
        remaining -= entry['bytes']
    # Rehash all destinations AFTER all copies and capacity callbacks; seal last.
    capacity(output, 2 * 1024**2)
    _check_tree(output, expected, receipt=False)
    for name, source in sources.items():
        regular(source)
        binding.check_file(source, expected['files'][name])
    with (output / 'companion.json').open('x') as writer:
        json.dump(dict(status='ASSEMBLED_NOT_REBUILD_RELINK_VERIFIED', plan=expected), writer,
                  indent=2, sort_keys=True)
        writer.write('\n')
    return validate(output, expected)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('plan', 'assemble', 'validate'))
    parser.add_argument('--artifact', type=Path)
    parser.add_argument('--repo', type=Path, default=ROOT)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--plan', type=Path)
    parser.add_argument('--plan-sha256', help='independently retained plan digest; mandatory for validation')
    args = parser.parse_args()
    try:
        expected = None
        if args.plan:
            binding.hash_value(args.plan_sha256)
            if binding.digest(args.plan) != args.plan_sha256:
                raise ValueError('independent plan digest mismatch')
            expected = binding.load_json(args.plan)
        if args.mode == 'validate':
            if expected is None or args.output is None:
                raise ValueError('validate needs --output, --plan and --plan-sha256')
            result = validate(args.output, expected)
        elif args.artifact is None:
            raise ValueError('--artifact required')
        elif args.mode == 'plan':
            result = plan(args.artifact, repo=args.repo)
        elif args.output is None:
            raise ValueError('--output required')
        else:
            result = assemble(args.artifact, args.output, repo=args.repo, expected=expected)
    except (ValueError, OSError) as error:
        parser.exit(1, str(error) + '\n')
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
