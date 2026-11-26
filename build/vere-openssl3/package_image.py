#!/usr/bin/env python3
"""Prepare an isolated exact-candidate package context; never build or run it.

Production files and historical receipts are read-only inputs. No hash/path
runtime override is introduced: only the staged adapter's constant changes.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import stat
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
CANDIDATE_SHA256 = '58d07af97926e04bc17184bc18f53e5fb11d84fed63bd9daf2fe4ceb04c86698'
CANDIDATE_BYTES = 42399776
OFFICIAL_SHA256 = '47ad302e8934271dfc00dcdab1d553c6d6460b105e3099ff47e0e4e4231bb26d'
PREIMAGES = {
    'build/Dockerfile': '3cd45beba81c71007cb74370183dc268b8a5f020413541ff442e9a0268c1231f',
    'tools/browser-importer/runtime.py': '01e910b2eab56a2b2d2795b9a6872f70876bfc7f501482cf55daf5b2b60a6e93',
    '.dockerignore': '194a6da7d280649e083c39670e62aeddcd0a6b0b77a97848727d315a2aec8e2d',
    'build/notice-files.json': '72f94a0c531699ce01600f865c3a1c61cba5770cb397f8e0d9593268fedf647c',
    'build/vere-release.json': '5d9fc5036f55c1938c1cba75afe5e18a6fd047526797f4e216b16a441dec0537',
}
EVIDENCE = {
    'build_issue3_amd64_curl_build_02/artifact/candidate.json': '84f825a7ee511c9b4547bfd3b3f67b3fdff1ef769bec1a971bb2c932b6150991',
    'build_issue3_amd64_curl_report_01/result.json': 'f4517bea734d493e0a2e8eafab87dd0051c9d51605201339fceb0d03d6d0d76e',
}
SUPPORT = ('build/vere-openssl3/package_image.py',
           'tools/local-candidate/verify_image.py', 'scripts/inventory-public-image.py',
           'scripts/verify-notice-packaging.py')
MAX_FILE = 48 * 1024**2


def sha(data):
    return hashlib.sha256(data).hexdigest()


def load(root, name):
    spec = importlib.util.spec_from_file_location('isolated_' + Path(name).stem, root / name)
    assert spec is not None and spec.loader is not None
    module: Any = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def overlay(root):
    """Return only allowlisted public package files with isolated substitutions."""
    root = Path(root)
    # Validate the selection controls before deriving or reading any COPY input.
    files = {}
    for name, expected in PREIMAGES.items():
        files[name] = read_public(root / name)
        if sha(files[name]) != expected:
            raise ValueError('reviewed package source preimage changed')
    allowed = {line[1:] for line in files['.dockerignore'].decode().splitlines()
               if line.startswith('!') and not line.endswith('/')}
    for name in sorted(allowed - {'build/install_vere.py'} - files.keys()):
        files[name] = read_public(root / name, 8 * 1024**2)
    notices = load(root, 'scripts/verify-notice-packaging.py')
    verifier = load(root, 'tools/local-candidate/verify_image.py')
    contract = verifier.build_contract(root, read_regular=lambda _, name: files[name])
    names = {entry['source'] for entry in contract['files'].values()}
    names.update(('.dockerignore', 'build/Dockerfile'))
    files = {name: files[name] for name in sorted(names)}
    adapter = files['tools/browser-importer/runtime.py']
    if adapter.count(OFFICIAL_SHA256.encode()) != 1:
        raise ValueError('unique adapter guard required')
    files['tools/browser-importer/runtime.py'] = adapter.replace(
        OFFICIAL_SHA256.encode(), CANDIDATE_SHA256.encode())
    recipe = files['build/Dockerfile'].decode()
    first, final = recipe.split('\nFROM ')
    base = first.splitlines()[0].split()[1]
    # Refresh only the unavailable Python package pin in this isolated context.
    # Official Alpine v3.24 x86_64 APKINDEX was checked; other pins still match.
    if final.count('python3=3.14.8-r0') != 1:
        raise ValueError('unique historical Python pin required')
    final = final.replace('python3=3.14.8-r0', 'python3=3.14.10-r1')
    final = final.replace("# Preserve the accepted candidate's dependency pins; no runtime upgrade here.",
                          '# Isolated candidate: Python pin refreshed; other runtime pins retained.')
    # Keep user/entrypoint/volume/network defaults untouched.
    first = (f'FROM {base} AS vere-release\n'
             '# Local source-built candidate; hash only, never execute Vere.\n'
             'COPY --chown=0:0 candidate/urbit /out/urbit\n'
             f"RUN echo '{CANDIDATE_SHA256}  /out/urbit' | sha256sum -c - "
             '&& chmod 0555 /out/urbit\n')
    final = final.replace('\n', '\nLABEL io.uvm.candidate="issue-3-amd64-curl-build-02" '
                          'io.uvm.distribution-cleared="false"\n', 1)
    files['build/Dockerfile'] = (first + '\nFROM ' + final).encode()
    files['build/vere-release.json'] = (json.dumps({
        'candidate': 'vere-4.6-uvm-openssl-3.5.9-curl-8.23.0', 'architecture': 'linux/amd64',
        'executable_bytes': CANDIDATE_BYTES, 'executable_sha256': CANDIDATE_SHA256,
        'official_release': False, 'distribution_cleared': False,
    }, indent=2) + '\n').encode()
    ignore = files['.dockerignore'].decode()
    ignore = ignore.replace('!build/install_vere.py\n', '')
    ignore = ignore.replace(notices.BEGIN,
                            '!candidate/\ncandidate/**\n!candidate/urbit\n' + notices.BEGIN)
    files['.dockerignore'] = ignore.encode()
    return files


def read_public(path, limit=MAX_FILE):
    """No symlinks, hardlinks, special files or unbounded payloads."""
    path = Path(os.path.abspath(path))
    parent_fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parts[1:-1]:
            child_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
            os.close(parent_fd)
            parent_fd = child_fd
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent_fd)
    finally:
        os.close(parent_fd)
    with os.fdopen(fd, 'rb') as source:
        before = os.fstat(source.fileno())
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or
                before.st_size > limit):
            raise ValueError('public regular file or size bound')
        data = source.read(limit + 1)
        after = os.fstat(source.fileno())
    # atime may change on read; identity/content metadata must remain stable.
    fields = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
    if len(data) != before.st_size or any(getattr(before, k) != getattr(after, k) for k in fields):
        raise ValueError('public input changed while reading')
    return data


def validate_binary(data):
    if (len(data) != CANDIDATE_BYTES or sha(data) != CANDIDATE_SHA256 or
            data[:6] != b'\x7fELF\x02\x01' or int.from_bytes(data[18:20], 'little') != 62):
        raise ValueError('exact allocator-corrected AMD64 executable required')


def image_verifier(root=ROOT):
    """Task-local size allowance; never change the production verifier defaults."""
    module = load(Path(root), 'tools/local-candidate/verify_image.py')
    module.MAX_ELF = MAX_FILE
    module.MAX_FILE = MAX_FILE
    return module


def describe(data, mode=0o644):
    return {'sha256': sha(data), 'bytes': len(data), 'mode': mode}


def write_new(root, name, data, mode=0o644):
    target = root / name
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open('xb') as stream:
        stream.write(data)
    target.chmod(mode)


def prepare(root, output):
    """Stage into a new directory. Partial failures are retained, never retried."""
    root, output = Path(root).absolute(), Path(output).absolute()
    if os.path.lexists(output):
        raise FileExistsError('preparation output already exists; preserve it')
    for parent in [*reversed(output.parent.parents), output.parent]:
        if not stat.S_ISDIR(parent.lstat().st_mode):
            raise ValueError('output parent must exist without symlinks')
    # Host-only staging budget, not Docker admission or a runtime quota.
    if shutil.disk_usage(output.parent).free < 10 * 1024**3 + 128 * 1024**2:
        raise ValueError('10 GiB free reserve plus 128 MiB staging allowance required')
    files = overlay(root)
    binary = read_public(root / 'build_issue3_amd64_curl_build_02/artifact/urbit')
    validate_binary(binary)
    if stat.S_IMODE((root / 'build_issue3_amd64_curl_build_02/artifact/urbit').stat().st_mode) != 0o555:
        raise ValueError('accepted executable mode changed')
    evidence = {name: read_public(root / name) for name in EVIDENCE}
    if any(sha(data) != EVIDENCE[name] for name, data in evidence.items()):
        raise ValueError('accepted build/report receipt changed')
    files['candidate/urbit'] = binary
    support = {name: read_public(root / name) for name in SUPPORT}
    if sum(map(len, [*files.values(), *support.values(), *evidence.values()])) > 128 * 1024**2:
        raise ValueError('staging byte allowance exceeded')
    output.mkdir(mode=0o700)
    result = {
        'schema_version': 1, 'status': 'PREPARED_NOT_BUILT',
        'architecture': 'linux/amd64', 'image_id': None,
        'build_authorized': False, 'ship_execution_authorized': False,
        'distribution_cleared': False, 'production_preimages': PREIMAGES,
        'candidate_sha256': CANDIDATE_SHA256, 'candidate_bytes': CANDIDATE_BYTES,
        'context': {}, 'support': {}, 'evidence': {},
        'historical_notices_only': True,
    }
    for group, contents in (('context', files), ('support', support), ('evidence', evidence)):
        for name, data in sorted(contents.items()):
            mode = 0o555 if group == 'context' and name == 'candidate/urbit' else 0o644
            write_new(output / group, name, data, mode)
            result[group][name] = describe(data, mode)
    # Prepare the stream verifier's source contract without contacting Docker.
    contract = image_verifier(root).build_contract(output / 'context', read_regular=lambda _, name: files[name])
    result['selected_image_paths'] = len(contract['files'])
    result['notice_count'] = contract['notice_count']
    write_new(output, 'binding.json', (json.dumps(result, indent=2, sort_keys=True) + '\n').encode())
    verify(output, sha(read_public(output / 'binding.json')), root)
    return result


def verify(output, expected_sha256, support_root=ROOT):
    """Read back a pinned preparation; this never implies image/build acceptance."""
    output = Path(output)
    if not re.fullmatch('[0-9a-f]{64}', expected_sha256):
        raise ValueError('literal binding SHA-256 required')
    raw = read_public(output / 'binding.json')
    if sha(raw) != expected_sha256:
        raise ValueError('binding receipt changed')
    result = json.loads(raw)
    if (result['status'] != 'PREPARED_NOT_BUILT' or result['image_id'] is not None or
            result['build_authorized'] is not False or result['ship_execution_authorized'] is not False or
            result['distribution_cleared'] is not False or result['candidate_sha256'] != CANDIDATE_SHA256):
        raise ValueError('preparation must not convey execution authority or acceptance')
    context = {}
    for group in ('context', 'support', 'evidence'):
        expected_files = set(result[group])
        expected_dirs = {str(parent) for name in expected_files for parent in Path(name).parents
                         if str(parent) != '.'}
        found = set()
        for directory, dirs, files in os.walk(output / group, followlinks=False):
            for name in dirs + files:
                entry = Path(directory) / name
                relative = entry.relative_to(output / group).as_posix()
                mode = entry.lstat().st_mode
                if relative in expected_dirs and stat.S_ISDIR(mode):
                    continue
                if relative not in expected_files or not stat.S_ISREG(mode):
                    raise ValueError('unexpected preparation entry; payload not read')
                found.add(relative)
        if found != expected_files:
            raise ValueError('missing preparation file')
        for name, expected in result[group].items():
            if not re.fullmatch(r'[A-Za-z0-9_./+@-]+', name) or any(p in ('', '.', '..') for p in name.split('/')):
                raise ValueError('noncanonical preparation path')
            target = output / group / name
            data = read_public(target)
            if describe(data, stat.S_IMODE(target.stat().st_mode)) != expected:
                raise ValueError('prepared file changed')
            if group == 'context':
                context[name] = data
    for name in SUPPORT:
        if sha(read_public(Path(support_root) / name)) != result['support'][name]['sha256']:
            raise ValueError('verifier support changed; use the frozen support root')
    validate_binary(context['candidate/urbit'])
    verifier = image_verifier(support_root)
    contract = verifier.build_contract(output / 'context', read_regular=lambda _, name: context[name])
    if (contract['files']['bin/urbit']['sha256'] != CANDIDATE_SHA256 or
            len(contract['files']) != result['selected_image_paths']):
        raise ValueError('candidate image source binding changed')
    return result


def main():
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('prepare', 'verify'))
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--binding-sha256')
    args = parser.parse_args()
    if args.action == 'prepare':
        result = prepare(ROOT, args.output)
    else:
        result = verify(args.output, args.binding_sha256 or '')
    print(json.dumps({'status': result['status'], 'context_files': len(result['context']),
                      'selected_image_paths': result['selected_image_paths'],
                      'binding_sha256': sha(read_public(args.output / 'binding.json')),
                      'image_built': False, 'ship_executed': False}))


if __name__ == '__main__':
    main()
