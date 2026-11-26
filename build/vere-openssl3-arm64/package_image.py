#!/usr/bin/env python3
"""Prepare an isolated exact-candidate package context; never build or run it.

Production files and historical receipts are read-only inputs. No hash/path
runtime override is introduced. ARM guards, pins and helpers are isolated.
"""
import sys
sys.dont_write_bytecode = True
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
CANDIDATE_SHA256 = '711638a44386858d584f10d0c8891b08cf01f45af02fcfd78364055b9712d982'
CANDIDATE_BYTES = 41258080
BASE = 'alpine@sha256:e311ae748be7f56ae5cba304bc488f0786df68ee507513f654a5cc8597cffb42'
BINARY = 'build_issue3_arm64_production_build_01/artifact/urbit'
REPORT = 'build_issue3_arm64_production_report_01/result.json'
APK_LOCK = 'build/vere-openssl3-arm64/runtime-apks.json'
OFFICIAL_SHA256 = '47ad302e8934271dfc00dcdab1d553c6d6460b105e3099ff47e0e4e4231bb26d'
PREIMAGES = {
    'build/Dockerfile': '3cd45beba81c71007cb74370183dc268b8a5f020413541ff442e9a0268c1231f',
    'tools/browser-importer/runtime.py': '01e910b2eab56a2b2d2795b9a6872f70876bfc7f501482cf55daf5b2b60a6e93',
    '.dockerignore': '194a6da7d280649e083c39670e62aeddcd0a6b0b77a97848727d315a2aec8e2d',
    'build/notice-files.json': '72f94a0c531699ce01600f865c3a1c61cba5770cb397f8e0d9593268fedf647c',
    'build/vere-release.json': '5d9fc5036f55c1938c1cba75afe5e18a6fd047526797f4e216b16a441dec0537',
}
EVIDENCE = {
    'build_issue3_arm64_production_build_01/artifact/candidate.json': '87a245e756f6c0f0544deaa99c28c7c14678df5ab07edede0f941b1693374374',
    REPORT: '017c76557f9cd3017622ea39443e019beba9a4cef4e0dad400b89d075a046dee',
}
SUPPORT_PREIMAGES = {
    'tools/local-candidate/verify_image.py': '016e14d9149e7bba9665b09637385578b5d2b576a6e6f4dac71f1f9649a3b656',
    'scripts/inventory-public-image.py': '486525665591f4a24bb45ee2e8e86a7c969d5f3cedb614eafe4fcef64a5d4bc0',
    'scripts/verify-notice-packaging.py': '407611d01647f308bbf38fdd445036ceb1ee7db3254cdbcaec70be2c8b7dd0d0',
    APK_LOCK: '208ca276dc0f42f7f32ae74877788b86b4cc8b9cba59b4958e415a2f9e9f0f4e',
}
SUPPORT = ('build/vere-openssl3-arm64/package_image.py', *SUPPORT_PREIMAGES)
MAX_FILE = 48 * 1024**2


def sha(data):
    return hashlib.sha256(data).hexdigest()


def load(root, name):
    """Read helper bytes without following any path component; never emit pyc."""
    from types import ModuleType
    data = read_public(Path(root) / name)
    if name in SUPPORT_PREIMAGES and sha(data) != SUPPORT_PREIMAGES[name]:
        raise ValueError('reviewed verifier support preimage changed')
    module = ModuleType('isolated_' + Path(name).stem)
    module.__file__ = str(Path(root) / name)
    exec(compile(data, module.__file__, 'exec'), module.__dict__)
    return module


def replace_once(data, old, new):
    if data.count(old) != 1:
        raise ValueError('unique reviewed substitution required')
    return data.replace(old, new)


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
    verifier = _image_verifier(root, arm64=False)
    contract = verifier.build_contract(root, read_regular=lambda _, name: files[name])
    names = {entry['source'] for entry in contract['files'].values()}
    names.update(('.dockerignore', 'build/Dockerfile'))
    files = {name: files[name] for name in sorted(names)}
    adapter = files['tools/browser-importer/runtime.py']
    if adapter.count(OFFICIAL_SHA256.encode()) != 1:
        raise ValueError('unique adapter guard required')
    adapter = adapter.replace(OFFICIAL_SHA256.encode(), CANDIDATE_SHA256.encode())
    adapter = replace_once(adapter, b'pinned official AMD64 binary', b'pinned source-built ARM64 binary')
    adapter = replace_once(adapter, b'            digest = hashlib.sha256()\n',
        b"            header = os.pread(fd, 64, 0)\n"
        b"            if (len(header) != 64 or header[:6] != b'\\x7fELF\\x02\\x01' or\n"
        b"                    int.from_bytes(header[18:20], 'little') != 183 or\n"
        b"                    not sys.platform.startswith('linux') or os.uname().machine != 'aarch64'):\n"
        b"                raise ValueError()\n"
        b"            digest = hashlib.sha256()\n")
    files['tools/browser-importer/runtime.py'] = adapter
    recipe = files['build/Dockerfile'].decode()
    first, final = recipe.split('\nFROM ')
    base = BASE
    # Keep final-stage package/user/entrypoint/volume/network defaults untouched.
    first = (f'FROM --platform=linux/arm64 {base} AS vere-release\n'
             '# Local source-built candidate; hash only, never execute Vere.\n'
             'COPY --chown=0:0 candidate/urbit /out/urbit\n'
             f"RUN echo '{CANDIDATE_SHA256}  /out/urbit' | sha256sum -c - "
             '&& chmod 0555 /out/urbit\n')
    final = replace_once(final, final.splitlines()[0], '--platform=linux/arm64 ' + BASE)
    lock_raw = read_public(root / APK_LOCK)
    if sha(lock_raw) != SUPPORT_PREIMAGES[APK_LOCK]:
        raise ValueError('runtime APK lock changed')
    lock = json.loads(lock_raw)
    old_pins = 'zlib=1.3.2-r1 python3=3.14.8-r0 openssl=3.5.9-r0 nginx=1.30.6-r0'
    new_pins = ' '.join(name + '=' + lock['packages'][name]['V'] for name in ('zlib', 'python3', 'openssl', 'nginx'))
    final = replace_once(final, old_pins, new_pins)
    final = replace_once(final, '# Preserve the accepted candidate\'s dependency pins; no runtime upgrade here.',
                         '# ARM APK identities from the bound official v3.24 aarch64 index; Python differs.')
    final = final.replace('\n', '\nLABEL io.uvm.candidate="issue-3-arm64-production-build-01" '
                          'io.uvm.distribution-cleared="false"\n', 1)
    files['build/Dockerfile'] = (first + '\nFROM ' + final).encode()
    files['build/vere-release.json'] = (json.dumps({
        'candidate': 'vere-4.6-uvm-openssl-3.5.9-arm64', 'architecture': 'linux/arm64',
        'executable_bytes': CANDIDATE_BYTES, 'executable_sha256': CANDIDATE_SHA256,
        'official_release': False, 'distribution_cleared': False,
    }, indent=2) + '\n').encode()
    ignore = files['.dockerignore'].decode()
    ignore = ignore.replace('!build/install_vere.py\n', '')
    ignore = ignore.replace(notices.BEGIN,
                            '!candidate/\ncandidate/**\n!candidate/urbit\n' + notices.BEGIN)
    files['.dockerignore'] = ignore.encode()
    return files


def read_public(path, limit=MAX_FILE, *, expected_mode=None):
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
                before.st_size > limit or (expected_mode is not None and
                stat.S_IMODE(before.st_mode) != expected_mode)):
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
            data[:6] != b'\x7fELF\x02\x01' or int.from_bytes(data[18:20], 'little') != 183):
        raise ValueError('exact ARM64 production-build-01 executable required')


def _image_verifier(root, *, arm64):
    """Architecture-specific in-memory helper, from pinned nofollow-read sources."""
    from types import ModuleType
    root = Path(root)
    name = 'tools/local-candidate/verify_image.py'
    data = read_public(root / name)
    if sha(data) != SUPPORT_PREIMAGES[name]:
        raise ValueError('reviewed verifier support preimage changed')
    text = data.decode()
    parser_start = text.index("    spec = importlib.util.spec_from_file_location('candidate_public_parser'")
    parser_end = text.index('    module.MAX_STREAM =', parser_start)
    text = text[:parser_start] + "    module = _safe_load('scripts/inventory-public-image.py')\n" + text[parser_end:]
    notice_start = text.index("    spec = importlib.util.spec_from_file_location('candidate_notice_source'")
    notice_end = text.index('    if read_regular is not None:', notice_start)
    text = text[:notice_start] + "    notices = _safe_load('scripts/verify-notice-packaging.py')\n" + text[notice_end:]
    if arm64:
        text = replace_once(text, "release['architecture'] != 'linux/amd64'", "release['architecture'] != 'linux/arm64'")
        text = replace_once(text, "int.from_bytes(data[18:20], 'little') != 62", "int.from_bytes(data[18:20], 'little') != 183")

    def safe_load(helper):
        original = read_public(root / helper)
        if sha(original) != SUPPORT_PREIMAGES[helper]:
            raise ValueError('reviewed verifier support preimage changed')
        if arm64 and helper == 'scripts/inventory-public-image.py':
            original = replace_once(original, b"metadata.get('architecture') != 'amd64'",
                                    b"metadata.get('architecture') != 'arm64'")
        module = ModuleType('arm_helper_' + Path(helper).stem)
        module.__file__ = str(root / helper)
        exec(compile(original, module.__file__, 'exec'), module.__dict__)
        return module

    module: Any = ModuleType('isolated_arm64_image_verifier' if arm64 else 'isolated_production_contract')
    module.__file__ = str(root / name)
    module._safe_load = safe_load
    exec(compile(text, module.__file__, 'exec'), module.__dict__)
    module.MAX_ELF = MAX_FILE
    module.MAX_FILE = MAX_FILE
    if arm64:
        lock_raw = read_public(root / APK_LOCK)
        if sha(lock_raw) != SUPPORT_PREIMAGES[APK_LOCK]:
            raise ValueError('runtime APK lock changed')
        packages = json.loads(lock_raw)['packages']
        def verify_runtime_apks(observed):
            indexed = {item['name']: item for item in observed}
            for name, expected in packages.items():
                actual = indexed.get(name, {})
                if any(actual.get(field) != expected[key] for field, key in (
                        ('version', 'V'), ('architecture', 'A'), ('checksum', 'C'))):
                    raise ValueError('pinned ARM runtime APK identity changed')
        original_verify = module.verify_stream
        def verify_stream(source, metadata, contract):
            result = original_verify(source, metadata, contract)
            verify_runtime_apks(result['packages'])
            return result
        module.verify_runtime_apks = verify_runtime_apks
        module.verify_stream = verify_stream
    return module


def image_verifier(root=ROOT):
    return _image_verifier(root, arm64=True)


def validate_evidence(evidence):
    if set(evidence) != set(EVIDENCE) or any(sha(data) != EVIDENCE[name] for name, data in evidence.items()):
        raise ValueError('accepted build/report receipt changed')
    candidate = json.loads(evidence['build_issue3_arm64_production_build_01/artifact/candidate.json'])
    report = json.loads(evidence[REPORT])
    if (candidate['architecture'] != 'linux/arm64' or candidate['executable_sha256'] != CANDIDATE_SHA256 or
            candidate['executable_bytes'] != CANDIDATE_BYTES or report['status'] != 'PASS' or
            report['error'] is not None or report['executable_sha256_before'] != CANDIDATE_SHA256 or
            report['executable_sha256_after'] != CANDIDATE_SHA256 or
            report['linked_openssl_3_5_9'] is not True or report['compiled_headers_3_5_9'] is not True or
            report['ship_booted'] is not False or report['state'] != {
                'status': 'exited', 'running': False, 'exit_code': 0, 'oom_killed': False}):
        raise ValueError('exact passed ARM64 report required')


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
    binary = read_public(root / BINARY, expected_mode=0o555)
    validate_binary(binary)
    evidence = {name: read_public(root / name) for name in EVIDENCE}
    validate_evidence(evidence)
    files['candidate/urbit'] = binary
    support = {name: read_public(root / name) for name in SUPPORT}
    if sum(map(len, [*files.values(), *support.values(), *evidence.values()])) > 128 * 1024**2:
        raise ValueError('staging byte allowance exceeded')
    output.mkdir(mode=0o700)
    result = {
        'schema_version': 1, 'status': 'PREPARED_NOT_BUILT',
        'architecture': 'linux/arm64', 'image_id': None,
        'build_authorized': False, 'ship_execution_authorized': False,
        'distribution_cleared': False, 'production_preimages': PREIMAGES,
        'candidate_sha256': CANDIDATE_SHA256, 'candidate_bytes': CANDIDATE_BYTES,
        'context': {}, 'support': {}, 'evidence': {},
        'historical_notices_only': True,
        'base': BASE, 'runtime_apks_sha256': SUPPORT_PREIMAGES[APK_LOCK],
        'report_sha256': EVIDENCE[REPORT], 'elf_machine': 183,
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
            result['distribution_cleared'] is not False or result['candidate_sha256'] != CANDIDATE_SHA256 or
            result['architecture'] != 'linux/arm64' or result['candidate_bytes'] != CANDIDATE_BYTES or
            result['base'] != BASE or result['elf_machine'] != 183 or result['report_sha256'] != EVIDENCE[REPORT]):
        raise ValueError('preparation must not convey execution authority or acceptance')
    if set(os.listdir(output)) != {'binding.json', 'context', 'support', 'evidence'}:
        raise ValueError('unexpected preparation root entry')
    context, evidence = {}, {}
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
            data = read_public(target, expected_mode=expected['mode'])
            if describe(data, expected['mode']) != expected:
                raise ValueError('prepared file changed')
            if group == 'context':
                context[name] = data
            elif group == 'evidence':
                evidence[name] = data
    for name in SUPPORT:
        if sha(read_public(Path(support_root) / name)) != result['support'][name]['sha256']:
            raise ValueError('verifier support changed; use the frozen support root')
    validate_evidence(evidence)
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
