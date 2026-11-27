"""Nonexecuting probe preparation. No compiler, process, engine or TLS calls."""
from pathlib import Path
import hashlib
import json
import re
from typing import Any

HERE = Path(__file__).resolve().parent
B04_SHA = 'f2eba68682650ab6d9712017781612f4dbc3c01411c1ba5c7c4ecbb0f186b6b5'
B04_BYTES = 42467624
MODES = ('crypto', 'tls12', 'tls13', 'tls12-wronghost', 'tls13-wronghost',
         'tls12-untrusted', 'tls13-untrusted')
MAX_MANIFEST = 1048576
MAX_FILES = 2048
MAX_FILE = 67108864
MAX_TOTAL = 167772160
FAULTS = ('none', 'init', 'sha', 'siv', 'cert', 'ctx', 'ca', 'ssl', 'bio')


def require(ok, message):
    if not ok:
        raise ValueError(message)


def prepare(root, manifest: Any):
    """Validate an explicit PUBLIC staged tree; never extract, compile or run.

    Hash binding is not provenance authentication. The opaque dependency
    contract is recorded only, pending the other worker's independent review.
    """
    require(type(manifest) is dict, 'manifest object')
    require(len(json.dumps(manifest).encode()) <= MAX_MANIFEST, 'manifest byte limit')
    root = Path(root)
    require(root.is_absolute() and root.is_dir() and root == root.resolve(), 'canonical absolute root')
    require(set(manifest) == {'schema', 'evidence_scope', 'candidate_sha256',
        'candidate_bytes', 'final_link_authenticated', 'files'}, 'manifest fields')
    require(manifest['schema'] == 'issue3-b04-probe-input-v1' and
            manifest['evidence_scope'] == 'retained-library-only' and
            manifest['candidate_sha256'] == B04_SHA and
            type(manifest['candidate_bytes']) is int and manifest['candidate_bytes'] == B04_BYTES and
            manifest['final_link_authenticated'] is False, 'retained b04 scope only')
    files = manifest['files']
    require(type(files) is list and 1 <= len(files) <= MAX_FILES, 'file count limit')
    seen, roles, total = set(), {}, 0
    for f in files:
        require(type(f) is dict and set(f) == {'path', 'sha256', 'bytes', 'role'}, 'file fields')
        name, role = f['path'], f['role']
        require(type(name) is str and re.fullmatch(r'[A-Za-z0-9_./-]{1,240}', name) and
                all(n not in ('', '.', '..') for n in name.split('/')) and
                not name.startswith('/') and name not in seen, 'unique relative path')
        require(type(role) is str and role in ('libssl', 'libcrypto', 'libaes_siv', 'siv_header', 'arena_c', 'arena_h',
            'arena_engine', 'header', 'config', 'build_config', 'dependency_contract'), 'file role')
        require(type(f['bytes']) is int and 0 < f['bytes'] <= MAX_FILE and
            type(f['sha256']) is str and re.fullmatch('[a-f0-9]{64}', f['sha256']), 'file size/hash')
        total += f['bytes']
        require(total <= MAX_TOTAL, 'total byte limit')
        p = root / name
        require(p == p.resolve() and p.is_file(), 'regular nonsymlink input')
        require(p.stat().st_size == f['bytes'], 'input size drift')
        h = hashlib.sha256()
        read_bytes = 0
        with p.open('rb') as stream:
            while True:
                chunk = stream.read(min(1048576, f['bytes'] - read_bytes + 1))
                if not chunk:
                    break
                read_bytes += len(chunk)
                require(read_bytes <= f['bytes'], 'input grew beyond declared size')
                h.update(chunk)
        require(read_bytes == f['bytes'] and p.stat().st_size == f['bytes'], 'input size drift during read')
        require(h.hexdigest() == f['sha256'], 'input hash drift')
        seen.add(name)
        roles.setdefault(role, []).append(name)
    exact = {'libssl':'lib/libssl.a', 'libcrypto':'lib/libcrypto.a',
        'libaes_siv':'lib/libaes_siv.a', 'siv_header':'include/aes_siv.h',
        'build_config':'config/configdata.pm',
        'arena_c':'arena/openssl_owned_arena.c', 'arena_h':'arena/openssl_owned_arena.h',
        'arena_engine':'arena/palloc_engine.inc', 'dependency_contract':'contract.json'}
    for role, name in exact.items():
        require(roles.get(role) == [name], 'required unique role: ' + role)
    require({'include/openssl/ssl.h', 'include/openssl/evp.h', 'include/openssl/opensslv.h'}
        <= set(roles.get('header', [])), 'required headers')
    require({'include/openssl/configuration.h', 'include/openssl/opensslconf.h'}
        <= set(roles.get('config', [])), 'generated configuration headers')
    require(all(n.startswith(('include/openssl/', 'include/crypto/', 'include/internal/')) and n.endswith('.h')
        for r in ('header','config') for n in roles.get(r, [])), 'header layout')
    # A staged directory is exclusively these declared files, no hidden headers,
    # compiler helpers, device nodes or symlinked directories. No cleanup here.
    actual = set()
    allowed_dirs = {parent.as_posix() for name in seen for parent in Path(name).parents if parent != Path('.')}
    for count, p in enumerate(root.rglob('*'), 1):
        require(count <= 4096, 'tree entry limit')
        require(not p.is_symlink() and (p.is_dir() or p.is_file()), 'special/symlink input')
        if p.is_file():
            actual.add(p.relative_to(root).as_posix())
        else:
            require(p.relative_to(root).as_posix() in allowed_dirs, 'undeclared staged directory')
    require(actual == seen, 'undeclared staged files')
    return dict(schema='issue3-b04-probe-plan-v1', status='PREPARED_NOT_AUTHORIZED',
        evidence_scope='retained-library-only', target_executed=False,
        final_elf_acceptance=False, dependency_contract_semantics_verified=False,
        input_sha256=hashlib.sha256(json.dumps(manifest, sort_keys=True,
            separators=(',', ':')).encode()).hexdigest(), root=str(root),
        files=files, modes=list(MODES), arena_bytes=134217728,
        source_files={name:dict(bytes=(HERE/name).stat().st_size,
            sha256=hashlib.sha256((HERE/name).read_bytes()).hexdigest())
            for name in ('probe.c','prepare.py')},
        invocations=[dict(mode=mode,fault='none') for mode in MODES] +
            [dict(mode='crypto',fault=f) for f in ('init','sha','siv')] +
            [dict(mode='tls13',fault=f) for f in ('cert','ctx','ca','ssl','bio')],
        bounds=dict(per_process_seconds=20, whole_run_seconds=330,
            stdout_bytes=16384, stderr_bytes=16384, memory_bytes=268435456,
            pids=16, cpu=1, swap_bytes=0, fault_processes=8),
        compiler_and_transport='UNBOUND: independent integration and fresh grant required')


def parse_json(text, limit):
    require(type(text) is str and len(text.encode()) <= limit, 'JSON byte limit')
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'duplicate JSON key')
            result[key] = value
        return result
    def constant(value):
        raise ValueError('nonfinite JSON')
    return json.loads(text, object_pairs_hook=pairs, parse_constant=constant)


def validate_result(stdout, returncode, expected_mode, expected_fault='none'):
    """Syntactic result/cleanup admission, not independent proof it ran.

    The later runner must bind captured bytes, exact program/inputs/transport,
    effective limits and settlement. A fixture can pass this parser.
    """
    require(expected_mode in MODES and expected_fault in FAULTS, 'expected case')
    require((expected_mode == 'crypto' and expected_fault in ('none','init','sha','siv')) or
        (expected_mode != 'crypto' and expected_fault not in ('sha','siv')), 'fault/mode pair')
    result = parse_json(stdout, 16384)
    require(type(result) is dict and set(result) == {'schema','mode','fault','status',
        'case_ok','injected','live_blocks','destroyed','allocations',
        'peak_charged_bytes','failed_line'}, 'result fields')
    require(result['schema'] == 'issue3-b04-probe-result-v1' and
        result['mode'] == expected_mode and result['fault'] == expected_fault, 'result binding')
    for key in ('case_ok','injected','live_blocks','destroyed','allocations',
                'peak_charged_bytes','failed_line'):
        require(type(result[key]) is int and 0 <= result[key] < 2**63, 'result integer')
    require(type(returncode) is int and returncode == 0, 'successful process exit')
    require(result['live_blocks'] == 0 and result['destroyed'] == 1 and
        0 < result['peak_charged_bytes'] <= 134217728 and result['allocations'] > 0,
        'cleanup/arena certificate')
    require(result['case_ok'] in (0,1) and result['injected'] in (0,1), 'result booleans')
    if expected_fault == 'none':
        require(result['status'] == 'CASE_PASS' and result['case_ok'] == 1 and
            result['injected'] == 0 and result['failed_line'] == 0, 'baseline case pass required')
    else:
        require(result['status'] == 'FAULT_OBSERVED' and result['injected'] == 1,
            'fault must actually be reached')
    return dict(result=result, evidence_scope='retained-library-only',
        baseline_case=expected_fault == 'none', final_elf_acceptance=False,
        execution_provenance_verified=False)


def main():
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True, help='exclusive staged public input directory')
    parser.add_argument('--manifest', type=Path, required=True, help='public manifest OUTSIDE staged root')
    args = parser.parse_args()
    require(args.manifest.is_file() and not args.manifest.is_symlink(), 'regular manifest')
    with args.manifest.open('rb') as stream:
        data = stream.read(MAX_MANIFEST + 1)
    require(len(data) <= MAX_MANIFEST, 'manifest byte limit')
    plan = prepare(args.root, parse_json(data.decode('utf-8'), MAX_MANIFEST))
    print(json.dumps(plan, sort_keys=True, indent=2))


if __name__ == '__main__':
    main()
