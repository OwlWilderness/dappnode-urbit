"""Separate static owned-OpenSSL AMD64 verifier. Never executes Vere.

The baseline default-heap verifier is retained unchanged under baseline/.
No historical/default-heap acceptance is broadened by this verifier.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tarfile

HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location('owned_verify_support', HERE / 'owned_support.py')
assert _spec is not None and _spec.loader is not None
owned = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(owned)

BASE_CHANGED = {
    'build.zig', 'pkg/vere/main.c', 'pkg/vere/king.c', 'pkg/noun/manage.c',
    'pkg/vere/vere.h', 'pkg/vere/io/cttp.c', 'pkg/vere/io/http.c',
    'ext/openssl/build.zig', 'ext/openssl/build.zig.zon',
    'ext/urcrypt/build.zig', 'ext/urcrypt/build.zig.zon', 'ext/urcrypt/sha.c',
    'ext/h2o/build.zig', 'ext/h2o/build.zig.zon', 'ext/h2o/socket.c',
    'ext/curl/build.zig', 'ext/curl/build.zig.zon', 'ext/gmp/build.zig.zon',
    'ext/sigsegv/build.zig.zon', 'ext/natpmp/build.zig.zon'}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def linkage(binary):
    data = Path(binary).read_bytes()
    if data[:6] != b'\x7fELF\x02\x01' or int.from_bytes(data[18:20], 'little') != 62:
        raise ValueError('not AMD64 ELF')
    symbols = subprocess.check_output(['nm', str(binary)], text=True, timeout=60)
    if 'uvm_i3_' in symbols:
        raise ValueError('diagnostic symbols present')
    required = ('u3_openssl_owned_start', 'u3_openssl_owned_seal', 'u3_openssl_arena_init',
        'u3_openssl_arena_malloc', 'u3_openssl_arena_realloc', 'u3_openssl_arena_free',
        'u3_openssl_arena_live_blocks', 'u3_openssl_arena_destroy',
        'u3_ssl_shutdown_run', 'u3_h2o_openssl_shutdown', 'OPENSSL_cleanup',
        '__gmp_set_memory_functions', 'u3_openssl_arena_snapshot',
        'u3_arena_measure_startup',
        'u3_arena_measure_phase', 'u3_arena_measure_destroyed')
    names = {line.split()[-1] for line in symbols.splitlines() if line.split()}
    if not set(required) <= names:
        raise ValueError('owned allocator/cleanup/GMP symbol missing')
    def disassemble(name):
        text = subprocess.check_output(['objdump', '--disassemble-symbols=' + name, str(binary)],
                                       text=True, timeout=60)
        if '<' + name + '>:' not in text:
            raise ValueError('required disassembly missing: ' + name)
        return text
    start = disassemble('u3_openssl_owned_start')
    for name in ('CRYPTO_set_mem_functions', 'u3_openssl_arena_init',
                 'u3_openssl_arena_malloc', 'u3_openssl_arena_realloc', 'u3_openssl_arena_free',
                 'u3_arena_measure_startup'):
        if name not in start:
            raise ValueError('owned callback registration absent: ' + name)
    init = disassemble('u3m_init')
    if '__gmp_set_memory_functions' not in init:
        raise ValueError('GMP allocator registration missing')
    if 'u3_openssl_owned_start' not in init and 'u3_openssl_owned_start' not in disassemble('_cm_crypto'):
        raise ValueError('owned startup not reachable from crypto initialization')
    exit_code = disassemble('exit')
    if any(n not in exit_code for n in ('__funcs_on_exit', 'libc_exit_fini', '__stdio_exit_needed')):
        raise ValueError('normal libc cleanup missing')
    return dict(executable_sha256=sha(data), executable_bytes=len(data), architecture='linux/amd64',
                owned_callbacks_registered=True, gmp_registration_retained=True,
                normal_libc_cleanup_retained=True, openssl_cleanup_linked=True, vere_executed=False)


def verify_sources(artifact, frozen):
    artifact, frozen = Path(artifact), Path(frozen)
    manifest = owned.validate_recipe(frozen)
    receipt = json.loads((artifact / 'candidate.json').read_text())
    overlay = json.loads((artifact / 'owned-overlay.json').read_text())
    if (artifact / 'owned-recipe.json').read_bytes() != (frozen / 'owned-recipe.json').read_bytes():
        raise ValueError('frozen recipe manifest mismatch')
    # Root H2O payload is intentionally replaced by its final owned source.
    # The baseline exact original remains under baseline/h2o-socket.c.
    for name, digest in manifest['files'].items():
        expected = overlay['source_changes']['ext/h2o/socket.c'] if name == 'h2o-socket.c' else digest
        if sha(owned.regular(artifact, name).read_bytes()) != expected:
            raise ValueError('frozen/delivered recipe input mismatch: ' + name)
    binding = owned.build_bindings(artifact)
    if any(receipt.get(k) != v for k, v in binding.items()):
        raise ValueError('owned candidate binding mismatch')
    if (overlay.get('schema_version') != 1 or overlay.get('strategy') != 'process-owned-palloc-adaptation' or
            overlay.get('recipe_manifest_sha256') != binding['owned_recipe_manifest_sha256'] or
            overlay.get('preimages_sha256') != binding['owned_preimages_sha256'] or
            overlay.get('baseline_receipts_scope') != 'intermediate-hardening-only-not-final-source'):
        raise ValueError('owned overlay binding/scope mismatch')
    expected = owned.replay_expected(frozen, artifact / 'owned-preimages.json', overlay['arena_bytes'])
    if overlay['source_changes'] != expected:
        raise ValueError('owned source receipt mismatch')
    changes = receipt['source_changes']
    if set(changes) != BASE_CHANGED | set(expected) or any(changes.get(n) != h for n, h in expected.items()):
        raise ValueError('final source mapping incomplete/mismatched')
    lock = json.loads((frozen / 'inputs.json').read_text())
    baseline_expected = {n: item['sha256'] for n, item in lock['curl_overlays'].items()}
    baseline_expected.update({
        'ext/h2o/build.zig': lock['h2o_overlay']['build_sha256'],
        'ext/h2o/build.zig.zon': lock['source_preimages']['ext/h2o/build.zig.zon'],
        'ext/urcrypt/build.zig': lock['sha_overlay']['build_sha256'],
        'ext/urcrypt/sha.c': lock['sha_overlay']['sha256'],
        'ext/urcrypt/build.zig.zon': lock['source_preimages']['ext/urcrypt/build.zig.zon']})
    for name, digest in baseline_expected.items():
        if changes.get(name) != digest:
            raise ValueError('retained baseline hardening mismatch: ' + name)
    for name, digest in overlay['baseline_intermediate_receipts'].items():
        if not name.startswith('baseline-') or '/' in name or sha(owned.regular(artifact, name).read_bytes()) != digest:
            raise ValueError('baseline intermediate receipt mismatch')
    h2o = json.loads((artifact / 'h2o-overlay.json').read_text())
    if h2o != dict(scope='final-owned', source_changes={n: h for n, h in changes.items() if n.startswith('ext/h2o/')},
                   socket_sha256=expected['ext/h2o/socket.c']):
        raise ValueError('final H2O receipt mismatch')
    prefix = lock['inputs']['vere']['root'] + '/'
    with tarfile.open(artifact / 'source-materials.tar.gz') as archive:
        members = archive.getmembers()
        for name, digest in changes.items():
            matches = [m for m in members if m.name == prefix + name]
            if len(matches) != 1 or not matches[0].isfile() or matches[0].size > 2 * 1024**2:
                raise ValueError('missing/duplicate/nonregular archived source: ' + name)
            stream = archive.extractfile(matches[0])
            assert stream is not None
            with stream:
                if sha(stream.read()) != digest:
                    raise ValueError('archived source receipt mismatch: ' + name)
    return dict(status='PASS', source_receipts_verified=True, frozen_recipe_verified=True,
                owned_arena_bytes=overlay['arena_bytes'], source_files=len(changes), vere_executed=False)


def verify(attempt):
    attempt = Path(attempt)
    result = json.loads((attempt / 'result.json').read_text())
    if (result.get('status') != 'PASS' or result.get('exit_code') != 0 or
            not result.get('preserved') or result.get('active_after')):
        raise ValueError('successful settled build required')
    artifact = attempt / 'artifact'
    checked = linkage(artifact / 'urbit')
    receipt = json.loads((artifact / 'candidate.json').read_text())
    for key in ('executable_sha256', 'executable_bytes', 'architecture'):
        if checked[key] != receipt.get(key):
            raise ValueError('binary receipt mismatch: ' + key)
    if (artifact / 'urbit').stat().st_mode & 0o777 != 0o555:
        raise ValueError('binary mode mismatch')
    for name, key in (('candidate.py', 'recipe_sha256'), ('inputs.json', 'inputs_sha256'),
        ('Dockerfile', 'dockerfile_sha256'), ('builder-apks.json', 'builder_apks_sha256'),
        ('builder-apk-db.txt', 'builder_apk_db_sha256')):
        if sha(owned.regular(artifact, name).read_bytes()) != receipt.get(key):
            raise ValueError('build receipt mismatch: ' + name)
    checked.update(verify_sources(artifact, attempt / 'frozen-recipe'))
    return checked


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--attempt', type=Path)
    mode.add_argument('--linkage-only', type=Path)
    args = parser.parse_args()
    print(json.dumps(verify(args.attempt) if args.attempt else linkage(args.linkage_only), indent=2))
