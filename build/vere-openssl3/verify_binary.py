"""Static AMD64 allocator-candidate verification; never execute the binary."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tarfile

ALLOCATOR_SHA256 = '2b06d6a006595ea7440690b325e8c994505a6040a97087e877a19c5e0c46d321'
CURL_OVERLAYS = {
    'ext/curl/build.zig': {
        'file': 'curl-build.zig',
        'sha256': '2e422b3cd0669ef3d3d028b9b104f842dbbd4061bd78593b39775fefa805c092'},
    'ext/curl/build.zig.zon': {
        'file': 'curl-build.zig.zon',
        'sha256': '5a2e9e951b89a95794550cdf5d12cb6a8a7e349f1ce76092dea4fbdd2e1a8b78'},
}


H2O_OVERLAY = {'file': 'h2o-socket.c', 'sha256': 'd61916d7de924e2337b6a73dbcd044b525bf503b11affc53fd6f6c0ca90c37b2', 'build_sha256': '174d1bd82eb826b626f06be07ee69aec0091ff958f8f14c2564b1aed593793b0', 'upstream_sha256': 'a301247dbd95f7145aa1cc3c83a720c93bf5d1d3d7a5a961846eea7dbfd8476d', 'upstream_revision': '3bbfe369a5c31d38cc1717e5281ca6af89ecf787'}

def sha(data):
    return hashlib.sha256(data).hexdigest()


def linkage(binary):
    data = binary.read_bytes()
    if data[:6] != b'\x7fELF\x02\x01' or int.from_bytes(data[18:20], 'little') != 62:
        raise ValueError('not AMD64 ELF')
    symbols = subprocess.check_output(['nm', str(binary)], text=True, timeout=60)
    if 'uvm_i3_' in symbols:
        raise ValueError('diagnostic symbols present')
    init = subprocess.check_output(['objdump', '--disassemble-symbols=u3m_init', str(binary)], text=True, timeout=60)
    if '<u3m_init>:' not in init or 'CRYPTO_set_mem_functions' in init:
        raise ValueError('OpenSSL loom allocator still registered or init missing')
    if '__gmp_set_memory_functions' not in init:
        raise ValueError('GMP allocator registration missing')
    exit_code = subprocess.check_output(['objdump', '--disassemble-symbols=exit', str(binary)], text=True, timeout=60)
    for symbol in ('<exit>:', '__funcs_on_exit', 'libc_exit_fini', '__stdio_exit_needed'):
        if symbol not in exit_code:
            raise ValueError('normal libc cleanup missing: ' + symbol)
    if ' OPENSSL_cleanup\n' not in symbols:
        raise ValueError('OpenSSL cleanup symbol absent')
    return dict(executable_sha256=sha(data), executable_bytes=len(data), architecture='linux/amd64',
                no_uvm_i3_symbols=True, openssl_loom_hook_absent_from_u3m_init=True,
                gmp_registration_retained=True, normal_libc_cleanup_retained=True,
                openssl_cleanup_linked=True, vere_executed=False)


def verify(attempt):
    artifact = attempt / 'artifact'
    frozen = attempt / 'frozen-recipe'
    result = json.loads((attempt / 'result.json').read_text())
    if result['status'] != 'PASS' or result['exit_code'] != 0 or not result['preserved'] or result['active_after']:
        raise ValueError('successful settled build required')
    binary = artifact / 'urbit'
    checked = linkage(binary)
    receipt = json.loads((artifact / 'candidate.json').read_text())
    for key in ('executable_sha256', 'executable_bytes', 'architecture'):
        if receipt[key] != checked[key]:
            raise ValueError('binary receipt mismatch: ' + key)
    if binary.stat().st_mode & 0o777 != 0o555:
        raise ValueError('binary mode mismatch')
    for name, key in (('candidate.py', 'recipe_sha256'), ('inputs.json', 'inputs_sha256'),
                      ('Dockerfile', 'dockerfile_sha256'), ('builder-apks.json', 'builder_apks_sha256')):
        if sha((artifact / name).read_bytes()) != receipt[key] or (artifact / name).read_bytes() != (frozen / name).read_bytes():
            raise ValueError('frozen recipe receipt mismatch: ' + name)
    if sha((artifact / 'builder-apk-db.txt').read_bytes()) != receipt['builder_apk_db_sha256']:
        raise ValueError('builder package database mismatch')
    lock = json.loads((artifact / 'inputs.json').read_text())
    if 'curl_version' in lock:
        if lock['curl_version'] != '8.23.0' or lock.get('curl_overlays') != CURL_OVERLAYS:
            raise ValueError('curl version or pinned overlay mapping mismatch')
        curl_changes = {name: digest for name, digest in receipt['source_changes'].items()
                        if name.startswith('ext/curl/')}
        expected_changes = {name: item['sha256'] for name, item in CURL_OVERLAYS.items()}
        if curl_changes != expected_changes:
            raise ValueError('curl source_changes must contain exactly both pinned overlays')
        for item in CURL_OVERLAYS.values():
            for directory in (frozen, artifact):
                path = directory / item['file']
                if not path.is_file() or sha(path.read_bytes()) != item['sha256']:
                    raise ValueError('curl frozen/delivered overlay mismatch: ' + str(path))
        overlay_path = artifact / 'curl-overlay.json'
        if not overlay_path.is_file():
            raise ValueError('curl overlay receipt missing')
        expected_overlay = dict(
            source_preimages={name: lock['source_preimages'][name] for name in CURL_OVERLAYS},
            source_changes=expected_changes, overlays=CURL_OVERLAYS)
        if json.loads(overlay_path.read_text()) != expected_overlay:
            raise ValueError('curl overlay receipt mismatch')
    if 'h2o_overlay' not in lock and (
            any(n.startswith('ext/h2o/') for n in receipt['source_changes']) or
            (artifact / 'h2o-overlay.json').exists() or
            any((d / 'h2o-socket.c').exists() for d in (frozen, artifact))):
        raise ValueError('H2O overlay lock binding missing')
    if 'h2o_overlay' in lock:
        item = lock['h2o_overlay']
        pinned = H2O_OVERLAY
        preimages = {'ext/h2o/build.zig': '942bad939c453827422ff413f20cc083f097f5f74927f20df3a1b6d6d6fe033d',
                     'ext/h2o/build.zig.zon': 'f34b10dac1bf01e4de26c545c55cede029bae7b86396019279eec5ea9782cb70'}
        if item != pinned or any(lock['source_preimages'].get(n) != h for n, h in preimages.items()):
            raise ValueError('H2O pinned overlay/preimage mismatch')
        expected = {'ext/h2o/build.zig': item['build_sha256'],
                    'ext/h2o/socket.c': item['sha256'],
                    'ext/h2o/build.zig.zon': preimages['ext/h2o/build.zig.zon']}
        actual = {n: h for n, h in receipt['source_changes'].items() if n.startswith('ext/h2o/')}
        if actual != expected:
            raise ValueError('H2O changed-source mapping mismatch')
        for directory in (frozen, artifact):
            path = directory / item['file']
            if not path.is_file() or sha(path.read_bytes()) != item['sha256']:
                raise ValueError('H2O frozen/delivered overlay mismatch')
        path = artifact / 'h2o-overlay.json'
        overlay = dict(overlay=item, source_changes=expected, source_preimages=preimages)
        if not path.is_file() or json.loads(path.read_text()) != overlay:
            raise ValueError('H2O overlay receipt missing or mismatched')
    if 'curl_buffer_sha256' in lock:
        if receipt['source_changes'].get('pkg/vere/king.c') != lock['curl_buffer_sha256']:
            raise ValueError('curl buffer changed-source mapping mismatch')
    if 'sha_overlay' in lock:
        item = lock['sha_overlay']
        if item.get('file') != 'sha-stack.c':
            raise ValueError('SHA overlay filename mismatch')
        expected = {'ext/urcrypt/build.zig': item['build_sha256'],
                    'ext/urcrypt/sha.c': item['sha256'],
                    'ext/urcrypt/build.zig.zon': lock['source_preimages']['ext/urcrypt/build.zig.zon']}
        if any(receipt['source_changes'].get(name) != digest for name, digest in expected.items()):
            raise ValueError('SHA changed-source mapping mismatch')
        for directory in (frozen, artifact):
            path = directory / item['file']
            if not path.is_file() or sha(path.read_bytes()) != item['sha256']:
                raise ValueError('SHA frozen/delivered overlay mismatch')
        path = artifact / 'sha-overlay.json'
        expected_overlay = dict(overlay=item, source_changes=expected,
            source_preimages={name: lock['source_preimages'][name] for name in
                              ('ext/urcrypt/build.zig', 'ext/urcrypt/build.zig.zon')})
        if not path.is_file() or json.loads(path.read_text()) != expected_overlay:
            raise ValueError('SHA overlay receipt missing or mismatched')
    if 'ca_hardening' in lock:
        expected = lock['ca_hardening']
        targets = {'pkg/vere/main.c', 'pkg/vere/vere.h', 'pkg/vere/io/cttp.c'}
        if (not isinstance(expected, dict) or set(expected) != targets or
                set(lock.get('ca_preimages', {})) != targets - {'pkg/vere/io/cttp.c'} or
                any(receipt['source_changes'].get(name) != digest
                    for name, digest in expected.items())):
            raise ValueError('CA changed-source mapping mismatch')
        path = artifact / 'ca-overlay.json'
        overlay = dict(source_preimages=lock['ca_preimages'], source_changes=expected)
        if not path.is_file() or json.loads(path.read_text()) != overlay:
            raise ValueError('CA overlay receipt missing or mismatched')
    if 'allocation_hardening' in lock:
        expected = lock['allocation_hardening']
        targets = {'pkg/vere/io/cttp.c', 'pkg/vere/io/http.c'}
        if (not isinstance(expected, dict) or set(expected) != targets or
                any(receipt['source_changes'].get(name) != digest
                    for name, digest in expected.items())):
            raise ValueError('allocation changed-source mapping mismatch')
        path = artifact / 'allocation-overlay.json'
        overlay = dict(source_preimages={name: lock['source_preimages'][name] for name in targets},
                       source_changes=expected)
        if not path.is_file() or json.loads(path.read_text()) != overlay:
            raise ValueError('allocation overlay receipt missing or mismatched')
    prefix = lock['inputs']['vere']['root'] + '/'
    with tarfile.open(artifact / 'source-materials.tar.gz') as archive:
        members = archive.getmembers()
        for relative, expected in receipt['source_changes'].items():
            matches = [m for m in members if m.name == prefix + relative]
            if len(matches) > 1:
                raise ValueError('duplicate archived changed-source member')
            member = archive.getmember(prefix + relative)
            if not member.isfile() or member.size > 2 * 1024**2:
                raise ValueError('public source member type/size')
            stream = archive.extractfile(member)
            assert stream is not None
            if sha(stream.read()) != expected:
                raise ValueError('archived changed-source mismatch')
    if receipt['source_changes'].get('pkg/noun/manage.c') != ALLOCATOR_SHA256:
        raise ValueError('allocator source differs from reviewed correction')
    checked.update(source_receipts_verified=True, frozen_recipe_verified=True,
                   allocator_source_sha256=ALLOCATOR_SHA256, status='PASS')
    return checked


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--attempt', type=Path)
    mode.add_argument('--linkage-only', type=Path)
    args = parser.parse_args()
    print(json.dumps(verify(args.attempt) if args.attempt else linkage(args.linkage_only), indent=2))
