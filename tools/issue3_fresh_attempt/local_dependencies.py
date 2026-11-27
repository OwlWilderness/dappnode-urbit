"""Three naked tarballs only; independent check plus real Zig cache insertion.

Zig 0.15.2 src/Package/Fetch.zig path_or_url/runResource/computeHash and
src/main.zig cmdFetch. Archive digest is NOT its Zig package identity.
"""
import base64
import hashlib
import json
from pathlib import Path, PurePosixPath
import struct
import subprocess
import tarfile

PINS = {
    'softblas': (3089655, '1fc6c978708982d2f50405670b6fb6b1344936b22935d0037724c8de0fbfffbc', 'N-V-__8AAJD5MgBhfBHYae8jFlcaQw9R-TRw4tcUFB3rO9-q', 'ext/softblas/build.zig.zon', 'https://github.com/urbit/SoftBLAS/archive/cbffb33f19ea02f9ffbd184d445123c57929ec53.tar.gz'),
    'pdjson': (11577, '928913d44d9021d69c0d23a8f59ed67028e5abf1ae7910f79c23a7af4e779b92', 'N-V-__8AADC9AACneJx7RTm9Hui7GCYJ2Qdv8Z_CUCbJphyi', 'ext/pdjson/build.zig.zon', 'https://github.com/skeeto/pdjson/archive/67108d883061043e55d0fb13961ac1b6fc8a485c.tar.gz'),
    'backtrace': (683836, '609c17352ec38eaf5ff6618fcbfb38cd8fa0e94a15a0d9aa259df514bbf47fcd', 'N-V-__8AADzSKgBaRtVnvQd2FZXVZ4ehq7SHwyHiBL8xSONl', 'ext/backtrace/build.zig.zon', 'https://github.com/ianlancetaylor/libbacktrace/archive/4ead348bb45f753121ca0bd44170ff8352d4c514.tar.gz'),
}


def regular(path):
    path = Path(path).absolute()
    if path.resolve() != path or not path.is_file():
        raise ValueError('missing/nonregular local input: ' + str(path))
    return path


def verify_openssl(cache, openssl):
    expected = {
        Path(openssl)/'libcrypto.a': 'fbb59550719a1fe746cf821e8b71f5992169cd4d62c2222e303451c85968b018',
        Path(openssl)/'libssl.a': '88d69a5a6bcf54b4008915ce995f3e5ef01f4cc61bc3a194caad2805cdffe08e',
        Path(cache)/'openssl-cache.json': 'cbad8432cfdfda00f90b3ab85d0455961ab077ec86d463dbe8a65187bbed8b69',
    }
    for path, digest in expected.items():
        try:
            actual = hashlib.sha256(regular(path).read_bytes()).hexdigest()
        except ValueError as error:
            raise ValueError('OpenSSL retained input missing/nonregular') from error
        if actual != digest:
            raise ValueError('OpenSSL retained archive/cache hash mismatch')


def package_hash(path):
    rows, roots, total = {}, set(), 0
    with tarfile.open(path, 'r:gz') as archive:
        for index, m in enumerate(archive):
            if index >= 4096:
                raise ValueError('tar entry bound')
            p = PurePosixPath(m.name)
            if p.is_absolute() or '..' in p.parts or not p.parts:
                raise ValueError('unsafe tar path')
            roots.add(p.parts[0])
            if m.isdir():
                continue
            name = '/'.join(p.parts[1:])
            if not m.isfile() or not name or name in rows or name == 'build.zig.zon' or m.size > 32*1024**2:
                raise ValueError('unsupported naked package entry')
            stream = archive.extractfile(m)
            if stream is None:
                raise ValueError('missing archive member')
            data = stream.read(32*1024**2+1)
            total += len(data)
            if len(data) != m.size or total > 64*1024**2:
                raise ValueError('tar byte bound')
            rows[name] = hashlib.sha256(name.encode()+b'\0\0'+data).digest()
    if len(roots) != 1 or not rows:
        raise ValueError('single nonempty package root required')
    digest = hashlib.sha256(b''.join(rows[n] for n in sorted(rows))).digest()
    return 'N-V-' + base64.urlsafe_b64encode(struct.pack('<II', 0xffff, total)+digest[:25]).decode().rstrip('=')


def verify(folder):
    result = {}
    for name, (size, digest, pin, _, _) in PINS.items():
        path = regular(Path(folder)/(name+'.tar.gz'))
        if path.stat().st_size != size or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise ValueError('dependency archive hash/size mismatch: ' + name)
        if package_hash(path) != pin:
            raise ValueError('dependency Zig hash mismatch: ' + name)
        result[name] = dict(bytes=size, sha256=digest, zig_hash=pin)
    return result


def seed(folder, zig, output, source, runner=subprocess.check_output):
    verified = verify(folder)
    cache = Path(output)/'zig-cache'
    # Never trust an existing tree by filename. Zig itself trusts cache hits.
    if cache.exists() or cache.is_symlink():
        raise ValueError('local Zig cache must be fresh')
    for name, (_, _, pin, manifest, url) in PINS.items():
        text = regular(Path(source)/manifest).read_text()
        if text.count('"'+pin+'"') != 1 or text.count('"'+url+'"') != 1:
            raise ValueError('original URL/package pin mismatch: ' + name)
    cache.mkdir()
    if runner([str(zig), 'version'], text=True, timeout=15).strip() != '0.15.2':
        raise ValueError('pinned Zig version mismatch')
    for name, (_, _, pin, _, _) in PINS.items():
        cmd = [str(zig), 'fetch', '--global-cache-dir', str(cache), str(Path(folder)/(name+'.tar.gz'))]
        actual = runner(cmd, text=True, timeout=120).strip()
        if actual != pin or not (cache/'p'/pin).is_dir():
            raise ValueError('target Zig package identity/cache mismatch: ' + name)
    regular(Path(output)/'inputs.json')
    (Path(output)/'local-dependencies.json').write_text(json.dumps(dict(
        packages=verified, actual_zig_fetch=True, original_manifest_pins_unchanged=True), indent=2)+'\n')
    return verified
