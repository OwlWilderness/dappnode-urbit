"""Read-only b04 dependency evidence contract; never executes target code."""
import json
import hashlib
import re
import stat
import struct
import tarfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
ATTEMPT = Path('/tmp/issue3-owned-trial-20261030-b04-observed')
SCHEMA = 'issue3-b04-dependency-contract-v1'
BINARY_PIN = {'bytes': 42467624, 'sha256': 'f2eba68682650ab6d9712017781612f4dbc3c01411c1ba5c7c4ecbb0f186b6b5'}
BUILD_RECEIPT = 'docs/openssl-candidate-evidence/instrumented-b04-20261030.json'
REPORT_RECEIPT = 'docs/openssl-candidate-evidence/owned-b04-report-20261030.json'
BUILD_PIN = {'bytes': 27757, 'sha256': '69b47ee85ef1b24b8604990c0d5044386d98ac1a2049f1d9b88fd3490df448a1'}
REPORT_PIN = {'bytes': 19480, 'sha256': '6c8650dec16390f800ace04414c750e213055fd81950addb2465ee07e8a94d4d'}
REQUIRED_LIBRARIES = ('libcrypto.a', 'libssl.a', 'libcurl.a', 'libgmp.a', 'liblibuv.a', 'libh2o.a', 'liblmdb.a')


def require(ok, message):
    if not ok:
        raise ValueError(message)


def identity(data):
    return {'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}


def read_pin(root, name, pin):
    relative(name)
    validate_pin(pin)
    path = Path(root)
    require(not path.is_symlink(), 'symlink public input root')
    for part in name.split('/'):
        path = path / part
        if path.is_symlink():
            raise ValueError('symlink public input: ' + name)
    if not stat.S_ISREG(path.stat().st_mode):
        raise ValueError('nonregular public input: ' + name)
    if path.stat().st_size != pin['bytes']:
        raise ValueError('size mismatch: ' + name)
    data = path.read_bytes()
    if len(data) != pin['bytes'] or hashlib.sha256(data).hexdigest() != pin['sha256']:
        raise ValueError('hash mismatch: ' + name)
    return data


def relative(name):
    if (not isinstance(name, str) or not name or '\\' in name or
            any(p in ('', '.', '..') for p in name.split('/')) or
            any(ord(c) < 32 or ord(c) > 126 for c in name)):
        raise ValueError('noncanonical relative identity')
    return name


def validate_pin(pin):
    if (not isinstance(pin, dict) or type(pin.get('bytes')) is not int or pin['bytes'] < 0 or
            not isinstance(pin.get('sha256'), str) or not re.fullmatch('[0-9a-f]{64}', pin['sha256'])):
        raise ValueError('malformed size/hash pin')
    return pin


def strict_json(text):
    """Decode JSON without silently overwriting duplicate identifiers."""
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError('duplicate JSON key: ' + key)
            result[key] = value
        return result
    def constant(value):
        raise ValueError('nonfinite JSON constant: ' + value)
    value = json.loads(text, object_pairs_hook=pairs, parse_constant=constant)
    require(isinstance(value, dict), 'receipt JSON object required')
    return value


def report_versions(text):
    """Parse the exact no-state public report, not a version substring in logs."""
    require(isinstance(text, str) and len(text) < 8192, 'public report shape')
    lines = text.splitlines()
    require(bool(lines) and lines[0] == 'urbit 4.6-uvm-openssl3.5.9', 'b04 report banner')
    versions = {}
    for line in lines[1:]:
        match = re.fullmatch(r'([a-z0-9-]+): ([^\r\n]+)', line)
        require(match is not None, 'malformed report line')
        assert match is not None
        key, value = match.groups()
        require(key not in versions, 'duplicate report field: ' + key)
        versions[key] = value
    expected = {'gmp': '6.2.1', 'sigsegv': '2.14',
                'openssl': 'OpenSSL 3.5.9 29 Sep 2026',
                'openssl-headers': 'OpenSSL 3.5.9 29 Sep 2026',
                'curl-linked': '8.23.0', 'curl-headers': '8.23.0',
                'libuv': '1.50.0', 'libh2o': '0.13.6', 'lmdb': '0.9.70', 'curl': '8.23.0'}
    require(versions == expected, 'missing/mismatched dependency report')
    return versions


def validate_receipts(build, report, result, candidate):
    """Semantic validation; callers must authenticate receipt bytes first."""
    require(build.get('schema') == 'issue3-instrumented-b04-result-v1' and
            build.get('attempt') == 'issue3-owned-20261030-b04', 'b04 build receipt schema/attempt')
    require(result.get('status') == 'COMPILE_PASS' and result.get('attempt') == build['attempt'] and
            type(result.get('build_exit_code')) is int and result['build_exit_code'] == 0 and
            all(result.get(k) is True for k in ('build_launched', 'settled', 'artifact_complete')) and
            result.get('error') is None, 'successful settled b04 build required')
    require(report.get('schema') == 'issue3-owned-b04-report-qualification-v1' and
            report.get('status') == 'REPORT_PASS' and report.get('report_only') is True and
            type(report.get('target_invocations')) is int and report['target_invocations'] == 1 and
            report.get('authenticated_final_link_inputs') is False, 'owned b04 report schema/scope')
    require({k: report.get('artifact', {}).get(k) for k in BINARY_PIN} == BINARY_PIN,
            'old/substituted report artifact')
    observed = report.get('result', {})
    require(observed.get('schema') == 'issue3-owned-report-v1' and observed.get('status') == 'PASS' and
            type(observed.get('client_exit_code')) is int and observed['client_exit_code'] == 0 and
            all(observed.get(k) == BINARY_PIN['sha256'] for k in
                ('executable_sha256_before', 'executable_sha256_after')) and
            observed.get('ship_booted') is False, 'successful exact-ELF report required')
    state = observed.get('state', {})
    require(state.get('status') == 'exited' and state.get('running') is False and
            type(state.get('pid')) is int and state['pid'] == 0 and
            type(state.get('exit_code')) is int and state['exit_code'] == 0 and
            state.get('oom_killed') is False, 'settled report required')
    require(candidate.get('architecture') == 'linux/amd64' and
            candidate.get('executable_sha256') == BINARY_PIN['sha256'] and
            type(candidate.get('executable_bytes')) is int and
            candidate['executable_bytes'] == BINARY_PIN['bytes'], 'old/substituted candidate artifact')
    return report_versions(report.get('public_report'))


def validate_libraries(artifact, manifest):
    require(type(manifest.get('schema')) is int and manifest['schema'] == 1 and
            manifest.get('authenticated_final_link_inputs') is False and
            manifest.get('headers_and_adapters') == 'source-materials.tar.gz', 'retained library scope/schema')
    files = manifest.get('files')
    require(isinstance(files, dict) and bool(files), 'missing public library inventory')
    folded = set()
    for name, pin in files.items():
        relative(name)
        require(name.startswith('public-libraries/'), 'public library namespace')
        require(name.casefold() not in folded, 'duplicate portable library identity')
        folded.add(name.casefold())
        read_pin(artifact, name, pin)
    require('public-libraries/openssl/configdata.pm' in files, 'OpenSSL config identity missing')
    for name in REQUIRED_LIBRARIES:
        require(any(Path(n).name == name for n in files), 'missing required retained library: ' + name)
    return {'files': files, 'bytes': sum(p['bytes'] for p in files.values()),
            'authenticated_final_link_inputs': False,
            'by_basename': {name: sorted(n for n in files if Path(n).name == name)
                            for name in REQUIRED_LIBRARIES}}


def archive_members(archive, required):
    """Read selected public members once; no extraction or symlink following."""
    selected = {}
    folded = set()
    for member in archive:
        if member.name not in required:
            continue
        relative(member.name)
        require(member.name not in selected, 'duplicate archive identity: ' + member.name)
        require(member.name.casefold() not in folded, 'duplicate portable archive identity: ' + member.name)
        folded.add(member.name.casefold())
        require(member.isfile() and 0 <= member.size <= 2 * 1024**2,
                'nonregular/oversize archive identity: ' + member.name)
        stream = archive.extractfile(member)
        require(stream is not None, 'unreadable archive identity')
        with stream:
            data = stream.read(2 * 1024**2 + 1)
        require(len(data) == member.size, 'archive member size mismatch')
        selected[member.name] = data
    require(set(selected) == set(required), 'missing required archive identities')
    return selected


def source_contract(artifact, candidate, lock, libraries):
    prefix = lock['inputs']['vere']['root'] + '/'
    original = lock['inputs']['openssl']['root'] + '/'
    changes = candidate.get('source_changes')
    require(isinstance(changes, dict) and len(changes) == 39, 'final source mapping missing/incomplete')
    for name, digest in changes.items():
        relative(name)
        validate_pin({'bytes': 0, 'sha256': digest})
    source = Path(artifact) / 'source-materials.tar.gz'
    # Inventory only the supported dependency header namespaces. This identifies
    # retained headers, NOT the compiler's actual include search/access sequence.
    prebuilt = prefix + 'ext/openssl/prebuilt/include/'
    upstream = original + 'include/'
    curl = 'p/N-V-__8AAMjlVwH79yAHsK65VUcPuhOO6BWgpLDvvnlWPLly/include/'
    groups = {'openssl_prebuilt': prebuilt, 'openssl_configured_source': upstream, 'curl': curl}
    with tarfile.open(source) as archive:
        names = [m.name for m in archive.getmembers()]
        headers = {name for name in names if name.endswith('.h') and
                   any(name.startswith(root) for root in groups.values())}
        required = headers | {prefix + n for n in changes} | {original + 'configdata.pm'}
        required |= {prefix + n for n in ('ext/curl/build.zig.zon', 'ext/openssl/build.zig.zon')}
        selected = archive_members(archive, required)
    for name, digest in changes.items():
        require(identity(selected[prefix + name])['sha256'] == digest, 'archived source hash mismatch: ' + name)
    for root in (prebuilt, upstream):
        for name in ('openssl/ssl.h', 'openssl/opensslconf.h', 'openssl/configuration.h', 'openssl/opensslv.h'):
            require(root + name in selected, 'missing configured OpenSSL header: ' + name)
        require(b'3.5.9' in selected[root + 'openssl/opensslv.h'], 'OpenSSL header version')
    require(curl + 'curl/curlver.h' in selected and b'8.23.0' in selected[curl + 'curl/curlver.h'],
            'curl header identity/version')
    config = identity(selected[original + 'configdata.pm'])
    require(config == libraries['files']['public-libraries/openssl/configdata.pm'],
            'retained/source OpenSSL config hash mismatch')
    require(b'curl-8.23.0.tar.gz' in selected[prefix + 'ext/curl/build.zig.zon'] and
            b'.version = "3.5.9"' in selected[prefix + 'ext/openssl/build.zig.zon'],
            'archived dependency manifest versions')
    inventory = {name: identity(data) for name, data in sorted(selected.items())}
    return {'source_changes': changes, 'members': inventory}, {
        key: {'archive_prefix': root, 'files': {n[len(root):]: inventory[n] for n in sorted(headers)
                                              if n.startswith(root)}} for key, root in groups.items()}, {
        'retained_path': 'public-libraries/openssl/configdata.pm',
        'archive_member': original + 'configdata.pm', **config}


def validate_report_bundle(repo, report):
    name = 'docs/openssl-candidate-evidence/owned-b04-report-20261030-evidence.tar.gz'
    read_pin(repo, name, report['durable_bundle'])
    pins = report['bundle_members']
    with tarfile.open(Path(repo) / name) as archive:
        require(set(m.name for m in archive.getmembers()) == set(pins), 'unexpected report bundle members')
        selected = archive_members(archive, pins)
    for member, data in selected.items():
        validate_pin(pins[member])
        require(identity(data) == pins[member], 'report bundle member hash mismatch: ' + member)
    require(selected['executed/urbit-R.txt'].decode('utf-8') == report['public_report'], 'public report text mismatch')
    require(strict_json(selected['executed/result.json']) == report['result'], 'report result member mismatch')
    require(identity(selected['executed/public-report.log']) ==
            {'bytes': report['result']['public_report_bytes'], 'sha256': report['result']['public_report_sha256']},
            'report capture hash mismatch')
    require(identity(selected['executed/fresh-static.json']) ==
            {k: report['static_receipt'][k] for k in ('bytes', 'sha256')}, 'report static member mismatch')
    return selected


def validate_public(repo=REPO, attempt=ATTEMPT):
    """Validate pinned original b04 public bytes without executing any recipe.

    Alternate roots permit read-only relocated evidence, never alternate pins.
    Paths inside historical receipts are descriptive and are never followed.
    """
    repo, attempt = Path(repo), Path(attempt)
    build = strict_json(read_pin(repo, BUILD_RECEIPT, BUILD_PIN))
    report = strict_json(read_pin(repo, REPORT_RECEIPT, REPORT_PIN))
    artifact = attempt / 'artifact'
    result = strict_json(read_pin(attempt, 'result.json', report['build_result']))
    pins = build['artifact_hashes']
    require(pins['urbit'] == BINARY_PIN, 'old/substituted build artifact')
    candidate = strict_json(read_pin(artifact, 'candidate.json', pins['candidate.json']))
    versions = validate_receipts(build, report, result, candidate)
    validate_report_bundle(repo, report)
    raw = read_pin(artifact, 'urbit', BINARY_PIN)
    require((artifact / 'urbit').stat().st_mode & 0o777 == 0o555, 'b04 ELF mode')
    require(raw[:6] == b'\x7fELF\x02\x01' and struct.unpack_from('<H', raw, 18)[0] == 62,
            'AMD64 ELF64 identity')
    offset = struct.unpack_from('<Q', raw, 32)[0]
    stride, count = struct.unpack_from('<HH', raw, 54)
    require(stride == 56 and count > 0 and offset + stride * count <= len(raw), 'ELF program table')
    require(all(struct.unpack_from('<I', raw, offset + i * stride)[0] not in (2, 3)
                for i in range(count)), 'dynamic/interpreter ELF refused')
    bindings = build['frozen_recipe_bindings']
    # These helpers are identified but not imported/executed by this validator.
    for name, digest in bindings.items():
        relative(name)
        data = (attempt / 'frozen-recipe' / name).read_bytes()
        read_pin(attempt / 'frozen-recipe', name, {'bytes': len(data), 'sha256': digest})
    for name in ('inputs.json', 'verify_binary.py', 'owned_support.py'):
        data = (artifact / name).read_bytes()
        read_pin(artifact, name, {'bytes': len(data), 'sha256': bindings[name]})
    lock = strict_json((artifact / 'inputs.json').read_bytes())
    require(type(lock.get('schema_version')) is int and lock['schema_version'] == 1 and
            lock.get('target') == 'x86_64-linux-musl' and lock.get('openssl_version') == '3.5.9' and
            lock.get('curl_version') == '8.23.0' and lock.get('zig_version') == '0.15.2', 'owned dependency lock')
    require(candidate.get('inputs_sha256') == bindings['inputs.json'], 'candidate input lock binding')
    manifest = strict_json(read_pin(artifact, 'public-libraries.json', pins['public-libraries.json']))
    libraries = validate_libraries(artifact, manifest)
    read_pin(artifact, 'source-materials.tar.gz', pins['source-materials.tar.gz'])
    source, headers, config = source_contract(artifact, candidate, lock, libraries)
    source['archive'] = {'path': str(artifact / 'source-materials.tar.gz'), **pins['source-materials.tar.gz']}
    return {'schema': SCHEMA, 'status': 'RETAINED_DEPENDENCY_EVIDENCE_PASS',
            'artifact': {'path': str(artifact / 'urbit'), **BINARY_PIN},
            'artifact_root': str(artifact), 'versions': versions,
            'receipts': {'build': BUILD_PIN, 'report': REPORT_PIN, 'candidate': pins['candidate.json'],
                         'inputs': {'sha256': bindings['inputs.json'], 'bytes': len((artifact / 'inputs.json').read_bytes())},
                         'public_libraries': pins['public-libraries.json']},
            'dependency_pins': lock['inputs'], 'retained_libraries': libraries,
            'source': source, 'headers': headers, 'openssl_config': config,
            'frozen_recipe_bindings': bindings,
            'authenticated_final_link_inputs': False, 'authenticated_compile_headers': False,
            'crypto_tls_qualified': False, 'target_executed_by_validator': False,
            'limitations': ['Retained archives are not authenticated final-link inputs.',
                            'Retained header trees are not actual compile-header access evidence.',
                            'No crypto/TLS, ship lifecycle, package, production sizing or release acceptance.']}


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', type=Path, default=REPO)
    parser.add_argument('--attempt', type=Path, default=ATTEMPT)
    args = parser.parse_args()
    print(json.dumps(validate_public(args.repo, args.attempt), indent=2, sort_keys=True))
