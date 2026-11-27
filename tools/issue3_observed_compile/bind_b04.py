"""Read-only exact b04 -> retained-library probe binding. Never stages or executes.

Use python3 -m tools.issue3_observed_compile.bind_b04 [--pair original|zig-adapted].
Only bind_public/prepare_public authenticate retained public evidence. Returned
JSON is a preparation plan, never an execution grant or final-ELF attestation.
"""
import hashlib
import json
from pathlib import Path
import tarfile
import time

from tools.issue3_fresh_attempt import b04_dependency_contract as dependency
from tools.issue3_observed_compile import prepare as probe

SIV_ROOT = 'p/N-V-__8AADRgAQComAaFJaS9o75BOcaFVew6nO8D7ZTGMRXd/'
SIV_MEMBERS = {
    SIV_ROOT + 'aes_siv.h': dict(bytes=1981, sha256='6b1064b2cc1db8342bf910d69bb95c873f2d8655fe88669d2e3261eb69234b5c'),
    SIV_ROOT + 'aes_siv.c': dict(bytes=18991, sha256='b1d1a0d5f53d3e59f52ae682dc15969346db04c3e1db4bbdb1d0a3e996abdfb8'),
}
SIV_LIBRARY = 'public-libraries/zig-local-cache/o/5cf68a89da795759f924872283162e2d/libaes_siv.a'
PAIRS = {
    'original': ('public-libraries/openssl/libssl.a', 'public-libraries/openssl/libcrypto.a'),
    'zig-adapted': (
        'public-libraries/zig-local-cache/o/e189098b3ecc58e0f507d6c1f21415df/libssl.a',
        'public-libraries/zig-local-cache/o/87fbf61ea07d13b307eeb9fa77129f6e/libcrypto.a'),
}


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def supplemental(archive):
    """Read only two exact SIV members, bounded streaming, no extraction."""
    found, total = {}, 0
    deadline = time.monotonic() + 90
    folded = {n.casefold() for n in SIV_MEMBERS}
    with tarfile.open(archive, 'r|gz') as tar:
        for count, member in enumerate(tar, 1):
            total += member.size
            probe.require(count <= 100000 and 0 <= total <= 4 * 1024**3 and
                          time.monotonic() < deadline, 'supplemental archive bound')
            if member.name.casefold() not in folded:
                continue
            probe.require(member.name in SIV_MEMBERS and member.name not in found,
                          'duplicate/portable SIV member identity')
            probe.require(member.isfile() and member.size == SIV_MEMBERS[member.name]['bytes'],
                          'SIV member type/size')
            stream = tar.extractfile(member)
            if stream is None:
                raise ValueError('SIV member unreadable')
            with stream:
                data = stream.read(member.size + 1)
            probe.require(dependency.identity(data) == SIV_MEMBERS[member.name], 'SIV member hash')
            found[member.name] = dependency.identity(data)
    probe.require(found == SIV_MEMBERS, 'SIV members missing')
    return found


def bind_public(pair='original', repo=dependency.REPO, attempt=dependency.ATTEMPT):
    """Reauthenticate original b04 evidence and emit a non-staging binding."""
    probe.require(pair in PAIRS, 'explicit original or zig-adapted pair required')
    contract = dependency.validate_public(repo, attempt)
    extras = supplemental(contract['source']['archive']['path'])
    # Rehash after supplemental reading; source is public, not hostile-write safe.
    archive = contract['source']['archive']
    h, size = hashlib.sha256(), 0
    with Path(archive['path']).open('rb') as stream:
        for chunk in iter(lambda: stream.read(1048576), b''):
            size += len(chunk)
            probe.require(size <= archive['bytes'], 'source archive grew')
            h.update(chunk)
    probe.require(dict(bytes=size, sha256=h.hexdigest()) ==
                  {k: archive[k] for k in ('bytes', 'sha256')}, 'source archive drift')
    files, origins = [], {}
    def add(role, path, pin, origin):
        files.append(dict(role=role, path=path, **pin))
        origins[path] = origin
    libraries = contract['retained_libraries']['files']
    ssl, crypto = PAIRS[pair]
    for role, path, origin in (
        ('libssl', 'lib/libssl.a', ssl), ('libcrypto', 'lib/libcrypto.a', crypto),
        ('libaes_siv', 'lib/libaes_siv.a', SIV_LIBRARY),
        ('build_config', 'config/configdata.pm', contract['openssl_config']['retained_path'])):
        add(role, path, libraries[origin], dict(kind='retained-file', path=origin))
    add('siv_header', 'include/aes_siv.h', extras[SIV_ROOT + 'aes_siv.h'],
        dict(kind='archive-member', path=SIV_ROOT + 'aes_siv.h'))
    tree = contract['headers']['openssl_prebuilt']
    for path, pin in sorted(tree['files'].items()):
        role = 'config' if path in ('openssl/configuration.h', 'openssl/opensslconf.h') else 'header'
        add(role, 'include/' + path, pin, dict(kind='archive-member', path=tree['archive_prefix'] + path))
    prefix = contract['dependency_pins']['vere']['root'] + '/'
    for role, name in (('arena_c', 'openssl_owned_arena.c'),
                       ('arena_h', 'openssl_owned_arena.h'), ('arena_engine', 'palloc_engine.inc')):
        origin = prefix + 'pkg/noun/' + name
        add(role, 'arena/' + name, contract['source']['members'][origin],
            dict(kind='archive-member', path=origin))
    add('dependency_contract', 'contract.json', dependency.identity(encoded(contract)),
        dict(kind='canonical-generated-json', serialization='sort_keys=True, indent=2, trailing LF'))
    manifest = dict(schema='issue3-b04-probe-input-v1', evidence_scope='retained-library-only',
        candidate_sha256=probe.B04_SHA, candidate_bytes=probe.B04_BYTES,
        final_link_authenticated=False, files=files)
    return dict(schema='issue3-b04-probe-binding-v1', status='BOUND_NOT_STAGED_NOT_AUTHORIZED',
        pair=pair, manifest=manifest, origins=origins, dependency_contract=contract,
        supplemental_members=extras, dependency_contract_semantics_verified=True,
        authenticated_final_link_inputs=False, authenticated_compile_headers=False,
        target_executed=False, final_elf_acceptance=False,
        # Records only: not included into this standalone probe's compilation.
        arena_owned_config=contract['source']['members'][prefix + 'pkg/noun/openssl_owned_config.h'],
        adapter_sources={n: contract['source']['source_changes'][n] for n in
            ('ext/openssl/build.zig', 'ext/urcrypt/build.zig', 'ext/urcrypt/build.zig.zon')},
        source_files={n: dependency.identity((probe.HERE/n).read_bytes()) for n in
            ('probe.c', 'prepare.py', 'bind_b04.py')},
        compiler_and_transport='UNBOUND; new reviewed supervisor/effective limits and owner grant required')


def validate_selection(binding, manifest):
    """Semantic comparison for authenticated callers; does not authenticate JSON."""
    probe.require(manifest == binding['manifest'], 'exact retained probe selection required')


def prepare_public(root, manifest, pair='original', repo=dependency.REPO, attempt=dependency.ATTEMPT):
    """Validate later stage against freshly authenticated evidence, without execution."""
    binding = bind_public(pair, repo, attempt)
    validate_selection(binding, manifest)
    plan = probe.prepare(root, manifest)
    plan.update(dependency_contract_semantics_verified=True,
                binding_sha256=hashlib.sha256(encoded(binding)).hexdigest(), retained_pair=pair)
    return plan


def main():
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pair', choices=tuple(PAIRS), default='original')
    args = parser.parse_args()
    print(encoded(bind_public(args.pair)).decode(), end='')


if __name__ == '__main__':
    main()
