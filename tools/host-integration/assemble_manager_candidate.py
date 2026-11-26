#!/usr/bin/env python3
"""Assemble an offline local ARM64 candidate, never an official SDK release.

No engine, network, installation or host-plan approval is performed. Inputs are
read-only; the output must be fresh. A failed write leaves incomplete evidence
in place and must not be retried into the same output directory.
"""
import argparse
import hashlib
import json
import lzma
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import sys
import tarfile

VERSION = '0.2.129'
IMAGE = 'dappmanager.dnp.dappnode.eth:' + VERSION
PIN = 'a21bab295d4c68c3b6115498b18a8efaf89d52a0'
PATCH_SHA256 = 'c7149f6b0923b013c354e89e43e02378c15e0bf7fe52c7671eeb693090ecbd50'
SOURCE_ARCHIVE_SHA256 = 'c958726dee40246aa67d3ac736fb20305befc4f238511346c0b5724419eb759d'
SOURCE_COMPOSE_SHA256 = 'a7ecdf8eddc8778d5f8520a987ec4e1f1ea2e50d8e850f76bcef541c4b95eaac'
ARCHIVE_NAME = 'dappmanager.dnp.dappnode.eth_0.2.129_linux-arm64.txz'
MOUNT = '/run/uvm-maintenance:/run/uvm-maintenance:ro'


def digest(data):
    return hashlib.sha256(data).hexdigest()


def file_digest(path):
    value = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            value.update(chunk)
    return value.hexdigest()


def tree_digest(directory):
    records = [[p.relative_to(directory).as_posix(), oct(p.stat().st_mode & 0o777),
                file_digest(p)] for p in sorted(directory.rglob('*')) if p.is_file()]
    return digest(json.dumps(records, separators=(',', ':')).encode())


def write_json(path, data):
    with path.open('x') as stream:
        stream.write(json.dumps(data, indent=2, sort_keys=True) + '\n')


def regular_inventory(directory):
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError('input root must be a regular directory, not a symlink')
    files = {}
    for path in sorted(directory.rglob('*')):
        mode = path.lstat().st_mode
        if stat.S_ISDIR(mode):
            continue
        if not stat.S_ISREG(mode):
            raise ValueError('input closure contains a symlink or nonregular file: ' + str(path))
        files[path.relative_to(directory).as_posix()] = file_digest(path)
    return files


def validate_candidate(prepared):
    regular_inventory(prepared)
    candidate = json.loads((prepared / 'candidate.json').read_text())
    required = {'schema': 1, 'state': 'source-prepared', 'image_state': 'image-pending',
        'installable': False, 'version': VERSION, 'compose_image': IMAGE,
        'image_id': None, 'archive': None, 'cid': None, 'content_hash': None,
        'historical_releases_are_candidate_identity': False,
        'source_tag': 'v' + VERSION, 'source_commit': PIN,
        'source_archive_sha256': SOURCE_ARCHIVE_SHA256, 'patch_sha256': PATCH_SHA256}
    for key, expected in required.items():
        if key not in candidate or type(candidate[key]) is not type(expected) or candidate[key] != expected:
            raise ValueError('candidate field mismatch: ' + key)
    source = prepared / 'source'
    if file_digest(prepared / 'provenance/upstream-dappmanager.patch') != PATCH_SHA256:
        raise ValueError('patch bytes mismatch')
    if tree_digest(source) != candidate.get('source_tree_sha256'):
        raise ValueError('source tree SHA256 mismatch')
    for name, field in [('dappnode_package.json', 'manifest_sha256'),
                        ('docker-compose.yml', 'compose_sha256')]:
        if file_digest(source / name) != candidate.get(field):
            raise ValueError('source ' + field + ' mismatch')
    return candidate


def validate_host(host):
    files = regular_inventory(host)
    manifest = json.loads((host / 'manifest.json').read_text())
    if type(manifest.get('version')) is not int or manifest['version'] != 1 or manifest.get('deployment_qualified') is not False:
        raise ValueError('host companion must be source-only manifest version 1')
    expected = manifest.get('files')
    files.pop('manifest.json', None)
    if not isinstance(expected, dict) or not expected or files != expected:
        raise ValueError('host companion file inventory or SHA256 mismatch')
    return manifest


def validate_archive(archive, expected_image_id, candidate):
    """Stream tar/xz without extracting; bind config and every layer to the ID."""
    if not isinstance(expected_image_id, str) or not re.fullmatch(r'sha256:[0-9a-f]{64}', expected_image_id):
        raise ValueError('expected image ID must be exact lowercase sha256: plus 64 hex digits')
    if archive.is_symlink() or not stat.S_ISREG(archive.stat().st_mode):
        raise ValueError('image archive must be a regular file')
    expected_hex = expected_image_id.split(':')[1]
    config_names = {expected_hex + '.json', 'blobs/sha256/' + expected_hex}
    retained, hashes, seen = {}, {}, set()
    try:
        with lzma.open(archive, 'rb', format=lzma.FORMAT_XZ) as stream:
            with tarfile.open(fileobj=stream, mode='r|') as tar:
                for member in tar:
                    path = PurePosixPath(member.name)
                    if (path.is_absolute() or '..' in path.parts or member.name != path.as_posix()
                            or member.name in seen or not (member.isfile() or member.isdir())):
                        raise ValueError('unsafe or duplicate archive member: ' + member.name)
                    seen.add(member.name)
                    if member.isdir():
                        continue
                    data_stream = tar.extractfile(member)
                    if data_stream is None:
                        raise ValueError('archive member has no data')
                    keep = member.name == 'manifest.json' or member.name in config_names
                    if keep and member.size > 16 * 1024 * 1024:
                        raise ValueError('archive config/manifest exceeds 16 MiB')
                    value = hashlib.sha256()
                    chunks = []
                    for chunk in iter(lambda: data_stream.read(1024 * 1024), b''):
                        value.update(chunk)
                        if keep:
                            chunks.append(chunk)
                    hashes[member.name] = value.hexdigest()
                    if keep:
                        retained[member.name] = b''.join(chunks)
            # Tar EOF is earlier than xz EOF: force checksum/trailer validation.
            for unused in iter(lambda: stream.read(1024 * 1024), b''):
                pass
    except (OSError, EOFError, lzma.LZMAError, tarfile.TarError) as error:
        raise ValueError('invalid xz Docker-save archive: ' + str(error)) from error
    try:
        manifest = json.loads(retained['manifest.json'])
        if not isinstance(manifest, list) or len(manifest) != 1 or manifest[0]['RepoTags'] != [IMAGE]:
            raise ValueError('archive must contain exactly one image and the exact single RepoTag')
        entry = manifest[0]
        config_name = entry['Config']
        if config_name not in config_names or hashes.get(config_name) != expected_hex:
            raise ValueError('archive config digest does not match expected image ID')
        config = json.loads(retained[config_name])
        if config.get('architecture') != 'arm64' or config.get('os') != 'linux':
            raise ValueError('image must be Linux ARM64')
        labels = config.get('config', {}).get('Labels', {})
        required_labels = {'org.uvm.issue19.source': candidate['source_commit'],
            'org.uvm.issue19.patch-sha256': candidate['patch_sha256'],
            'org.uvm.issue19.source-tree-sha256': candidate['source_tree_sha256']}
        for key, value in required_labels.items():
            if labels.get(key) != value:
                raise ValueError('image config label mismatch: ' + key)
        layers = entry['Layers']
        rootfs = config['rootfs']
        if not isinstance(layers, list) or not layers or rootfs['type'] != 'layers':
            raise ValueError('archive layers are missing')
        actual = ['sha256:' + hashes[name] for name in layers]
        if actual != rootfs['diff_ids']:
            raise ValueError('archive layer digest mismatch')
    except (KeyError, TypeError, AttributeError, json.JSONDecodeError) as error:
        raise ValueError('invalid Docker-save archive metadata: ' + str(error)) from error
    return {'config_sha256': expected_hex, 'layer_count': len(layers),
            'labels': required_labels, 'repo_tags': [IMAGE]}


def package_metadata(source):
    manifest = json.loads((source / 'dappnode_package.json').read_text())
    if manifest.get('version') != VERSION or manifest.get('name') != IMAGE.split(':')[0]:
        raise ValueError('source package manifest name/version mismatch')
    compose_bytes = (source / 'docker-compose.yml').read_bytes()
    # Pin the complete reviewed YAML before textual surgery. Counts/regex alone
    # miss quoted keys, flow mappings and additional services with build keys.
    if digest(compose_bytes) != SOURCE_COMPOSE_SHA256:
        raise ValueError('Compose differs from the reviewed version-aligned source')
    compose = compose_bytes.decode()
    # Deliberately support only the reviewed prepared-source layout, not a YAML
    # reformatter: fail closed on other shapes rather than guessing semantics.
    anchors = [('build', '    build: .\n'),
               ('image', '    image: "' + IMAGE + '"\n'),
               ('volumes', '    volumes:\n')]
    for key, anchor in anchors:
        property_lines = re.findall(r'^\s*' + key + r'\s*:.*$', compose, re.MULTILINE)
        # A top-level volumes definition is expected in the real source.
        if key == 'volumes':
            property_lines = [line for line in property_lines if line.startswith('    ')]
        if len(property_lines) != 1 or compose.count(anchor) != 1:
            raise ValueError('Compose ' + key + ' layout mismatch')
    if '/run/uvm-maintenance' in compose:
        raise ValueError('Compose already contains a maintenance mount')
    compose = compose.replace('    build: .\n', '')
    compose = compose.replace('    volumes:\n', '    volumes:\n      - "' + MOUNT + '"\n')
    return manifest, compose


def assemble(prepared, host, archive, expected_image_id, output):
    prepared, host, archive, output = map(Path, (prepared, host, archive, output))
    resolved_output = output.resolve()
    for directory in (prepared.resolve(), host.resolve()):
        if resolved_output == directory or directory in resolved_output.parents or resolved_output in directory.parents:
            raise ValueError('output must be outside input closures; overlap refused')
    if output.exists() or output.is_symlink():
        raise ValueError('output must be fresh; path already exists')
    source_candidate_sha256 = file_digest(prepared / 'candidate.json')
    host_manifest_sha256 = file_digest(host / 'manifest.json')
    archive_sha256 = file_digest(archive)
    candidate = validate_candidate(prepared)
    validate_host(host)
    image_verification = validate_archive(archive, expected_image_id, candidate)
    source = prepared / 'source'
    source_manifest, compose = package_metadata(source)
    output.mkdir(mode=0o700, parents=False, exist_ok=False)
    manifest = {key: source_manifest[key] for key in (
        'name', 'version', 'description', 'type', 'author', 'contributors', 'keywords',
        'links', 'repository', 'bugs', 'license') if key in source_manifest}
    manifest['architectures'] = ['linux/arm64']
    write_json(output / 'dappnode_package.json', manifest)
    (output / 'docker-compose.yml').write_text(compose)
    shutil.copyfile(archive, output / ARCHIVE_NAME)
    shutil.copytree(host, output / 'host-companion')
    provenance = output / 'provenance'
    provenance.mkdir(mode=0o700)
    shutil.copyfile(prepared / 'candidate.json', provenance / 'source-candidate.json')
    shutil.copyfile(prepared / 'provenance/upstream-dappmanager.patch',
                    provenance / 'upstream-dappmanager.patch')
    checks = [(output / ARCHIVE_NAME, archive_sha256),
              (output / 'host-companion/manifest.json', host_manifest_sha256),
              (provenance / 'source-candidate.json', source_candidate_sha256),
              (provenance / 'upstream-dappmanager.patch', PATCH_SHA256)]
    for path, expected in checks:
        if file_digest(path) != expected:
            raise ValueError('copied input changed or copy digest mismatch: ' + str(path))
    validate_host(output / 'host-companion')
    if validate_candidate(prepared) != candidate or file_digest(prepared / 'candidate.json') != source_candidate_sha256:
        raise ValueError('source candidate changed during copy')
    result = {'schema': 1, 'state': 'local-arm64-candidate', 'version': VERSION,
        'installable': False, 'installed': False, 'host_plan_approved': False,
        'official_release': False, 'architectures': ['linux/arm64'], 'compose_image': IMAGE,
        'image_id': expected_image_id, 'image_archive': ARCHIVE_NAME,
        'image_archive_sha256': archive_sha256, 'image_verification': image_verification,
        'host_manifest_sha256': host_manifest_sha256,
        'source_commit': candidate['source_commit'], 'patch_sha256': candidate['patch_sha256'],
        'source_tree_sha256': candidate['source_tree_sha256'],
        'source_candidate_sha256': source_candidate_sha256,
        'source_archive_sha256': candidate['source_archive_sha256'],
        'qualification': 'Offline local candidate only; no installation or host-plan qualification.'}
    write_json(output / 'local-provenance.json', result)
    files = {p.relative_to(output).as_posix(): file_digest(p)
             for p in sorted(output.rglob('*')) if p.is_file()}
    write_json(output / 'sha256-manifest.json', {'schema': 1, 'files': files})
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--prepared', type=Path, required=True)
    parser.add_argument('--host-companion', type=Path, required=True)
    parser.add_argument('--image-archive', type=Path, required=True)
    parser.add_argument('--expected-image-id', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        result = assemble(args.prepared, args.host_companion, args.image_archive,
                          args.expected_image_id, args.output)
    except (OSError, ValueError, KeyError, TypeError, tarfile.TarError) as error:
        print('candidate assembly refused: ' + str(error), file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__':
    sys.exit(main())
