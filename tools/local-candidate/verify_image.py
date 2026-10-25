#!/usr/bin/env python3
"""Verify selected public candidate files via a bounded Docker-save PIPE.

No container, archive file, Config parsing, private-state read or executable run.
Only selected-file hashes/metadata and the exact installed APK database persist.
Unexpected/unselected image files are NOT inventoried; their bytes pass/discard.
"""
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import tarfile
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
MAX_FILE = 32 * 1024**2
MAX_ELF = 24 * 1024**2
MAX_RETAINED = 128 * 1024**2
MAX_PATHS = 1024
DOC_ROOT = 'usr/share/doc/uvm/'
COPIED_MANIFEST = DOC_ROOT + 'notice-files.json'


def load_parser():
    # An isolated module instance: never weaken the original tool's defaults.
    spec = importlib.util.spec_from_file_location('candidate_public_parser', ROOT / 'scripts/inventory-public-image.py')
    assert spec is not None and spec.loader is not None
    module: Any = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.MAX_STREAM = 1024**3
    module.MAX_SELECTED = MAX_FILE
    module.MAX_RETAINED = MAX_RETAINED
    # Check the ELF header's size before layer_view can acquire its payload.
    # A task-local tar facade leaves stdlib and the original parser untouched.
    from types import SimpleNamespace
    class CandidateMember(tarfile.TarInfo):
        @classmethod
        def fromtarfile(cls, tarfile):
            member = super().fromtarfile(tarfile)
            if module.safe_path(member.name) == 'bin/urbit' and member.size > MAX_ELF:
                raise ValueError('ELF payload byte bound')
            return member
    module.tarfile = SimpleNamespace(open=lambda **kwargs: tarfile.open(tarinfo=CandidateMember, **kwargs))
    return module


def selected_inventory(source, metadata, paths):
    """Small task-local outer adapter; reuse layer parser, overlay rules, APK parser."""
    parser = load_parser()
    parser.validate_metadata(metadata)
    selected = {parser.DB_PATH, *paths}
    layers, manifest = {}, None
    reader = parser.Reader(source, parser.MAX_STREAM)
    with tarfile.open(fileobj=reader, mode='r|') as archive:
        for count, member in enumerate(archive, 1):
            if count > 1024:
                raise ValueError('outer member bound')
            path = parser.safe_path(member.name)
            if re.fullmatch(r'[0-9a-f]{64}/layer.tar', path):
                if (not member.isfile() or member.size > parser.MAX_LAYER or
                        path in layers or len(layers) >= 64):
                    raise ValueError('layer bound or duplicate')
                retained = sum(len(info.get('content', b'')) for layer in layers.values()
                               for info in layer['changes'].values())
                layers[path] = parser.layer_view(archive.extractfile(member), selected, MAX_RETAINED - retained)
            elif path == 'manifest.json':
                if manifest is not None or not member.isfile() or member.size > 65536:
                    raise ValueError('invalid manifest')
                manifest = json.loads(archive.extractfile(member).read(65537))
            # Config and legacy layer JSON are deliberately never extractfile'd.
    reader.drain()
    if not isinstance(manifest, list) or len(manifest) != 1 or not isinstance(manifest[0], dict):
        raise ValueError('single legacy manifest required')
    manifest = manifest[0]
    if manifest.get('Config') != metadata['image_id'][7:] + '.json':
        raise ValueError('config filename binding')
    order = manifest.get('Layers')
    if (not isinstance(order, list) or any(not isinstance(x, str) for x in order) or
            len(set(order)) != len(order) or set(order) != set(layers) or
            [layers[x]['sha256'] for x in order] != metadata['layers']):
        raise ValueError('ordered RootFS binding')
    state = {}
    for index, name in enumerate(order):
        layer = layers[name]
        for target, opaque in layer['removals']:
            state = {p: info for p, info in state.items() if not (
                (p == target and not opaque) or p.startswith(target + '/') or (not target and opaque))}
        for path, info in layer['changes'].items():
            if info['kind'] != 'directory':
                state = {p: v for p, v in state.items() if not p.startswith(path + '/')}
            state[path] = dict(info, layer_index=index)
    return state, order, reader.count


def build_contract(source_root):
    """Read frozen public inputs; derive final destinations from its Dockerfile."""
    import shlex
    spec = importlib.util.spec_from_file_location('candidate_notice_source', ROOT / 'scripts/verify-notice-packaging.py')
    assert spec is not None and spec.loader is not None
    notices = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(notices)
    raw = notices.read_regular(source_root, 'build/notice-files.json')
    manifest = json.loads(raw)
    if (not isinstance(manifest, dict) or set(manifest) != {'schema_version', 'destination', 'files'} or
            manifest['schema_version'] != 1 or manifest['destination'] != '/' + DOC_ROOT.rstrip('/') or
            not isinstance(manifest['files'], dict) or len(manifest['files']) != 395):
        raise ValueError('exact source notice manifest required')
    for name in manifest['files']:
        notices.public_path(name)
        if not (name.startswith(('THIRD_PARTY/', 'LICENSES/')) or name == 'LICENSE.md' or
                name in ('docs/artwork.md', 'docs/distribution-review.md', 'docs/notice-packaging.md')):
            raise ValueError('source notice outside public roots')
    # Existing source/hash/context-allowlist verifier; no Docker or writes.
    notices.verify(source_root)
    dockerfile = notices.read_regular(source_root, 'build/Dockerfile')
    release_raw = notices.read_regular(source_root, 'build/vere-release.json')
    release = json.loads(release_raw)
    if (release['architecture'] != 'linux/amd64' or
            not isinstance(release['executable_sha256'], str) or
            not re.fullmatch(r'[0-9a-f]{64}', release['executable_sha256']) or
            type(release['executable_bytes']) is not int or not 64 <= release['executable_bytes'] <= MAX_ELF):
        raise ValueError('source executable contract')
    final = dockerfile.decode().split('\nFROM ')
    if len(final) != 2:
        raise ValueError('reviewed two-stage Dockerfile required')
    files, covered, elf = {}, set(), False
    for line in final[1].splitlines():
        if not line.startswith('COPY '):
            continue
        tokens = shlex.split(line)[1:]
        if tokens == ['--from=vere-release', '/out/urbit', '/bin/urbit']:
            if elf:
                raise ValueError('duplicate executable copy')
            files['bin/urbit'] = dict(source='build/vere-release.json', role='elf',
                                     size=release['executable_bytes'], sha256=release['executable_sha256'])
            elf = True
            continue
        if len(tokens) < 3 or tokens.pop(0) != '--chown=0:0':
            raise ValueError('unsupported final COPY')
        destination = tokens.pop()
        if not destination.startswith('/'):
            raise ValueError('absolute copy destination required')
        for source in tokens:
            if source == 'THIRD_PARTY/':
                sources = sorted(p for p in manifest['files'] if p.startswith(source))
                if not sources or destination != '/' + DOC_ROOT + source:
                    raise ValueError('notice directory mapping')
            else:
                notices.public_path(source)
                sources = [source]
            for name in sources:
                suffix = name[len(source):] if source.endswith('/') else name.rsplit('/', 1)[-1]
                target = destination + suffix if destination.endswith('/') else destination
                target = target.removeprefix('/')
                role = 'notice' if name in manifest['files'] else 'manifest' if name == 'build/notice-files.json' else 'code'
                if target in files:
                    raise ValueError('ambiguous copy destination')
                if role == 'code' and not (name.startswith('tools/browser-importer/') or
                        name in ('build/volume_guard.py', 'build/docker-entrypoint.sh')):
                    raise ValueError('nonpublic local COPY input')
                data = notices.read_regular(source_root, name)
                digest = hashlib.sha256(data).hexdigest()
                if role == 'notice' and digest != manifest['files'][name]:
                    raise ValueError('source changed during mapping')
                files[target] = dict(source=name, role=role, size=len(data), sha256=digest)
                covered.add(name)
    if not set(manifest['files']).issubset(covered) or not elf:
        raise ValueError('missing source COPY mapping')
    contract = dict(files=files, manifest_bytes=raw, manifest_sha256=hashlib.sha256(raw).hexdigest(),
                    notice_count=len(manifest['files']), dockerfile_sha256=hashlib.sha256(dockerfile).hexdigest(),
                    release_contract_sha256=hashlib.sha256(release_raw).hexdigest())
    validate_contract(contract)
    return contract


def validate_contract(contract):
    """Trust only source-manifest names, never names supplied by the image."""
    parser = load_parser()
    raw = contract['manifest_bytes']
    if hashlib.sha256(raw).hexdigest() != contract['manifest_sha256']:
        raise ValueError('source manifest binding')
    manifest = json.loads(raw)
    if (set(manifest) != {'schema_version', 'destination', 'files'} or
            manifest['schema_version'] != 1 or manifest['destination'] != '/' + DOC_ROOT.rstrip('/') or
            not isinstance(manifest['files'], dict) or len(manifest['files']) != contract['notice_count']):
        raise ValueError('source manifest schema')
    files = contract['files']
    if not isinstance(files, dict) or not 1 <= len(files) + 1 <= MAX_PATHS:
        raise ValueError('selected path bound')
    notices = set()
    for path, expected in files.items():
        if path != parser.safe_path(path) or not re.fullmatch(r'[A-Za-z0-9_./+@-]+', path):
            raise ValueError('noncanonical public path')
        source, role = expected['source'], expected['role']
        if (not isinstance(source, str) or source != parser.safe_path(source) or
                not re.fullmatch(r'[A-Za-z0-9_./+@-]+', source) or
                not isinstance(expected['sha256'], str) or
                not re.fullmatch(r'[0-9a-f]{64}', expected['sha256']) or
                type(expected['size']) is not int or not 0 <= expected['size'] <= MAX_FILE):
            raise ValueError('invalid public expectation')
        if role == 'notice':
            if (source not in manifest['files'] or path != DOC_ROOT + source or
                    manifest['files'][source] != expected['sha256'] or
                    not (source.startswith(('THIRD_PARTY/', 'LICENSES/')) or source == 'LICENSE.md' or
                         source in ('docs/artwork.md', 'docs/distribution-review.md', 'docs/notice-packaging.md'))):
                raise ValueError('notice outside source allowlist')
            notices.add(source)
        elif role == 'manifest':
            if (path != COPIED_MANIFEST or source != 'build/notice-files.json' or
                    expected['sha256'] != contract['manifest_sha256'] or expected['size'] != len(raw)):
                raise ValueError('manifest destination binding')
        elif role == 'elf':
            if path != 'bin/urbit' or source != 'build/vere-release.json' or expected['size'] > MAX_ELF:
                raise ValueError('ELF outside allowlist')
        elif role == 'code':
            destination = ('opt/importer/web/' if source.startswith('tools/browser-importer/web/') else
                           'opt/importer/' if source.startswith('tools/browser-importer/') or source == 'build/volume_guard.py' else
                           'usr/local/bin/' if source == 'build/docker-entrypoint.sh' else None)
            if destination is None or path != destination + source.rsplit('/', 1)[-1]:
                raise ValueError('code outside source mapping')
        else:
            raise ValueError('unknown selection role')
    if notices != set(manifest['files']) or COPIED_MANIFEST not in files or 'bin/urbit' not in files:
        raise ValueError('incomplete selected public contract')


def verify_stream(source, metadata, contract):
    validate_contract(contract)
    state, order, stream_bytes = selected_inventory(source, metadata, contract['files'])
    parser = load_parser()
    required = {*contract['files'], parser.DB_PATH}
    parents = {}
    for path in required:
        info = state.get(path)
        if (info is None or info['kind'] != 'regular' or info['uid'] != 0 or info['gid'] != 0 or
                info['mode'] & 0o7022 or not info['mode'] & 0o004):
            raise ValueError('selected file type, owner, readability or mode')
        for parent in Path(path).parents:
            ancestor = parent.as_posix()
            if ancestor == '.':
                continue
            entry = state.get(ancestor)
            if (entry is None or entry['kind'] != 'directory' or entry['uid'] != 0 or entry['gid'] != 0 or
                    entry['mode'] & 0o7022 or not entry['mode'] & 0o001):
                raise ValueError('selected parent type, owner or traversal mode')
            parents[ancestor] = {k: entry[k] for k in ('kind', 'mode', 'uid', 'gid', 'layer_index')}
    # Compare copied manifest bytes before examining any copied-file expectations.
    if state[COPIED_MANIFEST]['content'] != contract['manifest_bytes']:
        raise ValueError('copied manifest differs from trusted source')
    for path, expected in contract['files'].items():
        info = state[path]
        if info['sha256'] != expected['sha256'] or info['size'] != expected['size']:
            raise ValueError('selected copy hash or size drift')
        if expected['role'] in ('notice', 'manifest') and info['mode'] & 0o222:
            raise ValueError('documentation must be read-only')
        # The Dockerfile launches its service-readable script with sh; only the
        # directly executed Vere ELF needs an execute bit.
        if path == 'bin/urbit' and not info['mode'] & 0o001:
            raise ValueError('executable not service executable')
        if expected['role'] == 'elf':
            data = info['content']
            if len(data) < 64 or data[:6] != b'\x7fELF\x02\x01' or int.from_bytes(data[18:20], 'little') != 62:
                raise ValueError('ELF architecture')
    db = state[parser.DB_PATH]['content']
    packages = parser.parse_apk(db)
    selected = {path: {key: info[key] for key in
                       ('kind', 'mode', 'uid', 'gid', 'size', 'sha256', 'layer_index')}
                for path, info in state.items() if path in {*contract['files'], parser.DB_PATH}}
    for path, expected in contract['files'].items():
        selected[path].update(source=expected['source'], source_sha256=expected['sha256'],
                              source_size=expected['size'], role=expected['role'])
    return dict(schema_version=1, status='PASS_SELECTED_CANDIDATE_FILES', image=metadata,
                selected_files=selected, selected_parent_directories=parents, notice_count=contract['notice_count'],
                manifest_sha256=contract['manifest_sha256'],
                dockerfile_sha256=contract['dockerfile_sha256'],
                package_count=len(packages), packages=packages,
                layer_order=order, stream_bytes=stream_bytes,
                config_parsed=False, container_executed=False,
                unexpected_image_files_checked=False, distribution_clearance=False,
                _installed_apk_db=db)


def collect(image_id, source_root):
    if not re.fullmatch(r'sha256:[0-9a-f]{64}', image_id):
        raise ValueError('literal full image ID required')
    contract = build_contract(source_root)
    parser = load_parser()
    # Reuse the original 120s producer, selected inspect, kill/reap and recheck.
    parser.inventory_stream = lambda stream, metadata, notice_paths=(): verify_stream(stream, metadata, contract)
    result = parser.collect(image_id)
    if build_contract(source_root) != contract:
        raise ValueError('frozen public source changed')
    return result


def publish(result, output):
    """Exclusive flat evidence; never persist copied source, ELF or image bytes."""
    import os
    keys = ('schema_version', 'status', 'image', 'selected_files', 'selected_parent_directories',
            'notice_count', 'manifest_sha256', 'dockerfile_sha256', 'package_count', 'packages',
            'layer_order', 'stream_bytes', 'config_parsed', 'container_executed',
            'unexpected_image_files_checked', 'distribution_clearance')
    serial = {key: result[key] for key in keys}
    payload = (json.dumps(serial, sort_keys=True, indent=2) + '\n').encode()
    parts = os.path.abspath(output).strip('/').split('/')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        os.mkdir(parts[-1], mode=0o700, dir_fd=fd)
        child = os.open(parts[-1], os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
        os.close(fd)
        fd = child
        for name, data in (('inventory.json', payload), ('installed-apk-db.txt', result['_installed_apk_db'])):
            target = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
            with os.fdopen(target, 'wb') as out:
                out.write(data)
    finally:
        os.close(fd)


def main(argv=None):
    import argparse
    import os
    import sys
    class SanitizedArguments(argparse.ArgumentParser):
        def error(self, message):
            raise ValueError('invalid verifier arguments')
    arguments = SanitizedArguments(description=__doc__)
    arguments.add_argument('--image', required=True, help='Full literal sha256 image ID, never a tag')
    arguments.add_argument('--source-root', required=True, type=Path, help='Frozen public build-context root')
    arguments.add_argument('--output', required=True, type=Path, help='New evidence directory; never an image archive')
    try:
        args = arguments.parse_args(argv)
        if not re.fullmatch(r'sha256:[0-9a-f]{64}', args.image) or os.path.lexists(args.output):
            raise ValueError('image identity or output admission')
        result = collect(args.image, args.source_root)
        publish(result, args.output)
        print(json.dumps(dict(status=result['status'], notice_count=result['notice_count'],
                              selected_file_count=len(result['selected_files']), package_count=result['package_count'],
                              layer_count=len(result['layer_order']), config_parsed=False, container_executed=False)))
        return 0
    except Exception:
        # Never emit raw Docker stderr, exception text, arbitrary fields or bytes.
        print('REFUSED: candidate public-file verification failed', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
