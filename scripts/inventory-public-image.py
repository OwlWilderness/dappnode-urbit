#!/usr/bin/env python3
"""Read public APK metadata from a Docker-save STREAM, never a container.

Only the installed APK database and explicitly selected public notice files are
retained. Image config and legacy layer JSON are skipped, never parsed/copied.
Supported input: legacy Docker-save tar with manifest.json and raw layer.tar.
Unsupported formats fail closed. No pull/build/run/load/export-file operation.
"""
import re
import hashlib
import json
import tarfile
import os
import signal
import subprocess
import threading

INSPECT_FORMAT = '{"image_id":{{json .Id}},"layers":{{json .RootFS.Layers}},"architecture":{{json .Architecture}}}'


def inspect_image(image_id):
    if not re.fullmatch(r'sha256:[0-9a-f]{64}', image_id):
        raise InventoryError('full literal image ID required')
    response = subprocess.run(['docker', 'image', 'inspect', '--format', INSPECT_FORMAT, image_id],
                              stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                              text=True, timeout=30, check=True)
    if len(response.stdout) > 16384:
        raise InventoryError('oversized selected metadata')
    metadata = json.loads(response.stdout)
    if metadata.get('image_id') != image_id:
        raise InventoryError('selected image identity mismatch')
    validate_metadata(metadata)
    return metadata


def collect(image_id, notice_paths=()):
    """Bounded inspection only: no release archive, container or config read."""
    metadata = inspect_image(image_id)
    producer = subprocess.Popen(['docker', 'image', 'save', image_id],
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                start_new_session=True)
    expired = threading.Event()
    def stop():
        expired.set()
        if producer.poll() is None:
            try:
                os.killpg(producer.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
    timer = threading.Timer(120, stop)
    timer.daemon = True
    timer.start()
    try:
        result = inventory_stream(producer.stdout, metadata, notice_paths)
        if producer.wait(timeout=15) != 0 or expired.is_set():
            raise InventoryError('filesystem stream producer failed or timed out')
    finally:
        timer.cancel()
        producer.stdout.close()
        if producer.poll() is None:
            stop()
        producer.wait(timeout=15)
    if inspect_image(image_id) != metadata:
        raise InventoryError('selected image metadata changed')
    return result


def publish(result, output):
    """Publish only flat public evidence into a new no-symlink directory."""
    path = os.path.abspath(output)
    parts = path.strip('/').split('/')
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
        def write(name, data):
            target = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
            with os.fdopen(target, 'wb') as out:
                out.write(data)
        serial = dict(result, selected_files={})
        for name, info in sorted(result['selected_files'].items()):
            filename = 'installed-apk-db.txt' if name == DB_PATH else 'notice-' + info['sha256'] + '.txt'
            write(filename, info['content'])
            serial['selected_files'][name] = {k: v for k, v in info.items() if k != 'content'}
            serial['selected_files'][name]['file'] = filename
        write('inventory.json', (json.dumps(serial, indent=2, sort_keys=True) + '\n').encode())
    finally:
        os.close(fd)

DB_PATH = 'lib/apk/db/installed'
MAX_STREAM = 512 * 1024 * 1024
MAX_LAYER = 256 * 1024 * 1024
MAX_SELECTED = 8 * 1024 * 1024
MAX_RETAINED = 16 * 1024 * 1024
MAX_MEMBERS = 100000


class Reader:
    """Bound streaming input and optionally hash every raw layer byte."""
    def __init__(self, source, limit, digest=False):
        self.source, self.limit, self.count = source, limit, 0
        self.digest = hashlib.sha256() if digest else None

    def read(self, size=-1):
        size = min(65536, self.limit - self.count + 1) if size < 0 else min(size, self.limit - self.count + 1)
        data = self.source.read(size)
        self.count += len(data)
        if self.count > self.limit:
            raise InventoryError('stream byte limit exceeded')
        if self.digest is not None:
            self.digest.update(data)
        return data

    def drain(self):
        while self.read(65536):
            pass


def safe_path(path):
    path = path.removeprefix('./').rstrip('/')
    if not path or path.startswith('/') or chr(92) in path or any(
            x in ('', '.', '..') for x in path.split('/')) or any(ord(x) < 32 for x in path):
        raise InventoryError('unsafe archive path')
    return path


def layer_view(source, selected, remaining):
    reader = Reader(source, MAX_LAYER, True)
    changes, removals = {}, []
    retained = 0
    relevant = set(selected)
    for path in selected:
        parts = path.split('/')
        relevant.update('/'.join(parts[:n]) for n in range(1, len(parts)))
    with tarfile.open(fileobj=reader, mode='r|') as tf:
        for count, member in enumerate(tf, 1):
            if count > MAX_MEMBERS:
                raise InventoryError('layer member limit exceeded')
            path = safe_path(member.name)
            parent, _, base = path.rpartition('/')
            if base.startswith('.wh.'):
                if not member.isfile() or member.size != 0:
                    raise InventoryError('invalid whiteout marker')
                opaque = base == '.wh..wh..opq'
                target = parent if opaque else (parent + '/' if parent else '') + base[4:]
                if not opaque:
                    safe_path(target)
                if any(p == target or p.startswith(target + '/') or (not target and opaque) for p in relevant):
                    removals.append((target, opaque))
                continue
            if path not in relevant:
                continue
            if path in changes and not (member.isdir() and changes[path]['kind'] == 'directory'):
                raise InventoryError('ambiguous duplicate selected path')
            kind = 'directory' if member.isdir() else 'regular' if member.isfile() and not member.sparse else 'unsupported'
            info = dict(kind=kind, mode=member.mode, uid=member.uid, gid=member.gid, size=member.size)
            if path in selected and kind == 'regular':
                if member.size > MAX_SELECTED or retained + member.size > remaining:
                    raise InventoryError('selected file byte limit exceeded')
                retained += member.size
                content = tf.extractfile(member).read(MAX_SELECTED + 1)
                if len(content) != member.size:
                    raise InventoryError('truncated selected file')
                info.update(content=content, sha256=hashlib.sha256(content).hexdigest())
            changes[path] = info
    reader.drain()
    return dict(sha256='sha256:' + reader.digest.hexdigest(), changes=changes, removals=removals)


def validate_metadata(metadata):
    if (not isinstance(metadata, dict) or
            set(metadata) != {'image_id', 'architecture', 'layers'} or
            not isinstance(metadata.get('image_id'), str) or
            not re.fullmatch(r'sha256:[0-9a-f]{64}', metadata['image_id']) or
            metadata.get('architecture') != 'amd64' or
            not isinstance(metadata.get('layers'), list) or
            not 1 <= len(metadata['layers']) <= 64 or
            any(not isinstance(x, str) or not re.fullmatch(r'sha256:[0-9a-f]{64}', x) for x in metadata['layers'])):
        raise InventoryError('invalid exact image identity/architecture/layers')


def inventory_stream(source, metadata, notice_paths=()):
    """No archive/config extraction; retain only exact selected public files."""
    validate_metadata(metadata)
    if len(notice_paths) > 64:
        raise InventoryError('notice path count exceeded')
    selected = {DB_PATH, *notice_paths}
    if any(p != safe_path(p) or not public_notice(p) for p in notice_paths):
        raise InventoryError('notice path outside public notice allowlist')
    layers, manifest, retained = {}, None, 0
    reader = Reader(source, MAX_STREAM)
    with tarfile.open(fileobj=reader, mode='r|') as tf:
        for count, member in enumerate(tf, 1):
            if count > 1024:
                raise InventoryError('outer member limit exceeded')
            path = safe_path(member.name)
            if re.fullmatch(r'[0-9a-f]{64}/layer.tar', path):
                if not member.isfile() or member.size > MAX_LAYER or path in layers:
                    raise InventoryError('invalid layer member')
                layers[path] = layer_view(tf.extractfile(member), selected, MAX_RETAINED - retained)
                retained = sum(len(info.get('content', b'')) for layer in layers.values() for info in layer['changes'].values())
                if retained > MAX_RETAINED:
                    raise InventoryError('retained public file byte limit exceeded')
            elif path == 'manifest.json':
                if manifest is not None or not member.isfile() or member.size > 65536:
                    raise InventoryError('invalid manifest')
                manifest = json.loads(tf.extractfile(member).read(65537))
            # Deliberately do not extract/read image config or legacy layer JSON.
    reader.drain()
    if not isinstance(manifest, list) or len(manifest) != 1:
        raise InventoryError('exactly one legacy image manifest required')
    manifest = manifest[0]
    if not isinstance(manifest, dict):
        raise InventoryError('invalid manifest record')
    if manifest.get('Config') != metadata['image_id'].removeprefix('sha256:') + '.json':
        raise InventoryError('manifest image ID mismatch')
    order = manifest.get('Layers')
    if (not isinstance(order, list) or any(not isinstance(p, str) for p in order) or
            len(order) != len(set(order)) or set(order) != set(layers)):
        raise InventoryError('manifest layer set mismatch')
    if [layers[n]['sha256'] for n in order] != metadata['layers']:
        raise InventoryError('ordered RootFS layer digest mismatch')
    state = {}
    for index, name in enumerate(order):
        layer = layers[name]
        for target, opaque in layer['removals']:
            state = {p: v for p, v in state.items() if not (
                (p == target and not opaque) or p.startswith(target + '/') or (not target and opaque))}
        for p, info in layer['changes'].items():
            if info['kind'] != 'directory':
                state = {q: v for q, v in state.items() if not q.startswith(p + '/')}
            state[p] = dict(info, layer_index=index)
    final = {}
    for path in selected:
        if path not in state:
            continue
        for n in range(1, len(path.split('/'))):
            ancestor = '/'.join(path.split('/')[:n])
            if ancestor in state and state[ancestor]['kind'] != 'directory':
                raise InventoryError('selected file has non-directory ancestor')
        if state[path]['kind'] != 'regular':
            raise InventoryError('selected file is not regular')
        final[path] = state[path]
    if DB_PATH not in final:
        raise InventoryError('installed APK database absent from final view')
    packages = parse_apk(final[DB_PATH]['content'])
    return dict(schema_version=1, image=metadata, package_count=len(packages),
                packages=packages, selected_files=final,
                missing_notice_paths=sorted(selected - set(final)),
                layer_order=order, stream_bytes=reader.count,
                config_parsed=False, container_executed=False, legal_clearance=False,
                coverage_complete=False)


class InventoryError(ValueError):
    """Input cannot support a bounded, unambiguous inventory."""


def public_notice(path):
    if path == 'usr/lib/python3.14/LICENSE.txt':
        return True
    return (path.startswith('usr/share/licenses/') or
            path.startswith('usr/share/doc/')) and bool(re.fullmatch(
                r'(LICENSE|COPYING|COPYRIGHT|NOTICE)([._-][A-Za-z0-9._-]+)?',
                path.rsplit('/', 1)[-1], re.I))


def parse_apk(data):
    """Parse all installed records; never silently discard malformed/duplicate APKs."""
    if not data or len(data) > MAX_SELECTED:
        raise InventoryError('empty/oversized installed database')
    packages, seen = [], set()
    try:
        records = re.split(r'\n\s*\n', data.decode('utf-8').strip())
        for record in records:
            fields, notices = {}, []
            directory, file_count = '', 0
            for line in record.splitlines():
                if len(line) < 2 or line[1] != ':':
                    raise InventoryError('malformed APK field')
                key, value = line[0], line[2:]
                if key == 'F':
                    directory = safe_path(value) if value else ''
                elif key == 'R':
                    path = safe_path((directory + '/' if directory else '') + value)
                    file_count += 1
                    if public_notice(path):
                        notices.append(path)
                elif key in 'afMZ':  # repeatable file metadata, not package identity
                    continue
                elif key in fields:
                    raise InventoryError('duplicate APK field')
                else:
                    fields[key] = value
            for key in ('P', 'V', 'A', 'L', 'o'):
                if not fields.get(key):
                    raise InventoryError('required APK field absent')
            if not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9+_.-]*', fields['P']):
                raise InventoryError('invalid APK name')
            if fields['P'] in seen:
                raise InventoryError('duplicate installed APK name')
            if fields.get('c') and not re.fullmatch(r'[0-9a-f]{40}', fields['c']):
                raise InventoryError('malformed APK source commit')
            seen.add(fields['P'])
            packages.append(dict(name=fields['P'], version=fields['V'],
                                 architecture=fields['A'], license=fields['L'],
                                 origin=fields['o'], source_commit=fields.get('c'),
                                 upstream_url=fields.get('U'), checksum=fields.get('C'),
                                 dependencies=fields.get('D', '').split(),
                                 installed_file_count=file_count,
                                 notice_paths=sorted(set(notices))))
    except (UnicodeError, KeyError) as exc:
        raise InventoryError('malformed installed APK database') from exc
    return sorted(packages, key=lambda p: p['name'])


def main():
    import argparse
    import sys
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', required=True, help='Exact retained public sha256 image ID, not a tag')
    parser.add_argument('--output', required=True, help='New evidence directory; never an image archive')
    parser.add_argument('--notice-path', action='append', default=[], help='Exact public license/doc notice path')
    args = parser.parse_args()
    try:
        if os.path.lexists(args.output):
            raise InventoryError('output must not already exist')
        for path in args.notice_path:
            if path != safe_path(path) or not public_notice(path):
                raise InventoryError('notice path outside allowlist')
        result = collect(args.image, args.notice_path)
        publish(result, args.output)
        print(json.dumps(dict(status='PASS_INSTALLED_APK_INVENTORY_ONLY',
                              package_count=result['package_count'],
                              layer_count=len(result['layer_order']),
                              public_files=len(result['selected_files']),
                              config_parsed=False, container_executed=False,
                              output=args.output)))
        return 0
    except (InventoryError, OSError, ValueError, tarfile.TarError, subprocess.SubprocessError):
        # No untrusted payload or Docker stderr in errors.
        print('REFUSED: image identity, bounded stream, database or output verification failed', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
