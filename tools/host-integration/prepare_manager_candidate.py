#!/usr/bin/env python3
"""Prepare pinned Dappmanager source only; never build, publish, or install.

Requires a pristine local v0.2.129 Git checkout and the fixed reviewed patch.
The exclusive output contains source/, provenance/, and candidate.json. An image
or SDK release archive is NOT produced. Historical releases.json is upstream
source history, not candidate release identity. No Git/network/engine writes to
inputs are performed. A failed post-creation run retains its incomplete output;
use a different fresh path, never retry into the old one.
"""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import subprocess
import sys
import tarfile

PIN = 'a21bab295d4c68c3b6115498b18a8efaf89d52a0'
TAG = 'v0.2.129'
VERSION = '0.2.129'
PATCH_SHA256 = 'c7149f6b0923b013c354e89e43e02378c15e0bf7fe52c7671eeb693090ecbd50'
IMAGE = 'dappmanager.dnp.dappnode.eth:' + VERSION


def digest(data):
    return hashlib.sha256(data).hexdigest()


def git(directory, *args, data=None):
    env = {key: value for key, value in os.environ.items() if not key.startswith('GIT_')}
    env.update(GIT_OPTIONAL_LOCKS='0', GIT_NO_REPLACE_OBJECTS='1', GIT_TERMINAL_PROMPT='0',
               GIT_CEILING_DIRECTORIES=str(Path(directory).resolve().parent))
    child = subprocess.run(['git', '-c', 'core.fsmonitor=false', '-c', 'core.hooksPath=/dev/null',
                            '-C', str(directory), *args], input=data,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, timeout=90)
    if child.returncode:
        raise ValueError('git operation refused: ' + child.stderr.decode(errors='replace').strip())
    return child.stdout


def tree_digest(directory):
    records = []
    for path in sorted(directory.rglob('*')):
        if path.is_file():
            records.append([path.relative_to(directory).as_posix(),
                            oct(path.stat().st_mode & 0o777), digest(path.read_bytes())])
    return digest(json.dumps(records, separators=(',', ':')).encode())


def prepare(source, patch, output):
    source, patch, output = Path(source).resolve(), Path(patch).resolve(), Path(output).absolute()
    resolved_output = output.resolve()
    if resolved_output == source or source in resolved_output.parents:
        raise ValueError('output must be outside source')
    patch_bytes = patch.read_bytes()
    if digest(patch_bytes) != PATCH_SHA256:
        raise ValueError('patch SHA256 mismatch')
    if Path(git(source, 'rev-parse', '--show-toplevel').decode().strip()).resolve() != source:
        raise ValueError('source must be a checkout root')
    if git(source, 'rev-parse', 'HEAD').decode().strip() != PIN:
        raise ValueError('source HEAD pin mismatch')
    if git(source, 'rev-parse', 'refs/tags/' + TAG + '^{commit}').decode().strip() != PIN:
        raise ValueError('source tag pin mismatch')
    if git(source, 'status', '--porcelain=v1', '--untracked-files=all', '--ignored'):
        raise ValueError('source is not pristine (including ignored files)')
    archive = git(source, 'archive', '--format=tar', PIN)
    tracked = set(git(source, 'ls-tree', '-r', '--name-only', '-z', PIN).decode().rstrip('\0').split('\0'))
    archived = set()
    with tarfile.open(fileobj=io.BytesIO(archive), mode='r:') as tar:
        for member in tar:
            if not member.isfile():
                if not member.isdir():
                    raise ValueError('source archive contains unsupported entry')
                continue
            archived.add(member.name)
            path = source / member.name
            stream = tar.extractfile(member)
            if stream is None or path.is_symlink() or any(p.is_symlink() for p in path.parents if p != source):
                raise ValueError('source tracked path is not a regular file')
            if not path.is_file() or path.read_bytes() != stream.read():
                raise ValueError('source tracked bytes drift: ' + member.name)
            if bool(path.stat().st_mode & 0o111) != bool(member.mode & 0o111):
                raise ValueError('source tracked mode drift: ' + member.name)
    if archived != tracked:
        raise ValueError('source archive inventory drift')
    output.mkdir(mode=0o700, parents=False, exist_ok=False)
    prepared = output / 'source'
    prepared.mkdir(mode=0o700)
    with tarfile.open(fileobj=io.BytesIO(archive), mode='r:') as tar:
        for member in tar:
            name = PurePosixPath(member.name)
            if name.is_absolute() or '..' in name.parts or not (member.isfile() or member.isdir()):
                raise ValueError('unsafe source archive member')
            path = prepared.joinpath(*name.parts)
            if member.isdir():
                path.mkdir(parents=True, exist_ok=True)
            else:
                path.parent.mkdir(parents=True, exist_ok=True)
                stream = tar.extractfile(member)
                if stream is None:
                    raise ValueError('source archive file has no data')
                with path.open('xb') as target:
                    target.write(stream.read())
                path.chmod(member.mode & 0o777)
    original_manifest = json.loads((prepared / 'dappnode_package.json').read_text())
    original_compose = (prepared / 'docker-compose.yml').read_bytes()
    git(prepared, 'apply', '--check', '-', data=patch_bytes)
    git(prepared, 'apply', '-', data=patch_bytes)
    manifest_path = prepared / 'dappnode_package.json'
    manifest = json.loads(manifest_path.read_text())
    if manifest != original_manifest:
        raise ValueError('candidate manifest drift or inherited release identity')
    if manifest.get('version') != '0.2.71':
        raise ValueError('candidate unexpected source manifest version')
    manifest['version'] = VERSION
    manifest_path.write_text(json.dumps(manifest, indent=2) + '\n')
    compose_path = prepared / 'docker-compose.yml'
    old_image = b'image: "dappmanager.dnp.dappnode.eth:0.2.71"'
    if compose_path.read_bytes() != original_compose or original_compose.count(old_image) != 1:
        raise ValueError('candidate Compose drift (mounts/networks must remain unchanged)')
    compose = original_compose.replace(old_image, ('image: "' + IMAGE + '"').encode())
    compose_path.write_bytes(compose)
    provenance = output / 'provenance'
    provenance.mkdir(mode=0o700)
    (provenance / 'upstream-dappmanager.patch').write_bytes(patch_bytes)
    receipt = {
        'schema': 1, 'state': 'source-prepared', 'image_state': 'image-pending',
        'installable': False, 'version': VERSION, 'compose_image': IMAGE,
        'image_id': None, 'archive': None, 'cid': None, 'content_hash': None,
        'source_path': str(source), 'source_tag': TAG, 'source_commit': PIN,
        'source_archive_sha256': digest(archive), 'patch_path': str(patch),
        'patch_sha256': digest(patch_bytes), 'source_tree_sha256': tree_digest(prepared),
        'manifest_sha256': digest(manifest_path.read_bytes()), 'compose_sha256': digest(compose),
        'historical_releases_are_candidate_identity': False,
    }
    (output / 'candidate.json').write_text(json.dumps(receipt, indent=2, sort_keys=True) + '\n')
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True, type=Path)
    parser.add_argument('--patch', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    try:
        receipt = prepare(args.source, args.patch, args.output)
    except (OSError, ValueError, subprocess.SubprocessError, tarfile.TarError) as error:
        print('source preparation refused: ' + str(error), file=sys.stderr)
        return 2
    print(json.dumps(receipt, sort_keys=True))
    return 0


if __name__ == '__main__':
    sys.exit(main())
