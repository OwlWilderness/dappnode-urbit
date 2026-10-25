#!/usr/bin/env python3
"""Verify public legacy Docker-save TXZ bytes without extraction or Docker.

This module is only for explicitly selected public image archives, not private
state. Config bytes are hashed/parsed in memory and never emitted. One XZ stream
and a complete outer tar are required; concatenation is deliberately unsupported.
"""
import hashlib
import json
import lzma
import os
import re
import stat
import tarfile

CHUNK = 65536
XZ_MEMORY_LIMIT = 64 * 1024 * 1024
MAX_CONFIG = 1024 * 1024
MAX_MANIFEST = 65536
MAX_METADATA = 1024 * 1024
MAX_MEMBERS = 1024
MAX_LAYERS = 64
HEX = r'[0-9a-f]{64}'


def _json(data):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ArchiveError('duplicate JSON key')
            result[key] = value
        return result

    def constant(_value):
        raise ArchiveError('nonstandard JSON constant')

    return json.loads(data.decode('utf-8'), object_pairs_hook=pairs,
                      parse_constant=constant)


class ArchiveError(ValueError):
    """The public archive cannot establish the requested image binding."""


class _XZReader:
    """Single-pass compressed hash and bounded incremental decompression."""
    def __init__(self, source, limit):
        self.source = source
        self.limit = limit
        self.decoder = lzma.LZMADecompressor(format=lzma.FORMAT_XZ,
                                            memlimit=XZ_MEMORY_LIMIT)
        self.digest = hashlib.sha256()
        self.compressed = 0
        self.expanded = 0
        self.done = False

    def read(self, size):
        size = min(size, CHUNK)
        while not self.done:
            if self.decoder.eof:
                if self.decoder.unused_data or self.source.read(1):
                    raise ArchiveError('trailing XZ data refused')
                self.done = True
                return b''
            raw = b''
            if self.decoder.needs_input:
                raw = self.source.read(min(CHUNK, self.limit - self.compressed + 1))
                if not raw:
                    raise ArchiveError('incomplete XZ stream')
                self.compressed += len(raw)
                if self.compressed > self.limit:
                    raise ArchiveError('compressed byte limit exceeded')
                self.digest.update(raw)
            data = self.decoder.decompress(raw, max_length=size)
            self.expanded += len(data)
            if self.expanded > self.limit:
                raise ArchiveError('expanded byte limit exceeded')
            if data:
                return data
        return b''

    def exact(self, size):
        result = bytearray()
        while len(result) < size:
            data = self.read(size - len(result))
            if not data:
                raise ArchiveError('truncated tar data')
            result.extend(data)
        return bytes(result)


def _scan(reader, image_id):
    config_digest = None
    config = None
    manifest = None
    repositories = None
    layer_hashes = {}
    seen = set()
    legacy = set()
    while True:
        header = reader.exact(512)
        if header == bytes(512):
            if reader.exact(512) != bytes(512):
                raise ArchiveError('invalid tar terminator')
            padding = 0
            while data := reader.read(CHUNK):
                padding += len(data)
                if any(data):
                    raise ArchiveError('nonzero terminal tar padding')
            if padding % 512:
                raise ArchiveError('unaligned terminal tar padding')
            break
        member = tarfile.TarInfo.frombuf(header, 'utf-8', 'strict')
        name = member.name
        raw_name = header[:100].split(b'\0', 1)[0].decode('utf-8')
        if (header[257:265] not in (b'ustar\x0000', b'ustar  \x00') or
                member.type not in (tarfile.REGTYPE, tarfile.AREGTYPE, tarfile.DIRTYPE) or
                member.linkname or any(header[345:500]) or
                raw_name not in (name, name + '/' if member.isdir() else name)):
            raise ArchiveError('unsupported tar header')
        if name in seen or len(seen) >= MAX_MEMBERS:
            raise ArchiveError('duplicate or excessive tar members')
        seen.add(name)
        if member.isdir():
            if not re.fullmatch(HEX, name) or member.size != 0:
                raise ArchiveError('unsupported directory')
            legacy.add(name)
            limit = 0
        elif name == image_id[7:] + '.json':
            limit = MAX_CONFIG
        elif name == 'manifest.json':
            limit = MAX_MANIFEST
        elif name == 'repositories':
            limit = MAX_METADATA
        elif re.fullmatch(HEX + r'/(layer\.tar|json|VERSION)', name):
            legacy.add(name.split('/')[0])
            limit = reader.limit if name.endswith('/layer.tar') else MAX_METADATA
        else:
            raise ArchiveError('unsupported archive member path')
        if member.size < 0 or member.size > min(limit, reader.limit):
            raise ArchiveError('member byte limit exceeded')
        digest = hashlib.sha256()
        retained = bytearray()
        selected = name in ('manifest.json', 'repositories', image_id[7:] + '.json')
        remaining = member.size
        while remaining:
            data = reader.exact(min(CHUNK, remaining))
            remaining -= len(data)
            digest.update(data)
            if selected:
                retained.extend(data)
        if any(reader.exact((-member.size) % 512)):
            raise ArchiveError('nonzero member tar padding')
        if member.name == 'manifest.json':
            manifest = _json(retained)
        elif member.name == 'repositories':
            repositories = _json(retained)
            if not isinstance(repositories, dict):
                raise ArchiveError('invalid repositories metadata')
        elif member.name == image_id[7:] + '.json':
            config_digest = 'sha256:' + digest.hexdigest()
            config = _json(retained)
        elif member.name.endswith('/layer.tar'):
            layer_hashes[member.name] = 'sha256:' + digest.hexdigest()
    if legacy != {name.split('/')[0] for name in layer_hashes}:
        raise ArchiveError('unreferenced legacy metadata')
    return manifest, config, config_digest, layer_hashes, repositories


def verify_archive(path, *, image_id, repo_tag, layers, max_bytes=8589934592):
    """Return only public binding metadata; refusals never include input text.

    max_bytes bounds compressed bytes, expanded tar bytes and each raw layer.
    Config/legacy metadata: 1 MiB each; manifest: 64 KiB; 64 layers/1024 members.
    XZ decoder memory: 64 MiB. Legacy json/VERSION payloads are bounded/discarded,
    not interpreted. Layer contents are hashed, not extracted or inspected.
    The caller must supply a public archive under a trusted parent directory.
    """
    try:
        if (not isinstance(image_id, str) or not re.fullmatch('sha256:' + HEX, image_id) or
                not isinstance(repo_tag, str) or len(repo_tag) > 255 or
                not re.fullmatch(r'[a-z0-9][a-z0-9._:/-]*:[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}', repo_tag) or
                not isinstance(layers, (list, tuple)) or not 1 <= len(layers) <= MAX_LAYERS or
                any(not isinstance(x, str) or not re.fullmatch('sha256:' + HEX, x) for x in layers) or
                type(max_bytes) is not int or not 0 < max_bytes <= 8589934592):
            raise ArchiveError('invalid expected public image contract')
        layers = list(layers)
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, 'rb') as source:
            before = os.fstat(source.fileno())
            if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= max_bytes:
                raise ArchiveError('invalid archive file')
            reader = _XZReader(source, max_bytes)
            manifest, config, config_digest, layer_hashes, repositories = _scan(reader, image_id)
            after = os.fstat(source.fileno())
            if ((before.st_size, before.st_mtime_ns, before.st_ctime_ns) !=
                    (after.st_size, after.st_mtime_ns, after.st_ctime_ns) or
                    reader.compressed != before.st_size):
                raise ArchiveError('archive changed during verification')
        if (config_digest != image_id or not isinstance(manifest, list) or
                len(manifest) != 1 or not isinstance(manifest[0], dict) or
                set(manifest[0]) != {'Config', 'RepoTags', 'Layers'} or
                manifest[0].get('Config') != image_id[7:] + '.json'):
            raise ArchiveError('image config identity mismatch')
        record = manifest[0]
        if record.get('RepoTags') != [repo_tag]:
            raise ArchiveError('exact repository tag mismatch')
        if (not isinstance(config, dict) or config.get('os') != 'linux' or config.get('architecture') != 'amd64' or
                config.get('rootfs') != {'type': 'layers', 'diff_ids': list(layers)}):
            raise ArchiveError('platform or rootfs mismatch')
        order = record.get('Layers', [])
        if (not isinstance(order, list) or not 1 <= len(order) <= MAX_LAYERS or
                any(not isinstance(name, str) for name in order) or
                set(order) != set(layer_hashes) or len(order) != len(set(order)) or
                [layer_hashes.get(name) for name in order] != list(layers)):
            raise ArchiveError('ordered layer digest mismatch')
        repository, tag = repo_tag.rsplit(':', 1)
        if repositories is not None and repositories != {repository: {tag: order[-1].split('/')[0]}}:
            raise ArchiveError('legacy repository binding mismatch')
        return dict(image_id=image_id, repo_tag=repo_tag, platform='linux/amd64',
                    layers=list(layers), archive_sha256=reader.digest.hexdigest(),
                    archive_bytes=reader.compressed)
    except (OSError, ValueError, TypeError, RecursionError, EOFError, tarfile.TarError, lzma.LZMAError):
        raise ArchiveError('public archive verification refused') from None
