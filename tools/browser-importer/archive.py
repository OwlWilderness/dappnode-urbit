"""Local-only, Python 3.10 stdlib ZIP pier staging; never starts a ship.

The caller must exclusively own the archive and a newly created empty 0700
stage throughout extraction, and discard the entire stage on any failure.
No identity, database health, bootability or installation claim is made.

Only stored/deflated, single-volume ZIP/ordinary ZIP64 are supported. Unknown
extra fields, trailing data and extended ZIP64 end records fail closed.
Hard caps: 100000 entries, 64 path components, 64 MiB central-directory bytes
(and at most max_entries * 4096 bytes). All archive entry types, paths, local
headers and collision trees are checked before filesystem writes. Payload CRC
checks occur while streaming, so corruption can leave partial staged files.

macOS policy: validate but discard __MACOSX resource files whose final name is
._<name> and whose exact target exists in the one pier tree; accept only their
necessary directory scaffolding. Orphan/ambiguous metadata and any inline ._*
pier paths are rejected (including legitimate names beginning ._). Create ditto
ZIPs with --keepParent plus --sequesterRsrc or --norsrc; default resource-bearing
ditto ZIPs put AppleDouble entries inside the pier and are not accepted. Finder
metadata, resource forks, archived ownership, timestamps and modes are never
restored. expanded_bytes includes discarded resource data; files counts only
imported regular files. Progress contains only stage and these aggregate counts.

Requires POSIX descriptor-relative APIs, O_DIRECTORY/O_NOFOLLOW, directory
fsync and a filesystem with those guarantees; unsupported platforms fail closed.
"""
from contextlib import ExitStack
import os
import stat
import struct
from pathlib import Path
import unicodedata
import zipfile
import zlib


class ArchiveError(Exception):
    """Archive or staging directory failed validation (no private names)."""


def _validate_extra(extra):
    # Only ZIP64, timestamps and Unix uid/gid are accepted; never restored.
    seen = set()
    while extra:
        if len(extra) < 4:
            raise ArchiveError('malformed ZIP extra field')
        kind, size = struct.unpack_from('<HH', extra)
        if (kind not in (0x0001, 0x5455, 0x7875, 0x5855) or kind in seen or
                size > len(extra) - 4 or (kind == 0x5855 and size not in (8, 12))):
            raise ArchiveError('unsupported ZIP extra field')
        seen.add(kind)
        extra = extra[4 + size:]


def _preflight(source, max_entries):
    """Bound central-directory allocation before ZipFile reads it into RAM."""
    source.seek(0, os.SEEK_END)
    size = source.tell()
    source.seek(max(0, size - 65557))
    tail = source.read(65557)
    offset = tail.rfind(b'PK\x05\x06')
    if offset < 0 or len(tail) - offset < 22:
        raise ArchiveError('invalid ZIP end record')
    record = struct.unpack('<4s4H2LH', tail[offset:offset + 22])
    _, disk, cd_disk, disk_count, count, cd_size, cd_offset, comment = record
    end = size - len(tail) + offset
    if offset + 22 + comment != len(tail) or disk or cd_disk or disk_count != count:
        raise ArchiveError('unsupported ZIP layout')
    central_end = end
    classic = (count, cd_size, cd_offset)
    source.seek(max(0, end - 20))
    locator = source.read(20) if end >= 20 else b''
    # Writers can emit ZIP64 below the classic fields' saturation thresholds.
    # The locator, not only sentinel values, determines the central-dir end.
    if (locator.startswith(b'PK\x06\x07') or count == 65535 or
            cd_size == 0xffffffff or cd_offset == 0xffffffff):
        if len(locator) != 20:
            raise ArchiveError('invalid ZIP64 locator')
        sig, disk, position, disks = struct.unpack('<4sLQL', locator)
        if sig != b'PK\x06\x07' or disk or disks != 1 or position + 56 != end - 20:
            raise ArchiveError('unsupported ZIP64 layout')
        source.seek(position)
        record64 = source.read(56)
        if len(record64) != 56:
            raise ArchiveError('invalid ZIP64 record')
        sig, length, made, needed, disk, cd_disk, disk_count, count, cd_size, cd_offset = struct.unpack('<4sQ2H2L4Q', record64)
        if sig != b'PK\x06\x06' or length != 44 or disk or cd_disk or disk_count != count:
            raise ArchiveError('unsupported ZIP64 layout')
        if any(old != sentinel and old != new for old, new, sentinel in
               zip(classic, (count, cd_size, cd_offset), (65535, 0xffffffff, 0xffffffff))):
            raise ArchiveError('inconsistent ZIP64 end records')
        central_end = position
    if (count > max_entries or cd_size > min(64 * 1024 * 1024, max_entries * 4096)
            or cd_offset + cd_size != central_end or cd_offset < 0):
        raise ArchiveError('central directory limit or layout rejected')
    source.seek(cd_offset)
    actual = 0
    while source.tell() < central_end:
        header = source.read(46)
        if len(header) != 46 or header[:4] != b'PK\x01\x02':
            raise ArchiveError('invalid central directory')
        name, extra, comment = struct.unpack_from('<3H', header, 28)
        actual += 1
        if actual > max_entries or source.tell() + name + extra + comment > central_end:
            raise ArchiveError('central directory limit rejected')
        source.seek(name + extra + comment, os.SEEK_CUR)
    if actual != count:
        raise ArchiveError('central directory count mismatch')
    source.seek(0)
    return cd_offset


def _local_headers(source, entries, central_start):
    previous_end = 0
    for info in sorted(entries, key=lambda i: i.header_offset):
        if (info.header_offset < previous_end or info.flag_bits & ~0x080e or
                info.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED) or
                (info.is_dir() and (info.file_size or info.CRC))):
            raise ArchiveError('unsupported ZIP member')
        source.seek(info.header_offset)
        header = source.read(30)
        if len(header) != 30 or header[:4] != b'PK\x03\x04':
            raise ArchiveError('invalid local ZIP header')
        _, version, flags, compression, time, date, crc, compressed, expanded, name_len, extra_len = struct.unpack('<4s5H3L2H', header)
        name = source.read(name_len)
        extra = source.read(extra_len)
        _validate_extra(extra)
        if (flags != info.flag_bits or compression != info.compress_type or len(extra) != extra_len or
                b'\x00' in name or name.decode('utf-8' if flags & 0x800 else 'cp437') != info.orig_filename):
            raise ArchiveError('inconsistent local ZIP header')
        if not flags & 8:
            if expanded == 0xffffffff or compressed == 0xffffffff:
                offset = 0
                sizes = None
                while offset < len(extra):
                    kind, length = struct.unpack_from('<HH', extra, offset)
                    if kind == 1:
                        sizes = extra[offset + 4:offset + 4 + length]
                    offset += 4 + length
                if sizes is None or len(sizes) < 16:
                    raise ArchiveError('invalid local ZIP64 sizes')
                expanded, compressed = struct.unpack_from('<2Q', sizes)
            if (crc, compressed, expanded) != (info.CRC, info.compress_size, info.file_size):
                raise ArchiveError('inconsistent local ZIP sizes')
        previous_end = source.tell() + info.compress_size
        if previous_end > central_start:
            raise ArchiveError('overlapping ZIP member')


def _open_directory_chain(path):
    """Open every component, including parents, without following links."""
    path = Path(path)
    if '..' in path.parts:
        raise ArchiveError('unsafe staging path')
    parts = Path(os.path.abspath(path)).parts
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def _directories(root_fd, parts):
    fd = os.dup(root_fd)
    try:
        for part in parts:
            try:
                os.mkdir(part, 0o700, dir_fd=fd)
                os.fsync(fd)
            except FileExistsError:
                pass
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
            os.fchmod(fd, 0o700)
        return fd
    except BaseException:
        os.close(fd)
        raise


def extract_zip(archive_path: Path, destination: Path, *, max_expanded_bytes: int,
                max_entries: int = 100000, max_depth: int = 64,
                max_ratio: int = 1000, progress=None) -> dict:
    """Extract into an existing empty 0700 stage, leaving cleanup to caller."""
    limits = (max_expanded_bytes, max_entries, max_depth, max_ratio)
    if any(type(v) is not int or v <= 0 for v in limits):
        raise ArchiveError('limits must be positive integers')
    root_fd = None
    try:
        root_fd = _open_directory_chain(destination)
        status = os.fstat(root_fd)
        if status.st_uid != os.getuid() or stat.S_IMODE(status.st_mode) != 0o700 or os.listdir(root_fd):
            raise ArchiveError('stage must be empty and private')
        return _extract(archive_path, root_fd, max_expanded_bytes,
                        min(max_entries, 100000), min(max_depth, 64), max_ratio, progress)
    except (OSError, ValueError, zipfile.BadZipFile, NotImplementedError, RuntimeError, zlib.error, EOFError):
        raise ArchiveError('archive extraction rejected') from None
    finally:
        if root_fd is not None:
            os.close(root_fd)


def _consume(archive, info, output, total, max_expanded_bytes, max_ratio, progress, files):
    member_bytes = 0
    with archive.open(info) as source:
        while True:
            block = source.read(65536)
            if not block:
                break
            member_bytes += len(block)
            total += len(block)
            if (total > max_expanded_bytes or member_bytes > info.file_size or
                    member_bytes > max_ratio * max(1, info.compress_size)):
                raise ArchiveError('expanded data limit exceeded')
            if output is not None:
                output.write(block)
            if progress:
                progress({'stage': 'extracting', 'expanded_bytes': total, 'files': files})
        if member_bytes != info.file_size:
            raise ArchiveError('expanded size mismatch')
    return total


def _extract(archive_path, root_fd, max_expanded_bytes, max_entries, max_depth, max_ratio, progress):
    total = files = 0
    with ExitStack() as stack:
        archive_path = Path(archive_path)
        parent = _open_directory_chain(archive_path.parent)
        try:
            fd = os.open(archive_path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        finally:
            os.close(parent)
        source = stack.enter_context(os.fdopen(fd, 'rb'))
        if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
            raise ArchiveError('archive must be a regular file')
        central_start = _preflight(source, max_entries)
        archive = stack.enter_context(zipfile.ZipFile(source))
        entries = archive.infolist()
        _local_headers(source, entries, central_start)
        if (len(entries) > max_entries or sum(i.file_size for i in entries) > max_expanded_bytes
                or any(i.file_size > max_ratio * max(1, i.compress_size) for i in entries)):
            raise ArchiveError('archive resource limit exceeded')
        for info in entries:
            _validate_extra(info.extra)
            mode = info.external_attr >> 16
            kind = stat.S_IFMT(mode)
            expected = stat.S_IFDIR if info.is_dir() else stat.S_IFREG
            if (kind not in (0, expected) or mode & 0o7000 or
                    (info.external_attr & 0x10 and not info.is_dir()) or
                    info.external_attr & 0x400):
                raise ArchiveError('nonregular archive entry')
            name = info.orig_filename
            parts = (name[:-1] if name.endswith('/') else name).split('/')
            if (len(parts) > max_depth or '\x00' in name or '\\' in name or name.startswith('/') or
                    any(p in ('', '.', '..') or ':' in p for p in parts)):
                raise ArchiveError('unsafe archive path')
            if parts[0] != '__MACOSX' and any(p.startswith('._') for p in parts):
                raise ArchiveError('inline macOS metadata is not supported')
        nodes = {}
        explicit = set()
        roots = set()
        has_file = False
        for info in entries:
            parts = tuple(info.orig_filename.rstrip('/').split('/'))
            if parts[0] != '__MACOSX':
                roots.add(parts[0])
                has_file |= not info.is_dir()
            for length in range(1, len(parts) + 1):
                raw = parts[:length]
                key = tuple(unicodedata.normalize('NFC', p).casefold() for p in raw)
                directory = length < len(parts) or info.is_dir()
                previous = nodes.get(key)
                if previous is not None and previous != (raw, directory):
                    raise ArchiveError('ambiguous archive tree')
                if length == len(parts):
                    if key in explicit:
                        raise ArchiveError('duplicate archive entry')
                    explicit.add(key)
                nodes[key] = (raw, directory)
        if len(roots) != 1 or not has_file:
            raise ArchiveError('archive must contain one nonempty pier')
        root = next(iter(roots))
        urb = nodes.get((unicodedata.normalize('NFC', root).casefold(), '.urb'))
        if urb != ((root, '.urb'), True):
            raise ArchiveError('pier requires a real .urb directory')
        metadata = set()
        resource_parents = set()
        for info in entries:
            parts = tuple(info.orig_filename.rstrip('/').split('/'))
            if parts[0] == '__MACOSX':
                metadata.add(info.orig_filename)
                if not info.is_dir():
                    if len(parts) < 2 or not parts[-1].startswith('._') or len(parts[-1]) <= 2:
                        raise ArchiveError('unrecognized macOS metadata')
                    target = parts[1:-1] + (parts[-1][2:],)
                    key = tuple(unicodedata.normalize('NFC', p).casefold() for p in target)
                    node = nodes.get(key)
                    if not target or target[0] != root or node is None or node[0] != target:
                        raise ArchiveError('unmatched macOS metadata')
                    resource_parents.update(parts[:n] for n in range(1, len(parts)))
        for info in entries:
            if info.orig_filename in metadata and info.is_dir():
                if tuple(info.orig_filename.rstrip('/').split('/')) not in resource_parents:
                    raise ArchiveError('orphan macOS metadata directory')
        for info in entries:
            if info.orig_filename in metadata:
                total = _consume(archive, info, None, total, max_expanded_bytes, max_ratio, progress, files)
                if progress:
                    progress({'stage': 'extracting', 'expanded_bytes': total, 'files': files})
                continue
            parts = info.filename.rstrip('/').split('/')[1:]
            parent = _directories(root_fd, ['ship'] + (parts if info.is_dir() else parts[:-1]))
            try:
                if not info.is_dir():
                    fd = os.open(parts[-1], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                 0o600, dir_fd=parent)
                    with os.fdopen(fd, 'wb') as output:
                        total = _consume(archive, info, output, total, max_expanded_bytes, max_ratio, progress, files)
                        output.flush()
                        os.fsync(output.fileno())
                    files += 1
                else:
                    total = _consume(archive, info, None, total, max_expanded_bytes, max_ratio, progress, files)
                os.fsync(parent)
            finally:
                os.close(parent)
            if progress:
                progress({'stage': 'extracting', 'expanded_bytes': total, 'files': files})
        os.fsync(root_fd)
    return {'expanded_bytes': total, 'files': files}
