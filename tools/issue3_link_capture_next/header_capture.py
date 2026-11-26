"""File-only verifier/retainer for an explicitly exported Zig header graph.

This module does NOT observe the Zig graph, compiler, preprocessor or linker. The
caller must supply graph facts from an independently authenticated make-phase
export after compilation. No recipe currently calls this component.
"""
import hashlib
import json
import os
from pathlib import Path
import stat
import unicodedata

MAX_HEADERS = 10000
MAX_HEADER_BYTES = 256 * 1024 * 1024
MAX_TOTAL_HEADER_BYTES = 256 * 1024 * 1024


def _shape(value, keys, optional=()):
    if not isinstance(value, dict) or not set(value).issubset(set(keys) | set(optional)) or not set(keys).issubset(value):
        raise ValueError('unsupported graph shape')


def _label(value, allow_empty=False, require_namespace=False):
    if allow_empty and value == '':
        return ''
    if not isinstance(value, str) or not value or '\\' in value or '\x00' in value or value.startswith('/') or any(x in ('', '.', '..') for x in value.split('/')):
        raise ValueError('noncanonical header label')
    if require_namespace and '/' not in value:
        raise ValueError('noncanonical header label')
    return value


def _safe_path(value, kind):
    if not isinstance(value, str) or not os.path.isabs(value) or '\x00' in value:
        raise ValueError('absolute source path required')
    path = Path(value)
    if '..' in path.parts or '.' in path.parts:
        raise ValueError('noncanonical source path')
    for ancestor in (path, *path.parents):
        if ancestor.is_symlink():
            raise ValueError('symlinked source path')
    if kind == 'file' and not path.is_file() or kind == 'directory' and not path.is_dir():
        raise ValueError('source type or existence')
    return path


def _inventory(root, includes, excludes):
    files = {}
    for current, dirs, names in os.walk(root, followlinks=False):
        for name in dirs + names:
            path = Path(current) / name
            mode = path.lstat().st_mode
            if not stat.S_ISDIR(mode) and not stat.S_ISREG(mode):
                raise ValueError('special or symlinked header tree entry')
        for name in names:
            path = Path(current) / name
            rel = path.relative_to(root).as_posix()
            _label(rel)
            if (includes is None or any(rel.endswith(x) for x in includes)) and not any(rel.endswith(x) for x in excludes):
                files[rel] = path
                if len(files) > MAX_HEADERS:
                    raise ValueError('header count limit')
    return files


def _digest(path):
    h = hashlib.sha256()
    size = 0
    with path.open('rb') as stream:
        while chunk := stream.read(1024 * 1024):
            h.update(chunk)
            size += len(chunk)
            if size > MAX_HEADER_BYTES:
                raise ValueError('header size limit')
    return h.hexdigest(), size


def _copy_header(source, target, remaining):
    size = 0
    with source.open('rb') as stream, target.open('xb') as destination:
        while chunk := stream.read(min(1024 * 1024, MAX_HEADER_BYTES - size + 1, remaining - size + 1)):
            size += len(chunk)
            if size > MAX_HEADER_BYTES:
                raise ValueError('header size limit')
            if size > remaining:
                raise ValueError('aggregate header size limit')
            destination.write(chunk)
    return size


def capture(graph, output):
    """Copy verified registered headers to a fresh destination and issue receipt.

    Refuses inconsistent graph/copy data; cannot authenticate supplied graph facts.
    Labels are literal POSIX namespace/filename paths; directory prefixes may be
    empty or one component. Both per-file and aggregate copied bytes are bounded.
    Partial output on copy failure is deliberately left in place, without receipt.
    """
    _shape(graph, ('schema', 'modules', 'registrations'))
    if type(graph['schema']) is not int or graph['schema'] != 1:
        raise ValueError('unsupported schema')
    modules = graph['modules']
    regs = graph['registrations']
    if not isinstance(modules, list) or not modules or not isinstance(regs, list) or not regs:
        raise ValueError('empty graph')
    paths = []
    for module in modules:
        _shape(module, ('id', 'includes', 'macros', 'target', 'c_flags'))
        if not isinstance(module['id'], str) or not module['id'] or not isinstance(module['target'], str) or not module['target']:
            raise ValueError('missing module identity')
        if not isinstance(module['macros'], list) or not all(isinstance(m, str) for m in module['macros']):
            raise ValueError('invalid literal macros')
        if not isinstance(module['c_flags'], list) or not all(isinstance(f, str) for f in module['c_flags']):
            raise ValueError('invalid C flags')
        if not isinstance(module['includes'], list):
            raise ValueError('invalid includes')
        for include in module['includes']:
            _shape(include, ('kind', 'path'))
            if include['kind'] not in ('path', 'path_system', 'path_after', 'other_step', 'config_header_step', 'framework_path', 'framework_path_system', 'embed_path'):
                raise ValueError('unknown include tag')
            paths.append(str(_safe_path(include['path'], 'directory')) if include['kind'] == 'other_step' else include['path'])
            if not isinstance(include['path'], str) or not os.path.isabs(include['path']):
                raise ValueError('unresolved include path')
    selected = {}
    destinations = set()
    total_size = 0
    for reg in regs:
        _shape(reg, ('owner', 'kind', 'source', 'emitted', 'dest'), ('include_extensions', 'exclude_extensions'))
        if not isinstance(reg['owner'], str) or not reg['owner'] or reg['kind'] not in ('file', 'directory'):
            raise ValueError('registration owner/type')
        kind = reg['kind']
        source = _safe_path(reg['source'], kind)
        emitted = _safe_path(reg['emitted'], kind)
        if not any(emitted == Path(base) or emitted.is_relative_to(Path(base)) for base in paths):
            raise ValueError('emitted header absent from consumer include order')
        dest = _label(reg['dest'], allow_empty=kind == 'directory', require_namespace=kind == 'file')
        includes = reg.get('include_extensions', ['.h'])
        excludes = reg.get('exclude_extensions', [])
        if (not isinstance(excludes, list) or not all(isinstance(x, str) and x for x in excludes) or
                includes is not None and (not isinstance(includes, list) or not all(isinstance(x, str) and x for x in includes))):
            raise ValueError('invalid extension filters')
        if kind == 'file':
            if 'include_extensions' in reg or 'exclude_extensions' in reg:
                raise ValueError('file registration has directory filters')
            items = [(dest, source, emitted)]
        else:
            src = _inventory(source, includes, excludes)
            out = _inventory(emitted, includes, excludes)
            if not src or src.keys() != out.keys():
                raise ValueError('source/emitted header inventory differs')
            items = [(_label('/'.join(filter(None, (dest, rel))), require_namespace=True), src[rel], out[rel]) for rel in src]
        for label, src, dst in items:
            key = unicodedata.normalize('NFC', label).casefold()
            if key in destinations:
                raise ValueError('colliding installed header')
            destinations.add(key)
            if len(destinations) > MAX_HEADERS:
                raise ValueError('header count limit')
            expected = _digest(src)
            if expected != _digest(dst):
                raise ValueError('source/emitted header differs')
            total_size += expected[1]
            if total_size > MAX_TOTAL_HEADER_BYTES:
                raise ValueError('aggregate header size limit')
            selected[label] = (src, dst, reg['owner'])
    output = Path(output)
    if not output.is_absolute() or '..' in output.parts or output.exists() or output.is_symlink():
        raise ValueError('fresh absolute output required')
    _safe_path(str(output.parent), 'directory')
    # All graph and input validation happens before creating the output.
    output.mkdir()
    records = []
    copied_size = 0
    for label, (src, emitted, owner) in sorted(selected.items()):
        target = output / 'headers' / label
        target.parent.mkdir(parents=True, exist_ok=True)
        copied_size += _copy_header(emitted, target, MAX_TOTAL_HEADER_BYTES - copied_size)
        digest, size = _digest(src)
        if _digest(emitted) != (digest, size) or _digest(target) != (digest, size):
            raise ValueError('header changed during copy')
        records.append({'label': label, 'owner': owner, 'source': str(src), 'emitted': str(emitted),
                        'sha256': digest, 'size': size})
    for record in records:
        expected = (record['sha256'], record['size'])
        if _digest(Path(record['source'])) != expected or _digest(Path(record['emitted'])) != expected or _digest(output / 'headers' / record['label']) != expected:
            raise ValueError('late header mutation')
    receipt = {'schema': 1, 'modules': modules, 'registrations': regs, 'headers': records}
    (output / 'headers.json').write_text(json.dumps(receipt, sort_keys=True, separators=(',', ':')) + '\n')
    return receipt
