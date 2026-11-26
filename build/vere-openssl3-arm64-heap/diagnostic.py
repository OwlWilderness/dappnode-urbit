"""Strict source-only diagnostic overlay; no compiler or patch executable.

All hunks are resolved in memory before any patched file is written. Line
numbers are checked for ordering, not used to guess offsets: the base report
transform shifts later main.c lines. Every complete preimage must occur exactly
once, with no whitespace normalization, fuzz, or partial-context fallback.
"""
import hashlib
import json
from pathlib import PurePosixPath
import re
import shutil

RECIPE_FILES = ('diagnostic.py', 'vere.patch', 'spawn.patch', 'musl.patch', 'openssl.patch',
                'target-build.patch', 'uvm_issue3_diag.h')
ALLOWED = {
    'vere.patch': {'pkg/vere/' + n for n in
                   ('main.c', 'mars.c', 'lord.c', 'king.c', 'pier.c', 'vere.h')} | {'pkg/noun/manage.c'},
    'spawn.patch': {'pkg/vere/main.c', 'pkg/vere/lord.c'},
    'target-build.patch': {'build.zig'},
    'openssl.patch': {'crypto/init.c', 'crypto/cryptlib.c'},
    'musl.patch': {'src/exit/exit.c', 'src/exit/abort.c'},
}
HUNK = re.compile(r'@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@(?:[^\n]*)\n')


def digest(data):
    return hashlib.sha256(data).hexdigest()


def apply_diff(data, read_source, allowed):
    """Return path->bytes; reject unsupported formats or ambiguous preimages."""
    lines = data.decode('utf-8').splitlines(keepends=True)
    results = {}
    index = 0
    while index < len(lines):
        if not lines[index].startswith('--- a/') or index + 1 >= len(lines):
            raise ValueError('expected plain unified diff old-file header')
        name = lines[index][6:].removesuffix('\n')
        path = PurePosixPath(name)
        if (name not in allowed or path.is_absolute() or '..' in path.parts or
                str(path) != name or name in results or
                lines[index + 1] != '+++ b/' + name + '\n'):
            raise ValueError('unsafe, duplicate or mismatched patch path: ' + name)
        source = read_source(name).decode('utf-8').splitlines(keepends=True)
        index += 2
        cursor = 0
        output = []
        hunks = 0
        old_end = new_end = 0
        while index < len(lines) and not lines[index].startswith('--- a/'):
            match = HUNK.fullmatch(lines[index])
            if not match:
                raise ValueError('invalid hunk header: ' + name)
            old_start, old_count, new_start, new_count = (
                int(value) if value is not None else 1 for value in match.groups())
            if old_count == 0 or old_start < old_end or new_start < new_end:
                raise ValueError('empty preimage or unordered hunks: ' + name)
            old_end, new_end = old_start + old_count, new_start + new_count
            index += 1
            before, after = [], []
            while index < len(lines):
                line = lines[index]
                if line.startswith('@@ ') or line.startswith('--- a/'):
                    break
                if not line.endswith('\n') or line[:1] not in (' ', '+', '-'):
                    raise ValueError('unsupported hunk line: ' + name)
                if line[0] in ' -':
                    before.append(line[1:])
                if line[0] in ' +':
                    after.append(line[1:])
                index += 1
            if len(before) != old_count or len(after) != new_count:
                raise ValueError('hunk count mismatch: ' + name)
            positions = [i for i in range(len(source) - len(before) + 1)
                         if source[i:i + len(before)] == before]
            if len(positions) != 1 or positions[0] < cursor:
                raise ValueError('nonunique, missing or overlapping exact preimage: ' + name)
            position = positions[0]
            output.extend(source[cursor:position])
            output.extend(after)
            cursor = position + len(before)
            hunks += 1
        if not hunks:
            raise ValueError('file diff has no hunks: ' + name)
        output.extend(source[cursor:])
        results[name] = ''.join(output).encode('utf-8')
    if set(results) != allowed:
        raise ValueError('patch file set differs from required instrumentation set')
    return results


def prepare(here, output, trees, tree_hashes):
    # Read required final inputs first. Never fall back to the interim proposal.
    recipe = {name: (here / name).read_bytes() for name in RECIPE_FILES}
    source, openssl, zig = (trees[name] for name in ('vere', 'openssl', 'zig'))
    ordinary = zig / 'lib'
    runner = (ordinary / 'compiler/build_runner.zig').read_text()
    if 'mem.eql(u8, arg, "--verbose-cc")' not in runner or 'builder.verbose_cc = true;' not in runner:
        raise ValueError('pinned build-runner verbose-cc support not established')
    ordinary_hashes = tree_hashes(ordinary)
    private = source / 'issue3-zig-lib'
    shutil.copytree(ordinary, private)  # Exclusive new target, never overwrite.
    if tree_hashes(private) != ordinary_hashes:
        raise ValueError('private Zig lib copy mismatch')
    plans, records = {}, {}
    for patch, root, label in (
        ('vere.patch', source, 'vere'),
        ('spawn.patch', source, 'vere'),
        ('target-build.patch', source, 'vere'),
        ('openssl.patch', openssl, 'openssl'),
        ('musl.patch', private / 'libc/musl', 'vere/issue3-zig-lib/libc/musl'),
    ):
        def read_current(name):
            target = root / name
            return plans[target] if target in plans else target.read_bytes()
        changes = apply_diff(recipe[patch], read_current, ALLOWED[patch])
        for name, content in changes.items():
            target = root / name
            if not target.is_file() or target.is_symlink():
                raise ValueError('unsafe patch target')
            records[label + '/' + name] = {
                'before_sha256': digest(target.read_bytes()), 'after_sha256': digest(content)}
            plans[target] = content
    header = recipe['uvm_issue3_diag.h']
    header_targets = (source / 'pkg/vere/uvm_issue3_diag.h',
                      openssl / 'crypto/uvm_issue3_diag.h',
                      private / 'libc/musl/src/exit/uvm_issue3_diag.h')
    if any(target.exists() for target in header_targets):
        raise ValueError('diagnostic header destination already exists')
    for target, content in plans.items():
        target.write_bytes(content)
    for target in header_targets:
        with target.open('xb') as stream:
            stream.write(header)
    if tree_hashes(ordinary) != ordinary_hashes:
        raise ValueError('ordinary compiler library changed')
    manifest = dict(
        status='SOURCE_PREPARED_NOT_BINARY_COVERAGE',
        recipe_sha256={name: digest(content) for name, content in recipe.items()},
        changed_sources=records,
        header_sha256={str(target.relative_to(output)): digest(target.read_bytes())
                       for target in header_targets},
        ordinary_zig_lib_sha256=ordinary_hashes,
        private_zig_lib_sha256=tree_hashes(private),
        verbose_cc_source_supported=True,
        compiler_executed=False,
        binary_coverage_verified=False,
        unique_global_definitions_verified=False)
    for name, content in recipe.items():
        with (output / name).open('xb') as stream:
            stream.write(content)
    with (output / 'diagnostic-source-manifest.json').open('x') as stream:
        stream.write(json.dumps(manifest, sort_keys=True, indent=2) + '\n')
