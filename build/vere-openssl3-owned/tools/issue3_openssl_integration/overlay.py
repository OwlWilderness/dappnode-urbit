"""Compose the two implemented owned-OpenSSL source candidates.

This is a source transformation, not permission for a target/dependency build.
The arena is the pinned palloc adaptation, not unchanged current-road callbacks.
"""
import hashlib
import importlib.util
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
TOOLS = HERE.parent
MANAGE_SHA256 = '2b06d6a006595ea7440690b325e8c994505a6040a97087e877a19c5e0c46d321'


def sha(data):
    return hashlib.sha256(data).hexdigest()


def load_shutdown():
    path = TOOLS / 'issue3_openssl_shutdown/overlay.py'
    spec = importlib.util.spec_from_file_location('owned_shutdown_composition', path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def capacity_bytes(value):
    # The API accepts arbitrary bytes but rounds down. Composition refuses
    # silent rounding so the source/receipt show the exact requested bound.
    if type(value) is not int or not 128 * 1024 <= value <= 0xffffc000 or value % 16384:
        raise ValueError('arena capacity requires explicit page-aligned bytes in [131072,4294950912]')
    return value


def once(text, old, new):
    if text.count(old) != 1:
        raise ValueError('owned integration context mismatch')
    return text.replace(old, new, 1)


def render(sources, arena_bytes):
    """Render all outputs in memory; exact hardened source preimages required."""
    arena_bytes = capacity_bytes(arena_bytes)
    shutdown = load_shutdown()
    outputs = {name: shutdown.transform(name, sources[name]).encode()
               for name in shutdown.PINS['hardened_preimages']}
    manage = sources['pkg/noun/manage.c']
    if sha(manage.encode()) != MANAGE_SHA256:
        raise ValueError('owned allocator preimage mismatch')
    # Ordinary GMP callbacks and u3m_stop remain unchanged. Old OpenSSL-only
    # wrappers are removed instead of leaving dormant current-road alternatives.
    manage = once(manage, '#include "manage.h"',
                  '#include "manage.h"\n#include "openssl_owned_start.h"')
    begin = manage.index('/* _cm_malloc_ssl():')
    end = manage.index('/* _cm_realloc2():', begin)
    manage = manage[:begin] + '''extern void u3je_secp_init(void);

/* _cm_crypto(): register process-owned OpenSSL storage before crypto users. */
static void
_cm_crypto(void)
{
  if ( !u3_openssl_owned_start() ) {
    u3l_log("%s", "owned OpenSSL allocator initialization failed");
    abort();
  }
  u3je_secp_init();
}

''' + manage[end:]
    outputs['pkg/noun/manage.c'] = manage.encode()
    main = outputs['pkg/vere/main.c'].decode()
    main = once(main, '#include "openssl_owned_arena.h"',
                '#include "openssl_owned_arena.h"\n#include "openssl_owned_start.h"')
    # Fetch can use TLS without constructing a noun loom. It must register the
    # same arena before SSL_library_init, just like the ordinary king startup.
    if sum(line.strip() == 'SSL_library_init();' for line in main.splitlines()) != 2:
        raise ValueError('OpenSSL initialization inventory changed')
    lines = main.splitlines(keepends=True)
    rewritten = []
    for line in lines:
        if line.strip() == 'SSL_library_init();':
            indent = line[:len(line) - len(line.lstrip())]
            rewritten.append(indent + 'if ( !u3_openssl_owned_start() ) abort();\n')
        rewritten.append(line)
    outputs['pkg/vere/main.c'] = ''.join(rewritten).encode()
    for name, payload in shutdown.PAYLOADS.items():
        content = (shutdown.HERE / payload).read_bytes()
        if sha(content) != shutdown.PINS['payload_sha256'][name]:
            raise ValueError('shutdown payload hash mismatch')
        if payload == 'runtime.inc':
            text = content.decode()
            # The no-loom fetch arena also needs cleanup; noun backing ownership
            # is a different lifetime from ownership of this native mapping.
            for expression in ('u3_openssl_arena_live_blocks()', 'u3_openssl_arena_destroy()'):
                text = once(text, '#ifndef U3_URTH_MASS\n  if ( _ssl_loom ) return ' + expression + ';\n#endif',
                                  '  return ' + expression + ';')
            text = text.replace('  return u3_openssl_arena_live_blocks();\n  return 0;',
                                '  return u3_openssl_arena_live_blocks();')
            text = text.replace('  return u3_openssl_arena_destroy();\n  return 1;',
                                '  return u3_openssl_arena_destroy();')
            text = once(text, '  OPENSSL_cleanup();',
                        '  if ( !u3_openssl_owned_seal() ) abort();\n  OPENSSL_cleanup();')
            content = text.encode()
        outputs[name] = content
    arena = TOOLS / 'issue3_openssl_owned_arena'
    pins = json.loads((arena / 'sources.json').read_text())['delivery_sha256']
    for name in ('openssl_owned_arena.c', 'openssl_owned_arena.h', 'palloc_engine.inc'):
        path = arena / name
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 2 * 1024**2:
            raise ValueError('arena payload hash/type mismatch: ' + name)
        content = path.read_bytes()
        if sha(content) != pins[name]:
            raise ValueError('arena payload hash mismatch: ' + name)
        outputs['pkg/noun/' + name] = content
    for name in ('openssl_owned_start.c', 'openssl_owned_start.h'):
        outputs['pkg/noun/' + name] = (HERE / name).read_bytes()
    outputs['pkg/noun/openssl_owned_config.h'] = (
        '#ifndef U3_OPENSSL_OWNED_CONFIG_H\n#define U3_OPENSSL_OWNED_CONFIG_H\n'
        f'#define U3_OPENSSL_ARENA_BYTES ((size_t){arena_bytes}ULL)\n#endif\n').encode()
    return outputs


GRAPH_PINS = {
    'pkg/noun/build.zig': ('noun-build.zig.pinned', 10687,
        'a68ffff6ea0ff3093ca5c379eba02c704444da10e7e1e72e6d74085c27266d43'),
    'pkg/noun/build.zig.zon': ('noun-build.zig.zon.pinned', 1759,
        '7e8bfba28c5dfc2fc8712181634188481c8b0531efca4a91da4d1112deab36c9'),
}


def public_graphs():
    outputs = {}
    for name, (payload, length, digest) in GRAPH_PINS.items():
        data = (HERE / payload).read_bytes()
        if len(data) != length or sha(data) != digest:
            raise ValueError('owned arena graph provenance mismatch: ' + name)
        outputs[name] = data
    return outputs


def apply(root, *, arena_bytes):
    """Compose into a fresh hardened public source tree; preflight all bytes
    and destinations before writing. Not disk-failure atomic or a hostile-
    filesystem race defense. The returned mapping includes unchanged manifests.
    """
    capacity_bytes(arena_bytes)
    root = Path(root).absolute()
    if root.resolve() != root or not root.is_dir():
        raise ValueError('owned integration requires regular non-symlink root')
    shutdown = load_shutdown()
    names = set(shutdown.PINS['hardened_preimages']) | {
        'pkg/noun/manage.c', 'ext/h2o/socket.c', *GRAPH_PINS}
    sources = {}
    for name in sorted(names):
        path = root / name
        if path.resolve() != path or not path.is_file() or path.stat().st_size > 2 * 1024**2:
            raise ValueError('owned integration requires bounded regular input: ' + name)
        sources[name] = path.read_text()
    expected_graphs = public_graphs()
    for name, data in expected_graphs.items():
        if sources[name].encode() != data:
            raise ValueError('owned integration graph preimage mismatch: ' + name)
    outputs = render(sources, arena_bytes)
    outputs['ext/h2o/socket.c'] = shutdown.transform_h2o(sources['ext/h2o/socket.c']).encode()
    graph = sources['pkg/noun/build.zig']
    graph = once(graph, '    "manage.c",\n',
                 '    "manage.c",\n    "openssl_owned_arena.c",\n    "openssl_owned_start.c",\n')
    graph = once(graph, '    "manage.h",\n',
                 '    "manage.h",\n    "openssl_owned_arena.h",\n    "openssl_owned_start.h",\n')
    outputs['pkg/noun/build.zig'] = graph.encode()
    outputs['pkg/noun/build.zig.zon'] = expected_graphs['pkg/noun/build.zig.zon']
    # Instrument only the complete owned/H2O/graph composition, before ANY
    # destination preflight or writes. Frozen recipe validation binds the sibling.
    spec = importlib.util.spec_from_file_location('owned_arena_measurement',
        TOOLS / 'issue3_arena_measurement/overlay.py')
    assert spec is not None and spec.loader is not None
    measurement = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(measurement)
    outputs = measurement.instrument(outputs)
    for name in outputs:
        path = root / name
        if path.resolve() != path or not path.parent.is_dir():
            raise ValueError('owned integration payload destination is unsafe: ' + name)
        if name not in names and path.exists():
            raise ValueError('owned integration payload collision: ' + name)
    for name, content in outputs.items():
        (root / name).write_bytes(content)
    return {name: sha(content) for name, content in outputs.items()}
