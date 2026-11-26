"""Pure, source-only instrumentation stage AFTER owned integration, before writes.

Selected only by the NEW owned recipe's post-composition stage. No target run is
implied. Collector failures invalidate evidence, never alter application cleanup.
"""
import hashlib
from pathlib import Path

HERE = Path(__file__).resolve().parent
PREIMAGES = {
    'pkg/noun/openssl_owned_start.c': 'fbc50e469a7964d4ca3df482a70a83a86f902c20ec2659198de2dfc855ff2977',
    'pkg/vere/main.c': '86658af9c74d9fe0f13881dc35f3a443729ddc6e243924d3220777c3832b90f4',
    'pkg/vere/king.c': '5c78d1a9b1f0424be54efaa89b61b3fc1f6b9965500c8ec67c5b6a962c079950',
    'pkg/vere/openssl_shutdown.inc': '111a529d6c6ff561e1a99b20100a26ebbf4646ee0237051df5b7a7c2a61ccfce',
}


def once(text, before, after):
    if text.count(before) != 1:
        raise ValueError('measurement source context mismatch')
    return text.replace(before, after, 1)


def instrument(outputs):
    """Return new byte mapping; never mutate inputs or perform filesystem writes.

    Bootstrap config/descriptor assignment in every process remains a controller
    integration gate. Unconfigured production behavior is deliberately unchanged.
    """
    result = dict(outputs)
    texts = {}
    for name, digest in PREIMAGES.items():
        if name not in outputs or hashlib.sha256(outputs[name]).hexdigest() != digest:
            raise ValueError('measurement integrated preimage mismatch: ' + name)
        texts[name] = outputs[name].decode()
    source = texts['pkg/noun/openssl_owned_start.c']
    source = once(source, '#include "openssl_owned_start.h"',
        '#include "openssl_owned_start.h"\n#include "arena_measure_collector.h"')
    source = once(source, '  return result;\n}',
        '  if ( result ) (void)u3_arena_measure_startup();\n  return result;\n}')
    texts['pkg/noun/openssl_owned_start.c'] = source
    runtime = texts['pkg/vere/openssl_shutdown.inc']
    runtime = once(runtime, '#include "completion.h"',
        '#include "completion.h"\n#include "arena_measure_collector.h"')
    runtime = once(runtime, '  OPENSSL_cleanup();',
        '  OPENSSL_cleanup();\n'
        '  (void)u3_arena_measure_phase(U3_MEASURE_PRE_DESTROY);')
    runtime = once(runtime, '  return u3_openssl_arena_destroy();',
        '  int success = u3_openssl_arena_destroy();\n'
        '  (void)u3_arena_measure_destroyed(success);\n  return success;')
    texts['pkg/vere/openssl_shutdown.inc'] = runtime
    # Loop-entry checkpoint is NOT certified application readiness or a workload
    # outcome. Named ready/TLS/churn/etc barriers use the explicit public API.
    for name in ('pkg/vere/main.c', 'pkg/vere/king.c'):
        text = texts[name]
        lines = text.splitlines(keepends=True)
        rewritten = []
        found = 0
        for line in lines:
            if line.lstrip().startswith('u3_ssl_shutdown_run('):
                indent = line[:len(line)-len(line.lstrip())]
                rewritten.append(indent + '(void)u3_arena_measure_phase(U3_MEASURE_APPLICATION);\n')
                found += 1
            rewritten.append(line)
        if not found:
            raise ValueError('measurement loop inventory absent: ' + name)
        texts[name] = ''.join(rewritten)
    texts['pkg/vere/king.c'] = '#include "arena_measure_collector.h"\n' + texts['pkg/vere/king.c']
    for name, text in texts.items():
        result[name] = text.encode()
    graph = outputs['pkg/noun/build.zig'].decode()
    graph = once(graph, '    "openssl_owned_start.c",\n',
        '    "openssl_owned_start.c",\n    "arena_measure_collector.c",\n')
    graph = once(graph, '    "openssl_owned_start.h",\n',
        '    "openssl_owned_start.h",\n    "arena_measure_collector.h",\n')
    result['pkg/noun/build.zig'] = graph.encode()
    for payload, target in [('collector.c', 'arena_measure_collector.c'),
                            ('collector.h', 'arena_measure_collector.h')]:
        name = 'pkg/noun/' + target
        if name in result:
            raise ValueError('measurement payload collision')
        result[name] = (HERE / payload).read_bytes().replace(b'#include "collector.h"',
                                                      b'#include "arena_measure_collector.h"')
    return result
