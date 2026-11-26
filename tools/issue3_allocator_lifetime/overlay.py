"""Isolated original-allocator ordering experiment; NOT production selection.

Source-only transformations. No build, execution, archive extraction or engine API.
"""
import hashlib
from pathlib import Path

MANAGE = 'pkg/noun/manage.c'
PREIMAGE = '2b06d6a006595ea7440690b325e8c994505a6040a97087e877a19c5e0c46d321'
POSTIMAGE = '6126a00974035b0495cd5440a532dda49df85d156ec021bf558c672ecd1f9d93'
BLOCKED = (b'#error "ORIGINAL_VERE_ALLOCATOR_BLOCKED: road retention and consumer quiescence are unqualified"\n')
DELTAS = (
    (b'/// @file\n\n', b'/// @file\n\n' + BLOCKED + b'\n'),
    (b'extern void u3je_secp_init(void);',
     b'/* One terminal OpenSSL lifecycle per process, on the owning thread.\n'
     b' * 0: cold, 1: registered, 2: stopping/stopped (never reinitialize). */\n'
     b'#if OPENSSL_VERSION_NUMBER >= 0x30000000L\n'
     b'static unsigned _cm_ssl_state;\n'
     b'#endif\n\n'
     b'extern void u3je_secp_init(void);'),
    (b'_cm_crypto(void)\n{',
     b'_cm_crypto(void)\n{\n'
     b'#if OPENSSL_VERSION_NUMBER >= 0x30000000L\n'
     b'  if ( _cm_ssl_state ) {\n'
     b'    u3l_log("%s", "openssl lifecycle cannot restart");\n'
     b'    abort();\n'
     b'  }\n'
     b'#endif'),
    (b'  u3je_secp_init();\n}',
     b'  u3je_secp_init();\n'
     b'#if OPENSSL_VERSION_NUMBER >= 0x30000000L\n'
     b'  _cm_ssl_state = 1;\n'
     b'#endif\n}'),
    (b'u3m_stop(void)\n{',
     b'u3m_stop(void)\n{\n'
     b'#if OPENSSL_VERSION_NUMBER >= 0x30000000L\n'
     b'  if ( 1 != _cm_ssl_state ) {\n'
     b'    return;\n'
     b'  }\n'
     b'  _cm_ssl_state = 2;\n'
     b'#endif\n'),
    (b'  /* OpenSSL 3 retains TLS/provider state beyond temporary road lifetimes.\n'
     b'   * Keep its default process-lifetime allocator; do not change GMP here. */\n'
     b'#if !defined(U3_URTH_MASS) && OPENSSL_VERSION_NUMBER < 0x30000000L',
     b'  /* Initialize OpenSSL with loom allocation functions. */\n#ifndef U3_URTH_MASS'),
    (b'  u3t_sstack_exit();\n\n  u3e_stop();\n  u3je_secp_stop();\n}',
     b'  u3t_sstack_exit();\n\n'
     b'#if OPENSSL_VERSION_NUMBER >= 0x30000000L\n'
     b'  OPENSSL_cleanup();\n'
     b'#endif\n\n'
     b'  u3e_stop();\n  u3je_secp_stop();\n}'),
)


def transform_manage(data: bytes) -> bytes:
    """Accept exactly the current default-heap-corrected manage.c, once."""
    if hashlib.sha256(data).hexdigest() != PREIMAGE:
        raise ValueError('allocator lifetime preimage mismatch: ' + MANAGE)
    for before, after in DELTAS:
        if data.count(before) != 1:
            raise ValueError('allocator lifetime source context mismatch: ' + MANAGE)
        data = data.replace(before, after, 1)
    if hashlib.sha256(data).hexdigest() != POSTIMAGE:
        raise ValueError('allocator lifetime postimage mismatch: ' + MANAGE)
    return data


def apply(root: Path) -> dict[str, str]:
    """Write only the guarded candidate manage.c in the caller's source tree.

    The resulting translation unit deliberately cannot be built. This API does
    NOT approve original road-backed allocation for process-retained objects.
    """
    root = root.absolute()
    target = root / MANAGE
    if root.resolve() != root or target.resolve() != target:
        raise ValueError('allocator lifetime refuses symlink source paths')
    if not target.is_file():
        raise ValueError('allocator lifetime requires regular source: ' + MANAGE)
    data = transform_manage(target.read_bytes())
    target.write_bytes(data)
    return {MANAGE: hashlib.sha256(data).hexdigest()}
