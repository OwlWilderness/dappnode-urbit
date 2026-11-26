"""Pinned, build-only Vere candidate. Never invokes Vere or accesses a pier.

--source-check only verifies/extracts public inputs and applies source changes.
--build is for the separately authorized isolated builder, not the host package.
Every output directory is single-use, including failed or interrupted attempts.
"""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import signal
import shutil
import subprocess
import tarfile
import time
import urllib.request

HERE = Path(__file__).resolve().parent
import importlib.util as _owned_import
_owned_spec = _owned_import.spec_from_file_location('owned_build_support', HERE / 'owned_support.py')
assert _owned_spec is not None and _owned_spec.loader is not None
owned = _owned_import.module_from_spec(_owned_spec)
_owned_spec.loader.exec_module(owned)
CAPACITY_CHECK_BYTES = 8 * 1024**2
COPY_CHUNK_BYTES = 1024**2
H2O_OVERLAY = {'file': 'h2o-socket.c', 'sha256': 'd61916d7de924e2337b6a73dbcd044b525bf503b11affc53fd6f6c0ca90c37b2', 'build_sha256': '174d1bd82eb826b626f06be07ee69aec0091ff958f8f14c2564b1aed593793b0', 'upstream_sha256': 'a301247dbd95f7145aa1cc3c83a720c93bf5d1d3d7a5a961846eea7dbfd8476d', 'upstream_revision': '3bbfe369a5c31d38cc1717e5281ca6af89ecf787'}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def verify_input(data, item):
    if len(data) != item['bytes'] or sha(data) != item['sha256']:
        raise ValueError('input hash/size mismatch')


def check_member(member, root):
    path = PurePosixPath(member.name)
    if (path.is_absolute() or '..' in path.parts or not path.parts or
            path.parts[0] != root or not (member.isfile() or member.isdir())):
        raise ValueError('unsafe source archive member')


def replace_once(text, old, new):
    if text.count(old) != 1:
        raise ValueError('source preimage mismatch (not a retryable patch)')
    return text.replace(old, new, 1)


def patch_build(text):
    text = replace_once(text, 'const VERSION = "4.6";',
                        'const VERSION = "4.6-uvm-openssl3.5.9";')
    start = text.index('    // Parse short git rev\n')
    end = text.index('    // Binary version\n', start)
    return text[:start] + '    const git_rev = "8ddc4b7";\n\n' + text[end:]


def patch_report(text):
    return replace_once(text,
        '  printf("openssl: %s\\n", SSLeay_version(SSLEAY_VERSION));',
        '#if OPENSSL_VERSION_MAJOR != 3 || OPENSSL_VERSION_MINOR != 5 || OPENSSL_VERSION_PATCH != 9\n'
        '#error "UVM candidate requires the pinned OpenSSL 3.5.9 headers"\n'
        '#endif\n'
        '  printf("openssl: %s\\n", OpenSSL_version(OPENSSL_VERSION));\n'
        '  printf("openssl-headers: %s\\n", OPENSSL_VERSION_TEXT);\n'
        '  printf("curl-linked: %s\\n", curl_version_info(CURLVERSION_NOW)->version);\n'
        '  printf("curl-headers: %s\\n", LIBCURL_VERSION);')


def apply_curl_overlay(source, lock):
    # Validate both upstream files and both overlays before replacing either.
    replacements = {}
    for target in ('ext/curl/build.zig', 'ext/curl/build.zig.zon'):
        if sha((source / target).read_bytes()) != lock['source_preimages'][target]:
            raise ValueError('curl source preimage mismatch: ' + target)
        item = lock['curl_overlays'][target]
        data = (HERE / item['file']).read_bytes()
        if sha(data) != item['sha256']:
            raise ValueError('curl overlay hash mismatch: ' + target)
        replacements[target] = data
    for target, data in replacements.items():
        (source / target).write_bytes(data)
    return {target: sha(data) for target, data in replacements.items()}


def patch_curl_timeout(text):
    # libcurl's variadic long option is type-checked by the newer headers.
    return replace_once(text,
        'curl_easy_setopt(cul_u, CURLOPT_SERVER_RESPONSE_TIMEOUT, 30);',
        'curl_easy_setopt(cul_u, CURLOPT_SERVER_RESPONSE_TIMEOUT, 30L);')


def patch_curl_buffer(text):
    """Own each transfer buffer until success explicitly hands it to the caller."""
    text = patch_curl_timeout(text)
    text = replace_once(text,
        '        buf_u->buf_y = c3_malloc(nee_d);\n'
        '        buf_u->cap_d = nee_d;',
        '        if ( buf_u->cap_d < nee_d ) {\n'
        '          buf_u->buf_y = c3_realloc(buf_u->buf_y, nee_d);\n'
        '          buf_u->cap_d = nee_d;\n'
        '        }')
    start = text.index('/* king_curl_bytes():')
    end = text.index('/* _king_get_atom():', start)
    before, after = text[:start], text[end:]
    text = text[start:end]
    text = replace_once(text, '  c3_i     ret_i = 0;\n  CURL    *cul_u;',
                              '  c3_i     ret_i = -1;\n  CURL    *cul_u;')
    text = replace_once(text, '  while ( tri_y > try_y ) {\n    sleep(try_y++);',
        '  while ( tri_y > try_y ) {\n'
        '    /* A retry is a new response, never an append to partial data. */\n'
        '    free(buf_u.buf_y);\n'
        '    buf_u = (u3_array){0};\n'
        '    sleep(try_y++);')
    text = replace_once(text, '      *hun_y = (c3_y*)buf_u.buf_y;\n      ret_i = 0;',
        '      *hun_y = (c3_y*)buf_u.buf_y;\n'
        '      buf_u.buf_y = 0;  /* ownership transferred to caller */\n'
        '      ret_i = 0;')
    return before + replace_once(text, '  curl_easy_cleanup(cul_u);\n\n  return ret_i;',
        '  curl_easy_cleanup(cul_u);\n'
        '  free(buf_u.buf_y);  /* failed/exhausted response only */\n\n'
        '  return ret_i;') + after


def patch_allocator(text):
    return replace_once(text,
        '  /* Initialize OpenSSL with loom allocation functions. */\n#ifndef U3_URTH_MASS',
        '  /* OpenSSL 3 retains TLS/provider state beyond temporary road lifetimes.\n'
        '   * Keep its default process-lifetime allocator; do not change GMP here. */\n'
        '#if !defined(U3_URTH_MASS) && OPENSSL_VERSION_NUMBER < 0x30000000L')


def patch_ca_source(name, text):
    """CA overlay follows report patch; pin the exact intermediate bytes."""
    pins = {
        'pkg/vere/main.c': '206929fef62b6f7246b7313675b6120ab876bc7ae8c4399342e1f0eceaf48549',
        'pkg/vere/vere.h': '20b6fe3b20f7100ec22ac47e1ecac20df4dc8a66475573cc0290e126e90f5c06',
    }
    if name not in pins or sha(text.encode()) != pins[name]:
        raise ValueError('CA source preimage mismatch: ' + name)
    if name.endswith('/vere.h'):
        return replace_once(text, 'void           (*ssl_x509_f)(void*);',
                                  'int            (*ssl_x509_f)(void*);')
    text = replace_once(text,
        '    u3l_log("boot: failed to decode embedded CA certificates");',
        '    BIO_free(cbio);\n'
        '    u3l_log("boot: failed to decode embedded CA certificates");')
    text = replace_once(text, 'static void\n_setup_ssl_x509(void* arg)',
                              'static int\n_setup_ssl_x509(void* arg)')
    text = replace_once(text, '  X509_STORE* cts = arg;\n  int i;',
        '  X509_STORE* cts = arg;\n'
        '  if ( !cts || !_cert_store ) {\n'
        '    return 0;\n'
        '  }\n'
        '  int i;')
    for kind in ('cert', 'crl'):
        field = 'x509' if kind == 'cert' else 'crl'
        text = replace_once(text,
            f'      X509_STORE_add_{kind}(cts, itmp->{field});',
            f'      if ( 1 != X509_STORE_add_{kind}(cts, itmp->{field}) ) {{\n'
            '        /* The global stack retains its reference on either result. */\n'
            '        return 0;\n'
            '      }')
    text = replace_once(text, '\n}\n\n/* _curl_ssl_ctx_cb():',
                              '\n  return 1;\n}\n\n/* _curl_ssl_ctx_cb():')
    text = replace_once(text, '  _setup_ssl_x509(cts);\n  return CURLE_OK;',
        '  return _setup_ssl_x509(cts) ? CURLE_OK : CURLE_ABORTED_BY_CALLBACK;')
    return replace_once(text,
        '  curl_easy_setopt(curl, CURLOPT_CAINFO, NULL);\n'
        '  curl_easy_setopt(curl, CURLOPT_CAPATH, NULL);\n'
        '  curl_easy_setopt(curl, CURLOPT_SSL_CTX_FUNCTION, _curl_ssl_ctx_cb);',
        '  if ( CURLE_OK != curl_easy_setopt(curl, CURLOPT_CAINFO, NULL) ||\n'
        '       CURLE_OK != curl_easy_setopt(curl, CURLOPT_CAPATH, NULL) ||\n'
        '       CURLE_OK != curl_easy_setopt(curl, CURLOPT_SSL_CTX_FUNCTION, _curl_ssl_ctx_cb) ) {\n'
        '    /* This void setup interface cannot report failure. Never transfer\n'
        '     * with an absent trust callback; refuse the process, not TLS. */\n'
        '    curl_easy_cleanup(curl);\n'
        '    exit(1);\n'
        '  }')


def apply_ca_overlay(source, lock):
    targets = ('pkg/vere/main.c', 'pkg/vere/vere.h')
    client = 'pkg/vere/io/cttp.c'
    expected = lock.get('ca_hardening', {})
    if (set(expected) != set(targets) | {client} or
            set(lock.get('ca_preimages', {})) != set(targets)):
        raise ValueError('CA source mapping mismatch')
    # The changed ABI, implementation and actual client must travel together.
    if (expected[client] != lock['allocation_hardening'][client] or
            sha((source / client).read_bytes()) != expected[client]):
        raise ValueError('CA client binding mismatch')
    replacements = {}
    for name in targets:
        text = (source / name).read_text()
        if sha(text.encode()) != lock['ca_preimages'][name]:
            raise ValueError('CA source preimage mismatch: ' + name)
        data = patch_ca_source(name, text).encode()
        if sha(data) != expected[name]:
            raise ValueError('CA source postimage mismatch: ' + name)
        replacements[name] = data
    for name, data in replacements.items():
        (source / name).write_bytes(data)
    return dict(expected)


def patch_allocation_source(name, text):
    """Fail-closed overlay of exact public source; never patches an artifact."""
    pins = {
        'pkg/vere/io/cttp.c': '257caa336c71e963be0b029796ef62c9e154806927d95a1f221b7dc5341e34b4',
        'pkg/vere/io/http.c': '7f80902b1ce7ec0adf717d6dd5b58a5b4f4a6b0d9d6bb16719271e7ed3a721cf',
    }
    if name not in pins or sha(text.encode()) != pins[name]:
        raise ValueError('allocation source preimage mismatch: ' + name)
    method = 'client' if name.endswith('/cttp.c') else 'server'
    text = replace_once(text,
        f'  SSL_CTX* tls_u = SSL_CTX_new(SSLv23_{method}_method());',
        f'  SSL_CTX* tls_u = SSL_CTX_new(SSLv23_{method}_method());\n'
        '  if ( 0 == tls_u ) {\n'
        '    return 0;\n'
        '  }')
    text = replace_once(text,
        '  SSL_CTX_set_cipher_list(tls_u,',
        '  if ( 1 != SSL_CTX_set_cipher_list(tls_u,')
    text = replace_once(text,
        '                          "RSA+AES:RSA+3DES:!aNULL:!MD5:!DSS");',
        '                          "RSA+AES:RSA+3DES:!aNULL:!MD5:!DSS") ) {\n'
        '    SSL_CTX_free(tls_u);\n'
        '    return 0;\n'
        '  }')
    if method == 'server':
        text = replace_once(text,
            '  SSL_CTX_set_default_verify_paths(tls_u);',
            '  if ( 1 != SSL_CTX_set_default_verify_paths(tls_u) ) {\n'
            '    SSL_CTX_free(tls_u);\n'
            '    return 0;\n'
            '  }')
        start = text.index('  {\n    BIO* bio_u = BIO_new_mem_buf(key_u.base, key_u.len);')
        end = text.index('  return tls_u;\n}', start) + len('  return tls_u;')
        text = replace_once(text, text[start:end], r'''  BIO* bio_u = 0;
  EVP_PKEY* pky_u = 0;
  X509* xer_u = 0;

  if ( 0 == (bio_u = BIO_new_mem_buf(key_u.base, key_u.len)) ||
       0 == (pky_u = PEM_read_bio_PrivateKey(bio_u, 0, 0, 0)) ||
       1 != SSL_CTX_use_PrivateKey(tls_u, pky_u) ) {
    goto fail;
  }
  EVP_PKEY_free(pky_u);
  pky_u = 0;
  BIO_free(bio_u);
  bio_u = 0;

  if ( 0 == (bio_u = BIO_new_mem_buf(cer_u.base, cer_u.len)) ||
       0 == (xer_u = PEM_read_bio_X509_AUX(bio_u, 0, 0, 0)) ||
       1 != SSL_CTX_use_certificate(tls_u, xer_u) ) {
    goto fail;
  }
  X509_free(xer_u);
  xer_u = 0;

  for (;;) {
    /* Only the PEM reader's normal end-of-input is success, not OOM or
     * decode errors. Isolate its error from earlier successful operations. */
    ERR_clear_error();
    xer_u = PEM_read_bio_X509(bio_u, 0, 0, 0);
    if ( 0 == xer_u ) {
      unsigned long err_l = ERR_peek_last_error();
      if ( BIO_eof(bio_u) && ERR_LIB_PEM == ERR_GET_LIB(err_l) &&
           PEM_R_NO_START_LINE == ERR_GET_REASON(err_l) ) {
        ERR_clear_error();
        break;
      }
      goto fail;
    }
    if ( 1 != SSL_CTX_add_extra_chain_cert(tls_u, xer_u) ) {
      goto fail;
    }
    /* add_extra_chain_cert takes ownership only on success. */
    xer_u = 0;
  }
  BIO_free(bio_u);
  return tls_u;

fail:
  X509_free(xer_u);
  EVP_PKEY_free(pky_u);
  BIO_free(bio_u);
  SSL_CTX_free(tls_u);
  /* Release operation-owned heap before any application logging/bail. */
  u3l_log("http: TLS context setup failed");
  return 0;''')
        return text
    text = replace_once(text,
        '  u3K.ssl_x509_f(SSL_CTX_get_cert_store(tls_u));',
        '  if ( 1 != u3K.ssl_x509_f(SSL_CTX_get_cert_store(tls_u)) ) {\n'
        '    SSL_CTX_free(tls_u);\n'
        '    return 0;\n'
        '  }')
    text = replace_once(text,
        '  u3_cttp* ctp_u = c3_calloc(sizeof(*ctp_u));',
        '  /* The caller links an unconditional driver. Refuse startup before\n'
        '   * allocating/registering handles; NULL must never disable TLS. */\n'
        '  SSL_CTX* tls_u = _cttp_init_tls();\n'
        '  if ( 0 == tls_u ) {\n'
        '    exit(1);\n'
        '  }\n'
        '  u3_cttp* ctp_u = c3_calloc(sizeof(*ctp_u));')
    text = replace_once(text,
        '  ctp_u->tls_u = _cttp_init_tls();',
        '  ctp_u->tls_u = tls_u;')
    text = replace_once(text,
        '      _cttp_creq_quit(ceq_u);\n      ceq_u = ceq_u->nex_u;',
        '      u3_creq* nex_u = ceq_u->nex_u;\n'
        '      _cttp_creq_quit(ceq_u);\n      ceq_u = nex_u;')
    text = replace_once(text,
        '    void*            tls_u;             //  client SSL_CTX*',
        '    void*            tls_u;             //  client SSL_CTX*\n'
        '    c3_w             ext_w;             //  shutdown begun (zero initially)\n'
        '    c3_w             clo_w;             //  outstanding embedded handle closes')
    text = replace_once(text, '/* _cttp_creq_unlink():', r'''/* _cttp_io_maybe_free(): DNS requests and both embedded handles own cttp.
 * H2O cancel synchronously unlinks its client timeout. A delayed socket TLS
 * close owns its SSL/context reference, not the retired client/driver.
 */
static void
_cttp_io_maybe_free(u3_cttp* ctp_u)
{
  if ( ctp_u->ext_w && !ctp_u->clo_w && !ctp_u->ceq_u ) {
    SSL_CTX_free(ctp_u->tls_u);
    c3_free(ctp_u);
  }
}

/* _cttp_creq_unlink():''')
    text = replace_once(text,
        '  _cttp_creq_unlink(ceq_u);\n',
        '  u3_cttp* ctp_u = ceq_u->ctp_u;\n'
        '  _cttp_creq_unlink(ceq_u);\n')
    text = replace_once(text,
        '  c3_free(ceq_u);\n}\n\n/* _cttp_creq_new():',
        '  c3_free(ceq_u);\n'
        '  _cttp_io_maybe_free(ctp_u);\n}\n\n/* _cttp_creq_new():')
    text = replace_once(text,
        '  SSL_CTX_free(ctp_u->tls_u);\n  c3_free(ctp_u);',
        '  u3_assert(ctp_u->clo_w);\n'
        '  --ctp_u->clo_w;\n'
        '  _cttp_io_maybe_free(ctp_u);')
    text = replace_once(text,
        '  //  close unused handle to free [ctp_u] after h2o is done\n'
        '  //\n'
        '  uv_close((uv_handle_t*)&ctp_u->nop_u, _cttp_io_exit_cb);',
        '  if ( ctp_u->ext_w ) {\n    return;\n  }\n'
        '  ctp_u->ext_w = 1;\n'
        '  ctp_u->clo_w = 2;')
    text = replace_once(text,
        '  h2o_timeout_dispose(u3L, &ctp_u->tim_u);',
        '  /* The pinned H2O libuv dispose queues this embedded timer with a\n'
        '   * NULL callback. Close it explicitly so its storage has a real\n'
        '   * completion barrier; nop-close ordering alone is insufficient. */\n'
        '  u3_assert(h2o_linklist_is_empty(&ctp_u->tim_u._entries));\n'
        '  ctp_u->tim_u._backend.timer.data = ctp_u;\n'
        '  uv_close((uv_handle_t*)&ctp_u->tim_u._backend.timer, _cttp_io_exit_cb);\n'
        '  uv_close((uv_handle_t*)&ctp_u->nop_u, _cttp_io_exit_cb);')
    text = replace_once(text,
        '  if ( u3_csat_addr == ceq_u->sat_e ) {',
        '  if ( u3_csat_addr == ceq_u->sat_e || u3_csat_quit == ceq_u->sat_e ) {')
    text = replace_once(text,
        '    return;  // wait to be called again on address resolution',
        '    return;  // the resolver alone releases a canceled DNS request')
    text = replace_once(text,
        '    _cttp_creq_quit(ceq_u);;',
        '    /* The resolver callback, not repeated cancellation, releases DNS. */\n'
        '    _cttp_creq_free(ceq_u);')
    text = replace_once(text,
        '  u3_creq* ceq_u;\n  c3_o     ret_o;',
        '  if ( ctp_u->ext_w ) {\n'
        '    u3z(tag); u3z(dat);\n'
        '    return c3n;\n'
        '  }\n\n'
        '  u3_creq* ceq_u;\n  c3_o     ret_o;')
    return text


def apply_allocation_overlay(source, lock):
    targets = ('pkg/vere/io/cttp.c', 'pkg/vere/io/http.c')
    if set(lock.get('allocation_hardening', {})) != set(targets):
        raise ValueError('allocation postimage mapping mismatch')
    replacements = {}
    for name in targets:
        text = (source / name).read_text()
        if sha(text.encode()) != lock['source_preimages'][name]:
            raise ValueError('allocation source preimage mismatch: ' + name)
        data = patch_allocation_source(name, text).encode()
        if sha(data) != lock['allocation_hardening'][name]:
            raise ValueError('allocation source postimage mismatch: ' + name)
        replacements[name] = data
    # No writes until every preimage, unique replacement and postimage passes.
    for name, data in replacements.items():
        (source / name).write_bytes(data)
    return {name: sha(data) for name, data in replacements.items()}


def patch_sha_build(text):
    if sha(text.encode()) != 'e56c7b287026d6843f3b4c2bb865194c41d6247595e292d4900a7f3a3c18fd9d':
        raise ValueError('SHA build source preimage mismatch')
    text = replace_once(text, '            "sha.c",\n', '')
    return replace_once(text,
        '    lib.installHeader(dep_c.path("urcrypt/urcrypt.h"), "urcrypt.h");',
        '    // Pinned stack SHA overlay; never compile the allocating one-shot wrapper.\n'
        '    lib.addCSourceFile(.{\n'
        '        .file = b.path("sha.c"),\n'
        '        .flags = &.{ "-O2", "-fno-omit-frame-pointer", "-fno-sanitize=all", "-g", "-Wall" },\n'
        '    });\n\n'
        '    lib.installHeader(dep_c.path("urcrypt/urcrypt.h"), "urcrypt.h");')


def apply_sha_overlay(source, lock):
    name = 'ext/urcrypt/build.zig'
    manifest = 'ext/urcrypt/build.zig.zon'
    manifest_sha = sha((source / manifest).read_bytes())
    if manifest_sha != lock['source_preimages'][manifest]:
        raise ValueError('SHA dependency manifest preimage mismatch')
    original = (source / name).read_text()
    if sha(original.encode()) != lock['source_preimages'][name]:
        raise ValueError('SHA build source preimage mismatch')
    item = lock['sha_overlay']
    if item['file'] != 'sha-stack.c':
        raise ValueError('SHA overlay filename mismatch')
    data = (HERE / item['file']).read_bytes()
    if sha(data) != item['sha256']:
        raise ValueError('SHA overlay hash mismatch')
    build = patch_sha_build(original).encode()
    if sha(build) != item['build_sha256']:
        raise ValueError('SHA build postimage mismatch')
    target = source / 'ext/urcrypt/sha.c'
    if target.exists() or target.is_symlink():
        raise ValueError('SHA local source already exists')
    target.write_bytes(data)
    (source / name).write_bytes(build)
    return {name: sha(build), manifest: manifest_sha, 'ext/urcrypt/sha.c': sha(data)}


def patch_h2o_build(text):
    if sha(text.encode()) != '942bad939c453827422ff413f20cc083f097f5f74927f20df3a1b6d6d6fe033d':
        raise ValueError('H2O build source preimage mismatch')
    text = replace_once(text, '            "common/socket.c",\n', '')
    return replace_once(text,
        '    h2o.installHeadersDirectory(h2o_c.path("include"), "", .{});',
        '    // Preserve relative backend/hostname includes of the pinned source.\n'
        '    h2o.addIncludePath(h2o_c.path("lib/common"));\n'
        '    h2o.addCSourceFile(.{\n'
        '        .file = b.path("socket.c"),\n'
        '        .flags = &.{ "-fno-sanitize=all", "-std=c99", "-g3", "-O2",\n'
        '            "-pthread", "-DH2O_USE_LIBUV", "-DH2O_USE_PICOTLS",\n'
        '            if (t.os.tag == .linux) "-D_GNU_SOURCE" else "" },\n'
        '    });\n\n'
        '    h2o.installHeadersDirectory(h2o_c.path("include"), "", .{});')


def apply_h2o_overlay(source, lock):
    name = 'ext/h2o/build.zig'
    zon = 'ext/h2o/build.zig.zon'
    for target, expected in (
        (name, '942bad939c453827422ff413f20cc083f097f5f74927f20df3a1b6d6d6fe033d'),
        (zon, 'f34b10dac1bf01e4de26c545c55cede029bae7b86396019279eec5ea9782cb70')):
        if lock['source_preimages'].get(target) != expected or sha((source / target).read_bytes()) != expected:
            raise ValueError('H2O source preimage mismatch: ' + target)
    item = lock['h2o_overlay']
    if item != H2O_OVERLAY:
        raise ValueError('H2O overlay mapping mismatch')
    data = (HERE / item['file']).read_bytes()
    if sha(data) != item['sha256']:
        raise ValueError('H2O overlay hash mismatch')
    build = patch_h2o_build((source / name).read_text()).encode()
    if sha(build) != item['build_sha256']:
        raise ValueError('H2O build postimage mismatch')
    target = source / 'ext/h2o/socket.c'
    if target.exists() or target.is_symlink():
        raise ValueError('H2O local source already exists')
    # All source, graph, manifest and payload checks precede either write.
    target.write_bytes(data)
    (source / name).write_bytes(build)
    return {name: sha(build), 'ext/h2o/socket.c': sha(data), zon: sha((source / zon).read_bytes())}


def object_adapter(members):
    """Rearchive actual generated objects, never put an archive inside another."""
    lines = ['const std = @import("std");', 'pub fn build(b: *std.Build) void {',
             '    const target = b.standardTargetOptions(.{});',
             '    const optimize = b.standardOptimizeOption(.{});',
             '    if (target.result.cpu.arch != .x86_64 or target.result.os.tag != .linux or target.result.abi != .musl)',
             '        @panic("UVM OpenSSL candidate supports only x86_64-linux-musl");']
    for lib in ('crypto', 'ssl'):
        names = members[lib]
        if not names or len(names) != len(set(names)) or any(
                not re.fullmatch(r'[A-Za-z0-9_.+-]+\.o', name) for name in names):
            raise ValueError('unsafe or duplicate OpenSSL object member')
        lines += [f'    const {lib} = b.addLibrary(.{{ .name = "{lib}", .linkage = .static,',
                  '        .root_module = b.createModule(.{ .target = target, .optimize = optimize }) });',
                  f'    {lib}.linkLibC();',
                  f'    {lib}.installHeadersDirectory(b.path("prebuilt/include/openssl"), "openssl", .{{}});']
        for name in sorted(names):
            lines.append(f'    {lib}.addObjectFile(b.path("prebuilt/{lib}/{name}"));')
        if lib == 'ssl':
            lines.append('    ssl.linkLibrary(crypto);')
        lines.append(f'    b.installArtifact({lib});')
    return '\n'.join(lines + ['}', ''])


def vere_build_command(zig):
    # Keep the CPU-query default used by Vere's exact target whitelist.
    return [zig, 'build', '-Dtarget=x86_64-linux-musl',
            '-Drelease=true', '-Dpace=once', '-j2', '--summary', 'all', '--verbose-link']


def image_build_command(context, export, attempt_id, *, arena_bytes=None):
    """For a fresh authorized supervisor only; does not launch or grant a retry."""
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,80}', attempt_id):
        raise ValueError('invalid fresh attempt ID')
    owned.capacity(arena_bytes)
    return ['docker', 'buildx', 'build', '--platform=linux/amd64', '--progress=plain',
            '--target=evidence', '--build-arg', 'UVM_OPENSSL_ARENA_BYTES=' + str(arena_bytes),
            '--build-arg', 'UVM_BUILD_ATTEMPT_ID=' + attempt_id,
            '--output=type=local,dest=' + str(export), '--file=' + str(context / 'Dockerfile'), str(context)]


def tree_hashes(root):
    """Bind cached generated source, headers and archives, not merely versions."""
    if not root.is_dir() or root.is_symlink():
        raise ValueError('OpenSSL cache tree missing or linked')
    hashes = {}
    for path in sorted(root.rglob('*')):
        if path.is_symlink() or not (path.is_dir() or path.is_file()):
            raise ValueError('OpenSSL cache contains a non-regular entry')
        if path.is_file():
            with path.open('rb') as file:
                digest = hashlib.sha256()
                for chunk in iter(lambda: file.read(1024**2), b''):
                    digest.update(chunk)
            hashes[str(path.relative_to(root))] = digest.hexdigest()
    return hashes


class CapacityGuard:
    """Sample at bounded byte/time intervals, not once per gzip header/write."""
    def __init__(self, output):
        self.output = output
        self.last_check = float('-inf')
        self.pending_bytes = 0

    def check(self, written=0, force=False):
        self.pending_bytes += written
        now = time.monotonic()
        if not force and self.pending_bytes < CAPACITY_CHECK_BYTES and now - self.last_check < 5:
            return
        used_kib = None
        for attempt in range(3):
            try:
                used_kib = int(subprocess.check_output(
                    ['du', '-sk', str(self.output)], timeout=15,
                    stderr=subprocess.PIPE).split()[0])
                break
            except subprocess.CalledProcessError as exc:
                lines = (exc.stderr or b'').decode(errors='replace').splitlines()
                prefixes = tuple('du: ' + str(self.output / cache / 'tmp') + '/'
                                 for cache in ('zig-local-cache', 'zig-cache'))
                transient = (exc.returncode == 1 and lines and all(
                    line.startswith(prefixes) and line.endswith(': No such file or directory')
                    for line in lines))
                if not transient or attempt == 2:
                    # Public builder paths only; retain the actual scan failure
                    # instead of losing stderr behind CalledProcessError.__str__.
                    print(json.dumps(dict(stage='capacity', status='scan-failed',
                                          exit_code=exc.returncode,
                                          stderr=(exc.stderr or b'')[:2048].decode(errors='replace'))),
                          flush=True)
                    raise
                time.sleep(0.1)
        assert used_kib is not None
        if used_kib > 6 * 1024**2 or shutil.disk_usage(self.output).free < 8 * 1024**3:
            raise RuntimeError('builder capacity limit reached')
        self.last_check = time.monotonic()
        self.pending_bytes = 0

    def copy_file(self, source, destination):
        with source.open('rb') as reader, destination.open('xb', buffering=0) as writer:
            shutil.copyfileobj(reader, GuardedWriter(writer, self), length=COPY_CHUNK_BYTES)


class GuardedWriter(io.BufferedIOBase):
    def __init__(self, writer, guard):
        self.writer = writer
        self.guard = guard

    def write(self, data):
        self.guard.check()
        written = self.writer.write(data)
        self.guard.check(written=written)
        return written

    def tell(self):
        return self.writer.tell()


class BuildStopped(BaseException):
    """SIGTERM is a stopped attempt, not a compiler error or a retry grant."""


def stop_on_sigterm(signum, frame):
    raise BuildStopped('SIGTERM')


class StageDiagnostics:
    """Bounded public build telemetry; never inspect cmdline, env or ship data."""
    def __init__(self, attempt, log_path, cwd, interval=30, quiet_seconds=120):
        self.attempt, self.log_path, self.cwd = attempt, log_path, cwd
        self.interval, self.quiet_seconds = interval, quiet_seconds
        self.offset = 0
        self.stream_limit = 2 * 1024**2
        self.last_sample = float('-inf')
        self.last_activity = time.monotonic()
        self.previous = None
        self.capped = False

    @staticmethod
    def process_sample(pgid, proc=Path('/proc')):
        if not proc.is_dir():
            return dict(cpu_ticks=None, processes=None)
        ticks, count = 0, 0
        for directory in proc.iterdir():
            if not directory.name.isdigit():
                continue
            try:
                # stat fields 3 onwards; comm may itself contain parentheses.
                fields = (directory / 'stat').read_text().rsplit(')', 1)[1].split()
                if int(fields[2]) == pgid:
                    ticks += sum(int(v) for v in fields[11:15])
                    count += 1
            except (OSError, ValueError, IndexError):
                continue  # A sampled process may exit during enumeration.
        return dict(cpu_ticks=ticks if count else None, processes=count)

    def object_sample(self):
        count = size = scanned = 0
        fingerprint = hashlib.sha256()
        deadline = time.monotonic() + 1
        complete = True
        for directory, dirs, files in os.walk(self.cwd, followlinks=False):
            scanned += 1
            if scanned > 100000 or time.monotonic() > deadline:
                complete = False
                break
            dirs[:] = sorted(d for d in dirs if d != '.git')
            for name in sorted(files):
                scanned += 1
                if scanned > 100000 or time.monotonic() > deadline:
                    complete = False
                    break
                if not (name.endswith(('.o', '.a', '.bin')) or name == 'urbit'):
                    continue
                path = Path(directory) / name
                try:
                    if path.is_symlink():
                        continue
                    stat = path.stat()
                except OSError:
                    continue
                count += 1
                size += stat.st_size
                fingerprint.update(f'{path.relative_to(self.cwd)}:{stat.st_size}:{stat.st_mtime_ns}\n'.encode())
            if not complete:
                break
        return dict(object_files=count, object_bytes=size, object_scan_complete=complete,
                    object_metadata_sha256=fingerprint.hexdigest())

    def update(self, pgid, force=False):
        size = self.log_path.stat().st_size
        if self.offset < min(size, self.stream_limit):
            with self.log_path.open('rb') as log:
                log.seek(self.offset)
                data = log.read(min(32768, self.stream_limit - self.offset))
            self.offset += len(data)
            self.attempt.event('compiler-output', text=data.decode(errors='replace'))
        if size > self.stream_limit and not self.capped:
            self.capped = True
            self.attempt.event('compiler-stream-capped', limit_bytes=self.stream_limit,
                               detail='Full log is inside the build filesystem only; metrics and final tail continue')
        now = time.monotonic()
        if not force and now - self.last_sample < self.interval:
            return
        sample = dict(log_bytes=size, **self.process_sample(pgid), **self.object_sample())
        signature = (size, sample['cpu_ticks'], sample['object_metadata_sha256'])
        if signature != self.previous:
            self.last_activity = now
        self.previous, self.last_sample = signature, now
        quiet = round(now - self.last_activity, 3)
        self.attempt.event('activity', quiet_seconds=quiet,
                           assessment='possibly-stalled' if quiet >= self.quiet_seconds else 'observing',
                           stall_proven=False, **sample)

    def tail(self):
        if self.log_path.is_file():
            with self.log_path.open('rb') as log:
                log.seek(max(0, log.seek(0, 2) - 12000))
                self.attempt.event('compiler-tail', text=log.read().decode(errors='replace'))


class Attempt:
    def __init__(self, output):
        # Exclusive creation is the replay interlock; never remove on failure.
        output.mkdir(mode=0o700, parents=False, exist_ok=False)
        self.output = output
        self.current = 'admitted'
        self.event('admitted')

    def event(self, status, *, mirror=None, **values):
        entry = dict(stage=self.current, status=status, **values)
        for path in [self.output / 'events.jsonl'] + ([mirror] if mirror else []):
            with path.open('a') as log:
                log.write(json.dumps(entry, sort_keys=True) + '\n')
                log.flush()
                os.fsync(log.fileno())
        print(json.dumps(entry, sort_keys=True), flush=True)

    def run(self, stage, argv, cwd, env, timeout=1800):
        self.current = stage
        self.event('entered', argv=argv)
        before = time.monotonic()
        guard = CapacityGuard(self.output)
        stopped = False
        def request_stop(signum, frame):
            # Latch rather than raise during Popen: even a signal arriving
            # during launch must leave us with the child's process-group ID.
            nonlocal stopped
            stopped = True
        previous = signal.signal(signal.SIGTERM, request_stop)
        process = None
        diagnostics = StageDiagnostics(self, self.output / (stage + '.log'), cwd)
        try:
            # Public compiler output only, never ship output/environment dumps.
            with (self.output / (stage + '.log')).open('xb') as log:
                process = subprocess.Popen(argv, cwd=cwd, env=env, stdout=log,
                                           stderr=subprocess.STDOUT, start_new_session=True)
                while True:
                    if stopped:
                        raise BuildStopped('SIGTERM')
                    diagnostics.update(process.pid)
                    if process.poll() is not None:
                        break
                    if time.monotonic() - before > timeout:
                        raise subprocess.TimeoutExpired(argv, timeout)
                    if env.get('UVM_BUILD_CAPACITY_GUARD') == '1':
                        guard.check()
                    try:
                        process.wait(timeout=0.2)
                    except subprocess.TimeoutExpired:
                        continue
                if stopped:
                    raise BuildStopped('SIGTERM')
        except BaseException as error:
            try:
                if process is not None:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass  # The group already exited; still reap our child.
                    process.wait(timeout=5)
            finally:
                self.event('stopped', limit_seconds=timeout, reason=type(error).__name__,
                           child_reaped=process is not None and process.poll() is not None)
                diagnostics.tail()
            raise
        finally:
            signal.signal(signal.SIGTERM, previous)
        self.event('returned', exit_code=process.returncode,
                   elapsed_seconds=round(time.monotonic() - before, 3))
        diagnostics.update(process.pid, force=True)
        if process.returncode:
            # Only public compiler output. Expose a bounded useful failure tail
            # even if BuildKit cannot export a failed layer's evidence directory.
            diagnostics.tail()
            raise RuntimeError(stage + ' failed; inspect the retained build log')


def prepare(attempt, lock, input_dir, *, arena_bytes):
    owned.capacity(arena_bytes)
    owned.validate_recipe(HERE)
    trees = {}
    materials = attempt.output / 'materials'
    materials.mkdir()
    for name, item in lock['inputs'].items():
        attempt.current = 'input-' + name
        filename = {'vere': 'vere-8ddc4b7.tar.gz', 'openssl': 'openssl-3.5.9.tar.gz',
                    'zig': 'zig-x86_64-linux-0.15.2.tar.xz'}[name]
        if input_dir is None:
            with urllib.request.urlopen(item['url'], timeout=90) as response:
                if not response.geturl().startswith('https://'):
                    raise ValueError('insecure input redirect')
                data = response.read(item['bytes'] + 1)
        else:
            with (input_dir / filename).open('rb') as source:
                data = source.read(item['bytes'] + 1)
        verify_input(data, item)
        archive_path = materials / filename
        archive_path.write_bytes(data)
        with tarfile.open(archive_path) as archive:
            members = archive.getmembers()
            for member in members:
                check_member(member, item['root'])
            # All members were restricted to regular files/directories within root.
            archive.extractall(attempt.output, members=members)
        trees[name] = attempt.output / item['root']
        attempt.event('verified', sha256=item['sha256'])
    source = trees['vere']
    for name, expected in lock['source_preimages'].items():
        if sha((source / name).read_bytes()) != expected:
            raise ValueError('Vere source preimage hash mismatch: ' + name)
    main = source / 'pkg/vere/main.c'
    if sha(main.read_bytes()) != '01e9f2de08464b136c46e2c1ec395161c64c7be4ce01f49072344ae62e2f1781':
        raise ValueError('Vere report source preimage hash mismatch')
    h2o_changes = apply_h2o_overlay(source, lock)
    (attempt.output / 'h2o-socket.c').write_bytes((source / 'ext/h2o/socket.c').read_bytes())
    (attempt.output / 'h2o-overlay.json').write_text(json.dumps(dict(
        source_preimages={name: lock['source_preimages'][name] for name in
                          ('ext/h2o/build.zig', 'ext/h2o/build.zig.zon')},
        source_changes=h2o_changes, overlay=lock['h2o_overlay']), indent=2) + '\n')
    sha_changes = apply_sha_overlay(source, lock)
    (attempt.output / 'sha-stack.c').write_bytes((source / 'ext/urcrypt/sha.c').read_bytes())
    (attempt.output / 'sha-overlay.json').write_text(json.dumps(dict(
        source_preimages={name: lock['source_preimages'][name] for name in
                          ('ext/urcrypt/build.zig', 'ext/urcrypt/build.zig.zon')},
        source_changes=sha_changes, overlay=lock['sha_overlay']), indent=2) + '\n')
    allocation_changes = apply_allocation_overlay(source, lock)
    (attempt.output / 'allocation-overlay.json').write_text(json.dumps(dict(
        source_preimages={name: lock['source_preimages'][name] for name in allocation_changes},
        source_changes=allocation_changes), indent=2) + '\n')
    curl_changes = apply_curl_overlay(source, lock)
    for target in curl_changes:
        # Freeze verified bytes from the patched tree, not a later recipe read.
        (attempt.output / lock['curl_overlays'][target]['file']).write_bytes(
            (source / target).read_bytes())
    (attempt.output / 'curl-overlay.json').write_text(json.dumps(dict(
        source_preimages={name: lock['source_preimages'][name] for name in curl_changes},
        source_changes=curl_changes, overlays=lock['curl_overlays']), indent=2) + '\n')
    build = source / 'build.zig'
    build.write_text(patch_build(build.read_text()))
    main.write_text(patch_report(main.read_text()))
    ca_changes = apply_ca_overlay(source, lock)
    (attempt.output / 'ca-overlay.json').write_text(json.dumps(dict(
        source_preimages=lock['ca_preimages'], source_changes=ca_changes), indent=2) + '\n')
    king = source / 'pkg/vere/king.c'
    king_data = patch_curl_buffer(king.read_text()).encode()
    if sha(king_data) != lock['curl_buffer_sha256']:
        raise ValueError('curl buffer source postimage mismatch')
    king.write_bytes(king_data)
    manage = source / 'pkg/noun/manage.c'
    manage.write_text(patch_allocator(manage.read_text()))
    # Keep the package identity; remove the obsolete OpenSSL/nasm/SDK graph.
    (source / 'ext/openssl/build.zig.zon').write_text(
        '.{ .name = .openssl, .fingerprint = 0x773a47f1ba90827f,\n'
        '   .version = "3.5.9", .dependencies = .{}, .paths = .{ "" } }\n')
    # Refuse accidental builds until the actual generated objects are available.
    (source / 'ext/openssl/build.zig').write_text(
        '@compileError("Run the authorized candidate builder to generate OpenSSL objects");\n')
    # Dead mirrors are changed only at the URL. Zig must still verify the
    # original package-content hashes; an alternate URL is not identity proof.
    for relative, old, new in (
        ('ext/gmp/build.zig.zon',
         'https://ftp.fr.openbsd.org/pub/OpenBSD/distfiles/gmp-6.3.0.tar.xz',
         'https://ftp.gnu.org/gnu/gmp/gmp-6.3.0.tar.xz'),
        ('ext/sigsegv/build.zig.zon',
         'https://ftp.fr.openbsd.org/pub/OpenBSD/distfiles/libsigsegv-2.14.tar.gz',
         'https://ftp.gnu.org/gnu/libsigsegv/libsigsegv-2.14.tar.gz'),
        ('ext/natpmp/build.zig.zon',
         'http://deb.debian.org/debian/pool/main/libn/libnatpmp/libnatpmp_20230423.orig.tar.gz',
         'https://deb.debian.org/debian/pool/main/libn/libnatpmp/libnatpmp_20230423.orig.tar.gz'),
    ):
        file = source / relative
        file.write_text(replace_once(file.read_text(), old, new))
    manifests = {str(p.relative_to(source)): sha(p.read_bytes())
                 for p in sorted(source.rglob('build.zig.zon'))}
    (attempt.output / 'dependency-manifests.json').write_text(json.dumps(manifests, indent=2) + '\n')
    shutil.copyfile(HERE / 'inputs.json', attempt.output / 'inputs.json')
    shutil.copyfile(HERE / 'candidate.py', attempt.output / 'candidate.py')
    owned.complete_preparation(HERE, source, attempt.output, arena_bytes=arena_bytes)
    attempt.current = 'source-preparation'
    attempt.event('passed', compiled=False, vere_executed=False)
    return trees


def compile_candidate(attempt, lock, trees, *, openssl_only=False, openssl_cache=None):
    if os.uname().sysname != 'Linux' or os.uname().machine != 'x86_64':
        raise ValueError('build requires the pinned Linux AMD64 builder')
    if shutil.disk_usage(attempt.output).free < 14 * 1024**3:
        raise ValueError('builder admission requires 6 GiB budget plus 8 GiB reserve')
    # Snapshot builder-resident inputs before compilation; validate and deliver
    # these exact bytes, never a later host-side copy of the recipe or APK DB.
    evidence = {'Dockerfile': (HERE / 'Dockerfile').read_bytes(),
                'builder-apks.json': (HERE / 'builder-apks.json').read_bytes(),
                'builder-apk-db.txt': Path('/lib/apk/db/installed').read_bytes()}
    for name, content in evidence.items():
        (attempt.output / name).write_bytes(content)
    tools = json.loads(evidence['builder-apks.json'])
    installed = {}
    for block in evidence['builder-apk-db.txt'].decode().split('\n\n'):
        fields = dict(line.split(':', 1) for line in block.splitlines() if ':' in line)
        if 'P' in fields:
            installed[fields['P']] = fields
    for package in tools['packages']:
        if any(installed.get(package['P'], {}).get(key) != value for key, value in package.items()):
            raise ValueError('builder package identity mismatch: ' + package['P'])
    zig = str(trees['zig'] / 'zig')
    source, openssl = trees['vere'], trees['openssl']
    temporary = attempt.output / 'tmp'
    temporary.mkdir()
    env = dict(os.environ, LC_ALL='C', TZ='UTC', SOURCE_DATE_EPOCH='1782999240',
               TMPDIR=str(temporary), UVM_BUILD_CAPACITY_GUARD='1',
               ZIG_GLOBAL_CACHE_DIR=str(attempt.output / 'zig-cache'),
               ZIG_LOCAL_CACHE_DIR=str(attempt.output / 'zig-local-cache'),
               CC=zig + ' cc -target x86_64-linux-musl -mcpu=baseline',
               AR=zig + ' ar', RANLIB=zig + ' ranlib')
    cache_binding = {name: sha((attempt.output / name).read_bytes()) for name in
                     ('inputs.json', 'candidate.py', 'Dockerfile', 'builder-apks.json', 'builder-apk-db.txt')}
    cache_binding.update(owned.build_bindings(attempt.output))
    cache_digest = None
    if openssl_cache is not None:
        cache_bytes = (openssl_cache / 'openssl-cache.json').read_bytes()
        cached = json.loads(cache_bytes)
        openssl = openssl_cache / lock['inputs']['openssl']['root']
        if (cached.get('bindings') != cache_binding or cached.get('status') != 'compiled' or
                cached.get('tree_sha256') != tree_hashes(openssl)):
            raise ValueError('OpenSSL cache identity/content mismatch')
        for name in ('libcrypto.a', 'libssl.a'):
            if name not in cached['tree_sha256']:
                raise ValueError('OpenSSL cache lacks compiled archive')
        trees['openssl'] = openssl
        cache_digest = sha(cache_bytes)
        (attempt.output / 'openssl-cache.json').write_bytes(cache_bytes)
        # Carry original public compiler diagnostics into the final delivery.
        cache_logs = attempt.output / 'openssl-cache-evidence'
        cache_logs.mkdir()
        guard = CapacityGuard(attempt.output)
        for path in sorted(openssl_cache.glob('openssl-*.log')):
            guard.copy_file(path, cache_logs / path.name)
        guard.copy_file(openssl_cache / 'events.jsonl', cache_logs / 'events.jsonl')
        attempt.current = 'openssl-cache'
        attempt.event('verified', cache_sha256=cache_digest, compiled_here=False)
    else:
        attempt.run('openssl-configure', ['perl', 'Configure', 'linux-x86_64',
                    'no-shared', 'no-module', 'no-tests', 'no-apps', 'no-docs',
                    '--prefix=/opt/uvm-openssl3', '--openssldir=/opt/uvm-openssl3/ssl',
                    '--libdir=lib', '-fPIC'], openssl, env)
        attempt.run('openssl-build', ['make', '-j2', 'build_libs'], openssl, env)
        attempt.run('openssl-configuration', ['perl', 'configdata.pm', '--dump'], openssl, env)
    if openssl_only:
        if openssl_cache is not None:
            raise ValueError('OpenSSL cache stage cannot consume another attempt')
        hashes = tree_hashes(openssl)
        if not all(name in hashes for name in ('libcrypto.a', 'libssl.a')):
            raise ValueError('OpenSSL cache lacks compiled archive')
        (attempt.output / 'openssl-cache.json').write_text(json.dumps(
            dict(status='compiled', bindings=cache_binding, tree_sha256=hashes,
                 vere_executed=False), indent=2) + '\n')
        CapacityGuard(attempt.output).check(force=True)
        attempt.current = 'openssl-cache'
        attempt.event('passed', vere_compiled=False, vere_executed=False)
        return
    prebuilt = source / 'ext/openssl/prebuilt'
    prebuilt.mkdir()
    shutil.copytree(openssl / 'include', prebuilt / 'include')
    members = {}
    archive_hashes = {}
    for lib in ('crypto', 'ssl'):
        archive = openssl / ('lib' + lib + '.a')
        names = subprocess.check_output([zig, 'ar', 't', str(archive)], env=env, text=True).splitlines()
        # Validate names and duplicates before extraction (no filesystem escapes).
        object_adapter({'crypto': names, 'ssl': names})
        destination = prebuilt / lib
        destination.mkdir()
        attempt.run('openssl-extract-' + lib, [zig, 'ar', 'x', str(archive)], destination, env)
        members[lib] = names
        archive_hashes[lib] = sha(archive.read_bytes())
    (source / 'ext/openssl/build.zig').write_text(object_adapter(members))
    (attempt.output / 'openssl-archives.json').write_text(json.dumps(
        dict(sha256=archive_hashes, members=members), indent=2) + '\n')
    attempt.run('vere-build', vere_build_command(zig), source, env)
    binary = source / 'zig-out/x86_64-linux-musl/urbit'
    data = binary.read_bytes()
    if data[:6] != b'\x7fELF\x02\x01' or int.from_bytes(data[18:20], 'little') != 62:
        raise ValueError('candidate is not Linux AMD64 ELF')
    if b'OpenSSL 3.5.9' not in data or b'OpenSSL 1.1.1w' in data:
        raise ValueError('candidate embedded OpenSSL version marker rejected')
    attempt.current = 'candidate-output'
    guard = CapacityGuard(attempt.output)
    guard.check(force=True)
    guard.copy_file(binary, attempt.output / 'urbit')
    (attempt.output / 'urbit').chmod(0o555)
    changed = ['build.zig', 'pkg/vere/main.c', 'pkg/vere/king.c', 'pkg/noun/manage.c', 'ext/openssl/build.zig',
               'pkg/vere/vere.h', 'pkg/vere/io/cttp.c', 'pkg/vere/io/http.c',
               'ext/urcrypt/build.zig', 'ext/urcrypt/build.zig.zon', 'ext/urcrypt/sha.c',
               'ext/h2o/build.zig', 'ext/h2o/build.zig.zon', 'ext/h2o/socket.c',
               'ext/curl/build.zig', 'ext/curl/build.zig.zon',
               'ext/openssl/build.zig.zon', 'ext/gmp/build.zig.zon',
               'ext/sigsegv/build.zig.zon', 'ext/natpmp/build.zig.zon']
    owned_overlay = json.loads((attempt.output / 'owned-overlay.json').read_text())
    final_changes = owned.final_source_changes(source, changed, owned_overlay)
    receipt = dict(candidate=lock['candidate'] + '-owned-palloc', executable_sha256=sha(data),
                   executable_bytes=len(data), architecture='linux/amd64',
                   source_changes=final_changes, **owned.build_bindings(attempt.output),
                   inputs_sha256=sha((attempt.output / 'inputs.json').read_bytes()),
                   recipe_sha256=sha((attempt.output / 'candidate.py').read_bytes()),
                   dockerfile_sha256=sha(evidence['Dockerfile']),
                   builder_apks_sha256=sha(evidence['builder-apks.json']),
                   builder_apk_db_sha256=sha(evidence['builder-apk-db.txt']),
                   openssl_cache_sha256=cache_digest,
                   static_version_marker=True, dependency_runtime_report=False,
                   vere_executed=False, image_bound=False, lifecycle_passed=False,
                   reproducibility_verified=False, distribution_cleared=False)
    (attempt.output / 'candidate.json').write_text(json.dumps(receipt, indent=2) + '\n')
    delivery = attempt.output / 'delivery'
    delivery.mkdir()
    for file in attempt.output.iterdir():
        if file.is_file():
            guard.copy_file(file, delivery / file.name)
            if file.name == 'urbit':
                (delivery / file.name).chmod(0o555)

    owned.copy_delivery(attempt.output, delivery, guard)

    owned.retain_public_libraries(source, openssl, attempt.output, delivery, guard)

    # Preserve exact archives, patched source, generated headers/configuration,
    # and fetched dependency source. Build caches/objects are not source delivery.
    def source_filter(member):
        parts = PurePosixPath(member.name).parts
        if '.zig-cache' in parts or 'zig-out' in parts or member.name.endswith(('.o', '.a')):
            return None
        return member
    with (delivery / 'source-materials.tar.gz').open('xb', buffering=0) as raw:
        with tarfile.open(fileobj=GuardedWriter(raw, guard), mode='w:gz') as archive:
            for folder in (attempt.output / 'materials', source, openssl, attempt.output / 'zig-cache/p',
                           attempt.output / 'openssl-cache-evidence'):
                if folder.is_dir():
                    archive.add(folder, arcname=folder.name, filter=source_filter)
    # Include the archive trailer/close and every delivery copy in the final
    # capacity decision. No success is emitted for partial evidence.
    guard.check(force=True)
    attempt.event('passed', mirror=delivery / 'events.jsonl', **receipt)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--source-check', action='store_true')
    mode.add_argument('--build', action='store_true')
    mode.add_argument('--openssl-only', action='store_true')
    parser.add_argument('--arena-bytes', type=int, required=True,
                        help='explicit page-aligned reservation; no production default')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--input-dir', type=Path)
    parser.add_argument('--openssl-cache', type=Path)
    parser.add_argument('--attempt-id')
    args = parser.parse_args()
    if args.openssl_cache and (not args.build or not args.attempt_id):
        parser.error('--openssl-cache requires --build and a fresh --attempt-id')
    if args.attempt_id and not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,80}', args.attempt_id):
        parser.error('invalid fresh attempt ID')
    owned.capacity(args.arena_bytes)
    owned.validate_recipe(HERE)
    lock = json.loads((HERE / 'inputs.json').read_text())
    attempt = Attempt(args.output.resolve())
    if args.attempt_id:
        attempt.event('authorization-label', attempt_id=args.attempt_id)
    previous = signal.signal(signal.SIGTERM, stop_on_sigterm)
    try:
        trees = prepare(attempt, lock, args.input_dir, arena_bytes=args.arena_bytes)
        if args.openssl_only or args.openssl_cache:
            compile_candidate(attempt, lock, trees, openssl_only=args.openssl_only,
                              openssl_cache=args.openssl_cache)
        elif args.build:
            compile_candidate(attempt, lock, trees)
    except BuildStopped:
        attempt.event('stopped', reason='SIGTERM')
        raise SystemExit(128 + signal.SIGTERM)
    except Exception as error:
        attempt.event('failed', error_type=type(error).__name__, detail=str(error))
        raise SystemExit(1)
    finally:
        signal.signal(signal.SIGTERM, previous)


if __name__ == '__main__':
    main()
