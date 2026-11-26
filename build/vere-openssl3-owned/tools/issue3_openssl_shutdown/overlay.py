"""Exact staged shutdown-completion overlay, after current source hardening.

Does not change recipes, graph/pins, allocator capacity or the arena worker.
"""
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
PINS = json.loads((HERE / 'sources.json').read_text())


def replace(text, before, after):
    if text.count(before) != 1:
        raise ValueError('shutdown source context mismatch: ' + before[:80])
    return text.replace(before, after, 1)


def transform(name, text):
    pin = PINS['hardened_preimages'][name]
    if hashlib.sha256(text.encode()).hexdigest() != pin:
        raise ValueError('shutdown preimage mismatch: ' + name)
    if name == 'pkg/vere/king.c':
        start = text.index('static void\n_king_done_cb(')
        end = text.index('/* u3_king_done():', start)
        text = text[:start] + '''static int _king_finishing;
static void
_king_done_cb(uv_handle_t* han_u)
{
  /* A close callback is not a safe event-runner/loop-close boundary. */
  (void)han_u;
}

''' + text[end:]
        text = replace(text, '  uv_handle_t* han_u = (uv_handle_t*)&u3K.tim_u;\n',
                       '''  uv_handle_t* han_u = (uv_handle_t*)&u3K.tim_u;

  if ( u3K.pir_u ) {
    return;
  }
  if ( _king_finishing ) {
    u3_ssl_shutdown_request(u3_Host.xit_i);
    return;
  }
  _king_finishing = 1;
''')
        text = replace(text, '  u3m_stop();\n  exit(u3_Host.xit_i);',
                       '  u3_ssl_shutdown_request(u3_Host.xit_i);')
        text = replace(text, '  uv_run(u3L, UV_RUN_DEFAULT);',
                       '  u3_ssl_shutdown_run(u3L);')
        text = replace(text, '    pir_f(pir_u);\n    pir_u = pir_u->nex_u;',
                       '    u3_pier* nex_u = pir_u->nex_u;\n    pir_f(pir_u);\n    pir_u = nex_u;')
        text = replace(text, '  _king_forall_unlink(u3_pier_bail);\n  u3_king_done();',
                       '  _king_forall_unlink(u3_pier_bail);\n  u3_king_done();\n'
                       '  /* Immediate bail callers must never resume into disposed state. */\n'
                       '  exit(u3_Host.xit_i);')
        text = text.replace('Does not return\n', 'Returns after queuing shutdown\n')
    elif name == 'pkg/vere/io/cttp.c':
        text = replace(text, '    SSL_CTX_free(ctp_u->tls_u);\n    c3_free(ctp_u);',
                       '    SSL_CTX_free(ctp_u->tls_u);\n    c3_free(ctp_u);\n'
                       '    u3_ssl_shutdown_release();')
        text = replace(text, '  return car_u;\n}',
                       '  u3_ssl_shutdown_hold();\n  return car_u;\n}')
    elif name == 'pkg/vere/io/http.c':
        text = replace(text, '  _http_serv_unlink(htp_u);\n  c3_free(htp_u);',
                       '  _http_serv_unlink(htp_u);\n  c3_free(htp_u);\n'
                       '  u3_ssl_shutdown_release();')
        text = replace(text, '  _http_serv_link(htd_u, htp_u);\n\n  return htp_u;',
                       '  _http_serv_link(htd_u, htp_u);\n'
                       '  u3_ssl_shutdown_hold();\n\n  return htp_u;')
        text = replace(text, '  if ( (0 == htp_u->hon_u) && (0 != h2o_u->ctx_u.shutdown_requested) ) {',
                       '  if ( (c3n == htp_u->liv) && (0 == htp_u->hon_u)\n'
                       '       && (0 != h2o_u->ctx_u.shutdown_requested) ) {')
        text = replace(text, '''  //  XX broken
  //
  // for ( u3_http* htp_u = htd_u->htp_u; htp_u; htp_u = htp_u->nex_u ) {
  //   _http_serv_close(htp_u);
  // }
''', '''  for ( u3_http* htp_u = htd_u->htp_u; htp_u; htp_u = htp_u->nex_u ) {
    if ( !uv_is_closing((uv_handle_t*)&htp_u->wax_u) ) {
      _http_serv_close(htp_u);
    }
  }
''')
        text = replace(text, '  _http_release_ports_file(u3_Host.dir_c);\n}',
                       '  _http_release_ports_file(u3_Host.dir_c);\n'
                       '  u3_ssl_shutdown_retire(htd_u, _http_exit_free);\n}')
        text = replace(text, '/* _http_io_exit(): shut down http.',
                       '''static void
_http_exit_free(void* ptr_v)
{
  u3_httd* htd_u = ptr_v;
  u3h_free(htd_u->sax_p);
  u3h_free(htd_u->nax_p);
  if ( NULL != htd_u->stk_u ) munmap(htd_u->stk_u, u3a_page);
  _http_auth_free(htd_u);
  c3_free(htd_u);
}

/* _http_io_exit(): shut down http.''')
        begin = text.index('static void\n_http_io_exit(')
        end = text.index('/* _http_io_info():', begin)
        body = text[begin:end]
        body = replace(body, '''  u3h_free(htd_u->sax_p);
  u3h_free(htd_u->nax_p);

  if ( NULL != htd_u->stk_u ) {
    munmap(htd_u->stk_u, u3a_page);
  }

''', '')
        body = replace(body, '  _http_auth_free(htd_u);\n', '')
        body = replace(body, '      _http_continue_respond(seq_u, u3k(dat), c3y);\n      seq_u = seq_u->nex_u;',
                       '      u3_hreq* nex_u = seq_u->nex_u;\n'
                       '      _http_continue_respond(seq_u, u3k(dat), c3y);\n      seq_u = nex_u;')
        text = text[:begin] + body + text[end:]
        for handler in ('_http_rec_accept', '_http_seq_accept', '_http_sat_accept'):
            signature = handler + '(h2o_handler_t* han_u, h2o_req_t* rec_u)\n{'
            text = replace(text, signature, signature + '''
  if ( u3_ssl_shutdown_pending() ) {
    h2o_send_error_generic(rec_u, 503, "shutting down", "shutting down", 0);
    return 0;
  }
''')
        text = replace(text, '_http_req_kill(u3_hreq* req_u)\n{',
                       '_http_req_kill(u3_hreq* req_u)\n{\n'
                       '  if ( u3_ssl_shutdown_pending() ) return;')
    elif name == 'pkg/vere/mars.c':
        text = replace(text, '/* _mars_flush(): send pending gifts.',
                       '''static void _mars_sign_close(void);

static void
_mars_disk_close(void* ptr_v)
{
  u3_disk_exit(ptr_v);
}

/* _mars_flush(): send pending gifts.''')
        text = replace(text, '      u3_disk_exit(mar_u->log_u);\n      u3s_cue_xeno_done',
                       '      u3_ssl_shutdown_retire(mar_u->log_u, _mars_disk_close);\n      u3s_cue_xeno_done')
        text = replace(text, '_mars_flush(u3_mars* mar_u)\n{\ntop:',
                       '_mars_flush(u3_mars* mar_u)\n{\n'
                       '  if ( u3_ssl_shutdown_pending() ) return;\ntop:')
        text = replace(text, '      u3m_stop();\n      exit(0);',
                       '      uv_timer_stop(&mar_u->sav_u.tim_u);\n'
                       '      uv_close((uv_handle_t*)&mar_u->sav_u.tim_u, 0);\n'
                       '      _mars_sign_close();\n'
                       '      u3_ssl_shutdown_worker();\n      return;')
        text = replace(text, '    u3_disk_exit(mar_u->log_u);\n    exit(0);',
                       '    u3_disk_exit(mar_u->log_u);\n'
                       '    /* The already-ahead path precedes save-timer init. */\n'
                       '    _mars_sign_close();\n'
                       '    u3_ssl_shutdown_worker();\n    return;')
        text = replace(text, '  u3_disk_exit(log_u);\n  exit(0);\n\n  return c3y;',
                       '  u3_disk_exit(log_u);\n  u3_ssl_shutdown_worker();\n\n  return c3y;')
    elif name == 'pkg/vere/main.c':
        text = replace(text, 'static STACK_OF(X509_INFO)* _cert_store;\n',
                       'static STACK_OF(X509_INFO)* _cert_store;\n'
                       '#include "openssl_owned_arena.h"\n'
                       '#include "openssl_shutdown.inc"\n')
        if text.count('u3m_stop();') != 10:
            raise ValueError('utility stop inventory changed')
        text = text.replace('u3m_stop();', 'u3_ssl_shutdown_loom();\n  u3_ssl_shutdown_request(0);')
        text = replace(text, '  return log_u;\n}',
                       '  u3_ssl_shutdown_loom();\n  return log_u;\n}')
        # Every direct noun boot also establishes backing ownership, including
        # eval/vile, whose old normal paths never called u3m_stop at all.
        lines = text.splitlines(keepends=True)
        result = []
        for line in lines:
            result.append(line)
            if 'u3m_boot(' in line or 'u3m_boot_lite(' in line:
                indent = line[:len(line)-len(line.lstrip())]
                result.append(indent + 'u3_ssl_shutdown_loom();\n')
        text = ''.join(result)
        text = replace(text, '  //  mars is spawned with [FD 0]',
                       '  _ssl_worker_io = 1;\n\n  //  mars is spawned with [FD 0]')
        for comment in ('  // does not return because _mars_flush does not return\n  //\n',
                        '  // does not return becase _mars_flush does not return\n'):
            text = replace(text, comment, '  //  Finalize only after the outer callback stack unwinds.\n')
        if text.count('  uv_run(lup_u, UV_RUN_DEFAULT);') != 2:
            raise ValueError('worker loop inventory changed')
        text = text.replace('  uv_run(lup_u, UV_RUN_DEFAULT);',
                            '  u3_ssl_shutdown_run(lup_u);\n'
                            '  /* Embedded worker handles still belong to this frame. */\n'
                            '  if ( !_ssl_loop_closed ) abort();')
        # A synchronous worker startup can already have requested final exit.
        admission = '  u3_newt_read(&inn_u);\n  //  Finalize'
        if text.count(admission) != 2:
            raise ValueError('worker admission inventory changed')
        text = text.replace(admission,
                            '  if ( !u3_ssl_shutdown_pending() ) u3_newt_read(&inn_u);\n  //  Finalize')
        text = replace(text, '    u3_mars_work(&mar_u);',
                       '    u3_ssl_shutdown_loom();\n    u3_mars_work(&mar_u);')
        text = replace(text, '    u3_mars_make(&mar_u);',
                       '    u3_mars_make(&mar_u);\n    u3_ssl_shutdown_loom();')
        # Utility eval owns stack-embedded output handle storage. It must finish
        # its output shutdown while that stack frame is still alive.
        text = replace(text, '    free(evl_c);\n  }\n}\n\n/* _cw_info():',
                       '    free(evl_c);\n  }\n'
                       '  _ssl_output = &std_u;\n'
                       '  u3_ssl_shutdown_request(0);\n'
                       '  u3_ssl_shutdown_run(uv_default_loop());\n'
                       '  /* Never return borrowed stack storage to a second runner. */\n'
                       '  if ( !_ssl_loop_closed ) abort();\n'
                       '}\n\n/* _cw_info():')
        # Successful fetch's early already-current exit must use the normal tail.
        text = replace(text, '        exit(0);\n      } break;',
                       '        return;\n      } break;')
        text = replace(text, '    case 1: {\n      return 0;\n    }',
                       '    case 1: {\n'
                       '      if ( !u3_ssl_shutdown_pending() ) u3_ssl_shutdown_request(0);\n'
                       '      u3_ssl_shutdown_run(uv_default_loop());\n'
                       '      return u3_ssl_shutdown_finish();\n    }')
        # Both initialized curl paths reach CA setup; failure remains terminal.
        for spaces in ('  ', '    '):
            text = replace(text, '\n' + spaces + '_setup_cert_store();',
                           '\n' + spaces + '_ssl_curl_ready = 1;\n' + spaces + '_setup_cert_store();')
        start = text.index('    //  uninitialize curl\n')
        end = text.index('\n  }\n\n  return 0;\n}', start)
        text = text[:start] + '    return u3_ssl_shutdown_finish();\n' + text[end:]
    elif name == 'pkg/vere/lord.c':
        text = replace(text, '/* _lord_stop_cb(): finally all done.',
                       '''static void
_lord_stop_free(void* ptr_v)
{
  u3_lord* god_u = ptr_v;
  u3s_cue_xeno_done(god_u->sil_u);
  c3_free(god_u);
}

/* _lord_stop_cb(): process notification, owner retired until loop close.''')
        text = replace(text, '  u3s_cue_xeno_done(god_u->sil_u);\n  c3_free(god_u);\n\n  if ( exit_f )',
                       '  u3_ssl_shutdown_retire(god_u, _lord_stop_free);\n\n  if ( exit_f )')
        text = replace(text, '  uv_read_stop((uv_stream_t*)&(god_u->err_u));',
                       '  uv_read_stop((uv_stream_t*)&(god_u->err_u));\n'
                       '  uv_close((uv_handle_t*)&god_u->err_u, 0);')
        text = replace(text, '/* _lord_on_serf_boot_exit_cb(): finish handling subprocess exit.',
                       '''static void
_lord_boot_free(void* ptr_v)
{
  _lord_boot* bot_u = ptr_v;
  u3s_cue_xeno_done(bot_u->sil_u);
  c3_free(bot_u);
}

/* _lord_on_serf_boot_exit_cb(): finish handling subprocess exit.''')
        text = replace(text, '  u3s_cue_xeno_done(bot_u->sil_u);\n  c3_free(bot_u);\n\n  if ( done_f )',
                       '  u3_ssl_shutdown_retire(bot_u, _lord_boot_free);\n\n  if ( done_f )')
    elif name == 'pkg/vere/pier.c':
        text = replace(text, '/* _pier_bail_impl(): immediately shutdown.',
                       '''static void
_pier_shutdown_free(void* ptr_v)
{
  u3_pier* pir_u = ptr_v;
  c3_free(pir_u->pax_c);
  c3_free(pir_u);
}

/* _pier_bail_impl(): immediately stop admission and queue shutdown.''')
        text = replace(text, '_pier_bail_impl(u3_pier* pir_u)\n{\n  pir_u->sat_e',
                       '_pier_bail_impl(u3_pier* pir_u)\n{\n'
                       '  u3_ssl_shutdown_request(u3_Host.xit_i);\n  pir_u->sat_e')
        text = replace(text, '  c3_free(pir_u->pax_c);\n  c3_free(pir_u);\n\n  u3_king_done();',
                       '  u3_ssl_shutdown_retire(pir_u, _pier_shutdown_free);\n\n  u3_king_done();')
        text = replace(text, '  u3_Host.xit_i = 1;\n  _pier_bail_impl(pir_u);',
                       '  u3_Host.xit_i = 1;\n  _pier_bail_impl(pir_u);\n'
                       '  /* Preserve fatal callers: no loop reentry or backing release. */\n'
                       '  exit(1);')
        text = replace(text, '  u3_work* wok_u = idl_u->data;\n  c3_free(wok_u);',
                       '  u3_work* wok_u = idl_u->data;\n'
                       '  u3_ssl_shutdown_retire(wok_u, free);')
    elif name == 'pkg/vere/vere.h':
        text = replace(text, '#endif /* ifndef U3_VERE_H */',
                       '#include "openssl_shutdown.h"\n\n#endif /* ifndef U3_VERE_H */')
    elif name == 'pkg/vere/newt.c':
        text = replace(text, '/* _moat_stop_cb(): finalize stop/close input stream..',
                       '''typedef struct _newt_stop_pair {
  u3_moat* moat;
  unsigned remaining;
} _newt_stop_pair;

/* _moat_stop_cb(): finalize both embedded input handles.''')
        text = replace(text, '  u3_moat* mot_u = han_u->data;\n  mot_u->bal_f(mot_u->ptr_v, -1, "");',
                       '''  _newt_stop_pair* pair = han_u->data;
  if ( !--pair->remaining ) {
    u3_moat* mot_u = pair->moat;
    c3_free(pair);
    mot_u->bal_f(mot_u->ptr_v, -1, "");
  }''')
        text = replace(text, '  mot_u->pyp_u.data = mot_u;\n\n  if ( bal_f )',
                       '''  _newt_stop_pair* pair = c3_malloc(sizeof(*pair));
  pair->moat = mot_u;
  pair->remaining = 2;
  mot_u->pyp_u.data = pair;
  mot_u->tim_u.data = pair;

  if ( bal_f )''')
        text = replace(text, '  uv_close((uv_handle_t*)&mot_u->tim_u, 0);',
                       '  uv_close((uv_handle_t*)&mot_u->tim_u, _moat_stop_cb);')
    elif name == 'pkg/vere/io/ames.c':
        text = replace(text, 'static void\n_ames_exit_cb(uv_handle_t* had_u)\n{\n  u3_ames* sam_u = had_u->data;',
                       'static void\n_ames_exit_free(void* ptr_v)\n{\n  u3_ames* sam_u = ptr_v;')
        text = replace(text, '/* _ames_io_exit(): terminate ames I/O.',
                       '''static void
_ames_exit_cb(uv_handle_t* had_u)
{
  u3_ssl_shutdown_retire(had_u->data, _ames_exit_free);
}

/* _ames_io_exit(): terminate ames I/O.''')
        text = replace(text, '  uv_close(&sam_u->had_u, _ames_exit_cb);',
                       '  uv_close(&sam_u->had_u, _ames_exit_cb);\n'
                       '  uv_close((uv_handle_t*)&sam_u->zar_u.tim_u, 0);')
        text = replace(text, '  c3_y             imp_y = res_u->imp_y;\n',
                       '''  c3_y             imp_y = res_u->imp_y;

  if ( u3_ssl_shutdown_pending() ) {
    sam_u->zar_u.pen_s--;
    uv_freeaddrinfo(aif_u);
    c3_free(res_u);
    return;
  }
''')
    elif name == 'pkg/vere/io/mesa.c':
        text = replace(text, 'static void\n_mesa_exit_cb(uv_handle_t* han_u) {\n  u3_mesa* sam_u = (u3_mesa*)han_u->data;\n  arena_free(&sam_u->par_u);\n}',
                       '''static void
_mesa_exit_free(void* ptr_v)
{
  u3_mesa* sam_u = ptr_v;
  arena_free(&sam_u->par_u);
}

static void
_mesa_exit_cb(uv_handle_t* han_u) {
  u3_ssl_shutdown_retire(han_u->data, _mesa_exit_free);
}''')
        text = replace(text, '  _try_resend(req_u, req_u->nex_d);\n  _update_resend_timer(req_u);',
                       '''  if ( u3_ssl_shutdown_pending() ) {
    uv_close((uv_handle_t*)&req_u->tim_u, _mesa_del_request_cb);
    return;
  }
  _try_resend(req_u, req_u->nex_d);
  _update_resend_timer(req_u);''')
        text = replace(text, '  u3_mesa_resend_data* res_u = tim_u->data;\n  u3_mesa_request_data* dat_u',
                       '''  u3_mesa_resend_data* res_u = tim_u->data;
  if ( u3_ssl_shutdown_pending() ) {
    _mesa_free_resend_data(res_u);
    return;
  }
  u3_mesa_request_data* dat_u''')
        text = replace(text, '  uv_udp_recv_stop(&u3_Host.wax_u);',
                       '''  uv_udp_recv_stop(&u3_Host.wax_u);
  /* Close initialized request timers, including inactive ones. CTAG_WAIT's
   * independent resend timer reaches its normal close in the pending guard. */
  for ( req_map_itr itr_u = vt_first(&sam_u->req_u);
        !vt_is_end(itr_u); itr_u = vt_next(itr_u) ) {
    u3_pend_req* req_u = itr_u.data->val;
    if ( req_u && ((u3_pend_req*)CTAG_WAIT != req_u)
         && !uv_is_closing((uv_handle_t*)&req_u->tim_u) ) {
      uv_timer_stop(&req_u->tim_u);
      req_u->tim_u.data = req_u;
      uv_close((uv_handle_t*)&req_u->tim_u, _mesa_del_request_cb);
    }
  }''')
    if hashlib.sha256(text.encode()).hexdigest() != PINS['changed_source_sha256'][name]:
        raise ValueError('shutdown postimage mismatch: ' + name)
    return text


def transform_h2o(text):
    if hashlib.sha256(text.encode()).hexdigest() != 'd61916d7de924e2337b6a73dbcd044b525bf503b11affc53fd6f6c0ca90c37b2':
        raise ValueError('shutdown H2O hardened payload preimage mismatch')
    text = replace(text, '''static void setup_bio(h2o_socket_t *sock)
{
    static BIO_METHOD *bio_methods = NULL;
    static pthread_mutex_t init_lock = PTHREAD_MUTEX_INITIALIZER;
''', '''static BIO_METHOD *bio_methods = NULL;
static pthread_mutex_t init_lock = PTHREAD_MUTEX_INITIALIZER;

/* The embedding process invokes this only after every TLS socket is gone. */
void u3_h2o_openssl_shutdown(void)
{
    pthread_mutex_lock(&init_lock);
    BIO_meth_free(bio_methods);
    bio_methods = NULL;
    pthread_mutex_unlock(&init_lock);
}

static void setup_bio(h2o_socket_t *sock)
{
''')
    if hashlib.sha256(text.encode()).hexdigest() != PINS['h2o']['postimage']:
        raise ValueError('shutdown H2O postimage mismatch')
    return text


PAYLOADS = {
    'pkg/vere/openssl_shutdown.inc': 'runtime.inc',
    'pkg/vere/openssl_shutdown.h': 'openssl_shutdown.h',
    'pkg/vere/completion.h': 'completion.h',
}


def apply(root: Path, h2o_payload='h2o-socket.c') -> dict[str, str]:
    """Apply to a fresh caller-owned source/recipe staging tree. h2o_payload
    must be the source selected by that tree's existing H2O replacement graph,
    copied beneath root. Preflight before any write; not a hostile-filesystem
    race-proof or disk-failure-atomic multi-file writer.
    """
    root = Path(root).absolute()
    if root.resolve() != root or not root.is_dir():
        raise ValueError('shutdown requires regular non-symlink root')
    relative = Path(h2o_payload)
    if relative.is_absolute() or '..' in relative.parts or not relative.parts:
        raise ValueError('shutdown requires relative H2O payload inside source root')
    if relative.as_posix() in PINS['hardened_preimages'] or relative.as_posix() in PAYLOADS:
        raise ValueError('shutdown H2O payload collides with another target')
    outputs = {}
    for name in list(PINS['hardened_preimages']) + [relative.as_posix()]:
        target = root / name
        if target.resolve() != target or not target.is_file():
            raise ValueError('shutdown refuses symlink/nonregular input: ' + name)
        text = target.read_text()
        outputs[name] = (transform(name, text) if name in PINS['hardened_preimages']
                         else transform_h2o(text)).encode()
    for name, payload in PAYLOADS.items():
        target = root / name
        if target.resolve() != target or target.exists():
            raise ValueError('shutdown refuses existing/symlink payload destination: ' + name)
        outputs[name] = (HERE / payload).read_bytes()
        if hashlib.sha256(outputs[name]).hexdigest() != PINS['payload_sha256'][name]:
            raise ValueError('shutdown payload hash mismatch: ' + name)
    for name, data in outputs.items():
        (root / name).write_bytes(data)
    return {name: hashlib.sha256(data).hexdigest() for name, data in outputs.items()}
