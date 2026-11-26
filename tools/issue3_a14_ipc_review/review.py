"""Source-only A14 IPC/persistence review; no target libraries/runtime calls."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tarfile

TOOLS = Path(__file__).resolve().parent
PROBES = {
    'persistence': [('pkg/vere/db/lmdb.c', ['u3_lmdb_save']),
                    ('pkg/vere/mars.c', ['_mars_flush', '_mars_disk_cb']),
                    ('pkg/vere/disk.c', ['_disk_commit_cb', '_disk_commit_done'])],
    'supervision': [('pkg/vere/lord.c', ['u3_lord_halt', '_lord_bail', '_lord_on_serf_exit'])],
    'framing': [('pkg/vere/newt.c', ['_newt_mess_head', '_newt_mess_tail', '_newt_meat_plan',
                                  '_newt_meat_poke', '_newt_meat_next_cb', 'u3_newt_decode',
                                  '_newt_read_cb', 'u3_newt_moat_stop'])],
    'signals': [('pkg/noun/manage.c', ['_cm_signal_handle_term', '_cm_signal_handle_intr',
                                     '_cm_signal_handle_alrm'])],
}


def load_sources(root):
    manifest = json.loads((TOOLS / 'sources.json').read_text())
    archive = root / manifest['archive']
    digest = hashlib.sha256()
    with archive.open('rb') as archive_bytes:
        for chunk in iter(lambda: archive_bytes.read(1024 * 1024), b''):
            digest.update(chunk)
    if digest.hexdigest() != manifest['archive_sha256']:
        raise ValueError('archive hash drift')
    result = {}
    with tarfile.open(archive) as stream:
        metadata = stream.getmembers()  # Inspect metadata before selected contents.
        selected = {}
        for name, pin in manifest['members'].items():
            matches = [m for m in metadata if m.name == pin['member']]
            if (len(matches) != 1 or not matches[0].isreg()
                    or matches[0].size != pin['bytes'] or not 0 < pin['bytes'] <= 400000):
                raise ValueError('duplicate/nonregular/size-drift member: ' + name)
            selected[name] = matches[0]
        for name, pin in manifest['members'].items():
            reader = stream.extractfile(selected[name])
            if reader is None:
                raise ValueError('unreadable member: ' + name)
            data = reader.read(pin['bytes'] + 1)
            if len(data) != pin['bytes'] or hashlib.sha256(data).hexdigest() != pin['sha256']:
                raise ValueError('member hash drift: ' + name)
            result[name] = data.decode()
    return result


def function(text, name):
    # Blank comments/strings at identical offsets before counting C braces.
    stripped = re.sub(r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'',
                      lambda m: ' ' * len(m.group()), text, flags=re.S)
    match = re.search(r'(?m)^(?:static\s+)?(?:void|c3_o)\s+\n?' + re.escape(name) + r'\([^;]*?\)\s*\{', stripped)
    if match is None:
        raise ValueError('function missing: ' + name)
    end = stripped.index('{', match.start()) + 1
    depth = 1
    while depth:
        depth += (stripped[end] == '{') - (stripped[end] == '}')
        end += 1
    return text[match.start():end]


def build_probe(sources, kind, directory):
    bodies = '\n'.join(function(sources[name], fun) for name, names in PROBES[kind] for fun in names)
    # Negative controls alter extracted bytes ONLY, never the archive or recipe.
    control = os.environ.get('ISSUE3_A14_IPC_CONTROL', '')
    if kind == 'persistence' and control == 'early-ack':
        before = '|| (gif_u->eve_d <= mar_u->log_u->dun_d)'
        assert bodies.count(before) == 1
        bodies = bodies.replace(before, '|| 1')
    if kind == 'persistence' and control == 'failed-commit-advances':
        before = 'if ( c3y == ret_o ) {\n    log_u->dun_d += len_w;'
        assert bodies.count(before) == 1
        bodies = bodies.replace(before, 'if ( 1 ) {\n    log_u->dun_d += len_w;')
    (directory / (kind + '-bodies.h')).write_text(bodies)
    binary = directory / kind
    result = subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror',
                             '-Wno-unused-parameter', '-Wno-unused-variable',
                             '-I', str(directory), str(TOOLS / (kind + '.c')), '-o', str(binary)],
                            capture_output=True, text=True, timeout=30, cwd=directory,
                            env=dict(os.environ, TMPDIR=str(directory)))
    if result.returncode:
        raise AssertionError(result.stderr)
    return binary


def check_source_contracts(s):
    def ordered(text, *tokens):
        pos = -1
        for token in tokens:
            pos = text.index(token, pos + 1)
    ordered(s['pkg/vere/mars.c'], 'u3_disk_plan(mar_u->log_u, &tac_u);',
            'gif_u->sat_e = u3_gift_fact_e;', 'gif_u->eve_d = mar_u->dun_d;')
    ordered(s['pkg/vere/pier.c'], 'u3_auto_done(egg_u);', 'u3_auto_kick(pir_u->wok_u->car_u, act);')
    ordered(s['pkg/vere/main.c'][s['pkg/vere/main.c'].index('_cw_work(c3_i argc'):],
            'u3_mars_load(&mar_u, u3_dlod_last);', 'u3_mars_play(&mar_u, eve_d, 0);',
            'u3_mars_work(&mar_u);', 'inn_u.bal_f = _cw_io_fail;')
    assert 'exit(1);' in function(s['pkg/vere/main.c'], '_cw_io_fail')
    ordered(s['pkg/vere/mars.c'], 'mar_u->dun_d + 1, bat_w', '_mars_poke_play(mar_u, &tac_u)')
    assert 'tac_u->mug_l != (mug_l = u3r_mug(cor))' in s['pkg/vere/mars.c']
    assert 'u3o_soft_mugs' in s['pkg/vere/mars.c']  # Not an unconditional mug guarantee.
    assert 'snapshot (%' in s['pkg/vere/disk.c']
    assert 'stale snapshot, downgrade runtime to replay' in s['pkg/vere/disk.c']
    ordered(s['pkg/noun/events.c'][s['pkg/noun/events.c'].index('void\nu3e_save'):],
            '_ce_patch_sync(pat_u);', '_ce_patch_apply(pat_u);', '_ce_image_sync(&u3P.img_u)',
            '_ce_patch_delete();')
    assert 'MAP_FIXED | MAP_PRIVATE' in s['pkg/noun/events.c']
    assert 'u3P.eph_i, _ce_len(pag_w)' in s['pkg/noun/events.c']
    assert 'c3_w ops_w = 0;' in s['pkg/vere/db/lmdb.c']
    assert 'MDB_NOSYNC' not in s['pkg/vere/db/lmdb.c']
    assert 'MDB_NOMETASYNC' not in s['pkg/vere/db/lmdb.c']
    assert 'god_u->ops_u.exit_cb = _lord_on_serf_exit;' in s['pkg/vere/lord.c']
    assert 'u3_lord_init' not in function(s['pkg/vere/lord.c'], '_lord_on_serf_exit')
    assert 'u3_Host.xit_i = 1;' in function(s['pkg/vere/pier.c'], 'u3_pier_bail')
    assert 'exit(u3_Host.xit_i);' in function(s['pkg/vere/king.c'], 'u3_king_done')
    assert 'u3m_soft(0, u3ke_cue' in s['pkg/vere/king.c']
    assert 'u3C.sign_hold_f = _king_sign_hold;' in s['pkg/vere/king.c']
