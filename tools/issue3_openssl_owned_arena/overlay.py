"""Reproducible, hash-bound adaptation of selected pinned Vere palloc bodies.
Does not modify any checkout's production allocator or global road pointers.
"""
import hashlib
import json
from pathlib import Path
import re

HERE = Path(__file__).resolve().parent
NAMES = ('_init_once', '_abs_dif', '_alloc_pages', '_make_chunks',
         '_alloc_words', '_imalloc', '_pages_size', '_free_pages',
         '_free_words', '_ifree', '_irealloc')


def function(source, name):
    match = re.search(r'(?m)^static (?:__inline__ |inline )?(?:void|u3_post|c3_w)\n'
                      + re.escape(name) + r'\([^;]*?\)\s*(?://[^\n]*)?\n?\{', source)
    if not match:
        raise ValueError('missing exact function: ' + name)
    end, depth = match.end(), 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[match.start():end]


def once(source, old, new):
    if source.count(old) != 1:
        raise ValueError('changed context: ' + old)
    return source.replace(old, new)


def render():
    pins = json.loads((HERE / 'sources.json').read_text())
    source = (HERE / 'palloc.c.pinned').read_bytes()
    assert hashlib.sha256(source).hexdigest() == pins['public_members']['pkg/noun/palloc.c']['sha256']
    source = source.decode()
    bodies = {name: function(source, name) for name in NAMES}
    bodies['_alloc_pages'] = once(bodies['_alloc_pages'],
        'pag_p = _extend_heap(siz_w);',
        'pag_p = _extend_heap(siz_w);\n    if ( !pag_p ) return 0;')
    bodies['_make_chunks'] = once(bodies['_make_chunks'],
        'c3_w    pag_w = post_to_page(pag_p);',
        'c3_w    pag_w;\n  if ( !pag_p ) return 0;\n  pag_w = post_to_page(pag_p);')
    bodies['_make_chunks'] = once(bodies['_make_chunks'],
        'hun_p = _imalloc(hun_u->siz_s);',
        'hun_p = _imalloc(hun_u->siz_s);\n    if ( !hun_p ) { _ifree(pag_p); return 0; }')
    bodies['_alloc_words'] = once(bodies['_alloc_words'],
        'pag_u = u3to(u3a_crag, _make_chunks(bit_g));',
        'u3_post new_p = _make_chunks(bit_g);\n    if ( !new_p ) return 0;\n    pag_u = u3to(u3a_crag, new_p);')
    bodies['_free_pages'] = once(bodies['_free_pages'],
        'fre_p = _imalloc(c3_wiseof(*cac_u));', 'fre_p = owner_dell_take();')
    bodies['_free_words'] = once(bodies['_free_words'],
        'if ( &(u3H->rod_u) == u3R )', 'if ( 1 ) /* independent arena: stable home-style ordering */')
    bodies['_free_words'] = once(bodies['_free_words'],
        '_free_words(u3_post som_p, c3_w pag_w, u3_post dir_p)\n{',
        '_free_words(u3_post som_p, c3_w pag_w, u3_post dir_p)\n{\n  (void)pag_w;')
    bodies['_ifree'] = once(bodies['_ifree'], '_ifree(u3_post som_p)\n{\n',
        '_ifree(u3_post som_p)\n{\n  if ( owner_dell_release(som_p) ) return;\n')
    bodies['_irealloc'] = once(bodies['_irealloc'],
        'u3_post new_p = _imalloc(len_w);',
        'u3_post new_p = _imalloc(len_w);\n    if ( !new_p ) return 0;')
    bodies['_alloc_pages'] = once(bodies['_alloc_pages'],
        '  return pag_p;', '  owner_charge_pages(siz_w);\n  return pag_p;')
    bodies['_free_pages'] = once(bodies['_free_pages'],
        '  //  XX groace', '  owner_release_pages(siz_w);\n\n  //  XX groace')
    # These occurrences are heap cursors, not a switched or hidden global u3R.
    for name in bodies:
        bodies[name] = bodies[name].replace('u3R->hat_p', 'owner.hat_p')
        assert 'u3R' not in bodies[name] and 'u3H' not in bodies[name]
    return ('/* Generated from SHA256 ' + pins['public_members']['pkg/noun/palloc.c']['sha256']
            + '; regenerate with overlay.py. No GC/checkpoint/pack code included. */\n'
            + '\n\n'.join(bodies[n] for n in NAMES) + '\n')


if __name__ == '__main__':
    (HERE / 'palloc_engine.inc').write_text(render())
