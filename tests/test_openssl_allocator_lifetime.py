"""Extracted host probes for the isolated, blocked original-allocator candidate."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import tarfile
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / 'tools/issue3_allocator_lifetime'
ARCHIVE = Path(os.environ.get(
    'ISSUE3_ALLOCATOR_LIFETIME_ARCHIVE',
    ROOT / 'build_issue3_amd64_curl_build_02/artifact/source-materials.tar.gz',
)).resolve()
SCRATCH = Path(os.environ.get('TMPDIR', tempfile.gettempdir())).resolve()
PREFIX = 'vere-8ddc4b786979574dbfcb655e3db1b634f658d0de/'
MANAGE = 'pkg/noun/manage.c'
MANAGE_SHA = '2b06d6a006595ea7440690b325e8c994505a6040a97087e877a19c5e0c46d321'


def archived_sources():
    if not ARCHIVE.is_file():
        raise unittest.SkipTest(
            'requires pinned public vere source archive; set ISSUE3_ALLOCATOR_LIFETIME_ARCHIVE'
        )
    pins = json.loads((TOOLS / 'sources.json').read_text())
    assert pins['archive_sha256'] == '8ed4fc8a6b4c1acba3e4e89860a4059e490feb3efaf2a818805770f24f65654f'
    digest = hashlib.sha256()
    with ARCHIVE.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    assert digest.hexdigest() == pins['archive_sha256']
    with tarfile.open(ARCHIVE) as archive:
        metadata = archive.getmembers()
        selected = {}
        # Validate every selected header before any selected member content read.
        for name, pin in pins['public_members'].items():
            members = [m for m in metadata if m.name == PREFIX + name]
            assert len(members) == 1 and members[0].isreg() and members[0].size == pin['bytes'], name
            selected[name] = members[0]
        sources = {}
        for name, member in selected.items():
            stream = archive.extractfile(member)
            assert stream is not None
            with stream:
                data = stream.read(member.size + 1)
            assert len(data) == member.size
            assert hashlib.sha256(data).hexdigest() == pins['public_members'][name]['sha256'], name
            sources[name] = data
    return sources


def archived_manage():
    data = archived_sources()[MANAGE]
    assert hashlib.sha256(data).hexdigest() == MANAGE_SHA
    return data


def overlay():
    path = TOOLS / 'overlay.py'
    assert path.is_file(), 'missing isolated source overlay (scaffold RED only)'
    spec = importlib.util.spec_from_file_location('allocator_lifetime', path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def function(source, name):
    """Return exact pinned function bytes, excluding surrounding declarations."""
    match = re.search(rb'(?m)^(?:static )?(?:void\*?|int|c3_o|c3_d|u3_noun)\s+'
                      + name.encode() + rb'\([^;]*?\)\s*\{', source)
    assert match, name
    end, depth = match.end(), 1
    while depth:
        depth += (source[end] == ord('{')) - (source[end] == ord('}'))
        end += 1
    return source[match.start():end].decode()


class ShutdownOrderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.original = archived_manage()

    def setUp(self):
        self.owned = tempfile.TemporaryDirectory(prefix='issue3-allocator-lifetime-', dir=SCRATCH)
        self.addCleanup(self.owned.cleanup)
        self.directory = Path(self.owned.name)

    def compile_run(self, source, argument=None):
        path = self.directory / 'probe.c'
        binary = self.directory / 'probe'
        path.write_text(source)
        result = subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror',
                                 '-Wno-unused-parameter', str(path), '-o', str(binary)],
                                capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        return subprocess.run([str(binary)] + ([] if argument is None else [argument]),
                              capture_output=True, text=True, timeout=5)

    def selected(self):
        control = os.environ.get('ISSUE3_ALLOCATOR_LIFETIME_CONTROL')
        if control == 'archived':
            return self.original
        if control is not None:
            raise ValueError('unknown allocator lifetime control')
        return overlay().transform_manage(self.original)

    def run_lifecycle(self, mode):
        source = self.selected()
        names = ('_cm_malloc_ssl', '_cm_realloc_ssl', '_cm_free_ssl', '_cm_crypto', 'u3m_stop')
        (self.directory / 'extracted.h').write_text('\n'.join(function(source, n) for n in names))
        binary = self.directory / 'lifecycle'
        result = subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror',
                                 '-Wno-unused-parameter', '-I', str(self.directory),
                                 str(TOOLS / 'lifecycle_probe.c'), '-o', str(binary)],
                                capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        return subprocess.run([str(binary), mode], capture_output=True, text=True, timeout=5)

    def test_one_shot_stop_and_initialization_refusals(self):
        for mode, status, message in (
                ('repeat-stop', 0, 'one-shot-cleanup-and-storage-stop\n'),
                ('repeat-init', 71, 'refused-before-reinit\n'),
                ('restart', 71, 'refused-before-reinit\n'),
                ('cold-stop', 0, 'cold-stop-noop\n'),
                ('registration-failure', 71, 'refused-before-reinit\n')):
            with self.subTest(mode=mode):
                result = self.run_lifecycle(mode)
                self.assertEqual(result.returncode, status, result.stdout + result.stderr)
                self.assertEqual(result.stdout, message)
                self.assertEqual(result.stderr, '')

    def test_live_consumer_counterexample_is_not_mistaken_for_retention_safety(self):
        # The extracted ordering change still tears down a live modeled user.
        # This is an expected negative counterexample, NOT a lifetime PASS.
        result = self.run_lifecycle('live-consumer')
        self.assertEqual(result.returncode, 84, result.stdout + result.stderr)
        self.assertEqual(result.stdout, 'unsafe-live-consumer\n')

    def test_full_translation_unit_refuses_unqualified_lifetime_candidate(self):
        source = self.selected()
        prefix = source.split(b'#include "manage.h"', 1)[0]
        result = subprocess.run(['cc', '-E', '-x', 'c', '-'], input=prefix,
                                capture_output=True, timeout=10)
        self.assertNotEqual(result.returncode, 0, 'unsafe candidate remains compilable')
        self.assertIn(b'ORIGINAL_VERE_ALLOCATOR_BLOCKED', result.stderr)

    def test_original_hooks_are_registered_and_forward_ordinary_allocations(self):
        source = self.selected()
        bodies = '\n'.join(function(source, name) for name in
                           ('_cm_malloc_ssl', '_cm_realloc_ssl', '_cm_free_ssl', '_cm_crypto'))
        result = self.compile_run('''
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define OPENSSL_VERSION_NUMBER 0x30500090L
static unsigned _cm_ssl_state;
static int registrations, allocations, resizes, frees, secp_inits;
void* u3a_malloc(size_t n) { ++allocations; return malloc(n); }
void* u3a_realloc(void* p, size_t n) { ++resizes; return realloc(p, n); }
void u3a_free(void* p) { ++frees; free(p); }
void u3je_secp_init(void) { ++secp_inits; }
void u3l_log(const char* format, const char* message) { (void)format; (void)message; }
static void* (*mem_malloc)(size_t, const char*, int);
static void* (*mem_realloc)(void*, size_t, const char*, int);
static void (*mem_free)(void*, const char*, int);
int CRYPTO_set_mem_functions(void* (*m)(size_t, const char*, int),
                             void* (*r)(void*, size_t, const char*, int),
                             void (*f)(void*, const char*, int)) {
  ++registrations; mem_malloc=m; mem_realloc=r; mem_free=f; return 1;
}
''' + bodies + '''
int main(void) {
  _cm_crypto();
  if (registrations != 1 || secp_inits != 1) return 72;
  if (mem_malloc != _cm_malloc_ssl || mem_realloc != _cm_realloc_ssl || mem_free != _cm_free_ssl) return 73;
  char* p = mem_malloc(19, __FILE__, __LINE__);
  memset(p, 0x34, 19);
  p = mem_realloc(p, 113, __FILE__, __LINE__);
  for (int i=0; i<19; ++i) if (p[i] != 0x34) return 74;
  mem_free(p, __FILE__, __LINE__);
  if (allocations != 1 || resizes != 1 || frees != 1) return 75;
  puts("original-hooks-and-ordinary-frees");
  return 0;
}
''')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout, 'original-hooks-and-ordinary-frees\n')

    def test_cleanup_precedes_storage_stop_boundary(self):
        source = self.selected()
        body = function(source, 'u3m_stop')
        result = self.compile_run('''
#include <stdio.h>
#include <stdlib.h>
#define OPENSSL_VERSION_NUMBER 0x30500090L
static unsigned _cm_ssl_state = 1;
static int storage_live = 1, cleanup_count;
void u3t_sstack_exit(void) {}
void u3je_secp_stop(void) {}
void OPENSSL_cleanup(void) {
  if (!storage_live) exit(62);
  ++cleanup_count;
}
void u3e_stop(void) {
  /* Hypothetical invalidation oracle, not actual Vere page behavior. */
  if (cleanup_count != 1) exit(61);
  storage_live = 0;
}
''' + body + '''
int main(void) {
  (void)_cm_ssl_state;
  u3m_stop();
  if (cleanup_count != 1 || storage_live) return 63;
  puts("cleanup-before-storage-stop");
  return 0;
}
''')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout, 'cleanup-before-storage-stop\n')


class CallerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        owned = tempfile.TemporaryDirectory(prefix='issue3-allocator-callers-', dir=SCRATCH)
        cls.addClassCleanup(owned.cleanup)
        cls.directory = Path(owned.name)
        cls.sources = archived_sources()
        original = cls.sources[MANAGE]
        control = os.environ.get('ISSUE3_ALLOCATOR_LIFETIME_CONTROL')
        if control not in (None, 'archived'):
            raise ValueError('unknown allocator lifetime control')
        data = original if control else overlay().transform_manage(original)
        names = ('_cm_malloc_ssl', '_cm_realloc_ssl', '_cm_free_ssl', '_cm_crypto', 'u3m_stop')
        (cls.directory / 'extracted.h').write_text('\n'.join(function(data, n) for n in names))
        (cls.directory / 'callers.h').write_text(
            function(cls.sources['pkg/vere/mars.c'], '_mars_flush') + '\n' +
            function(cls.sources['pkg/vere/king.c'], 'u3_king_done'))
        cls.binary = cls.directory / 'caller-probe'
        result = subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror',
                                 '-Wno-unused-parameter', '-I', str(cls.directory),
                                 str(TOOLS / 'callers_probe.c'), '-o', str(cls.binary)],
                                capture_output=True, text=True, timeout=30)
        assert result.returncode == 0, result.stderr

    def run_probe(self, mode):
        return subprocess.run([str(self.binary), mode], capture_output=True, text=True, timeout=5)

    def test_actual_mars_flush_reaches_cleanup_before_storage_stop(self):
        result = self.run_probe('mars')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout, 'mars:cleanup-before-storage-stop\n')

    def test_actual_king_done_does_not_supply_a_close_completion_barrier(self):
        # A documented negative result: cleanup can happen with a queued close.
        # This is not a proof the queued handle uses OpenSSL, nor a TLS teardown PASS.
        result = self.run_probe('king')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout, 'king:close-queued-without-drain-barrier\n')

    def test_actual_king_done_with_a_modeled_live_user_is_unsafe(self):
        result = self.run_probe('king-live')
        self.assertEqual(result.returncode, 84, result.stdout + result.stderr)
        self.assertEqual(result.stdout, 'unsafe-live-consumer\n')

    def test_all_ten_existing_utility_stop_sites_share_the_central_stop(self):
        utilities = ('_cw_info', '_cw_grab', '_cw_cram', '_cw_queu', '_cw_meld',
                     '_cw_melt', '_cw_pack', '_cw_play', '_cw_chop', '_cw_roll')
        source = self.sources['pkg/vere/main.c']
        self.assertEqual(source.count(b'u3m_stop();'), len(utilities))
        for name in utilities:
            with self.subTest(utility=name):
                self.assertEqual(function(source, name).count('u3m_stop();'), 1)
        self.assertEqual(self.sources['pkg/vere/mars.c'].count(b'u3m_stop();'), 1)
        self.assertEqual(self.sources['pkg/vere/king.c'].count(b'u3m_stop();'), 1)


class ApplyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.original = archived_manage()
        cls.mod = overlay()

    def setUp(self):
        owned = tempfile.TemporaryDirectory(prefix='issue3-allocator-apply-', dir=SCRATCH)
        self.addCleanup(owned.cleanup)
        self.directory = Path(owned.name)
        self.root = self.directory / 'candidate'
        self.target = self.root / MANAGE
        self.target.parent.mkdir(parents=True)
        self.target.write_bytes(self.original)
        self.sentinel = self.root / 'preserved-unrelated-source'
        self.sentinel.write_bytes(b'curl/TLS/SHA/CA/H2O/cttp/GMP unchanged\n')

    def test_apply_rejects_symlink_root_parent_or_target_before_write(self):
        for level in ('root', 'parent', 'target'):
            with self.subTest(level=level):
                base = self.directory / level
                real = base / 'real'
                target = real / MANAGE
                target.parent.mkdir(parents=True)
                target.write_bytes(self.original)
                alias = base / 'alias'
                if level == 'root':
                    alias.symlink_to(real, target_is_directory=True)
                elif level == 'parent':
                    (alias / 'pkg').mkdir(parents=True)
                    (alias / 'pkg/noun').symlink_to(target.parent, target_is_directory=True)
                else:
                    (alias / MANAGE).parent.mkdir(parents=True)
                    (alias / MANAGE).symlink_to(target)
                with self.assertRaisesRegex(ValueError, 'symlink'):
                    self.mod.apply(alias)
                self.assertEqual(target.read_bytes(), self.original)

    def test_source_drift_upstream_and_replay_refuse_before_write(self):
        upstream = self.original.replace(
            b'  /* OpenSSL 3 retains TLS/provider state beyond temporary road lifetimes.\n'
            b'   * Keep its default process-lifetime allocator; do not change GMP here. */\n'
            b'#if !defined(U3_URTH_MASS) && OPENSSL_VERSION_NUMBER < 0x30000000L',
            b'  /* Initialize OpenSSL with loom allocation functions. */\n#ifndef U3_URTH_MASS', 1)
        self.assertEqual(hashlib.sha256(upstream).hexdigest(),
                         '25eaa5384e190067d19a4a731d120efb8174367bb02296e4b2b2d8b53f90fa68')
        result = self.mod.transform_manage(self.original)
        for data in (self.original + b'!', b'!' + self.original[1:], upstream, result):
            with self.subTest(sha256=hashlib.sha256(data).hexdigest()):
                self.target.write_bytes(data)
                with self.assertRaisesRegex(ValueError, 'preimage'):
                    self.mod.apply(self.root)
                self.assertEqual(self.target.read_bytes(), data)

    def test_postimage_and_context_mutations_refuse_before_write(self):
        with mock.patch.object(self.mod, 'POSTIMAGE', '0' * 64):
            with self.assertRaisesRegex(ValueError, 'postimage'):
                self.mod.apply(self.root)
        with mock.patch.object(self.mod, 'DELTAS', ((b'missing context', b'unreviewed replacement'),)):
            with self.assertRaisesRegex(ValueError, 'context'):
                self.mod.apply(self.root)
        self.assertEqual(self.target.read_bytes(), self.original)

    def test_only_reviewed_registration_state_stop_and_refusal_bytes_change(self):
        result = self.mod.transform_manage(self.original)
        before, after = self.original, result
        for name in ('_cm_malloc_ssl', '_cm_realloc_ssl', '_cm_free_ssl', '_cm_realloc2',
                     '_cm_free2', 'u3m_init', 'u3m_fall', 'u3m_love', 'u3m_flog'):
            self.assertEqual(function(before, name), function(after, name), name)
        self.assertIn(b'mp_set_memory_functions(u3a_malloc, _cm_realloc2, _cm_free2);', after)
        for name in ('_cm_crypto', 'u3m_stop'):
            before = before.replace(function(before, name).encode(), b'', 1)
            after = after.replace(function(after, name).encode(), b'', 1)
        after = after.replace(self.mod.BLOCKED + b'\n', b'', 1)
        added_state = (
            b'/* One terminal OpenSSL lifecycle per process, on the owning thread.\n'
            b' * 0: cold, 1: registered, 2: stopping/stopped (never reinitialize). */\n'
            b'#if OPENSSL_VERSION_NUMBER >= 0x30000000L\n'
            b'static unsigned _cm_ssl_state;\n'
            b'#endif\n\n')
        self.assertEqual(after.count(added_state), 1)
        after = after.replace(added_state, b'', 1)
        self.assertEqual(after, before)
        pins = json.loads((TOOLS / 'sources.json').read_text())
        self.assertEqual(pins['changed_source_preimages'], {MANAGE: self.mod.PREIMAGE})
        self.assertEqual(pins['changed_source_sha256'], {MANAGE: self.mod.POSTIMAGE})

    def test_apply_preserves_actual_current_ca_and_curl_hardening(self):
        sources = archived_sources()
        path = ROOT / 'build/vere-openssl3/candidate.py'
        spec = importlib.util.spec_from_file_location('lifetime_existing_recipe', path)
        assert spec is not None and spec.loader is not None
        recipe = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(recipe)
        main = recipe.patch_ca_source('pkg/vere/main.c', sources['pkg/vere/main.c'].decode()).encode()
        upstream_king = sources['pkg/vere/king.c'].replace(
            b'curl_easy_setopt(cul_u, CURLOPT_SERVER_RESPONSE_TIMEOUT, 30L);',
            b'curl_easy_setopt(cul_u, CURLOPT_SERVER_RESPONSE_TIMEOUT, 30);', 1)
        self.assertEqual(hashlib.sha256(upstream_king).hexdigest(),
                         '49d175e108cfd77e531d3346b9449680cab7e3ba4a8885c66d806af5ed969801')
        king = recipe.patch_curl_buffer(upstream_king.decode()).encode()
        lock = json.loads((ROOT / 'build/vere-openssl3/inputs.json').read_text())
        self.assertEqual(hashlib.sha256(main).hexdigest(), lock['ca_hardening']['pkg/vere/main.c'])
        self.assertEqual(hashlib.sha256(king).hexdigest(), lock['curl_buffer_sha256'])
        unchanged = {'pkg/vere/main.c': main, 'pkg/vere/king.c': king,
                     'pkg/vere/mars.c': sources['pkg/vere/mars.c']}
        for name, data in unchanged.items():
            target = self.root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
        self.mod.apply(self.root)
        for name, data in unchanged.items():
            self.assertEqual((self.root / name).read_bytes(), data, name)

    def test_apply_returns_actual_changed_source_mapping_and_preserves_siblings(self):
        self.assertTrue(hasattr(self.mod, 'apply'), 'missing apply API (scaffold RED)')
        changes = self.mod.apply(self.root)
        self.assertEqual(changes, {MANAGE: hashlib.sha256(self.target.read_bytes()).hexdigest()})
        self.assertEqual(changes, {MANAGE: self.mod.POSTIMAGE})
        self.assertEqual(self.sentinel.read_bytes(), b'curl/TLS/SHA/CA/H2O/cttp/GMP unchanged\n')
        self.assertEqual(sorted(str(p.relative_to(self.root)) for p in self.root.rglob('*') if p.is_file()),
                         [MANAGE, 'preserved-unrelated-source'])


if __name__ == '__main__':
    unittest.main()
