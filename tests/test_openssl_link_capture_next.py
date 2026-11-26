"""File-only checks for a future Zig graph header export, not a build trace."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / 'tools/issue3_link_capture_next/header_capture.py'


def load():
    spec = importlib.util.spec_from_file_location('header_capture_next', MODULE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class HeaderCaptureTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.source = self.root / 'source'
        self.emitted = self.root / 'emitted'
        for p in (self.source / 'openssl', self.emitted / 'openssl'):
            p.mkdir(parents=True)
        for base in (self.source, self.emitted):
            (base / 'openssl/configuration.h').write_bytes(b'#define CFG 1\n')
            (base / 'openssl/opensslconf.h').write_bytes(b'#include "configuration.h"\n')
            (base / 'openssl/ignored.txt').write_bytes(b'not installed')
        self.graph = {
            'schema': 1,
            'modules': [{'id': 'vere', 'includes': [
                {'kind': 'path', 'path': '/zig/cache/A'},
                {'kind': 'other_step', 'path': str(self.emitted)},
                {'kind': 'other_step', 'path': str(self.emitted)}],
                'macros': ['-DUSE_OPENSSL=1', '-DUSE_OPENSSL=1'],
                'target': 'x86_64-linux-musl', 'c_flags': ['-fPIC']}],
            'registrations': [{'owner': 'openssl', 'kind': 'directory',
                'source': str(self.source), 'emitted': str(self.emitted),
                'dest': '', 'include_extensions': ['.h'], 'exclude_extensions': []}]
        }

    def capture(self):
        return load().capture(self.graph, self.root / 'retained')

    def test_copies_verified_headers_and_preserves_ordered_configuration(self):
        receipt = self.capture()
        self.assertEqual(receipt['modules'], self.graph['modules'])
        self.assertEqual([h['label'] for h in receipt['headers']],
                         ['openssl/configuration.h', 'openssl/opensslconf.h'])
        self.assertEqual((self.root / 'retained/headers/openssl/configuration.h').read_bytes(), b'#define CFG 1\n')
        self.assertFalse((self.root / 'retained/headers/openssl/ignored.txt').exists())
        self.assertEqual(json.loads((self.root / 'retained/headers.json').read_text()), receipt)

    def test_refuses_unnamespaced_installed_labels_before_output(self):
        for kind in ('file', 'directory'):
            with self.subTest(kind=kind):
                reg = self.graph['registrations'][0]
                reg.clear()
                if kind == 'file':
                    reg.update(owner='openssl', kind=kind,
                               source=str(self.source / 'openssl/configuration.h'),
                               emitted=str(self.emitted / 'openssl/configuration.h'),
                               dest='configuration.h')
                else:
                    reg.update(owner='openssl', kind=kind,
                               source=str(self.source / 'openssl'),
                               emitted=str(self.emitted / 'openssl'), dest='')
                output = self.root / ('reject-' + kind)
                with self.assertRaisesRegex(ValueError, 'noncanonical header label'):
                    load().capture(self.graph, output)
                self.assertFalse(output.exists())

    def test_refuses_aggregate_budget_before_output(self):
        module = load()
        setattr(module, 'MAX_HEADER_BYTES', 32)
        setattr(module, 'MAX_TOTAL_HEADER_BYTES', 32)
        for base in (self.source, self.emitted):
            for name in ('configuration.h', 'opensslconf.h'):
                (base / 'openssl' / name).write_bytes(b'x' * 24)
        with self.assertRaisesRegex(ValueError, 'aggregate header size limit'):
            module.capture(self.graph, self.root / 'retained')
        self.assertFalse((self.root / 'retained').exists())

    def test_bounds_actual_copies_after_preflight_growth(self):
        module = load()
        setattr(module, 'MAX_HEADER_BYTES', 8)
        setattr(module, 'MAX_TOTAL_HEADER_BYTES', 8)
        for base in (self.source, self.emitted):
            for name in ('configuration.h', 'opensslconf.h'):
                (base / 'openssl' / name).write_bytes(b'abc')
        output = self.root / 'retained'
        mkdir = Path.mkdir

        def grow_after_preflight(path, *args, **kwargs):
            result = mkdir(path, *args, **kwargs)
            if path == output:
                for base in (self.source, self.emitted):
                    (base / 'openssl/opensslconf.h').write_bytes(b'abcdef')
            return result

        with patch.object(Path, 'mkdir', grow_after_preflight):
            with self.assertRaisesRegex(ValueError, 'aggregate header size limit'):
                module.capture(self.graph, output)
        self.assertFalse((output / 'headers.json').exists())
        self.assertLessEqual(sum(p.stat().st_size for p in output.rglob('*') if p.is_file()), 8)
        self.assertEqual((output / 'headers/openssl/configuration.h').read_bytes(), b'abc')

    def test_refuses_noncanonical_labels_without_normalizing(self):
        labels = ('', 'openssl', 'openssl/', '/openssl/a.h', 'openssl//a.h',
                  'openssl/./a.h', 'openssl/../a.h', 'openssl/a.h/',
                  'openssl\\a.h', 'openssl/a\x00.h')
        reg = self.graph['registrations'][0]
        reg.clear()
        reg.update(owner='openssl', kind='file',
                   source=str(self.source / 'openssl/configuration.h'),
                   emitted=str(self.emitted / 'openssl/configuration.h'))
        for index, label in enumerate(labels):
            with self.subTest(label=repr(label)):
                reg['dest'] = label
                output = self.root / f'reject-{index}'
                with self.assertRaisesRegex(ValueError, 'noncanonical header label'):
                    load().capture(self.graph, output)
                self.assertFalse(output.exists())

    def test_directory_prefix_and_literal_nested_label_remain_supported(self):
        reg = self.graph['registrations'][0]
        reg.update(source=str(self.source / 'openssl'),
                   emitted=str(self.emitted / 'openssl'), dest='literal-e\u0301')
        receipt = self.capture()
        self.assertEqual([h['label'] for h in receipt['headers']],
                         ['literal-e\u0301/configuration.h', 'literal-e\u0301/opensslconf.h'])
        self.assertEqual(receipt['registrations'][0]['dest'], 'literal-e\u0301')

    def test_aggregate_boundary_including_empty_headers(self):
        for index, (size, budget, accepted) in enumerate(((4, 7, False), (4, 8, True),
                                                         (4, 9, True), (0, 0, True))):
            with self.subTest(size=size, budget=budget):
                module = load()
                setattr(module, 'MAX_HEADER_BYTES', 4)
                setattr(module, 'MAX_TOTAL_HEADER_BYTES', budget)
                for base in (self.source, self.emitted):
                    for name in ('configuration.h', 'opensslconf.h'):
                        (base / 'openssl' / name).write_bytes(b'x' * size)
                output = self.root / f'boundary-{index}'
                if accepted:
                    receipt = module.capture(self.graph, output)
                    self.assertEqual(sum(h['size'] for h in receipt['headers']), 2 * size)
                    self.assertTrue((output / 'headers.json').is_file())
                else:
                    with self.assertRaisesRegex(ValueError, 'aggregate header size limit'):
                        module.capture(self.graph, output)
                    self.assertFalse(output.exists())

    def test_bounded_copy_enforces_per_file_and_aggregate_edges(self):
        module = load()
        setattr(module, 'MAX_HEADER_BYTES', 4)
        source = self.root / 'copy-source'
        for index, (size, remaining, error) in enumerate(((4, 4, None), (5, 8, 'header size limit'),
                                                        (4, 3, 'aggregate header size limit'),
                                                        (0, 0, None))):
            with self.subTest(size=size, remaining=remaining):
                source.write_bytes(b'x' * size)
                target = self.root / f'copy-{index}'
                if error:
                    with self.assertRaisesRegex(ValueError, error):
                        module._copy_header(source, target, remaining)
                    self.assertLessEqual(target.stat().st_size, min(4, remaining))
                else:
                    self.assertEqual(module._copy_header(source, target, remaining), size)
                    self.assertEqual(target.read_bytes(), source.read_bytes())

    def test_preflight_per_file_bound_remains_independent(self):
        module = load()
        setattr(module, 'MAX_HEADER_BYTES', 8)
        setattr(module, 'MAX_TOTAL_HEADER_BYTES', 64)
        with self.assertRaisesRegex(ValueError, '^header size limit$'):
            module.capture(self.graph, self.root / 'retained')
        self.assertFalse((self.root / 'retained').exists())

    def test_alias_destinations_count_copied_bytes_not_unique_sources(self):
        source = self.source / 'openssl/configuration.h'
        emitted = self.emitted / 'openssl/configuration.h'
        self.graph['registrations'] = [dict(owner='openssl', kind='file',
            source=str(source), emitted=str(emitted), dest=label)
            for label in ('openssl/a.h', 'openssl/b.h')]
        module = load()
        setattr(module, 'MAX_TOTAL_HEADER_BYTES', source.stat().st_size)
        with self.assertRaisesRegex(ValueError, 'aggregate header size limit'):
            module.capture(self.graph, self.root / 'retained')
        self.assertFalse((self.root / 'retained').exists())

    def test_duplicate_and_portable_collision_refusal_before_output(self):
        for index, labels in enumerate((('openssl/a.h', 'openssl/a.h'),
                                        ('openssl/a.h', 'OpenSSL/A.h'),
                                        ('openssl/\u00e9.h', 'openssl/e\u0301.h'))):
            with self.subTest(labels=labels):
                self.graph['registrations'] = [dict(owner='openssl', kind='file',
                    source=str(self.source / 'openssl/configuration.h'),
                    emitted=str(self.emitted / 'openssl/configuration.h'), dest=label)
                    for label in labels]
                output = self.root / f'collision-{index}'
                with self.assertRaisesRegex(ValueError, 'colliding installed header'):
                    load().capture(self.graph, output)
                self.assertFalse(output.exists())

    def test_copy_and_late_mutation_never_issue_receipt(self):
        for index, late in enumerate((False, True)):
            with self.subTest(late=late):
                module = load()
                copy = module._copy_header
                output = self.root / f'mutation-{index}'
                def mutate(source, target, remaining):
                    size = copy(source, target, remaining)
                    if not late:
                        target.write_bytes(b'changed')
                    elif target.name == 'opensslconf.h':
                        (output / 'headers/openssl/configuration.h').write_bytes(b'changed')
                    return size
                with patch.object(module, '_copy_header', mutate):
                    with self.assertRaisesRegex(ValueError, 'late header mutation' if late else 'header changed during copy'):
                        module.capture(self.graph, output)
                self.assertFalse((output / 'headers.json').exists())

    def test_partial_io_failure_preserves_unreceipted_output_and_sibling(self):
        module = load()
        sibling = self.root / 'unrelated-evidence'
        sibling.write_bytes(b'keep')
        output = self.root / 'retained'
        def fail(source, target, remaining):
            target.write_bytes(b'partial')
            raise OSError('injected copy failure')
        with patch.object(module, '_copy_header', fail):
            with self.assertRaisesRegex(OSError, 'injected copy failure'):
                module.capture(self.graph, output)
        self.assertEqual((output / 'headers/openssl/configuration.h').read_bytes(), b'partial')
        self.assertFalse((output / 'headers.json').exists())
        self.assertEqual(sibling.read_bytes(), b'keep')
        with self.assertRaisesRegex(ValueError, 'fresh absolute output required'):
            module.capture(self.graph, output)

    def test_refuses_mismatched_emitted_copy_without_receipt(self):
        (self.emitted / 'openssl/configuration.h').write_bytes(b'wrong')
        with self.assertRaises(ValueError): self.capture()
        self.assertFalse((self.root / 'retained/headers.json').exists())

    def test_refuses_missing_emitted_header(self):
        (self.emitted / 'openssl/configuration.h').unlink()
        with self.assertRaises(ValueError): self.capture()
        self.assertFalse((self.root / 'retained/headers.json').exists())

    def test_refuses_extra_emitted_header(self):
        (self.emitted / 'openssl/extra.h').write_bytes(b'extra')
        with self.assertRaises(ValueError): self.capture()

    def test_refuses_symlinked_header_without_receipt(self):
        (self.source / 'openssl/configuration.h').unlink()
        (self.source / 'openssl/configuration.h').symlink_to('opensslconf.h')
        with self.assertRaises(ValueError): self.capture()
        self.assertFalse((self.root / 'retained/headers.json').exists())

    def test_refuses_duplicate_destination_with_distinct_source(self):
        other = self.root / 'other'
        (other / 'openssl').mkdir(parents=True)
        (other / 'openssl/configuration.h').write_bytes(b'changed')
        self.graph['registrations'].append({'owner': 'another', 'kind': 'file',
            'source': str(other / 'openssl/configuration.h'),
            'emitted': str(self.emitted / 'openssl/configuration.h'),
            'dest': 'openssl/configuration.h'})
        with self.assertRaises(ValueError): self.capture()

    def test_refuses_path_traversal_label(self):
        self.graph['registrations'][0]['dest'] = '../elsewhere'
        with self.assertRaises(ValueError): self.capture()
        self.assertFalse((self.root / 'elsewhere').exists())

    def test_refuses_missing_graph_binding(self):
        self.graph['modules'][0]['includes'] = []
        with self.assertRaises(ValueError): self.capture()
        self.assertFalse((self.root / 'retained/headers.json').exists())

    def test_refuses_unrecognized_graph_fields(self):
        self.graph['observed_preprocessor_access'] = True
        with self.assertRaises(ValueError): self.capture()

    def test_refuses_existing_destination(self):
        (self.root / 'retained').mkdir()
        with self.assertRaises(ValueError): self.capture()

    def test_default_h_filter_and_exclusion_take_precedence(self):
        reg = self.graph['registrations'][0]
        del reg['include_extensions']
        reg['exclude_extensions'] = ['opensslconf.h']
        receipt = self.capture()
        self.assertEqual([h['label'] for h in receipt['headers']], ['openssl/configuration.h'])

    def test_refuses_unsafe_source_ancestor(self):
        alias = self.root / 'alias'
        alias.symlink_to(self.source, target_is_directory=True)
        self.graph['registrations'][0]['source'] = str(alias)
        with self.assertRaises(ValueError): self.capture()

    def test_refuses_file_registration_not_under_consumer_include_tree(self):
        self.graph['registrations'] = [{'owner': 'openssl', 'kind': 'file',
            'source': str(self.source / 'openssl/configuration.h'),
            'emitted': str(self.emitted / 'openssl/configuration.h'),
            'dest': 'openssl/configuration.h'}]
        self.graph['modules'][0]['includes'] = [{'kind': 'path', 'path': '/unrelated/include'}]
        with self.assertRaises(ValueError): self.capture()
        self.assertFalse((self.root / 'retained').exists())

    def test_receipt_binds_registration_filters(self):
        self.graph['registrations'][0]['exclude_extensions'] = ['.txt']
        receipt = self.capture()
        self.assertEqual(receipt['registrations'], self.graph['registrations'])

    def test_emitted_subtree_may_be_within_consumer_include_root(self):
        self.graph['modules'][0]['includes'][1]['path'] = str(self.emitted.parent)
        receipt = self.capture()
        self.assertEqual(len(receipt['headers']), 2)


if __name__ == '__main__': unittest.main()
