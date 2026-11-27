"""Host fixture execution evidence, never a target/toolchain qualification."""
import importlib.util
import base64
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'tools/issue3_link_capture_next/execution_capture.py'


class ExecutionCapture(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='issue3-link-host-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.python = str(Path(sys.executable).resolve())
        self.script = self.root / 'fixture.py'
        self.script.write_text('''import json, pathlib, sys
r = pathlib.Path.cwd()
mode = sys.argv[1]
if mode == 'bad': sys.exit(7)
if mode == 'dep': (r/'dependency').write_bytes(b'compiled-fixture')
if mode == 'graph':
 assert (r/'dependency').read_bytes() == b'compiled-fixture'
 (r/'graph.json').write_text(json.dumps({'schema':1,'modules':[{'id':'fixture','includes':[],'macros':['X=1','X=1'],'target':'host-fixture','c_flags':[]}],'registrations':[]}))
if mode == 'link':
 assert pathlib.Path(sys.argv[2][1:]).read_bytes() == b'"a b.o"\\n'
 (r/'binary').write_bytes(b'host-output-not-ELF')
''')
        self.rsp = self.root / 'args.rsp'
        self.rsp.write_bytes(b'"a b.o"\n')

    def module(self):
        self.assertTrue(SOURCE.is_file(), 'capture implementation missing (scaffold RED)')
        spec = importlib.util.spec_from_file_location('capture_execution', SOURCE)
        assert spec is not None and spec.loader is not None
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod

    def run_capture(self, **changes):
        m = self.module()
        pins = {str(p): m.file_pin(p) for p in (Path(self.python), self.script)}
        args = dict(cwd=self.root, dependency=[self.python, str(self.script), 'dep'],
                    exporter=[self.python, str(self.script), 'graph'],
                    linker=[self.python, str(self.script), 'link', '@args.rsp'],
                    graph=self.root/'graph.json', binary=self.root/'binary',
                    output=self.root/'evidence', pins=pins)
        args.update(changes)
        return m, pins, m.capture_host_fixture(**args)

    def test_real_fixture_chain_records_response_and_graph(self):
        m, pins, result = self.run_capture()
        self.assertEqual(result['evidence_class'], 'observed-host-fixture')
        self.assertFalse(result['target_authenticated'])
        self.assertEqual([s['returncode'] for s in result['steps']], [0, 0, 0])
        self.assertTrue(all(s['pid'] > 0 for s in result['steps']))
        self.assertEqual((self.root/'evidence/response-0.bin').read_bytes(), self.rsp.read_bytes())
        verified = m.verify_host_fixture(self.root/'evidence', pins, m.file_pin(self.root/'evidence/receipt.json'))
        self.assertEqual(verified, result)

    def test_empty_graph_is_not_make_phase_evidence(self):
        self.script.write_text(self.script.read_text().replace("if mode == 'graph':", "if mode == 'graph':\n (r/'graph.json').write_text('{}')\n sys.exit(0)"))
        with self.assertRaisesRegex(ValueError, 'graph'):
            self.run_capture()
        self.assertFalse((self.root/'evidence/receipt.json').exists())

    def test_unpinned_script_refused_before_execution(self):
        m = self.module()
        with self.assertRaisesRegex(ValueError, 'pinned.*script'):
            self.run_capture(pins={self.python: m.file_pin(self.python)})
        self.assertFalse((self.root/'dependency').exists())

    def test_aggregate_capture_limit_refused(self):
        m = self.module()
        setattr(m, 'MAX_BYTES', 300)
        self.rsp.write_bytes(b'a' * 200)
        pins = {str(p): m.file_pin(p) for p in (Path(self.python), self.script)}
        with self.assertRaisesRegex(ValueError, 'aggregate'):
            m.capture_host_fixture(cwd=self.root,
                dependency=[self.python,str(self.script),'dep'],
                exporter=[self.python,str(self.script),'graph'],
                linker=[self.python,str(self.script),'link','@args.rsp'],
                graph=self.root/'graph.json', binary=self.root/'binary',
                output=self.root/'evidence', pins=pins)
        self.assertFalse((self.root/'binary').exists())

    def test_nested_response_refused_before_link(self):
        self.rsp.write_bytes(b'@another.rsp\n')
        with self.assertRaisesRegex(ValueError, 'nested'):
            self.run_capture()
        self.assertFalse((self.root/'binary').exists())

    def test_extra_retained_file_refused(self):
        m, pins, _ = self.run_capture()
        (self.root/'evidence/extra').write_bytes(b'not bound')
        with self.assertRaisesRegex(ValueError, 'inventory'):
            m.verify_host_fixture(self.root/'evidence', pins, m.file_pin(self.root/'evidence/receipt.json'))

    def test_symlinked_output_parent_refused(self):
        (self.root/'alias').symlink_to(self.root, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, 'nonlinked'):
            self.run_capture(output=self.root/'alias/evidence')
        self.assertFalse((self.root/'dependency').exists())

    def test_fixture_failure_never_issues_receipt(self):
        with self.assertRaisesRegex(ValueError, 'unsuccessful'):
            self.run_capture(dependency=[self.python, str(self.script), 'bad'])
        self.assertFalse((self.root/'evidence/receipt.json').exists())
        self.assertFalse((self.root/'graph.json').exists())

    def test_response_mutation_never_issues_receipt(self):
        self.script.write_text(self.script.read_text().replace("if mode == 'link':", "if mode == 'link':\n (r/'args.rsp').write_bytes(b'changed')\n sys.exit(0)"))
        with self.assertRaisesRegex(ValueError, 'response changed'):
            self.run_capture()
        self.assertFalse((self.root/'evidence/receipt.json').exists())

    def test_literal_non_utf8_argument_boundaries_survive(self):
        args = [os.fsencode(self.python), os.fsencode(str(self.script)), b'link',
                b'@args.rsp', b'a b', b'"quoted"', b'line\nfeed', b'\xff']
        _, _, result = self.run_capture(linker=args)
        self.assertEqual([base64.b64decode(x) for x in result['steps'][2]['argv_b64']], args)

    def test_retained_graph_corruption_before_receipt_refused(self):
        m = self.module()
        real_run = m.run
        def corrupting_run(argv, cwd):
            result = real_run(argv, cwd)
            if argv[2] == 'link':
                (self.root/'evidence/graph.json').write_bytes(b'{}')
            return result
        setattr(m, 'run', corrupting_run)
        pins = {str(p): m.file_pin(p) for p in (Path(self.python), self.script)}
        with self.assertRaisesRegex(ValueError, 'retained.*changed'):
            m.capture_host_fixture(cwd=self.root,
                dependency=[self.python,str(self.script),'dep'],
                exporter=[self.python,str(self.script),'graph'],
                linker=[self.python,str(self.script),'link','@args.rsp'],
                graph=self.root/'graph.json', binary=self.root/'binary',
                output=self.root/'evidence', pins=pins)
        self.assertFalse((self.root/'evidence/receipt.json').exists())

    def test_retained_response_corruption_refused_at_readback(self):
        m, pins, _ = self.run_capture()
        seal = m.file_pin(self.root/'evidence/receipt.json')
        (self.root/'evidence/response-0.bin').write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError, 'mismatch'):
            m.verify_host_fixture(self.root/'evidence', pins, seal)

    def test_wrong_out_of_band_seal_refused(self):
        m, pins, _ = self.run_capture()
        with self.assertRaisesRegex(ValueError, 'binding'):
            m.verify_host_fixture(self.root/'evidence', pins, {'sha256': '0'*64, 'bytes': 1})

    def test_boolean_schema_refused_even_with_sealed_receipt(self):
        m, pins, result = self.run_capture()
        result['schema'] = True
        path = self.root/'evidence/receipt.json'
        path.write_text(json.dumps(result))
        with self.assertRaisesRegex(ValueError, 'schema|class'):
            m.verify_host_fixture(self.root/'evidence', pins, m.file_pin(path))

    def test_deadline_reaps_owned_child_without_receipt(self):
        m = self.module()
        self.script.write_text(self.script.read_text().replace("if mode == 'dep':", "if mode == 'dep':\n import time\n time.sleep(10)\nif mode == 'dep':"))
        setattr(m, 'TIMEOUT', 0.05)
        pins = {str(p): m.file_pin(p) for p in (Path(self.python), self.script)}
        with self.assertRaisesRegex(ValueError, 'deadline'):
            m.capture_host_fixture(cwd=self.root,
                dependency=[self.python,str(self.script),'dep'],
                exporter=[self.python,str(self.script),'graph'],
                linker=[self.python,str(self.script),'link','@args.rsp'],
                graph=self.root/'graph.json', binary=self.root/'binary',
                output=self.root/'evidence', pins=pins)
        self.assertFalse((self.root/'evidence/receipt.json').exists())

    def test_no_cached_graph_allowed(self):
        (self.root/'graph.json').write_text('{}')
        with self.assertRaisesRegex(ValueError, 'fresh'):
            self.run_capture()
        self.assertFalse((self.root/'dependency').exists())

    def test_pin_mismatch_stops_before_output_creation(self):
        m = self.module()
        pins = {str(p): m.file_pin(p) for p in (Path(self.python), self.script)}
        self.script.write_text(self.script.read_text() + '\n# drift\n')
        with self.assertRaisesRegex(ValueError, 'pin mismatch'):
            self.run_capture(pins=pins)
        self.assertFalse((self.root/'evidence').exists())

    def test_target_claim_refused_even_with_sealed_receipt(self):
        m, pins, result = self.run_capture()
        result['target_authenticated'] = True
        path = self.root/'evidence/receipt.json'
        path.write_text(json.dumps(result))
        with self.assertRaisesRegex(ValueError, 'class'):
            m.verify_host_fixture(self.root/'evidence', pins, m.file_pin(path))

    def test_oversized_pin_refused_before_reading(self):
        m = self.module()
        setattr(m, 'MAX_PIN_BYTES', 1)
        with self.assertRaisesRegex(ValueError, 'pin byte limit'):
            m.file_pin(self.script)

    def test_verifier_aggregate_limit_refused(self):
        m, pins, _ = self.run_capture()
        output = self.root/'evidence'
        seal = m.file_pin(output/'receipt.json')
        setattr(m, 'MAX_BYTES', sum(p.stat().st_size for p in output.iterdir()) - 1)
        with self.assertRaisesRegex(ValueError, 'aggregate'):
            m.verify_host_fixture(output, pins, seal)


if __name__ == '__main__':
    unittest.main()
