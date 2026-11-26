"""Host-only successor tests. No Docker, compiler or ship subprocesses."""
import importlib.util
import json
import os
from pathlib import Path
import runpy
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'tools/issue3_fresh_attempt/prepare.py'


class PreparationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='issue3-fresh-test-', dir=os.environ['TMPDIR'])
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def load(self):
        self.assertTrue(SOURCE.is_file(), 'fresh preparation implementation absent (scaffold RED)')
        spec = importlib.util.spec_from_file_location('fresh_prepare', SOURCE)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_unbound_generation_refuses_before_any_subprocess(self):
        m = self.load()
        out = self.root / 'successor'
        m.prepare(ROOT, out)
        self.assertFalse(list(out.rglob('*authorization*')))
        self.assertFalse(list(out.rglob('spent.json')))
        for stage, script in [('build', 'run_build.py'), ('report', 'run_report.py'),
                              ('package', 'run_build.py'), ('lifecycle', 'run_lifecycle.py')]:
            with self.subTest(stage=stage):
                with patch.dict(sys.modules), patch.object(sys, 'path', [str(out/stage), *sys.path]):
                    sys.modules.pop('gate', None)
                    with patch('subprocess.Popen') as popen, patch('subprocess.run') as run, patch('subprocess.check_output') as query:
                        with self.assertRaisesRegex(Exception, 'UNBOUND'):
                            runpy.run_path(str(out/stage/script), run_name='__main__')
                        popen.assert_not_called()
                        run.assert_not_called()
                        query.assert_not_called()

    def test_generated_sources_do_not_bind_historical_artifacts(self):
        m = self.load()
        out = m.prepare(ROOT, self.root / 'fresh')
        old_tokens = ('58d07af97926e04bc17184bc18f53e5fb11d84fed63bd9daf2fe4ceb04c86698',
                      '333864be7b25a51c4daf25156ced45424c1dfbfd27273e1aa2b320d95a356f8b',
                      'build_issue3_amd64_curl_build_02', 'amd64-curl-package-01',
                      'issue3-amd64-curl-report-01', 'amd64-curl-report-01')
        for source in out.rglob('*.py'):
            for token in old_tokens:
                self.assertTrue(token not in source.read_text(), (source, token))
        self.assertTrue((out/'lifecycle/base.py').is_file())
        self.assertTrue((out/'lifecycle/lifecycle_guest.py').is_file())
        cfg = json.loads((out/'lifecycle/config.json').read_text())
        self.assertEqual(cfg['state'], 'UNBOUND')
        self.assertEqual(cfg['budget']['admission_bytes'], 23 * 1024**3)
        self.assertEqual(cfg['budget']['admission_bytes'],
                         cfg['budget']['floor_bytes'] + cfg['budget']['growth_bytes'])
        self.assertIn("CONFIG['budget']['admission_bytes']", (out/'lifecycle/run_lifecycle.py').read_text())

    def gate_fixture(self):
        import hashlib
        m = self.load()
        out = m.prepare(ROOT, self.root / 'fixture')
        spec = importlib.util.spec_from_file_location('test_fresh_gate', out/'report/gate.py')
        assert spec and spec.loader
        gate = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(gate)
        def public(name, value):
            raw = value if isinstance(value, bytes) else json.dumps(value).encode()
            path = self.root / name
            path.write_bytes(raw)
            return dict(path=str(path), size=len(raw), sha256=hashlib.sha256(raw).hexdigest())
        binary = public('candidate', b'synthetic binary, never executed')
        result = public('build-result.json', dict(attempt_id='issue3-fresh-build-test', stage='build',
                        status='PASS', exit_code=0, preserved=True, active_after=[]))
        verification = public('build-verification.json', dict(status='PASS', architecture='linux/amd64',
                             attempt_id='issue3-fresh-build-test', stage='build', build_result_sha256=result['sha256'],
                             executable_sha256=binary['sha256'], executable_bytes=binary['size'],
                             **{k: True for k in ('no_uvm_i3_symbols', 'openssl_loom_hook_absent_from_u3m_init',
                                 'gmp_registration_retained', 'normal_libc_cleanup_retained', 'openssl_cleanup_linked',
                                 'source_receipts_verified', 'frozen_recipe_verified')}))
        cfg = m.template('report')
        cfg.update(state='BOUND', attempt_id='issue3-fresh-report-test', failure_model='attended-best-effort-stop-retain')
        cfg['artifacts'].update(image='sha256:'+'a'*64, executable_sha256=binary['sha256'], executable_size=binary['size'])
        cfg['inputs']['binary'] = binary
        cfg['predecessors'] = [dict(stage='build', attempt_id='issue3-fresh-build-test', result=result, verification=verification)]
        self.public = public
        return gate, cfg, out/'report/run_report.py'

    def test_generator_refuses_symlink_source_before_reading_target(self):
        import hashlib
        m = self.load()
        repo = self.root / 'public-source-repo'
        repo.mkdir()
        target = self.root / 'not-an-approved-source'
        target.write_bytes(b'synthetic private canary; never read through the link')
        name = 'tools/issue3_fresh_attempt/historical/build.py.txt'
        link = repo / name
        link.parent.mkdir(parents=True)
        link.symlink_to(target)
        real_open = os.open
        def guarded_open(path, flags, *args, **kwargs):
            if str(path) == str(link) and not flags & os.O_NOFOLLOW:
                self.fail('source target opened before no-follow validation')
            return real_open(path, flags, *args, **kwargs)
        destination = self.root / 'unsafe-source-output'
        with patch('pathlib.Path.read_bytes', side_effect=AssertionError('unchecked source read')), \
                patch.object(os, 'open', side_effect=guarded_open):
            with self.assertRaisesRegex(Exception, 'unsafe'):
                m.prepare(repo, destination)
        self.assertFalse(destination.exists())

    def test_binary_verification_cannot_be_relabelled_as_another_fresh_build(self):
        gate, cfg, unused = self.gate_fixture()
        record = cfg['predecessors'][0]
        record['attempt_id'] = 'issue3-fresh-other-build'
        result = json.loads(Path(record['result']['path']).read_bytes())
        result['attempt_id'] = record['attempt_id']
        record['result'] = self.public('other-build-result.json', result)
        touched = []
        with self.assertRaisesRegex(gate.Refusal, 'binary receipt provenance'):
            gate.validate(cfg, 'report', self.approval(cfg), 'b'*64, now=100)
            touched.append('Docker')
        self.assertEqual(touched, [])

    def test_binary_verification_binds_exact_build_result_bytes(self):
        gate, cfg, unused = self.gate_fixture()
        record = cfg['predecessors'][0]
        result = json.loads(Path(record['result']['path']).read_bytes())
        result['reviewed_source_revision'] = 'different-synthetic-source'
        record['result'] = self.public('changed-build-result.json', result)
        with self.assertRaisesRegex(gate.Refusal, 'binary receipt provenance'):
            gate.validate(cfg, 'report', self.approval(cfg), 'b'*64, now=100)

    def bound_lifecycle_config(self):
        import copy
        gate, report, unused = self.gate_fixture()
        cfg = self.load().template('lifecycle')
        cfg.update(state='BOUND', attempt_id='issue3-fresh-lifecycle-test',
                   failure_model=report['failure_model'])
        cfg['artifacts'].update(report['artifacts'], adapter_sha256='d'*64, adapter_size=23)
        a = cfg['artifacts']
        binding = self.public('binding.json', dict(schema_version=1, status='PREPARED_NOT_BUILT',
            architecture='linux/amd64', candidate_sha256=a['executable_sha256'], candidate_bytes=a['executable_size'],
            context={'candidate/urbit': dict(sha256=a['executable_sha256'], bytes=a['executable_size'], mode=0o555),
                     'tools/browser-importer/runtime.py': dict(sha256=a['adapter_sha256'], bytes=a['adapter_size'], mode=0o644)}))
        report_result = self.public('report-result.json', dict(stage='report', attempt_id=report['attempt_id'],
            status='PASS', error=None, executable_sha256_before=a['executable_sha256'],
            executable_sha256_after=a['executable_sha256'], container_id='c'*64, preserved=True, active_after=[],
            state=dict(id='c'*64, image=report['artifacts']['image'], name='/'+report['attempt_id'],
                       label=report['attempt_id'], status='exited', running=False, exit_code=0, oom_killed=False, pid=0),
            linked_openssl_3_5_9=True, compiled_headers_3_5_9=True, linked_curl_8_23_0=True, compiled_curl_headers_8_23_0=True))
        package_result = self.public('package-qualification.json', dict(stage='package', attempt_id='issue3-fresh-package-test',
            status='PASS', schema_version=1, static_verification='PASS', independent_readback='PASS', build_exit_code=0,
            image_id=a['image'], binding_sha256=binding['sha256'],
            verification_summary=dict(executable_sha256=a['executable_sha256'], adapter_sha256=a['adapter_sha256'])))
        cfg['inputs'] = dict(binary=copy.deepcopy(report['inputs']['binary']), binding=binding,
                             receipt=package_result, pill=self.public('pill', b'synthetic pill; never executed'))
        cfg['predecessors'] = copy.deepcopy(report['predecessors']) + [
            dict(stage='report', attempt_id=report['attempt_id'], result=report_result, image=report['artifacts']['image']),
            dict(stage='package', attempt_id='issue3-fresh-package-test', result=package_result)]
        return gate, cfg

    def test_lifecycle_rejects_binding_for_different_source_executable(self):
        gate, cfg = self.bound_lifecycle_config()
        gate.validate(cfg, 'lifecycle', self.approval(cfg), 'b'*64, now=100)
        binding = json.loads(Path(cfg['inputs']['binding']['path']).read_bytes())
        binding['candidate_sha256'] = 'e'*64
        cfg['inputs']['binding'] = self.public('different-source-binding.json', binding)
        qualification = json.loads(Path(cfg['inputs']['receipt']['path']).read_bytes())
        qualification['binding_sha256'] = cfg['inputs']['binding']['sha256']
        pin = self.public('different-source-qualification.json', qualification)
        cfg['inputs']['receipt'] = cfg['predecessors'][-1]['result'] = pin
        with self.assertRaisesRegex(gate.Refusal, 'source binding'):
            gate.validate(cfg, 'lifecycle', self.approval(cfg), 'b'*64, now=100)

    def test_lifecycle_source_descriptors_match_both_executable_and_adapter(self):
        import copy
        gate, cfg = self.bound_lifecycle_config()
        original = json.loads(Path(cfg['inputs']['binding']['path']).read_bytes())
        for name, field, value in [('candidate/urbit', 'sha256', 'e'*64),
                                   ('candidate/urbit', 'bytes', True),
                                   ('tools/browser-importer/runtime.py', 'sha256', 'e'*64),
                                   ('tools/browser-importer/runtime.py', 'bytes', 24)]:
            with self.subTest(name=name, field=field):
                c, binding = copy.deepcopy(cfg), copy.deepcopy(original)
                binding['context'][name][field] = value
                c['inputs']['binding'] = self.public('descriptor-binding.json', binding)
                qualification = json.loads(Path(cfg['inputs']['receipt']['path']).read_bytes())
                qualification['binding_sha256'] = c['inputs']['binding']['sha256']
                pin = self.public('descriptor-qualification.json', qualification)
                c['inputs']['receipt'] = c['predecessors'][-1]['result'] = pin
                with self.assertRaisesRegex(gate.Refusal, 'source descriptor'):
                    gate.validate(c, 'lifecycle', self.approval(c), 'b'*64, now=100)

    def test_report_predecessor_requires_its_exact_container_identity(self):
        import copy
        gate, cfg = self.bound_lifecycle_config()
        original = json.loads(Path(cfg['predecessors'][1]['result']['path']).read_bytes())
        for key, value in [('image', 'sha256:'+'e'*64), ('name', '/historical-report'),
                           ('label', 'historical-report'), ('pid', False)]:
            with self.subTest(key=key):
                c, result = copy.deepcopy(cfg), copy.deepcopy(original)
                result['state'][key] = value
                c['predecessors'][1]['result'] = self.public('wrong-report-identity.json', result)
                with self.assertRaisesRegex(gate.Refusal, 'report receipt settlement'):
                    gate.validate(c, 'lifecycle', self.approval(c), 'b'*64, now=100)

    def test_report_predecessor_requires_preservation_and_no_active_resources(self):
        import copy
        gate, cfg = self.bound_lifecycle_config()
        original = json.loads(Path(cfg['predecessors'][1]['result']['path']).read_bytes())
        for changes in [dict(preserved=False), dict(active_after=['unsettled'])]:
            with self.subTest(changes=changes):
                c, result = copy.deepcopy(cfg), dict(original, **changes)
                c['predecessors'][1]['result'] = self.public('unsettled-report.json', result)
                with self.assertRaisesRegex(gate.Refusal, 'report receipt settlement'):
                    gate.validate(c, 'lifecycle', self.approval(c), 'b'*64, now=100)

    def test_explicit_binding_and_approval_admit_only_matching_receipts(self):
        gate, cfg, script = self.gate_fixture()
        # Approval remains an in-memory fixture, never an on-disk grant.
        approval = dict(authorized=True, stage='report', attempt_id=cfg['attempt_id'],
                        bundle_sha256='b'*64, action='execute', expires_unix=200,
                        failure_model=cfg['failure_model'], owner_grant='in-memory test only')
        touched = []
        accepted = gate.validate(cfg, 'report', approval, 'b'*64, now=100)
        if accepted:
            touched.append('fake Docker boundary')
        self.assertEqual(touched, ['fake Docker boundary'])
        bad = dict(approval, bundle_sha256='c'*64)
        touched.clear()
        with self.assertRaisesRegex(gate.Refusal, 'approval'):
            gate.validate(cfg, 'report', bad, 'b'*64, now=100)
            touched.append('fake Docker boundary')
        self.assertEqual(touched, [])

    def approval(self, cfg):
        return dict(authorized=True, stage=cfg['stage'], attempt_id=cfg['attempt_id'],
                    bundle_sha256='b'*64, action='execute', expires_unix=200,
                    failure_model='attended-best-effort-stop-retain', owner_grant='in-memory test only')

    def test_configuration_receipt_and_stage_refusals_at_dispatch_boundary(self):
        import copy
        gate, cfg, script = self.gate_fixture()
        mutations = [
            ('UNBOUND', lambda c: c.update(state='UNBOUND')),
            ('identity', lambda c: c.update(attempt_id='build_issue3_amd64_curl_report_01')),
            ('budget', lambda c: c['budget'].update(admission_bytes=1)),
            ('sequence', lambda c: c.update(predecessors=[])),
            ('identity', lambda c: c['artifacts'].update(image='latest')),
            ('input', lambda c: c['inputs']['binary'].update(sha256='0'*64)),
            ('receipt', lambda c: c['predecessors'][0].update(attempt_id='issue3-fresh-other')),
            ('receipt', lambda c: c['predecessors'][0].update(result=self.public('bad-result.json',
                dict(attempt_id='issue3-fresh-build-test', stage='build', status='PASS', exit_code=0, preserved=True, active_after=['unsettled'])))),
        ]
        for error, mutate in mutations:
            c = copy.deepcopy(cfg)
            mutate(c)
            with self.subTest(error=error, config=c):
                touched = []
                with self.assertRaisesRegex(gate.Refusal, error):
                    gate.validate(c, 'report', self.approval(c), 'b'*64, now=100)
                    touched.append('Docker')
                self.assertEqual(touched, [])

    def test_generated_report_reaches_fake_subprocess_only_after_preflight(self):
        import hashlib
        gate, cfg, unused = self.gate_fixture()
        configs = {s: self.load().template(s) for s in ('build', 'report', 'package', 'lifecycle')}
        configs['report'] = cfg
        out = self.load().prepare(ROOT, self.root/'bound', configs)
        folder = out/'report'
        approval = self.approval(cfg)
        approval['bundle_sha256'] = hashlib.sha256((folder/'bundle.json').read_bytes()).hexdigest()
        class Boundary(Exception):
            pass
        from types import SimpleNamespace
        from unittest.mock import Mock
        query = Mock(side_effect=Boundary('fake Docker boundary'))
        with patch.dict(sys.modules, {'gate': gate, 'supervision': SimpleNamespace(output=query)}), patch.object(gate, 'read_authorization', return_value=approval), \
                patch.object(gate, 'capacity', return_value=100*1024**3), patch.object(gate, 'now', return_value=100), \
                patch('subprocess.Popen', side_effect=AssertionError('live process forbidden')):
            with self.assertRaisesRegex(Boundary, 'fake Docker boundary'):
                runpy.run_path(str(folder/'run_report.py'), run_name='__main__')
            self.assertEqual(query.call_count, 1)
            self.assertEqual(query.call_args.args[0], ['docker', '--context', 'desktop-linux', 'ps', '-q'])
            query.reset_mock()
            approval['authorized'] = False
            with self.assertRaisesRegex(gate.Refusal, 'approval'):
                runpy.run_path(str(folder/'run_report.py'), run_name='__main__')
            query.assert_not_called()

    def test_approval_expiring_during_capacity_scan_is_not_admitted(self):
        import hashlib
        gate, cfg, unused = self.gate_fixture()
        configs = {s: self.load().template(s) for s in ('build', 'report', 'package', 'lifecycle')}
        configs['report'] = cfg
        folder = self.load().prepare(ROOT, self.root/'capacity-expiry', configs)/'report'
        approval = self.approval(cfg)
        approval['bundle_sha256'] = hashlib.sha256((folder/'bundle.json').read_bytes()).hexdigest()
        clock = [100]
        def observe_capacity(config):
            clock[0] = 201
            return 100*1024**3
        with patch.object(gate, 'read_authorization', return_value=approval), \
                patch.object(gate, 'capacity', side_effect=observe_capacity), \
                patch.object(gate, 'now', side_effect=lambda: clock[0]):
            with self.assertRaisesRegex(gate.Refusal, 'approval'):
                gate.preflight(folder/'run_report.py', 'report')

    def test_report_approval_expiring_during_inspection_refuses_before_spend(self):
        import hashlib
        from types import SimpleNamespace
        gate, cfg, unused = self.gate_fixture()
        configs = {s: self.load().template(s) for s in ('build', 'report', 'package', 'lifecycle')}
        configs['report'] = cfg
        out = self.load().prepare(ROOT, self.root/'expiring', configs)
        folder = out/'report'
        approval = self.approval(cfg)
        approval['bundle_sha256'] = hashlib.sha256((folder/'bundle.json').read_bytes()).hexdigest()
        clock, creates = [100], []
        def query(argv, **kwargs):
            args = argv[3:]
            clock[0] = 201
            if args[0] == 'create':
                creates.append(args)
                raise AssertionError('fake create reached after approval expiration')
            if args[:2] == ['image', 'inspect']:
                return (cfg['artifacts']['image']+' amd64').encode()
            return b''
        with patch.dict(sys.modules, {'gate': gate, 'supervision': SimpleNamespace(output=query)}), \
                patch.object(gate, 'read_authorization', return_value=approval), \
                patch.object(gate, 'capacity', return_value=100*1024**3), \
                patch.object(gate, 'now', side_effect=lambda: clock[0]), \
                patch('shutil.disk_usage', return_value=SimpleNamespace(free=100*1024**3)), \
                patch('subprocess.Popen', side_effect=AssertionError('live process forbidden')):
            with self.assertRaisesRegex(gate.Refusal, 'approval'):
                runpy.run_path(str(folder/'run_report.py'), run_name='__main__')
        self.assertEqual(creates, [])
        self.assertFalse((folder/'spent.json').exists())
        self.assertFalse((folder/'owned.json').exists())

    def test_lifecycle_approval_expiring_during_inspection_refuses_before_spend(self):
        import hashlib
        gate, cfg = self.bound_lifecycle_config()
        m = self.load()
        configs = {s: m.template(s) for s in ('build', 'report', 'package', 'lifecycle')}
        configs['lifecycle'] = cfg
        folder = m.prepare(ROOT, self.root/'expiring-life', configs)/'lifecycle'
        approval = self.approval(cfg)
        approval['bundle_sha256'] = hashlib.sha256((folder/'bundle.json').read_bytes()).hexdigest()
        clock, calls, writes = [100], [], []
        class Docker:
            def call(self, argv, **kwargs):
                calls.append(argv)
                if argv[0] == 'info':
                    clock[0] = 201
                    return dict(id='fixture-engine', running=0)
                raise AssertionError('fake mutation reached after approval expiration')
        with patch.dict(sys.modules, {'gate': gate}), patch.object(sys, 'path', [str(folder), *sys.path]), \
                patch.object(gate, 'read_authorization', return_value=approval), \
                patch.object(gate, 'capacity', return_value=100*1024**3), \
                patch.object(gate, 'now', side_effect=lambda: clock[0]):
            sys.modules.pop('base', None)
            life = runpy.run_path(str(folder/'run_lifecycle.py'), run_name='fixture')
            run = life['run']
            g, base = run.__globals__, life['base']
            plan = dict(epoch='e'*32, engine_id='fixture-engine', baseline={'containers': {}}, pins={})
            with patch.dict(g, {'authorize': lambda p: None, 'snapshot': lambda d: plan['baseline'],
                                'image_check': lambda d: None, 'capacity': lambda *a: 100*1024**3,
                                'pinned_inputs': lambda: {}}), \
                    patch.object(base, 'pinned', return_value=json.dumps(plan).encode()), \
                    patch.object(base, 'Docker', return_value=Docker()), \
                    patch.object(base, 'durable', side_effect=lambda path, value: writes.append(path)):
                with self.assertRaisesRegex(gate.Refusal, 'approval'):
                    run()
        self.assertEqual([args[0] for args in calls], ['info'])
        self.assertEqual(writes, [])

    def test_report_consumes_once_before_uncertain_create_and_never_replays(self):
        import hashlib
        from types import SimpleNamespace
        gate, cfg, unused = self.gate_fixture()
        configs = {s: self.load().template(s) for s in ('build', 'report', 'package', 'lifecycle')}
        configs['report'] = cfg
        folder = self.load().prepare(ROOT, self.root/'one-shot', configs)/'report'
        approval = self.approval(cfg)
        approval['bundle_sha256'] = hashlib.sha256((folder/'bundle.json').read_bytes()).hexdigest()
        calls = []
        class UncertainCreate(Exception):
            pass
        def query(argv, **kwargs):
            args = argv[3:]
            calls.append(args)
            if args[0] == 'create':
                raise UncertainCreate('fake uncertain create; no real engine')
            if args[:2] == ['image', 'inspect']:
                return (cfg['artifacts']['image']+' amd64').encode()
            return b''
        with patch.dict(sys.modules, {'gate': gate, 'supervision': SimpleNamespace(output=query)}), \
                patch.object(gate, 'read_authorization', return_value=approval), \
                patch.object(gate, 'capacity', return_value=100*1024**3), patch.object(gate, 'now', return_value=100), \
                patch('shutil.disk_usage', return_value=SimpleNamespace(free=100*1024**3)), \
                patch('subprocess.Popen', side_effect=AssertionError('live process forbidden')):
            with self.assertRaises(UncertainCreate):
                runpy.run_path(str(folder/'run_report.py'), run_name='__main__')
            spent = (folder/'spent.json').read_bytes()
            self.assertEqual(sum(args[0] == 'create' for args in calls), 1)
            count = len(calls)
            with self.assertRaisesRegex(gate.Refusal, 'spent'):
                runpy.run_path(str(folder/'run_report.py'), run_name='__main__')
            self.assertEqual(len(calls), count)
            self.assertEqual((folder/'spent.json').read_bytes(), spent)

    def test_package_is_unconditionally_blocked_after_mock_approval(self):
        import hashlib
        gate, life = self.bound_lifecycle_config()
        m = self.load()
        cfg = m.template('package')
        cfg.update(state='BOUND', attempt_id='issue3-fresh-package-blocked', failure_model=life['failure_model'],
                   artifacts=life['artifacts'], predecessors=life['predecessors'][:2],
                   inputs={k: life['inputs'][k] for k in ('binary', 'binding')})
        configs = {s: m.template(s) for s in ('build', 'report', 'package', 'lifecycle')}
        configs['package'] = cfg
        folder = m.prepare(ROOT, self.root/'blocked-package', configs)/'package'
        approval = self.approval(cfg)
        approval['bundle_sha256'] = hashlib.sha256((folder/'bundle.json').read_bytes()).hexdigest()
        with patch.object(gate, 'read_authorization', return_value=approval), patch.object(gate, 'now', return_value=100), \
                patch('subprocess.Popen') as popen, patch('subprocess.run') as run, patch('subprocess.check_output') as query:
            with self.assertRaisesRegex(gate.Refusal, 'BLOCKED: engine build closeout'):
                gate.preflight(folder/'run_build.py', 'package')
            popen.assert_not_called()
            run.assert_not_called()
            query.assert_not_called()
        self.assertFalse((folder/'spent.json').exists())

    def test_report_recovery_checks_exact_identity_before_stop(self):
        import ast
        from types import SimpleNamespace
        m = self.load()
        out = m.prepare(ROOT, self.root/'state')
        tree = ast.parse((out/'report/run_report.py').read_text())
        state_def = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'state')
        actual = dict(id='d'*64, image='sha256:'+'a'*64, name='/issue3-fresh-report-test',
                      label='issue3-fresh-report-test', pid=1, status='running', running=True,
                      exit_code=0, oom_killed=False)
        namespace = dict(json=json, bounded_output=lambda *a, **k: json.dumps(actual),
                         DOCKER=['fake-docker'], FORMAT='selected-leaves', CONTAINER='c'*64,
                         IMAGE='sha256:'+'a'*64, CONFIG={'attempt_id': 'issue3-fresh-report-test'})
        exec(compile(ast.Module(body=[state_def], type_ignores=[]), '<state>', 'exec'), namespace)
        with self.assertRaisesRegex(Exception, 'identity'):
            namespace['state']()
        actual['id'] = 'c'*64
        self.assertEqual(namespace['state'](), actual)

    def test_report_pipe_caps_bytes_and_settles_client_on_overflow(self):
        import io
        from types import SimpleNamespace
        module_path = SOURCE.with_name('supervision.py')
        self.assertTrue(module_path.exists(), 'bounded report pipe implementation absent')
        spec = importlib.util.spec_from_file_location('fresh_supervision', module_path)
        assert spec and spec.loader
        sup = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(sup)
        class Stream:
            def fileno(self): return 12
            def close(self): pass
        class Process:
            pid = 1234
            returncode = None
            stdout = Stream()
            def poll(self): return self.returncode
            def wait(self, timeout): self.returncode = 0; return 0
        class Selector:
            def __init__(self): self.active = True
            def register(self, *args): pass
            def get_map(self): return {1: 1} if self.active else {}
            def select(self, *args): return [(SimpleNamespace(fileobj=Stream()), None)]
            def unregister(self, *args): self.active = False
            def close(self): pass
        process = Process()
        sink = io.BytesIO()
        with patch.object(sup.subprocess, 'Popen', return_value=process) as start, \
                patch.object(sup.selectors, 'DefaultSelector', Selector), \
                patch.object(sup.os, 'read', side_effect=[b'x'*65536, b'y', b'']), \
                patch.object(sup.os, 'killpg') as stop:
            with self.assertRaisesRegex(Exception, 'output cap'):
                sup.capture(['fake-docker', 'start'], sink, lambda: False, lambda: None)
            self.assertLessEqual(len(sink.getvalue()), 65536)
            self.assertEqual(stop.call_args.args[0], 1234)
            self.assertIsNotNone(process.returncode)
            self.assertEqual(start.call_args.kwargs['stdout'], sup.subprocess.PIPE)

    def test_report_template_uses_capped_pipe_not_direct_log(self):
        import ast
        from types import SimpleNamespace
        out = self.load().prepare(ROOT, self.root/'pipe')
        tree = ast.parse((out/'report/run_report.py').read_text())
        block = next(n for n in tree.body if isinstance(n, ast.Try))
        captured = []
        def capture(*args):
            captured.append(args[0])
            return SimpleNamespace(returncode=0)
        namespace = dict(ROOT=self.root, DOCKER=['fake'], CONTAINER='c'*64, stop_requested=False,
                         CONFIG={}, process=None, subprocess=__import__('subprocess'))
        with patch.dict(sys.modules, {'supervision': SimpleNamespace(capture=capture),
                                      'gate': SimpleNamespace(capacity=lambda *args: 100*1024**3)}), \
                patch('subprocess.Popen', side_effect=AssertionError('uncapped subprocess prohibited')):
            exec(compile(ast.Module(body=block.body, type_ignores=[]), '<report-try>', 'exec'), namespace)
        self.assertEqual(captured, [['fake', 'start', '--attach', 'c'*64]])

    def test_invalid_bound_generation_leaves_no_successor(self):
        gate, cfg, unused = self.gate_fixture()
        cfg['budget']['admission_bytes'] = 1
        configs = {s: self.load().template(s) for s in ('build', 'report', 'package', 'lifecycle')}
        configs['report'] = cfg
        destination = self.root/'invalid'
        with self.assertRaisesRegex(Exception, 'budget'):
            self.load().prepare(ROOT, destination, configs)
        self.assertFalse(destination.exists())

    def test_runtime_floor_plus_growth_admission_boundaries(self):
        from types import SimpleNamespace
        gate, unused, script = self.gate_fixture()
        cfg = self.load().template('lifecycle')
        gib = 1024**3
        with patch('shutil.disk_usage', return_value=SimpleNamespace(free=23*gib)), patch.object(gate.os, 'walk', return_value=[]):
            self.assertEqual(gate.capacity(cfg), 23*gib)
        for free, initial, error in [(23*gib-1, None, 'admission'), (16*gib-1, 23*gib, 'floor'), (16*gib, 24*gib, 'growth')]:
            with self.subTest(error=error), patch('shutil.disk_usage', return_value=SimpleNamespace(free=free)), \
                    patch.object(gate.os, 'walk', return_value=[]):
                with self.assertRaisesRegex(gate.Refusal, error):
                    gate.capacity(cfg, initial)
        with patch('shutil.disk_usage', return_value=SimpleNamespace(free=16*gib)), patch.object(gate.os, 'walk', return_value=[]):
            self.assertEqual(gate.capacity(cfg, 23*gib), 16*gib)

    def test_build_is_unconditionally_blocked_after_mock_approval(self):
        import hashlib
        gate, unused, script = self.gate_fixture()
        m = self.load()
        configs = {s: m.template(s) for s in ('build', 'report', 'package', 'lifecycle')}
        cfg = configs['build']
        cfg.update(state='BOUND', attempt_id='issue3-fresh-build-test', failure_model='attended-best-effort-stop-retain')
        out = m.prepare(ROOT, self.root/'blocked', configs)
        approval = self.approval(cfg)
        approval['bundle_sha256'] = hashlib.sha256((out/'build/bundle.json').read_bytes()).hexdigest()
        with patch.object(gate, 'read_authorization', return_value=approval), patch.object(gate, 'now', return_value=100), \
                patch('subprocess.Popen') as popen, patch('subprocess.check_output') as query:
            with self.assertRaisesRegex(gate.Refusal, 'BLOCKED: engine build closeout'):
                gate.preflight(out/'build/run_build.py', 'build')
            popen.assert_not_called()
            query.assert_not_called()

    def test_frozen_drift_spent_and_symlinks_refuse_before_docker(self):
        import hashlib
        gate, cfg, script = self.gate_fixture()
        configs = {s: self.load().template(s) for s in ('build', 'report', 'package', 'lifecycle')}
        configs['report'] = cfg
        out = self.load().prepare(ROOT, self.root/'drift', configs)
        folder = out/'report'
        approval = self.approval(cfg)
        approval['bundle_sha256'] = hashlib.sha256((folder/'bundle.json').read_bytes()).hexdigest()
        with patch.object(gate, 'read_authorization', return_value=approval), patch.object(gate, 'capacity', return_value=0), \
                patch.object(gate, 'now', return_value=100), patch('subprocess.Popen') as popen:
            (folder/'spent.json').write_text('{}')
            with self.assertRaisesRegex(gate.Refusal, 'spent'):
                gate.preflight(folder/'run_report.py', 'report')
            # Only this test-owned synthetic latch is removed, never real attempt evidence.
            (folder/'spent.json').unlink()
            (folder/'supervision.py').write_text('# changed synthetic fixture')
            with self.assertRaisesRegex(gate.Refusal, 'drift'):
                gate.preflight(folder/'run_report.py', 'report')
            popen.assert_not_called()
        link = self.root/'link'
        link.symlink_to(Path(cfg['inputs']['binary']['path']))
        with self.assertRaisesRegex(gate.Refusal, 'unsafe'):
            gate.read_public(str(link))

    def lifecycle_fixture(self):
        from types import SimpleNamespace
        m = self.load()
        out = m.prepare(ROOT, self.root/'life')
        config = m.template('lifecycle')
        config['inputs'] = {k: {'path': str(self.root/k), 'sha256': 'a'*64} for k in ('pill', 'binding', 'receipt')}
        config['artifacts']['image'] = 'sha256:'+'b'*64
        path = out/'lifecycle'
        with patch.dict(sys.modules), patch.object(sys, 'path', [str(path), *sys.path]):
            sys.modules.pop('base', None)
            sys.modules['gate'] = SimpleNamespace(preflight=lambda *args: config)
            namespace = runpy.run_path(str(path/'run_lifecycle.py'), run_name='fixture')
        return namespace

    def test_lifecycle_settlement_never_stops_mismatched_identity(self):
        import copy
        life = self.lifecycle_fixture()
        p = life['phase_plan']('a'*32, 'bootstrap')
        state = dict(id='c'*64, image=p['image'], name='/'+p['container'], label=p['epoch'],
                     pid=1, exit=0, oom=False, mounts=[], status='running')
        calls = []
        class Docker:
            def call(self, argv, **kwargs):
                calls.append(argv)
                if argv[0] == 'stop':
                    state.update(pid=0, status='exited')
                    return b''
                return copy.deepcopy(state)
        with self.assertRaises(life['base'].Refusal):
            life['recover_owned'](Docker(), p, 'd'*64)
        self.assertFalse(any(c[0] == 'stop' for c in calls))
        calls.clear()
        result = life['recover_owned'](Docker(), p, 'c'*64)
        self.assertEqual(result['pid'], 0)
        self.assertEqual([c for c in calls if c[0] == 'stop'], [['stop', '--time=150', 'c'*64]])
        self.assertFalse(any(c[0] in ('rm', 'prune') for c in calls))

    def test_report_rejects_extra_or_missing_resources_at_closeout(self):
        gate, cfg, script = self.gate_fixture()
        before = dict(containers=['old'], images=['image'], volumes=['volume'], networks=['network'], tags=['tag'])
        after = dict(before, containers=['old', 'owned'])
        self.assertTrue(gate.settled_inventory(before, after, {'containers': ['owned']}))
        with self.assertRaisesRegex(gate.Refusal, 'inventory'):
            gate.settled_inventory(before, dict(after, containers=['old', 'owned', 'unexpected']), {'containers': ['owned']})
        with self.assertRaisesRegex(gate.Refusal, 'inventory'):
            gate.settled_inventory(before, dict(after, images=[]), {'containers': ['owned']})

    def test_lifecycle_refuses_reopen_until_bootstrap_is_settled(self):
        from unittest.mock import Mock
        life = self.lifecycle_fixture()
        run = life['run']
        g = run.__globals__
        epoch = 'e'*32
        plan = dict(epoch=epoch, engine_id='fixture-engine', pins={}, image=g['IMAGE'], baseline={'containers': {}})
        creates = []
        class Docker:
            def call(self, argv, **kwargs):
                if argv[0] == 'info': return dict(id='fixture-engine', running=0)
                if argv[:2] == ['volume', 'create']: return (argv[-1]+'\n').encode()
                if argv[:2] == ['volume', 'inspect']:
                    return dict(name=argv[-1], driver='local', label=epoch, options_count=0)
                if argv[0] == 'create': creates.append(argv); return ('c'*64).encode()
                if argv[0] == 'start': return b''
                raise AssertionError(argv)
        states = [dict(status='created', pid=0), dict(status='exited', pid=0, exit=0, oom=False),
                  dict(status='running', pid=99, exit=0, oom=False)]
        base = g['base']
        with patch.dict(g, {'require_bound': lambda: None, 'authorize': lambda p: None,
                'snapshot': lambda d: {'containers': {}}, 'image_check': lambda d: None,
                'capacity': lambda *args: 23*1024**3, 'pinned_inputs': lambda: {},
                'inspect_owned': Mock(side_effect=states), 'read_report': lambda *args: {},
                'require_pass': lambda *args: None, 'preserved': lambda *args: True}), \
                patch.object(base, 'pinned', return_value=json.dumps(plan).encode()), \
                patch.object(base, 'durable'), patch.object(base, 'Docker', return_value=Docker()), patch('builtins.print'):
            result = run()
        self.assertFalse(result['success'])
        self.assertEqual(len(creates), 1, 'unsettled bootstrap must block second create, not merely second start')

    def test_metadata_output_is_capped_before_decode(self):
        import io
        from types import SimpleNamespace
        spec = importlib.util.spec_from_file_location('fresh_supervision_output', SOURCE.with_name('supervision.py'))
        assert spec and spec.loader
        sup = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(sup)
        self.assertTrue(hasattr(sup, 'output'), 'bounded metadata adapter absent')
        def captured(argv, sink, stop, capacity, **kwargs):
            sink.write(b'public')
            return SimpleNamespace(returncode=0)
        with patch.object(sup, 'capture', side_effect=captured) as call:
            self.assertEqual(sup.output(['fake', 'inspect'], text=True, timeout=10), 'public')
            self.assertEqual(call.call_args.kwargs['timeout'], 10)
            self.assertEqual(call.call_args.kwargs['stderr'], sup.subprocess.DEVNULL)

    def test_inherited_capacity_helper_cannot_admit_at_21_gib(self):
        from types import SimpleNamespace
        life = self.lifecycle_fixture()
        base = life['base']
        p = dict(task=str(self.root), scratch_root=str(self.root), scratch_ceiling=10*1024**3, task_ceiling=1024**3)
        with patch.object(base.os, 'statvfs', return_value=SimpleNamespace(f_bavail=21*1024**3, f_frsize=1)), \
                patch.object(base, 'usage', return_value=0):
            with self.assertRaises(base.Refusal):
                base.capacity(p)

    def test_optimized_python_cannot_disable_inherited_assertions(self):
        from types import SimpleNamespace
        gate, cfg, script = self.gate_fixture()
        with patch.object(sys, 'flags', SimpleNamespace(optimize=1)):
            with self.assertRaisesRegex(gate.Refusal, 'optimized'):
                gate.preflight(script, 'report')


if __name__ == '__main__':
    unittest.main()
