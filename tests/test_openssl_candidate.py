"""Small source-only gate; no Docker, compiler, Vere or private-state access."""
from contextlib import contextmanager, redirect_stdout
import gzip
import importlib.util
import io
import json
import hashlib
import os
from pathlib import Path
import signal
import subprocess
import sys
import tarfile
import tempfile
import time
import unittest
from unittest import mock
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
RECIPE = ROOT / 'build/vere-openssl3'


class CandidateTests(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location('candidate', RECIPE / 'candidate.py')
        assert spec is not None and spec.loader is not None
        self.api = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.api)
        self.lock = json.loads((RECIPE / 'inputs.json').read_text())

    @contextmanager
    def synthetic_build(self):
        # Only delivery orchestration is real: never run any compiler or ELF.
        scratch = tempfile.TemporaryDirectory(prefix='issue3-delivery-', dir=os.environ['TMPDIR'])
        self.addCleanup(scratch.cleanup)
        parent = Path(scratch.name)
        recipe = parent / 'recipe'
        recipe.mkdir()
        for name in ('inputs.json', 'candidate.py', 'Dockerfile', 'builder-apks.json'):
            (recipe / name).write_bytes((RECIPE / name).read_bytes())
        tools = json.loads((recipe / 'builder-apks.json').read_text())
        db = parent / 'installed'
        db.write_text('\n\n'.join('\n'.join(f'{k}:{v}' for k, v in package.items())
                                 for package in tools['packages']))
        attempt = self.api.Attempt(parent / 'attempt')
        trees = {name: attempt.output / self.lock['inputs'][name]['root']
                 for name in ('vere', 'openssl', 'zig')}
        for tree in trees.values():
            tree.mkdir()
        (trees['openssl'] / 'include').mkdir()
        (trees['openssl'] / 'include/synthetic.h').write_text('synthetic header')
        for lib in ('crypto', 'ssl'):
            (trees['openssl'] / f'lib{lib}.a').write_bytes(b'synthetic archive')
        for name in ('build.zig', 'pkg/vere/main.c', 'pkg/noun/manage.c', 'ext/openssl/build.zig',
                     'pkg/vere/vere.h', 'pkg/vere/io/cttp.c', 'pkg/vere/io/http.c',
                     'ext/urcrypt/build.zig', 'ext/urcrypt/build.zig.zon', 'ext/urcrypt/sha.c',
                     'ext/h2o/build.zig', 'ext/h2o/build.zig.zon', 'ext/h2o/socket.c',
                     'ext/curl/build.zig', 'ext/curl/build.zig.zon',
                     'ext/openssl/build.zig.zon', 'ext/gmp/build.zig.zon',
                     'ext/sigsegv/build.zig.zon', 'ext/natpmp/build.zig.zon'):
            path = trees['vere'] / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('synthetic source\n')
        (trees['vere'] / 'pkg/vere/king.c').write_text(
            '  curl_easy_setopt(cul_u, CURLOPT_SERVER_RESPONSE_TIMEOUT, 30L);\n')
        (attempt.output / 'allocation-overlay.json').write_text(json.dumps({
            'source_changes': {name: hashlib.sha256((trees['vere'] / name).read_bytes()).hexdigest()
                               for name in ('pkg/vere/io/cttp.c', 'pkg/vere/io/http.c')}}))
        binary = trees['vere'] / 'zig-out/x86_64-linux-musl/urbit'
        binary.parent.mkdir(parents=True)
        binary.write_bytes(b'\x7fELF\x02\x01' + bytes(12) + b'\x3e\x00OpenSSL 3.5.9')
        binary.chmod(0o755)
        for name in ('inputs.json', 'candidate.py'):
            (attempt.output / name).write_bytes((recipe / name).read_bytes())
        with mock.patch.object(self.api, 'HERE', recipe), \
                mock.patch.object(self.api, 'Path', side_effect=lambda p: db if p == '/lib/apk/db/installed' else Path(p)), \
                mock.patch.object(self.api.os, 'uname', return_value=SimpleNamespace(sysname='Linux', machine='x86_64')), \
                mock.patch.object(self.api.shutil, 'disk_usage', return_value=SimpleNamespace(free=32 * 1024**3)), \
                mock.patch.object(self.api.subprocess, 'check_output', side_effect=lambda argv, **kw: b'0\tfixture\n' if argv[0] == 'du' else 'synthetic.o\n'), \
                mock.patch.object(attempt, 'run'):
            yield attempt, trees, recipe, db

    def test_delivery_executable_and_frozen_builder_bindings(self):
        with self.synthetic_build() as (attempt, trees, recipe, db):
            bindings = {'Dockerfile': 'dockerfile_sha256',
                        'builder-apks.json': 'builder_apks_sha256',
                        'builder-apk-db.txt': 'builder_apk_db_sha256',
                        'inputs.json': 'inputs_sha256', 'candidate.py': 'recipe_sha256'}
            original = {name: (db if name == 'builder-apk-db.txt' else recipe / name).read_bytes()
                        for name in bindings}
            def mutate_live_inputs(*args, **kwargs):
                for name in bindings:
                    (db if name == 'builder-apk-db.txt' else recipe / name).write_bytes(b'later bytes')
            attempt.run.side_effect = mutate_live_inputs
            event = attempt.event
            def verify_completed_output(status, **values):
                if status == 'passed' and attempt.current == 'candidate-output':
                    archive_path = attempt.output / 'delivery/source-materials.tar.gz'
                    self.assertTrue(archive_path.is_file(), 'success preceded archive creation')
                    gzip.decompress(archive_path.read_bytes())  # Require a complete gzip trailer.
                    with tarfile.open(archive_path) as archive:
                        extracted = archive.extractfile(trees['vere'].name + '/build.zig')
                        assert extracted is not None
                        self.assertEqual(extracted.read(), b'synthetic source\n')
                event(status, **values)
            attempt.event = verify_completed_output
            self.api.compile_candidate(attempt, self.lock, trees)
            with self.subTest(copy_frozen_dockerfile=True):
                self.assertIn('COPY inputs.json candidate.py builder-apks.json Dockerfile ./',
                              original['Dockerfile'].decode())
            for folder in (attempt.output, attempt.output / 'delivery'):
                with self.subTest(folder=folder.name):
                    self.assertEqual((folder / 'urbit').stat().st_mode & 0o777, 0o555)
                receipt = json.loads((folder / 'candidate.json').read_text())
                self.assertEqual((folder / 'allocation-overlay.json').read_bytes(),
                                 (attempt.output / 'allocation-overlay.json').read_bytes())
                for relative in ('ext/curl/build.zig', 'ext/curl/build.zig.zon', 'pkg/vere/king.c',
                                 'ext/urcrypt/build.zig', 'ext/urcrypt/build.zig.zon', 'ext/urcrypt/sha.c',
                                 'pkg/vere/vere.h', 'pkg/vere/io/cttp.c', 'pkg/vere/io/http.c'):
                    self.assertEqual(receipt['source_changes'].get(relative),
                                     hashlib.sha256((trees['vere'] / relative).read_bytes()).hexdigest())
                for name, field in bindings.items():
                    with self.subTest(folder=folder.name, binding=field):
                        self.assertEqual(receipt.get(field), hashlib.sha256(original[name]).hexdigest())
                        self.assertEqual((folder / name).read_bytes(), original[name])
            self.assertEqual((attempt.output / 'events.jsonl').read_bytes(),
                             (attempt.output / 'delivery/events.jsonl').read_bytes())

    def test_delivery_capacity_stops_partial_copy_and_compression(self):
        for phase in ('copy', 'compression'):
            with self.subTest(phase=phase), self.synthetic_build() as (attempt, trees, recipe, db):
                payload = os.urandom(512 * 1024)
                materials = attempt.output / 'materials'
                materials.mkdir()
                (materials / 'public-synthetic.bin').write_bytes(payload)
                (attempt.output / 'bulk.log').write_bytes(payload)
                target = attempt.output / 'delivery' / ('bulk.log' if phase == 'copy' else 'source-materials.tar.gz')
                def available_space(path):
                    used = target.stat().st_size if target.exists() else 0
                    return SimpleNamespace(free=0 if used >= 64 * 1024 else 32 * 1024**3)
                with mock.patch.object(self.api, 'CAPACITY_CHECK_BYTES', 64 * 1024), \
                        mock.patch.object(self.api, 'COPY_CHUNK_BYTES', 16 * 1024), \
                        mock.patch.object(self.api.shutil, 'disk_usage', side_effect=available_space):
                    with self.assertRaisesRegex(RuntimeError, 'capacity limit'):
                        self.api.compile_candidate(attempt, self.lock, trees)
                self.assertGreater(target.stat().st_size, 0)
                self.assertLess(target.stat().st_size, len(payload), 'guard must interrupt, not merely check afterward')
                events = [json.loads(line) for line in (attempt.output / 'events.jsonl').read_text().splitlines()]
                self.assertFalse(any(e['status'] == 'passed' for e in events))
                scans = [call for call in self.api.subprocess.check_output.call_args_list if call.args[0][0] == 'du']
                self.assertLess(len(scans), 20, 'do not walk the tree on every small archive write')

    def test_sigterm_stops_real_synthetic_process_group_and_restores_handler(self):
        scratch = tempfile.TemporaryDirectory(prefix='issue3-sigterm-', dir=os.environ['TMPDIR'])
        self.addCleanup(scratch.cleanup)
        parent = Path(scratch.name)
        child = parent / 'child.py'
        child.write_text(
            'import os, signal, subprocess, sys, time\nfrom pathlib import Path\n'
            'signal.signal(signal.SIGTERM, signal.SIG_IGN)\n'
            'Path("child.pid").write_text(str(os.getpid()))\n'
            'subprocess.Popen([sys.executable, "-c", '
            '"import os,time; from pathlib import Path; Path(\'grandchild.pid\').write_text(str(os.getpid())); time.sleep(30)"])\n'
            'time.sleep(30)\n')
        runner = parent / 'runner.py'
        runner.write_text(
            'import importlib.util, json, os, signal, sys\nfrom pathlib import Path\n'
            f'spec = importlib.util.spec_from_file_location("candidate", {str(RECIPE / "candidate.py")!r})\n'
            'api = importlib.util.module_from_spec(spec); spec.loader.exec_module(api)\n'
            'previous = signal.getsignal(signal.SIGTERM)\n'
            '# Replace preparation/compilation; only the real supervisor runs.\n'
            'api.prepare = lambda *args: {}\n'
            'def synthetic_stage(attempt, lock, trees):\n'
            '    before = signal.getsignal(signal.SIGTERM)\n'
            '    try:\n'
            '        attempt.run("synthetic-wait", [sys.executable, "child.py"], Path.cwd(), dict(os.environ), timeout=20)\n'
            '    except BaseException as error:\n'
            '        Path("stage-outcome.json").write_text(json.dumps(dict(error=type(error).__name__, restored=signal.getsignal(signal.SIGTERM) == before)))\n'
            '        raise\n'
            'api.compile_candidate = synthetic_stage\n'
            'sys.argv = ["candidate.py", "--build", "--output", "attempt"]\n'
            'try:\n'
            '    api.main()\n'
            'except SystemExit as error:\n'
            '    Path("outcome.json").write_text(json.dumps(dict(code=error.code, restored=signal.getsignal(signal.SIGTERM) == previous)))\n'
            '    raise\n')
        process = subprocess.Popen([sys.executable, str(runner)], cwd=parent,
                                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                   start_new_session=True)
        try:
            deadline = time.monotonic() + 5
            while not (parent / 'grandchild.pid').exists() and time.monotonic() < deadline:
                time.sleep(0.02)
            self.assertTrue((parent / 'grandchild.pid').exists(), 'synthetic children did not become ready')
            child_pid = int((parent / 'child.pid').read_text())
            grandchild_pid = int((parent / 'grandchild.pid').read_text())
            self.assertNotEqual(os.getpgid(child_pid), os.getpgid(process.pid))
            process.terminate()
            stdout, _ = process.communicate(timeout=8)
            self.assertEqual(process.returncode, 143, stdout.decode())
            outcome = json.loads((parent / 'outcome.json').read_text())
            self.assertEqual(outcome, {'code': 143, 'restored': True})
            self.assertEqual(json.loads((parent / 'stage-outcome.json').read_text()),
                             {'error': 'BuildStopped', 'restored': True})
            events = [json.loads(line) for line in (parent / 'attempt/events.jsonl').read_text().splitlines()]
            self.assertEqual(events[-1]['status'], 'stopped')
            self.assertFalse(any(e['status'] == 'returned' for e in events))
            for pid in (child_pid, grandchild_pid):
                state = subprocess.run(['ps', '-o', 'stat=', '-p', str(pid)],
                                       capture_output=True, text=True, timeout=2).stdout.strip()
                self.assertTrue(not state or state.startswith('Z'), f'synthetic child {pid} remains live: {state}')
        finally:
            # Bound even the RED fixture; retain all synthetic files/evidence.
            if (parent / 'child.pid').exists():
                try:
                    os.killpg(int((parent / 'child.pid').read_text()), signal.SIGKILL)
                except ProcessLookupError:
                    pass
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
            process.communicate(timeout=5)

    def test_input_corruption_is_rejected(self):
        item = {'bytes': 4, 'sha256': hashlib.sha256(b'good').hexdigest()}
        self.api.verify_input(b'good', item)
        with self.assertRaisesRegex(ValueError, 'input hash/size'):
            self.api.verify_input(b'evil', item)

    def test_patch_uses_updated_library_diagnostic_and_no_reflog(self):
        source = (ROOT / 'THIRD_PARTY/vere/evidence/vere/build.zig').read_text()
        patched = self.api.patch_build(source)
        self.assertNotIn('.git/logs/HEAD', patched)
        self.assertIn('4.6-uvm-openssl3.5.9', patched)
        with self.assertRaises(ValueError):
            self.api.patch_build(patched)
        diagnostic = self.api.patch_report('  printf("openssl: %s\\n", SSLeay_version(SSLEAY_VERSION));')
        self.assertIn('OpenSSL_version(OPENSSL_VERSION)', diagnostic)
        self.assertIn('OPENSSL_VERSION_MAJOR != 3', diagnostic)
        self.assertIn('openssl-headers:', diagnostic)

    def test_archive_member_guard_rejects_escape_and_links(self):
        for name, kind in [('src/../escape', tarfile.REGTYPE),
                           ('/src/escape', tarfile.REGTYPE),
                           ('src/link', tarfile.SYMTYPE)]:
            member = tarfile.TarInfo(name)
            member.type = kind
            with self.assertRaises(ValueError):
                self.api.check_member(member, 'src')
        self.api.check_member(tarfile.TarInfo('src/public.c'), 'src')

    def test_object_adapter_exports_headers_without_nested_archives(self):
        text = self.api.object_adapter({'crypto': ['a.o', 'z.o'], 'ssl': ['b.o']})
        self.assertIn('installHeadersDirectory', text)
        self.assertIn('ssl.linkLibrary(crypto)', text)
        self.assertIn('prebuilt/crypto/a.o', text)
        self.assertNotIn('.a"', text)
        with self.assertRaises(ValueError):
            self.api.object_adapter({'crypto': ['../escape.o'], 'ssl': ['b.o']})
        with self.assertRaises(ValueError):
            self.api.object_adapter({'crypto': ['a.o', 'a.o'], 'ssl': ['b.o']})

    def test_vere_command_preserves_upstream_cpu_query_default(self):
        # Vere's whitelist compares the CPU query, not just its architecture.
        command = self.api.vere_build_command('/pinned/zig')
        self.assertIn('-Dtarget=x86_64-linux-musl', command)
        self.assertFalse(any(arg.startswith('-Dcpu=') for arg in command))
        self.assertIn('-Dpace=once', command)

    def test_stage_diagnostics_and_replay_interlock(self):
        scratch = tempfile.TemporaryDirectory(prefix='issue3-diagnostic-', dir=os.environ['TMPDIR'])
        self.addCleanup(scratch.cleanup)
        parent = Path(scratch.name)
        output = parent / 'attempt'
        attempt = self.api.Attempt(output)
        previous = signal.getsignal(signal.SIGTERM)
        attempt.run('synthetic-success', [sys.executable, '-c', 'print("synthetic compiler output")'],
                    parent, dict(os.environ), timeout=10)
        with self.assertRaises(RuntimeError):
            attempt.run('synthetic-failure', [sys.executable, '-c', 'raise SystemExit(7)'],
                        parent, dict(os.environ), timeout=10)
        events = [json.loads(line) for line in (output / 'events.jsonl').read_text().splitlines()]
        self.assertEqual([event['exit_code'] for event in events if 'exit_code' in event], [0, 7])
        with mock.patch.object(self.api.shutil, 'disk_usage', return_value=SimpleNamespace(free=0)):
            with self.assertRaisesRegex(RuntimeError, 'capacity limit'):
                attempt.run('synthetic-capacity', [sys.executable, '-c', 'import time; time.sleep(10)'],
                            parent, dict(os.environ, UVM_BUILD_CAPACITY_GUARD='1'), timeout=15)
        with self.assertRaises(FileExistsError):
            self.api.Attempt(output)
        self.assertIs(signal.getsignal(signal.SIGTERM), previous)


    def test_openssl_cache_reuse_is_verified_and_skips_compilation(self):
        with self.synthetic_build() as (cached, trees, recipe, db):
            self.api.compile_candidate(cached, self.lock, trees, openssl_only=True)
            self.assertFalse(any(c.args[0] == 'vere-build' for c in cached.run.call_args_list),
                             'the cache stage must finish without building Vere')
            self.assertFalse((cached.output / 'urbit').exists())
            with self.synthetic_build() as (consumer, next_trees, _, _):
                self.api.compile_candidate(consumer, self.lock, next_trees, openssl_cache=cached.output)
                stages = [c.args[0] for c in consumer.run.call_args_list]
                self.assertIn('vere-build', stages)
                self.assertFalse(any(s in stages for s in ('openssl-configure', 'openssl-build', 'openssl-configuration')))
                self.assertTrue((consumer.output / 'delivery/openssl-cache.json').exists())
                receipt = json.loads((consumer.output / 'candidate.json').read_text())
                self.assertEqual(receipt['openssl_cache_sha256'],
                                 hashlib.sha256((cached.output / 'openssl-cache.json').read_bytes()).hexdigest())
            for relative in ('libcrypto.a', 'include/synthetic.h'):
                file = trees['openssl'] / relative
                original = file.read_bytes()
                file.write_bytes(b'tampered synthetic cache')
                with self.synthetic_build() as (refused, next_trees, _, _):
                    with self.assertRaisesRegex(ValueError, 'OpenSSL cache'):
                        self.api.compile_candidate(refused, self.lock, next_trees, openssl_cache=cached.output)
                    refused.run.assert_not_called()
                file.write_bytes(original)
        dockerfile = (RECIPE / 'Dockerfile').read_text()
        self.assertLess(dockerfile.index('--openssl-only'), dockerfile.index('ARG UVM_BUILD_ATTEMPT_ID'))
        command = self.api.image_build_command(Path('/frozen-recipe'), Path('/fresh-export'), 'fresh-03')
        self.assertNotIn('--no-cache', command)
        self.assertIn('UVM_BUILD_ATTEMPT_ID=fresh-03', command)

    def test_activity_samples_and_stream_cap(self):
        scratch = tempfile.TemporaryDirectory(prefix='issue3-activity-', dir=os.environ['TMPDIR'])
        self.addCleanup(scratch.cleanup)
        parent = Path(scratch.name)
        attempt = self.api.Attempt(parent / 'attempt')
        log = parent / 'compiler.log'
        log.write_text('synthetic output')
        obj = parent / 'synthetic.o'
        obj.write_bytes(b'obj')
        monitor = self.api.StageDiagnostics(attempt, log, parent, interval=0, quiet_seconds=0)
        monitor.stream_limit = 4
        proc = parent / 'proc'
        (proc / '123').mkdir(parents=True)
        # Linux fields 3..17; only this owned process group's numeric stat data.
        fields = ['S', '1', '123'] + ['0'] * 8 + ['10', '20', '3', '4']
        (proc / '123/stat').write_text('123 (synthetic (compiler)) ' + ' '.join(fields))
        self.assertEqual(monitor.process_sample(123, proc), {'cpu_ticks': 37, 'processes': 1})
        self.assertIsNone(monitor.process_sample(456, proc)['cpu_ticks'])
        captured = io.StringIO()
        with redirect_stdout(captured):
            monitor.update(123, force=True)
            monitor.update(123, force=True)
            before = monitor.previous
            obj.write_bytes(b'larger synthetic object')
            monitor.update(123, force=True)
        self.assertNotEqual(before, monitor.previous)
        events = [json.loads(line) for line in captured.getvalue().splitlines()]
        self.assertEqual(len([e for e in events if e['status'] == 'compiler-stream-capped']), 1)
        self.assertEqual(''.join(e['text'] for e in events if e['status'] == 'compiler-output'), 'synt')
        activity = [e for e in events if e['status'] == 'activity']
        self.assertEqual(activity[-1]['object_bytes'], obj.stat().st_size)
        self.assertTrue(all(not e['stall_proven'] for e in activity))
        with mock.patch.object(self.api.os, 'walk', return_value=iter([(str(parent), [], [])])), \
                mock.patch.object(self.api.time, 'monotonic', side_effect=[0, 2]):
            self.assertFalse(monitor.object_sample()['object_scan_complete'],
                             'empty directories must also honor the scan deadline')

    def test_live_compiler_output_and_timeout_tail(self):
        scratch = tempfile.TemporaryDirectory(prefix='issue3-live-log-', dir=os.environ['TMPDIR'])
        self.addCleanup(scratch.cleanup)
        parent = Path(scratch.name)
        attempt = self.api.Attempt(parent / 'attempt')
        captured = io.StringIO()
        observed_live = []
        event = attempt.event
        def observe(status, **values):
            if status == 'compiler-output':
                observed_live.append(not (parent / 'finished').exists())
            event(status, **values)
        attempt.event = observe
        command = [sys.executable, '-u', '-c',
                   'from pathlib import Path; import time; '
                   'print("synthetic live compiler line", flush=True); '
                   'time.sleep(0.5); Path("finished").touch()']
        with redirect_stdout(captured):
            attempt.run('synthetic-live', command, parent, dict(os.environ), timeout=5)
        self.assertTrue(any(observed_live), 'compiler output must arrive before child exit')
        self.assertIn('synthetic live compiler line', captured.getvalue())
        captured = io.StringIO()
        with redirect_stdout(captured), self.assertRaises(subprocess.TimeoutExpired):
            attempt.run('synthetic-timeout', [sys.executable, '-u', '-c',
                        'import time; print("synthetic timeout detail", flush=True); time.sleep(30)'],
                        parent, dict(os.environ), timeout=0.4)
        events = [json.loads(line) for line in captured.getvalue().splitlines()]
        tails = [e for e in events if e['status'] == 'compiler-tail']
        self.assertTrue(tails, 'timeout must expose retained compiler detail')
        self.assertIn('synthetic timeout detail', tails[-1]['text'])
        self.assertTrue(next(e for e in events if e['status'] == 'stopped')['child_reaped'])


if __name__ == '__main__':
    unittest.main()
