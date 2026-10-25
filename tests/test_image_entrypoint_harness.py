"""Host-only; never contacts Docker."""
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent / 'image-entrypoint'


def load():
    path = ROOT / 'run.py'
    assert path.exists(), 'harness implementation missing'
    spec = importlib.util.spec_from_file_location('image_entrypoint_run', path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class HarnessTests(unittest.TestCase):
    def test_immutable_image_refuses_before_docker(self):
        module = load()
        self.assertIsNotNone(module, 'harness implementation missing (scaffold RED)')
        with patch.object(module, 'docker') as command:
            for image in ('latest', 'repo:tag', 'sha256:' + 'A' * 64, 'sha256:abc'):
                with self.assertRaises(ValueError):
                    module.Harness(image)
            command.assert_not_called()

    def test_commands_are_offline_and_only_mount_tests(self):
        module = load()
        harness = module.Harness('sha256:' + 'a' * 64)
        command = harness.create_command('pending', 'empty')
        for flag in ('--pull=never', '--network=none', '--log-driver=none',
                     '--cap-drop=ALL', '--security-opt=no-new-privileges', '--read-only',
                     '--memory=256m', '--memory-swap=256m', '--pids-limit=32'):
            self.assertIn(flag, command)
        self.assertNotIn('--entrypoint', command)
        self.assertEqual(command[-11], harness.image)
        self.assertEqual(command[-10:], module.DEFAULT_CMD + ['--bind', '0.0.0.0'])
        self.assertIn('IMPORTER_ORIGIN=https://uvm.public.dappnode.private:8443', command)
        self.assertIn('URBIT_SHIP_ORIGIN=https://ship.uvm.public.dappnode.private:8443', command)
        self.assertNotIn('--publish', command)
        self.assertNotIn('--rm', command)
        mounts = [command[n + 1] for n, x in enumerate(command) if x == '--mount']
        self.assertEqual(len(mounts), 3)
        self.assertTrue(any('target=/urbit' in m and 'type=volume' in m for m in mounts))
        self.assertTrue(all('type=volume' in m or '/tests/' in m for m in mounts))

    def test_image_contract_rejects_arch_volume_and_entrypoint_drift(self):
        module = load()
        good = ['sha256:' + 'a' * 64, 'amd64', 'linux', '10000:10000',
                ['sh', '/usr/local/bin/docker-entrypoint.sh'], module.DEFAULT_CMD, ['/urbit']]
        harness = module.Harness(good[0])
        for index, value in ((1, 'arm64'), (4, ['urbit']), (6, ['/urbit', '/other'])):
            bad = list(good)
            bad[index] = value
            with self.assertRaises(ValueError):
                harness.validate_image(bad)
        harness.validate_image(good)

    def test_guard_test_module_loads_at_its_container_mount_path(self):
        module = load()
        command = module.Harness('sha256:' + 'a' * 64).create_command('unit', 'unit-volume', helper=True)
        mount = next(value for value in command if 'source=' + str(module.ROOT / 'tests/test_volume_guard.py') in value)
        target = next(part.removeprefix('target=') for part in mount.split(',') if part.startswith('target='))
        source = (module.ROOT / 'tests/test_volume_guard.py').read_text()
        namespace = {'__file__': target, '__name__': 'image_guard_tests'}
        exec(compile(source, target, 'exec'), namespace)
        self.assertIn('VolumeGuardTests', namespace)

    def test_public_output_rejects_extra_fields_and_non_json(self):
        module = load()
        for raw in ('private-canary', '{"state":"pending","password":"canary"}'):
            with self.assertRaises(ValueError):
                module.public_result(raw, {'state'})
        self.assertEqual(module.public_result('{"state":"pending"}', {'state'}), {'state': 'pending'})

    def test_finally_attempts_every_stop_after_failure(self):
        module = load()
        harness = module.Harness('sha256:' + 'a' * 64)
        harness.containers = {'one': 'b' * 64, 'two': 'c' * 64}
        with patch.object(harness, 'stop', side_effect=[RuntimeError('uncertain'), None]) as stop:
            with self.assertRaises(RuntimeError):
                harness.finish()
            self.assertEqual(stop.call_count, 2)

    def test_bad_image_preflight_never_creates_resources(self):
        module = load()
        harness = module.Harness('sha256:' + 'a' * 64)
        with patch.object(module, 'docker', return_value='[]') as command:
            with self.assertRaises(ValueError):
                harness.run()
        self.assertEqual(command.call_count, 1)
        self.assertEqual(command.call_args.args[:2], ('image', 'inspect'))
        self.assertNotIn('{{json .Config}}', command.call_args.args)

    def test_command_failure_never_echoes_canary(self):
        import contextlib
        import io
        import subprocess
        module = load()
        output = io.StringIO()
        result = subprocess.CompletedProcess([], 1, 'credential-shaped-canary', 'private-error')
        with patch.object(module.subprocess, 'run', return_value=result) as run:
            with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
                with self.assertRaisesRegex(RuntimeError, '^Docker operation refused$'):
                    module.docker('container', 'start', 'a' * 64)
        self.assertEqual(output.getvalue(), '')
        self.assertEqual(run.call_args.kwargs['stderr'], subprocess.DEVNULL)
        self.assertEqual(run.call_args.kwargs['timeout'], 40)

    def test_invalid_known_image_id_cannot_reach_docker_via_create(self):
        module = load()
        harness = module.Harness('sha256:' + 'a' * 64)
        # Roles are names, not arbitrary user-supplied mount/command fragments.
        with self.assertRaises(ValueError):
            harness.create_command('../../private', 'empty')

    def test_metadata_projection_never_reads_volume_source_path(self):
        module = load()
        harness = module.Harness('sha256:' + 'a' * 64)
        harness.containers['pending'] = 'b' * 64
        harness.container_volumes['pending'] = 'empty'
        import json
        state = ['b' * 64, '/' + harness.name('pending'), harness.image, harness.prefix,
                 'running', 0, 123, False, 'none', 'none', ['ALL'], ['no-new-privileges'],
                 {}, 268435456, 32, True, 268435456, 'no', 'rw,noexec,nosuid,nodev,size=32m,mode=1777']
        with patch.object(module, 'docker', side_effect=[json.dumps(state), '']) as command:
            with self.assertRaises(ValueError):
                harness.state('pending')
        projection = command.call_args.args[3]
        self.assertIn('{{if eq .Type "bind"}}{{.Source}}{{end}}', projection)

    def test_checker_does_not_retry_unknown_process_uncertainty(self):
        import contextlib
        import io
        import json
        spec = importlib.util.spec_from_file_location('entrypoint_check', ROOT / 'check.py')
        assert spec is not None and spec.loader is not None
        checker = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(checker)
        output = io.StringIO()
        with patch.object(checker.sys, 'argv', ['check.py', 'pending']), \
                patch.object(checker, 'pending', side_effect=ValueError('uncertain process')), \
                contextlib.redirect_stdout(output):
            checker.main()
        self.assertEqual(json.loads(output.getvalue()), {'state': 'refused'})

    def test_exact_desktop_host_mount_projection_is_accepted(self):
        import json
        module = load()
        harness = module.Harness('sha256:' + 'a' * 64)
        harness.containers['unit'] = 'b' * 64
        harness.container_volumes['unit'] = 'unit-volume'
        state = ['b' * 64, '/' + harness.name('unit'), harness.image, harness.prefix,
                 'created', 0, 0, False, 'none', 'none', ['ALL'], ['no-new-privileges'],
                 {}, 268435456, 32, True, 268435456, 'no', 'rw,noexec,nosuid,nodev,size=32m,mode=1777']
        mounts = '\n'.join([
            'volume|' + harness.name('unit-volume') + '||/urbit|true',
            'bind||/host_mnt' + str(module.ROOT / 'tests/image-entrypoint/check.py') + '|/check.py|false',
            'bind||/host_mnt' + str(module.ROOT / 'tests/test_volume_guard.py') + '|/tests/test_volume_guard.py|false',
        ])
        with patch.object(module, 'docker', side_effect=[json.dumps(state), mounts]):
            self.assertEqual(harness.state('unit'), ('created', 0))

    def test_rosetta_python_projection_accepts_only_python_process_name(self):
        spec = importlib.util.spec_from_file_location('entrypoint_check', ROOT / 'check.py')
        assert spec is not None and spec.loader is not None
        checker = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(checker)
        for name in ('python3', 'urbit'):
            def text(path, *args, **kwargs):
                return name if path.name == 'comm' else 'header\n'
            with patch.object(checker.os, 'getpid', return_value=7), \
                    patch.object(checker.Path, 'iterdir', return_value=iter([Path('/proc/1'), Path('/proc/7')])), \
                    patch.object(checker.Path, 'read_text', text), \
                    patch.object(checker.os, 'readlink', return_value='/rosetta/rosetta'):
                if name == 'python3':
                    checker.quiet_processes()
                else:
                    with self.assertRaises(ValueError):
                        checker.quiet_processes()


if __name__ == '__main__':
    unittest.main()
