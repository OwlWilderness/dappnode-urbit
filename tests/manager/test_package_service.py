"""Synthetic-only unit tests for the package HTTPS supervisor."""
import importlib.util
import os
from pathlib import Path
import sys
import subprocess
import threading
import time
import unittest
import tempfile
import signal
import select
from unittest import mock

SOURCE = Path(__file__).resolve().parents[2] / 'src' / 'manager'
sys.path.insert(0, str(SOURCE))


class PackageServiceTests(unittest.TestCase):
    def test_public_origin_defaults_disabled_and_cli_overrides_environment(self):
        service = self.module()
        with self.scratch() as directory:
            args = self.arguments(Path(directory))
            self.assertEqual(args.public_ship_origin, '')
            required = ['--pier-root', '/synthetic/pier', '--uploads-root', '/synthetic/uploads',
                        '--control-root', '/synthetic/control', '--password-hash-file', '/synthetic/auth']
            parser = service.make_parser({'URBIT_PUBLIC_SHIP_ORIGIN': 'https://public.example:9443'})
            self.assertEqual(parser.parse_args(required).public_ship_origin, 'https://public.example:9443')
            self.assertEqual(parser.parse_args(required + ['--public-ship-origin', '']).public_ship_origin, '')

    def test_default_shutdown_budget_preserves_runtime_grace(self):
        import inspect
        service = self.module()
        budget = inspect.signature(service.supervise).parameters['shutdown_timeout'].default
        self.assertGreaterEqual(budget, 130)
        self.assertLess(budget, 180)

    def module(self):
        self.assertTrue((SOURCE / 'package_service.py').is_file(), 'package supervisor missing')
        import package_service
        return package_service

    def test_origin_boundary(self):
        service = self.module()
        origin = service.parse_origin('https://admin.example:8443', 8443)
        self.assertEqual((origin.host, origin.authority), ('admin.example', 'admin.example:8443'))
        self.assertEqual(service.parse_origin('https://admin.example', 443).authority, 'admin.example')
        for value in ['http://admin.example:8443', 'https://Admin.example:8443',
                      'https://admin.example.:8443', 'https://admin.example:08443',
                      'https://admin.example:443', 'https://user@admin.example:8443',
                      'https://admin.example:8443/', 'https://admin.example:8443?',
                      'https://admin.example:8443#', 'https://127.0.0.1:8443',
                      'https://admin.example:8443\n', 'https://a;bad.example:8443']:
            with self.subTest(value=value), self.assertRaises(ValueError):
                service.parse_origin(value, 8443)


    def test_renderer_is_closed_and_separates_routes(self):
        service = self.module()
        config = service.render_nginx(
            admin_origin='https://admin.example:8443', ship_origin='https://ship.example:8443',
            bind='127.0.0.1', port=8443, importer_port=8080, ship_port=8081,
            certificate='/synthetic/cert.pem', key='/synthetic/key.pem',
            ca='/synthetic/ca.pem', runtime_dir='/synthetic/run')
        for required in ['ssl_reject_handshake on;', 'return 421;',
                         'if ($http_host != "admin.example:8443")',
                         'if ($ssl_server_name != "admin.example")',
                         'if ($http_host != "ship.example:8443")',
                         'if ($ssl_server_name != "ship.example")',
                         'proxy_pass https://127.0.0.1:8080;',
                         'proxy_ssl_verify on;', 'proxy_ssl_name admin.example;',
                         'proxy_pass http://127.0.0.1:8081;',
                         'proxy_cookie_domain ~.* ship.example;',
                         'proxy_set_header Host $http_host;',
                         'proxy_set_header Origin $http_origin;',
                         'proxy_set_header Forwarded "";',
                         'proxy_request_buffering off;', 'proxy_buffering off;',
                         'client_max_body_size 2m;', 'access_log off;',
                         'error_log /dev/null crit;', 'ssl_protocols TLSv1.2 TLSv1.3;']:
            self.assertIn(required, config)
        for kind in ('fastcgi', 'uwsgi', 'scgi'):
            self.assertIn(f'{kind}_temp_path "/synthetic/run/{kind}";', config)
        self.assertNotIn('12321', config)
        self.assertNotIn('root ', config)
        kwargs = dict(admin_origin='https://admin.example:8443',
                      ship_origin='https://ship.example:8443', bind='127.0.0.1', port=8443,
                      importer_port=8080, ship_port=8081, certificate='/synthetic/cert.pem',
                      key='/synthetic/key.pem', ca='/synthetic/ca.pem', runtime_dir='/synthetic/run')
        for change in [dict(ship_origin=kwargs['admin_origin']), dict(port=8080),
                       dict(ship_port=8080), dict(ship_port=12321), dict(importer_port=0), dict(bind='0.0.0.0;bad'),
                       dict(key='/bad/$variable'), dict(ca='/bad/";include bad;'),
                       dict(certificate='/bad/\n'), dict(runtime_dir='relative')]:
            with self.subTest(change=change), self.assertRaises(ValueError):
                service.render_nginx(**(kwargs | change))


    def test_supervision_reaps_both_and_preserves_enrollment_exit(self):
        service = self.module()
        for importer_code, nginx_code, expected in [
                ('import time; time.sleep(.15)', 'import time; time.sleep(30)', 0),
                ('import time; time.sleep(.15); raise SystemExit(7)', 'import time; time.sleep(30)', 78),
                ('import time; time.sleep(30)', 'import time; time.sleep(.15)', 78)]:
            children = []
            def spawn(*args, **kwargs):
                child = subprocess.Popen(*args, **kwargs)
                children.append(child)
                return child
            result = service.supervise([sys.executable, '-c', importer_code],
                                       [sys.executable, '-c', nginx_code],
                                       service.child_environment({}), threading.Event(),
                                       popen=spawn, shutdown_timeout=.2)
            self.assertEqual(result, expected)
            self.assertEqual(len(children), 2)
            self.assertTrue(all(child.poll() is not None for child in children))

    def test_optional_public_frontend_failure_stops_all_owned_groups(self):
        service = self.module()
        for failure in (0, 1, 2, 'launch'):
            with self.subTest(failure=failure), self.scratch() as directory:
                children = []
                # Each synthetic master owns a TERM-ignoring worker. Wait for all
                # workers before exiting so cleanup is exercised for every group.
                code = ('import subprocess,sys,time,pathlib; '
                        'subprocess.Popen([sys.executable,"-c",'
                        '"import signal,time; signal.signal(signal.SIGTERM,signal.SIG_IGN); time.sleep(30)"]); '
                        'root=pathlib.Path(sys.argv[1]); (root/sys.argv[2]).touch(); '
                        '\nwhile len(list(root.iterdir())) < 3: time.sleep(.01)\n'
                        'time.sleep(.1); '
                        'sys.exit(0) if sys.argv[2] == sys.argv[3] else time.sleep(30)')
                def spawn(*args, **kwargs):
                    if failure == 'launch' and len(children) == 2:
                        raise OSError('synthetic public launch failure')
                    child = subprocess.Popen(*args, **kwargs)
                    children.append(child)
                    return child
                commands = [[sys.executable, '-c', code, directory, str(i), str(failure)]
                            for i in range(3)]
                try:
                    if failure == 'launch':
                        with self.assertRaises(OSError):
                            service.supervise(commands[0], commands[1], {}, threading.Event(),
                                public_nginx_command=commands[2], popen=spawn, shutdown_timeout=.2)
                    else:
                        result = service.supervise(commands[0], commands[1], {}, threading.Event(),
                            public_nginx_command=commands[2], popen=spawn, shutdown_timeout=.2)
                        self.assertEqual(result, 0 if failure == 0 else 78)
                    self.assertEqual(len(children), 2 if failure == 'launch' else 3)
                    self.assertTrue(all(c.poll() is not None for c in children))
                    for child in children:
                        deadline = time.monotonic() + 2
                        while time.monotonic() < deadline:
                            # macOS can return EPERM for a group containing only
                            # dying zombies; require actual group disappearance.
                            groups = subprocess.check_output(
                                ['ps', '-axo', 'pgid='], text=True).split()
                            if str(child.pid) not in groups:
                                break
                            time.sleep(.02)
                        else:
                            self.fail('owned worker group survived')
                finally:
                    if any(c.poll() is None for c in children):
                        service.stop_children(children, .2)

    def test_signal_stop_and_forced_fallback_are_bounded(self):
        service = self.module()
        stop = threading.Event()
        timer = threading.Timer(.3, stop.set)
        children = []
        def spawn(*args, **kwargs):
            child = subprocess.Popen(*args, **kwargs)
            children.append(child)
            return child
        command = [sys.executable, '-c',
                   'import signal,time; signal.signal(signal.SIGTERM,signal.SIG_IGN); time.sleep(30)']
        timer.start()
        started = time.monotonic()
        try:
            self.assertEqual(service.supervise(command, command, service.child_environment({}),
                                              stop, popen=spawn, shutdown_timeout=.2), 0)
        finally:
            timer.cancel()
        self.assertLess(time.monotonic() - started, 3)
        self.assertTrue(all(child.poll() is not None for child in children))

    def test_second_launch_failure_reaps_first(self):
        service = self.module()
        children = []
        def spawn(*args, **kwargs):
            if children:
                raise OSError('synthetic failure; do not log this detail')
            child = subprocess.Popen(*args, **kwargs)
            children.append(child)
            return child
        with self.assertRaises(OSError):
            service.supervise([sys.executable, '-c', 'import time; time.sleep(30)'],
                              ['not-launched'], service.child_environment({}), threading.Event(),
                              popen=spawn, shutdown_timeout=.2)
        self.assertIsNotNone(children[0].poll())

    def test_child_environment_removes_tls_debug_and_legacy_identity(self):
        service = self.module()
        env = service.child_environment({'SSLKEYLOGFILE': '/never-write',
                                         'IMPORTER_BACKEND_TLS_NAME': 'legacy.example',
                                         'IMPORTER_BOOTSTRAP_SHA256': 'a' * 64})
        self.assertNotIn('SSLKEYLOGFILE', env)
        self.assertNotIn('IMPORTER_BACKEND_TLS_NAME', env)
        self.assertEqual(env['IMPORTER_BOOTSTRAP_SHA256'], 'a' * 64)


    def arguments(self, root, extra=()):
        service = self.module()
        return service.make_parser({'OWNER_CA_SHA256': 'a' * 64}).parse_args([
            '--pier-root', str(root / 'pier'), '--uploads-root', str(root / 'uploads'),
            '--control-root', str(root / 'control'),
            '--password-hash-file', str(root / 'control' / 'auth.json'),
            '--nginx', sys.executable, *extra])

    def scratch(self):
        return tempfile.TemporaryDirectory(prefix='package-service-test-',
                                           dir=Path(os.environ.get('IMPORTER_TEST_SCRATCH')
                                                    or tempfile.gettempdir()).resolve())

    def test_pending_has_no_child_or_listener_and_lock_excludes_duplicate(self):
        service = self.module()
        with self.scratch() as directory:
            root = Path(directory)
            args = self.arguments(root)
            stop = threading.Event()
            calls = []
            def ensure(control, names, pin):
                calls.append((control, names, pin))
                with self.assertRaises((OSError, ValueError)):
                    with service.lifetime_lock(control):
                        self.fail('duplicate controller admitted')
                if len(calls) == 2:
                    stop.set()
                return {'state': 'AWAITING_CERTIFICATE', 'request': '/synthetic/request.pem'}
            with mock.patch.object(service.subprocess, 'Popen', side_effect=AssertionError('child before TLS')):
                self.assertEqual(service.run_service(args, stop, ensure_tls=ensure,
                                                     poll_seconds=.01, environment={}), 0)
            self.assertEqual(len(calls), 2)
            self.assertEqual(calls[0][1], ('uvm.public.dappnode.private',
                                         'ship.uvm.public.dappnode.private'))
            self.assertFalse((root / 'pier').exists())
            with service.lifetime_lock(args.control_root):
                pass

    def test_invalid_pin_refused_before_ca_or_filesystem(self):
        service = self.module()
        with self.scratch() as directory:
            for pin in ('', 'A' * 64, 'a' * 63, 'a' * 64 + '\n'):
                args = self.arguments(Path(directory))
                args.owner_ca_sha256 = pin
                ensure = mock.Mock(side_effect=AssertionError('CA invoked before validation'))
                with self.assertRaises(ValueError):
                    service.run_service(args, threading.Event(), ensure_tls=ensure, environment={})
                ensure.assert_not_called()
            self.assertFalse((Path(directory) / 'control').exists())

    def test_ready_validates_config_before_launch_and_passes_direct_tls(self):
        service = self.module()
        with self.scratch() as directory:
            root = Path(directory)
            args = self.arguments(root)
            ready = {'state': 'READY', 'certificate': '/synthetic/cert.pem',
                     'key': '/synthetic/key.pem', 'ca': '/synthetic/ca.pem'}
            events = []
            def syntax(command, **kwargs):
                events.append('syntax')
                self.assertIn('-t', command)
                self.assertEqual(kwargs['stdout'], subprocess.DEVNULL)
                self.assertEqual(kwargs['stderr'], subprocess.DEVNULL)
                self.assertNotIn('SSLKEYLOGFILE', kwargs['env'])
                self.assertTrue(Path(command[command.index('-c') + 1]).is_file())
                return subprocess.CompletedProcess(command, 0)
            def supervise(importer, nginx, env, stop):
                events.append('launch')
                self.assertEqual(events, ['syntax', 'launch'])
                self.assertEqual(importer[importer.index('--bind') + 1], '127.0.0.1')
                self.assertEqual(importer[importer.index('--port') + 1], '8080')
                self.assertEqual(importer[importer.index('--tls-cert') + 1], ready['certificate'])
                self.assertEqual(importer[importer.index('--tls-key') + 1], ready['key'])
                self.assertNotIn('-t', nginx)
                self.assertFalse((Path(nginx[nginx.index('-p') + 1]) / 'public-ship').exists())
                self.assertNotIn('IMPORTER_BACKEND_TLS_NAME', env)
                return 0
            self.assertEqual(service.run_service(args, threading.Event(), ensure_tls=lambda *a: ready,
                                                supervisor=supervise, syntax_test=syntax,
                                                temp_dir=directory, environment={
                                                    'SSLKEYLOGFILE': '/never-write',
                                                    'IMPORTER_BACKEND_TLS_NAME': 'old.example'}), 0)
            self.assertEqual(events, ['syntax', 'launch'])

    def test_public_default_port_refused_before_tls_or_filesystem(self):
        service = self.module()
        args = self.arguments(Path('/synthetic'),
                              ['--public-ship-origin', 'https://public.example:443'])
        ensure = mock.Mock(side_effect=AssertionError('TLS before origin validation'))
        with mock.patch.object(service, 'lifetime_lock') as lock, \
                mock.patch.object(service.tempfile, 'TemporaryDirectory') as temporary:
            # A stopped service still validates configuration before any I/O.
            stop = threading.Event()
            stop.set()
            with self.assertRaises(ValueError):
                service.run_service(args, stop, ensure_tls=ensure, environment={})
            lock.assert_not_called()
            temporary.assert_not_called()
        ensure.assert_not_called()

    def test_public_options_refused_before_tls_or_filesystem(self):
        service = self.module()
        invalid = [dict(public_ship_origin=value) for value in (
            None, False, 1, ' ', 'http://public.example', 'https://Public.example',
            'https://public.example/', 'https://public.example:8443',
            'https://public.example:9444', 'https://public.example:444',
            'https://public.example:0443', 'https://public.example:65536',
            'https://127.0.0.1', 'https://user@public.example',
            'https://public.example?x', 'https://public.example#x',
            'https://public.example\n', 'https://public.example.',
            'https://uvm.public.dappnode.private',
            'https://ship.uvm.public.dappnode.private:9443')]
        invalid += [dict(ship_port=8082), dict(ship_port=12321), dict(importer_port=9444),
                    dict(port=9444, origin='https://admin.example:9444',
                         ship_origin='https://ship.example:9444')]
        for change in invalid:
            with self.subTest(change=change), self.scratch() as directory:
                args = self.arguments(Path(directory), ['--public-ship-origin', 'https://public.example'])
                for name, value in change.items():
                    setattr(args, name, value)
                ensure, launch = mock.Mock(), mock.Mock()
                with mock.patch.object(service, 'lifetime_lock') as lock, \
                     mock.patch.object(service.tempfile, 'TemporaryDirectory') as temporary:
                    with self.assertRaises(ValueError):
                        service.run_service(args, threading.Event(), ensure_tls=ensure,
                                            supervisor=launch, environment={})
                    lock.assert_not_called()
                    temporary.assert_not_called()
                ensure.assert_not_called()
                launch.assert_not_called()
                self.assertEqual(list(Path(directory).iterdir()), [])

    def test_public_backend_enabled_checks_both_configs_before_launch(self):
        service = self.module()
        from public_ingress import render_backend
        for origin in ('https://public.example', 'https://public.example:9443'):
            with self.subTest(origin=origin), self.scratch() as directory:
                args = self.arguments(Path(directory), ['--public-ship-origin', origin])
                ready = {'state': 'READY', 'certificate': '/synthetic/cert.pem',
                         'key': '/synthetic/key.pem', 'ca': '/synthetic/ca.pem'}
                checked = []
                def syntax(command, **kwargs):
                    config_path = Path(command[command.index('-c') + 1])
                    checked.append((command[:-1], config_path.read_text()))
                    self.assertEqual(command[-1], '-t')
                    self.assertEqual(config_path.stat().st_mode & 0o777, 0o600)
                    return subprocess.CompletedProcess(command, 0)
                def launch(importer, private, env, stop, *, public_nginx_command):
                    self.assertEqual(len(checked), 2)
                    self.assertEqual([private, public_nginx_command], [c[0] for c in checked])
                    private_dir = Path(private[private.index('-p') + 1])
                    public_dir = Path(public_nginx_command[public_nginx_command.index('-p') + 1])
                    self.assertEqual(public_dir.parent, private_dir)
                    self.assertEqual(public_dir.stat().st_mode & 0o777, 0o700)
                    self.assertEqual(checked[0][1], service.render_nginx(
                        admin_origin=args.origin, ship_origin=args.ship_origin, bind=args.bind,
                        port=args.port, importer_port=args.importer_port, ship_port=args.ship_port,
                        certificate=ready['certificate'], key=ready['key'], ca=ready['ca'],
                        runtime_dir=str(private_dir)))
                    self.assertEqual(checked[1][1], render_backend(
                        public_origin=origin, tls_name='ship.uvm.public.dappnode.private',
                        bind=args.bind, port=9444, ship_port=8081, certificate=ready['certificate'],
                        key=ready['key'], runtime_dir=str(public_dir)))
                    self.assertNotIn('8080', checked[1][1])
                    self.assertNotIn('8443', checked[1][1])
                    return 0
                ensure = mock.Mock(return_value=ready)
                self.assertEqual(service.run_service(args, threading.Event(), ensure_tls=ensure,
                    syntax_test=syntax, supervisor=launch, temp_dir=directory, environment={}), 0)
                ensure.assert_called_once_with(args.control_root,
                    ('uvm.public.dappnode.private', 'ship.uvm.public.dappnode.private'), 'a' * 64)

    def test_public_config_failure_or_timeout_never_launches_any_service(self):
        service = self.module()
        for failed_check, timeout in ((1, False), (2, False), (2, True)):
            with self.subTest(failed_check=failed_check, timeout=timeout), self.scratch() as directory:
                args = self.arguments(Path(directory), ['--public-ship-origin', 'https://public.example'])
                checked = []
                def syntax(command, **kwargs):
                    checked.append(command)
                    if len(checked) == failed_check and timeout:
                        raise subprocess.TimeoutExpired(command, 30)
                    return subprocess.CompletedProcess(command, int(len(checked) == failed_check))
                launch = mock.Mock()
                with self.assertRaises(subprocess.TimeoutExpired if timeout else ValueError):
                    service.run_service(args, threading.Event(),
                        ensure_tls=lambda *a: {'state': 'READY', 'certificate': '/cert',
                                              'key': '/key', 'ca': '/ca'},
                        syntax_test=syntax, supervisor=launch, temp_dir=directory, environment={})
                self.assertEqual(len(checked), failed_check)
                launch.assert_not_called()
                self.assertFalse(any(Path(directory).glob('urbit-frontend-*')))

    def test_public_renderer_is_explicitly_packaged_without_host_publication(self):
        root = SOURCE.parents[1]
        dockerfile = (root / 'build/Dockerfile').read_text()
        allowlist = (root / '.dockerignore').read_text().splitlines()
        self.assertTrue(any(line.startswith('COPY ') and
                            'src/manager/public_ingress.py' in line and
                            line.endswith('/opt/importer/') for line in dockerfile.splitlines()))
        self.assertIn('!src/manager/public_ingress.py', allowlist)
        self.assertNotIn('EXPOSE 9444', dockerfile)

    def test_bad_nginx_config_never_launches_services(self):
        service = self.module()
        with self.scratch() as directory:
            args = self.arguments(Path(directory))
            launch = mock.Mock(side_effect=AssertionError('launched invalid config'))
            with self.assertRaises(ValueError):
                service.run_service(args, threading.Event(),
                                    ensure_tls=lambda *a: {'state': 'READY', 'certificate': '/cert',
                                                          'key': '/key', 'ca': '/ca'},
                                    syntax_test=lambda *a, **kw: subprocess.CompletedProcess(a, 1),
                                    supervisor=launch, temp_dir=directory, environment={})
            launch.assert_not_called()


    def test_cli_pending_sigterm_is_responsive_and_safe(self):
        service = self.module()
        with self.scratch() as directory:
            root = Path(directory)
            argv = ['--pier-root', str(root / 'pier'), '--uploads-root', str(root / 'uploads'),
                    '--control-root', str(root / 'control'), '--password-hash-file', str(root / 'control/auth.json'),
                    '--owner-ca-sha256', 'a' * 64]
            code = ('import sys,types; sys.path.insert(0,sys.argv[1]); '
                    'm=types.ModuleType("owner_tls"); '
                    'm.ensure_owner_tls=lambda *a:{"state":"AWAITING_CERTIFICATE"}; '
                    'sys.modules["owner_tls"]=m; import package_service; '
                    'raise SystemExit(package_service.main(sys.argv[2:]))')
            child = subprocess.Popen([sys.executable, '-c', code, str(SOURCE), *argv],
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                     env=service.child_environment(os.environ))
            try:
                assert child.stderr is not None
                self.assertTrue(select.select([child.stderr], [], [], 5)[0])
                first = child.stderr.readline()
                self.assertIn(b'AWAITING_CERTIFICATE', first)
                child.send_signal(signal.SIGTERM)
                stdout, stderr = child.communicate(timeout=3)
                self.assertEqual(child.returncode, 0)
                self.assertEqual(stdout + stderr, b'')
            finally:
                if child.poll() is None:
                    child.kill()
                    child.communicate(timeout=3)

    def test_cli_invalid_arguments_do_not_echo_input(self):
        service = self.module()
        child = subprocess.run([sys.executable, str(SOURCE / 'package_service.py'),
                                '--port', 'synthetic-sensitive-detail'],
                               capture_output=True, env=service.child_environment(os.environ), timeout=5)
        self.assertEqual(child.returncode, 78)
        self.assertNotIn(b'synthetic-sensitive-detail', child.stderr)
        self.assertNotIn(b'Traceback', child.stderr)


    def test_frontend_master_failure_does_not_leave_worker_group(self):
        service = self.module()
        with self.scratch() as directory:
            marker = Path(directory) / 'worker.pid'
            code = ('import subprocess,sys,time,pathlib; '
                    'p=subprocess.Popen([sys.executable,"-c","import time; time.sleep(30)"]); '
                    f'pathlib.Path({str(marker)!r}).write_text(str(p.pid)); '
                    'time.sleep(.15); raise SystemExit(4)')
            children = []
            def spawn(*a, **kw):
                child = subprocess.Popen(*a, **kw)
                children.append(child)
                return child
            try:
                result = service.supervise([sys.executable, '-c', 'import time; time.sleep(30)'],
                                           [sys.executable, '-c', code], service.child_environment({}),
                                           threading.Event(), popen=spawn, shutdown_timeout=.2)
                self.assertEqual(result, 78)
                self.assertTrue(marker.exists())
                deadline = time.monotonic() + 2
                while time.monotonic() < deadline:
                    try:
                        os.killpg(children[1].pid, 0)
                    except ProcessLookupError:
                        break
                    time.sleep(.02)
                else:
                    self.fail('orphan frontend worker survived master failure')
            finally:
                if len(children) > 1:
                    try:
                        os.killpg(children[1].pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass


if __name__ == '__main__':
    unittest.main()
