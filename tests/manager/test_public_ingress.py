"""Synthetic static renderer validation only; not live Nginx/browser evidence."""
from pathlib import Path
import sys
import unittest

SOURCE = Path(__file__).resolve().parents[2] / 'src' / 'manager'
sys.path.insert(0, str(SOURCE))


class PublicIngressTests(unittest.TestCase):
    def module(self):
        self.assertTrue((SOURCE / 'public_ingress.py').is_file(), 'renderer missing')
        import public_ingress
        return public_ingress

    def backend(self, **changes):
        return self.module().render_backend(**(dict(
            public_origin='https://ship.example.test:9443', tls_name='ship.internal.test',
            bind='127.0.0.1', port=9444, ship_port=8081,
            certificate='/synthetic/backend.pem', key='/synthetic/backend-key.pem',
            runtime_dir='/synthetic/backend-run') | changes))

    def edge(self, **changes):
        return self.module().render_edge(**(dict(
            public_origin='https://ship.example.test:9443', bind='127.0.0.1', port=9443,
            backend_address='127.0.0.2', backend_port=9444,
            backend_tls_name='ship.internal.test', certificate='/synthetic/edge.pem',
            key='/synthetic/edge-key.pem', backend_ca='/synthetic/public-ca.pem',
            runtime_dir='/synthetic/edge-run') | changes))

    def test_backend_fixed_ship_route(self):
        config = self.backend()
        for expected in ('daemon off;', 'events {', 'http {',
                         'listen 127.0.0.1:9444 ssl default_server;',
                         'ssl_reject_handshake on;', 'server_name ship.internal.test ship.example.test;',
                         'if ($ssl_server_name != "ship.internal.test") { return 421; }',
                         'if ($http_host != "ship.example.test:9443") { return 421; }',
                         'proxy_pass http://127.0.0.1:8081;',
                         'proxy_set_header Host "ship.example.test:9443";',
                         'proxy_set_header Forwarded \'proto=https;host="ship.example.test:9443"\';'):
            self.assertIn(expected, config)
        self.assertEqual(config.count('proxy_pass '), 1)
        self.assertTrue(config.endswith('}\n'))

    def test_edge_fixed_verified_backend(self):
        config = self.edge()
        for expected in ('listen 127.0.0.1:9443 ssl default_server;',
                         'server_name ship.example.test;',
                         'if ($ssl_server_name != "ship.example.test") { return 421; }',
                         'if ($http_host != "ship.example.test:9443") { return 421; }',
                         'proxy_pass https://127.0.0.2:9444;',
                         'proxy_ssl_verify on;', 'proxy_ssl_verify_depth 1;',
                         'proxy_ssl_server_name on;', 'proxy_ssl_name ship.internal.test;',
                         'proxy_ssl_trusted_certificate "/synthetic/public-ca.pem";',
                         'proxy_ssl_protocols TLSv1.2 TLSv1.3;',
                         'proxy_set_header Host "ship.example.test:9443";'):
            self.assertIn(expected, config)
        self.assertEqual(config.count('proxy_pass '), 1)
        self.assertNotIn('resolver ', config)
        self.assertNotIn('proxy_ssl_certificate_key', config)

    def test_explicit_default_port_is_rejected_by_both_renderers(self):
        for render, options in ((self.backend, {}), (self.edge, {'port': 443})):
            with self.subTest(renderer=render.__name__):
                with self.assertRaises(ValueError):
                    render(public_origin='https://public.example:443', **options)

    def test_browser_serialized_origin_and_host_match_both_guards(self):
        import re
        # Known browser URL serialization omits HTTPS's default port, but
        # retains a nondefault port. These fixtures are not urlsplit output.
        for origin, host, port in (('https://public.example', 'public.example', 443),
                                   ('https://public.example:9443', 'public.example:9443', 9443)):
            for render, options in ((self.backend, {}), (self.edge, {'port': port})):
                with self.subTest(renderer=render.__name__, origin=origin):
                    config = render(public_origin=origin, **options)
                    self.assertIn(f'if ($http_host != "{host}") {{ return 421; }}', config)
                    self.assertIn(f'proxy_set_header Host "{host}";', config)
                    match = re.search(r'~(\S+) exact;', config)
                    self.assertIsNotNone(match)
                    assert match is not None
                    self.assertIsNotNone(re.fullmatch(match.group(1), origin))
                    self.assertIsNone(re.fullmatch(match.group(1), 'https://public.example:443'))

    def test_refuse_noncanonical_or_injected_inputs(self):
        shared = dict(
            public_origin=[None, '', 'http://ship.example.test:9443',
                           'https://Ship.example.test:9443', 'https://ship.example.test:09443',
                           'https://127.0.0.1:9443', 'https://ship.example.test:9443/',
                           'https://ship.example.test:9443\n', 'https://u@ship.example.test:9443',
                           'https://ship.example.test:9443;include evil;'],
            bind=['localhost', '127.00.0.1', '::1', '127.0.0.1;bad', 2130706433],
            port=[True, '9444', 0, 65536, 8443, 8080, 8081, 12321],
            certificate=['relative', '/x/../key', '/x/$bad', '/x/";bad', '/x/\n'],
            key=['relative', '/x/../key', '/x/$bad', '/x/";bad', '/x/\n'],
            runtime_dir=['relative', '/x/../run', '/x/$bad', '/x/";bad', '/x/\n'])
        bad_names = ['localhost', '*.internal.test', 'Ship.internal.test',
                     'ship.internal.test.', '127.0.0.1', 'a;bad.test', '', None]
        for renderer, specific in ((self.backend, dict(tls_name=bad_names,
                ship_port=[8080, 12321, 8082, True, '8081'], port=shared['port'] + [9443])),
                (self.edge, dict(backend_tls_name=bad_names,
                backend_address=shared['bind'], backend_port=shared['port'] + [9443],
                backend_ca=shared['key'], port=shared['port'] + [9445]))):
            for field, values in (shared | specific).items():
                for value in values:
                    with self.subTest(renderer=renderer.__name__, field=field, value=value):
                        with self.assertRaises(ValueError):
                            renderer(**{field: value})

    def test_origin_policy_is_exact_and_method_aware(self):
        import re
        for render in (self.backend, self.edge):
            config = render()
            self.assertIn('proxy_set_header Origin $http_origin;', config)
            self.assertIn('if ($public_origin_allowed = 0) { return 403; }', config)
            origin_map = re.search(r'map \$http_origin \$public_origin_state \{([^}]+)\}', config)
            self.assertIsNotNone(origin_map)
            assert origin_map is not None
            entries = origin_map.group(1)
            self.assertIn('default denied;', entries)
            self.assertIn('"" absent;', entries)
            match = re.search(r'~(\S+) exact;', entries)
            assert match is not None
            expression = match.group(1)
            for origin in ('https://ship.example.test:9443', 'https://foreign.example.test',
                           'null', 'https://SHIP.example.test:9443',
                           'https://shipXexample.test:9443', 'https://ship.example.test:9443/',
                           'https://ship.example.test:9443, https://foreign.example.test'):
                self.assertEqual(bool(re.fullmatch(expression, origin)),
                                 origin == 'https://ship.example.test:9443')
            self.assertIn('map "$public_origin_state:$request_method" $public_origin_allowed {', config)
            for line in ('default 0;', '~^exact: 1;', '~^absent:GET$ 1;', '~^absent:HEAD$ 1;'):
                self.assertIn(line, config)
            # Literal map keys are case-insensitive; use regex for HTTP methods.
            self.assertNotIn('"absent:GET"', config)
            self.assertNotIn('"absent:HEAD"', config)
            for method in ('POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'):
                self.assertNotIn(f'"absent:{method}" 1;', config)
            self.assertNotIn('Access-Control-Allow-Origin', config)

    def test_streaming_cookie_and_private_logging_contract(self):
        for render, runtime in ((self.backend, 'backend-run'), (self.edge, 'edge-run')):
            config = render()
            for expected in ('access_log off;', 'error_log /dev/null crit;',
                             'server_tokens off;', 'ssl_protocols TLSv1.2 TLSv1.3;',
                             'ssl_session_tickets off;', 'client_max_body_size 2m;',
                             'client_header_timeout 15s;', 'client_body_timeout 30s;',
                             'send_timeout 30s;', 'keepalive_timeout 30s;',
                             'map $http_upgrade $connection_upgrade {',
                             'default upgrade;', '"" close;',
                             'proxy_http_version 1.1;', 'proxy_request_buffering off;',
                             'proxy_buffering off;', 'proxy_max_temp_file_size 0;',
                             'proxy_connect_timeout 5s;', 'proxy_read_timeout 3600s;',
                             'proxy_send_timeout 60s;', 'proxy_next_upstream off;',
                             'proxy_set_header Upgrade $http_upgrade;',
                             'proxy_set_header Connection $connection_upgrade;',
                             'proxy_cookie_domain ~.* ship.example.test;',
                             'proxy_cookie_flags ~^urbauth- secure;',
                             'proxy_set_header X-Forwarded-Proto https;',
                             'proxy_set_header X-Forwarded-Host "ship.example.test:9443";',
                             'proxy_set_header X-Forwarded-Port 9443;',
                             'proxy_set_header X-Forwarded-For $remote_addr;',
                             'proxy_set_header X-Real-IP $remote_addr;',
                             'proxy_set_header X-Forwarded-Server "";',
                             'proxy_set_header X-Forwarded-Prefix "";'):
                self.assertIn(expected, config)
            self.assertIn(f'pid "/synthetic/{runtime}/nginx.pid";', config)
            for kind, directory in (('client_body', 'body'), ('proxy', 'proxy'),
                                    ('fastcgi', 'fastcgi'), ('uwsgi', 'uwsgi'), ('scgi', 'scgi')):
                self.assertIn(f'{kind}_temp_path "/synthetic/{runtime}/{directory}";', config)
            for forbidden in ('12321', ':8443', ':8080', '$http_forwarded',
                              '$proxy_add_x_forwarded_for', '$http_cookie', '$request_body',
                              'log_format', 'ssl_key_log', 'include ', 'root ', 'alias ',
                              'auth_basic', 'httponly', 'samesite', 'proxy_cookie_path'):
                self.assertNotIn(forbidden, config.lower())

    def test_tls_names_are_bare_names_and_host_cannot_disagree(self):
        for render, field in ((self.backend, 'tls_name'), (self.edge, 'backend_tls_name')):
            with self.subTest(renderer=render.__name__):
                with self.assertRaises(ValueError):
                    render(**{field: 'ship.internal.test:443'})
                self.assertIn('if ($host != "ship.example.test") { return 421; }', render())

    def test_scaffold_api(self):
        self.assertTrue(callable(self.module().render_backend))
        self.assertTrue(callable(self.module().render_edge))

    def test_rendering_is_pure_and_all_api_inputs_are_explicit(self):
        import inspect
        from unittest import mock
        module = self.module()
        for function in (module.render_backend, module.render_edge):
            for parameter in inspect.signature(function).parameters.values():
                self.assertEqual(parameter.kind, inspect.Parameter.KEYWORD_ONLY)
                self.assertIs(parameter.default, inspect.Parameter.empty)
        with mock.patch('builtins.open', side_effect=AssertionError('file I/O')), \
                mock.patch('subprocess.Popen', side_effect=AssertionError('process')), \
                mock.patch('socket.socket', side_effect=AssertionError('network')):
            for render in (self.backend, self.edge):
                self.assertEqual(render(), render())
                self.assertIn('"/synthetic/space dir/leaf.pem"',
                              render(certificate=Path('/synthetic/space dir/leaf.pem')))


if __name__ == '__main__':
    unittest.main()
