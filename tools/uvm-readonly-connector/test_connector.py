"""Offline-only synthetic handler checks. Never contacts the planet."""
import importlib.util
import json
from pathlib import Path
import unittest
import http.client
import socket
import ssl
import sys
import subprocess
import tempfile

# Guard all offline test code, not only the stdio child. This is a cooperative
# regression tripwire, not an OS sandbox or policy authorization mechanism.
def _offline_only(event, args):
    if event in ('socket.connect', 'socket.getaddrinfo', 'socket.bind', 'socket.sendto'):
        raise AssertionError('Network forbidden in connector source tests.')
sys.addaudithook(_offline_only)

ROOT = Path(__file__).resolve().parent

class ProjectionTests(unittest.TestCase):
    def test_sanitized_status_and_conservative_readiness(self):
        self.assertTrue((ROOT / 'connector.py').exists(), 'connector source absent (scaffold RED)')
        from connector import sanitize
        raw = {'state': 'READY_LOCKED', 'runtime': {'state': 'STOPPED', 'key': 'SECRET'},
               'provisioning': {'state': 'COMPLETE', 'identity': 'SECRET'},
               'job': {'state': 'READY_LOCKED', 'path': 'SECRET'},
               'start_available': True, 'local_recovery_available': False,
               'local_recovery': {'outcome': 'COMPLETE', 'operation_id': 'SECRET'},
               'csrf': 'SECRET', 'password': 'SECRET', 'logs': 'SECRET',
               'http_readiness': 'READY'}
        out = sanitize(json.dumps(raw).encode())
        self.assertNotIn('SECRET', json.dumps(out))
        self.assertEqual(out['initialization'], 'COMPLETE')
        self.assertEqual(out['ship_process'], 'STOPPED')
        self.assertEqual(out['recovery_outcome'], 'COMPLETE')
        self.assertIs(out['start_reported_available'], True)
        self.assertEqual(out['ship_http_readiness'], 'UNKNOWN_NOT_MEASURED')
        self.assertEqual(set(out), {'manager', 'ship_process', 'initialization', 'job_state',
                         'recovery_outcome', 'recovery_reported_available',
                         'start_reported_available', 'ship_http_readiness'})

class TransportTests(unittest.TestCase):
    def test_fixed_get_boundary_and_disabled_default(self):
        import connector
        self.assertTrue(hasattr(connector, 'Connector'), 'transport absent (scaffold RED)')
        import ssl
        calls = []
        class Reply:
            status = 200
            def getheader(self, name):
                return {'Content-Type': 'application/json', 'Content-Length': '2'}.get(name)
            def read(self, limit):
                self.limit = limit
                return b'{}'
        class LocalHandler:
            def __init__(self, host, port, **kwargs):
                calls.append((host, port, kwargs))
            def request(self, *args, **kwargs):
                calls.append((args, kwargs))
            def getresponse(self): return Reply()
            def close(self): calls.append('closed')
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        client = connector.Connector(context=context, session=lambda: 'A' * 43,
                                     connection_factory=LocalHandler)
        with self.assertRaises(connector.Refused): client.status()
        self.assertEqual(calls, [])
        client = connector.Connector(context=context, session=lambda: 'A' * 43,
                                     connection_factory=LocalHandler, authorized=True)
        result = client.status()
        self.assertEqual(result['manager'], 'AUTHENTICATED_STATUS_RECEIVED')
        self.assertEqual(calls[0][0:2], (connector.HOST, 8443))
        self.assertEqual(calls[1][0], ('GET', '/api/status'))
        self.assertEqual(set(calls[1][1]['headers']), {'Accept', 'Cookie', 'Host'})
        self.assertNotIn('X-CSRF-Token', calls[1][1]['headers'])
        self.assertEqual(calls[-1], 'closed')

class MCPTests(unittest.TestCase):
    def test_discovery_single_empty_input_tool_and_refusal_before_handler(self):
        self.assertTrue((ROOT / 'mcp_stdio.py').exists(), 'MCP source absent (scaffold RED)')
        from mcp_stdio import Protocol
        calls = []
        p = Protocol(lambda: calls.append('status') or {'ship_process': 'STOPPED'})
        def req(i, method, params=None):
            return p.handle({'jsonrpc': '2.0', 'id': i, 'method': method, 'params': params or {}})
        self.assertIn('error', req(0, 'tools/list'))
        init = req(1, 'initialize', {'protocolVersion': '2025-11-25', 'capabilities': {},
                                   'clientInfo': {'name': 'offline-test', 'version': '1'}})
        self.assertEqual(init['result']['protocolVersion'], '2025-11-25')
        p.handle({'jsonrpc': '2.0', 'method': 'notifications/initialized'})
        tools = req(2, 'tools/list')['result']['tools']
        self.assertEqual([t['name'] for t in tools], ['uvm_status'])
        self.assertEqual(tools[0]['inputSchema']['additionalProperties'], False)
        for action in ('start', 'stop', 'recover', 'provision', 'access-code', 'login', 'fetch'):
            self.assertIn('error', req(3, 'tools/call', {'name': action, 'arguments': {}}))
        for args in ({'url': 'http://127.0.0.1/SECRET'}, {'path': '/api/access-code'},
                     {'action': 'start'}, {'password': 'SECRET'}, {'headers': {'Cookie': 'SECRET'}},
                     {'csrf': 'SECRET'}, {'session': 'SECRET'}, {'ca': 'SECRET'}, [], 'SECRET', None):
            answer = req(4, 'tools/call', {'name': 'uvm_status', 'arguments': args})
            self.assertIn('error', answer)
            self.assertNotIn('SECRET', json.dumps(answer))
        self.assertEqual(calls, [])
        answer = req(5, 'tools/call', {'name': 'uvm_status', 'arguments': {}})
        self.assertFalse(answer['result']['isError'])
        self.assertEqual(calls, ['status'])

class CredentialTests(unittest.TestCase):
    def test_private_dedicated_session_file(self):
        self.assertTrue((ROOT / 'credentials.py').exists(), 'credential loader absent (scaffold RED)')
        import os
        import tempfile
        from credentials import read_session, load_context, PUBLIC_CA_SHA256
        self.assertEqual(PUBLIC_CA_SHA256, '', 'published trust template must remain unbound')
        from connector import Refused
        with tempfile.TemporaryDirectory(prefix='uvm-ro-') as td:
            # macOS /Users may itself have canonical aliases; resolve owned root.
            td = str(Path(td).resolve())
            path = Path(td) / 'session'
            path.write_text('A' * 43)
            path.chmod(0o600)
            self.assertEqual(read_session(str(path)), 'A' * 43)
            path.chmod(0o644)
            with self.assertRaises(Refused): read_session(str(path))
            path.chmod(0o600)
            alias = Path(td) / 'alias'
            alias.symlink_to(path)
            with self.assertRaises(Refused): read_session(str(alias))
            alias.unlink()
            os.link(str(path), str(alias))
            with self.assertRaises(Refused): read_session(str(path))
            alias.unlink()
            for value in ('A' * 43 + '\n', 'A' * 43 + '\r\nCookie:SECRET', 'SECRET', 'A' * 129):
                path.write_text(value)
                with self.assertRaises(Refused) as caught: read_session(str(path))
                self.assertNotIn('SECRET', str(caught.exception))
            with self.assertRaises(Refused): load_context(str(path))

class AdversarialTests(unittest.TestCase):
    def test_untrusted_payload_projection(self):
        from connector import sanitize, Refused
        for payload in (b'[]', b'null', b'{"csrf":"SECRET", "csrf":"SECRET"}',
                        b'{"x":NaN}', b'\xff', b'{' + b' ' * 65536, b'[' * 1500):
            with self.assertRaises(Refused) as caught: sanitize(payload)
            self.assertNotIn('SECRET', str(caught.exception))
        data = {'runtime': {'state': ['SECRET']}, 'provisioning': {'state': 'SECRET'},
                'job': {'state': '<script>SECRET</script>'},
                'local_recovery': {'outcome': {'secret': 'SECRET'}},
                'start_available': 1, 'local_recovery_available': 'true'}
        out = sanitize(json.dumps(data).encode())
        self.assertNotIn('SECRET', json.dumps(out))
        self.assertEqual(out['ship_process'], 'UNKNOWN')
        self.assertFalse(out['start_reported_available'])
        self.assertFalse(out['recovery_reported_available'])
        for state in ('RUNNING', 'STOPPED'):
            out = sanitize(json.dumps({'runtime': {'state': state}}).encode())
            self.assertEqual(out['initialization'], 'UNKNOWN')
            self.assertEqual(out['ship_http_readiness'], 'UNKNOWN_NOT_MEASURED')

    def test_transport_refusals_and_error_body_never_escape(self):
        import connector
        import ssl
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        cases = [
            (302, {}, b'SECRET'), (401, {}, b'SECRET'), (403, {}, b'SECRET'),
            (503, {}, b'SECRET'),
            (200, {'Content-Type': 'text/html', 'Content-Length': '6'}, b'SECRET'),
            (200, {'Content-Type': 'application/json', 'Content-Length': '999999'}, b'SECRET'),
            (200, {'Content-Type': 'application/json', 'Content-Length': '2',
                   'Transfer-Encoding': 'chunked'}, b'{}'),
            (200, {'Content-Type': 'application/json', 'Content-Length': '2'}, b'{'),
            (200, {'Content-Type': 'application/json', 'Content-Length': '6'}, b'SECRET'),
        ]
        for status, headers, body in cases:
            calls = []
            class Reply:
                def __init__(self): self.status = status
                def getheader(self, name): return headers.get(name)
                def read(self, limit):
                    calls.append(('read', limit))
                    return body
            class LocalHandler:
                def __init__(self, *args, **kwargs): pass
                def request(self, method, path, **kwargs): calls.append((method, path))
                def getresponse(self): return Reply()
                def close(self): calls.append('closed')
            client = connector.Connector(context=context, session=lambda: 'A' * 43,
                                         authorized=True, connection_factory=LocalHandler)
            with self.assertRaises(connector.Refused) as caught: client.status()
            self.assertNotIn('SECRET', str(caught.exception))
            self.assertEqual(calls[0], ('GET', '/api/status'))
            self.assertEqual(calls[-1], 'closed')
            self.assertEqual(sum(c[0] == 'GET' for c in calls if isinstance(c, tuple)), 1)
            if status != 200 or headers.get('Content-Type') != 'application/json':
                self.assertFalse(any(c[0] == 'read' for c in calls if isinstance(c, tuple)))

    def test_invalid_sessions_and_insecure_tls_refused_before_network(self):
        import connector
        import ssl
        calls = []
        def factory(*args, **kwargs):
            calls.append('network')
            raise OSError('SECRET')
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        for sid in ('SECRET', 'A' * 43 + '\r\nHost:evil', {}, None, 'A' * 44):
            client = connector.Connector(context=context, session=lambda: sid,
                                         authorized=True, connection_factory=factory)
            with self.assertRaises(connector.Refused): client.status()
        self.assertEqual(calls, [])
        client = connector.Connector(context=context, session=lambda: 'A' * 43,
                                     authorized=True, connection_factory=factory)
        context.check_hostname = False
        with self.assertRaises(connector.Refused): client.status()
        self.assertEqual(calls, [])
        with self.assertRaises(connector.Refused):
            connector.Connector(context=context, session=lambda: 'A' * 43)
        context.check_hostname = True
        with self.assertRaises(connector.Refused) as caught: client.status()
        self.assertNotIn('SECRET', str(caught.exception))
        self.assertEqual(calls, ['network'])

    def test_stdio_actual_subprocess_disabled_no_stderr_or_secrets(self):
        import os
        import subprocess
        messages = [
            {'jsonrpc': '2.0', 'id': 1, 'method': 'initialize',
             'params': {'protocolVersion': '2025-11-25', 'capabilities': {},
                        'clientInfo': {'name': 'offline', 'version': '1'}}},
            {'jsonrpc': '2.0', 'method': 'notifications/initialized'},
            {'jsonrpc': '2.0', 'id': 2, 'method': 'tools/list'},
            {'jsonrpc': '2.0', 'id': 3, 'method': 'tools/call',
             'params': {'name': 'uvm_status', 'arguments': {'url': 'https://evil/SECRET'}}},
            {'jsonrpc': '2.0', 'id': 4, 'method': 'tools/call',
             'params': {'name': 'uvm_status', 'arguments': {}}},
        ]
        command = [sys.executable, '-B', str(ROOT / 'offline_stdio_runner.py')]
        result = subprocess.run(command, input=b''.join(json.dumps(m).encode() + b'\n' for m in messages),
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10,
                                env={'PATH': '/usr/bin:/bin', 'PYTHONDONTWRITEBYTECODE': '1'}, cwd=str(ROOT))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, b'')
        self.assertNotIn(b'SECRET', result.stdout)
        replies = [json.loads(line) for line in result.stdout.splitlines()]
        self.assertEqual([r['id'] for r in replies], [1, 2, 3, 4])
        self.assertEqual(len(replies[1]['result']['tools']), 1)
        self.assertIn('error', replies[2])
        self.assertTrue(replies[3]['result']['isError'])

class ComposedTests(unittest.TestCase):
    def test_real_http_parser_and_serializer_via_owned_synthetic_handler(self):
        import io
        from connector import Connector, HOST
        from mcp_stdio import Protocol
        body = json.dumps({'runtime': {'state': 'RUNNING'},
                           'provisioning': {'state': 'COMPLETE'},
                           'job': {'state': 'READY_LOCKED'}, 'csrf': 'SECRET',
                           'local_recovery': {'outcome': 'COMPLETE', 'operation_id': 'SECRET'},
                           'logs': ['SECRET'], 'start_available': False}).encode()
        wire = b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: ' + str(len(body)).encode() + b'\r\n\r\n' + body
        sent = []
        class OwnedSocket:
            def sendall(self, data): sent.append(data)
            def makefile(self, mode): return io.BytesIO(wire)
            def close(self): pass
        class OwnedSyntheticHandler(http.client.HTTPSConnection):
            def connect(self):
                # Fixed production host remains visible at this boundary;
                # substitute only a socket with in-memory response bytes.
                if self.host != HOST or self.port != 8443:
                    raise AssertionError('Unexpected destination')
                self.sock = OwnedSocket()
        client = Connector(context=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT),
                           session=lambda: 'A' * 43, authorized=True,
                           connection_factory=OwnedSyntheticHandler)
        p = Protocol(client.status)
        p.handle({'jsonrpc': '2.0', 'id': 1, 'method': 'initialize',
                  'params': {'protocolVersion': '2025-11-25', 'capabilities': {}, 'clientInfo': {}}})
        p.handle({'jsonrpc': '2.0', 'method': 'notifications/initialized'})
        for name, arguments in [('uvm_status', {'url': 'https://evil/SECRET'}),
                                ('uvm_status', {'method': 'POST', 'path': '/api/start'}),
                                ('recover', {})]:
            rejected = p.handle({'jsonrpc': '2.0', 'id': 2, 'method': 'tools/call',
                                 'params': {'name': name, 'arguments': arguments}})
            self.assertIn('error', rejected)
        self.assertEqual(sent, [])
        answer = p.handle({'jsonrpc': '2.0', 'id': 3, 'method': 'tools/call',
                           'params': {'name': 'uvm_status', 'arguments': {}}})
        self.assertFalse(answer['result']['isError'])
        projected = json.loads(answer['result']['content'][0]['text'])
        self.assertEqual(projected['ship_process'], 'RUNNING')
        self.assertEqual(projected['ship_http_readiness'], 'UNKNOWN_NOT_MEASURED')
        self.assertNotIn('SECRET', json.dumps(answer))
        self.assertEqual(len(sent), 1)
        self.assertTrue(sent[0].startswith(b'GET /api/status HTTP/1.1\r\n'))
        self.assertIn(('Host: ' + HOST + ':8443\r\n').encode(), sent[0])
        self.assertNotIn(b'CSRF', sent[0])
        self.assertNotIn(b'POST', sent[0])

class ProtocolFramingTests(unittest.TestCase):
    def test_bounded_framing_notifications_and_invalid_messages(self):
        import io
        from mcp_stdio import Protocol, serve, MAX_MESSAGE
        calls = []
        protocol = Protocol(lambda: calls.append('status') or {})
        output = io.BytesIO()
        invalid = b'{"jsonrpc":"2.0","id":1,"method":"SECRET", "method":"SECRET"}\n'
        self.assertEqual(serve(io.BytesIO(invalid), output, protocol), 0)
        self.assertNotIn(b'SECRET', output.getvalue())
        self.assertEqual(json.loads(output.getvalue())['error']['code'], -32700)
        for raw in (b' ' * (MAX_MESSAGE + 1), b'{}'):
            output = io.BytesIO()
            self.assertEqual(serve(io.BytesIO(raw), output, protocol), 2)
            self.assertEqual(output.getvalue(), b'')
        protocol.handle({'jsonrpc': '2.0', 'id': 1, 'method': 'initialize',
                         'params': {'protocolVersion': '2025-11-25', 'capabilities': {}, 'clientInfo': {}}})
        protocol.handle({'jsonrpc': '2.0', 'method': 'notifications/initialized'})
        protocol.handle({'jsonrpc': '2.0', 'method': 'tools/call',
                         'params': {'name': 'uvm_status', 'arguments': {}}})
        self.assertEqual(calls, [])
        result = protocol.handle({'jsonrpc': '2.0', 'id': 'SECRET', 'method': 'tools/call',
                                  'params': {'name': 'uvm_status', 'arguments': {}}})
        self.assertNotIn('SECRET', json.dumps(result))
        self.assertEqual(calls, [])

if __name__ == '__main__':
    unittest.main(verbosity=2)
