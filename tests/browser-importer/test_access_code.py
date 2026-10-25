"""Owner access-code tests: synthetic data only; never launch a ship."""
import hashlib
import http.client
import json
import os
from pathlib import Path
import sys
import socket
import tempfile
import threading
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tools/browser-importer'))
from server import make_server
import runtime

PASSWORD = 'synthetic-owner-password'
CODE = 'sampel-sampel-sampel-sampel'


class Engine:
    def __init__(self):
        self.calls = 0

    def reveal_access_code(self):
        self.calls += 1
        return CODE


class AccessHTTPTests(unittest.TestCase):
    def setUp(self):
        salt = b'0123456789abcdef'
        self.engine = Engine()
        self.server = make_server(self.engine, ('127.0.0.1', 0), {
            'salt': salt.hex(), 'hash': hashlib.scrypt(PASSWORD.encode(), salt=salt,
                                                       n=16384, r=8, p=1).hex()})
        self.thread = threading.Thread(target=self.server.serve_forever)
        self.thread.start()
        self.cookie = ''
        self.csrf = ''
        status, headers, body = self.request('/api/login', {'password': PASSWORD})
        self.assertEqual(status, 200)
        self.cookie = headers['Set-Cookie'].split(';')[0]
        self.csrf = body['csrf']

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()

    def request(self, path='/api/access-code', body=None, *, method='POST', headers=None):
        conn = http.client.HTTPConnection('127.0.0.1', self.server.server_port, timeout=3)
        fields = {'Origin': self.server.origin, 'Cookie': self.cookie,
                  'X-CSRF-Token': self.csrf, 'Content-Type': 'application/json'}
        fields.update(headers or {})
        conn.request(method, path, json.dumps(body if body is not None else {'password': PASSWORD}), fields)
        response = conn.getresponse()
        result = response.status, dict(response.getheaders()), json.loads(response.read())
        conn.close()
        return result

    def test_refuses_bad_password_and_client_controls_before_runtime(self):
        for body in ({'password': 'wrong'}, {}, {'password': 3},
                     {'password': PASSWORD, 'expression': '+code'},
                     {'password': PASSWORD, 'path': '/tmp/pier'},
                     {'password': PASSWORD, 'port': 12321}):
            with self.subTest(body_keys=list(body)):
                status, headers, _ = self.request(body=body)
                self.assertIn(status, (400, 401, 429))
                self.assertEqual(headers['Cache-Control'], 'no-store')
        self.assertEqual(self.engine.calls, 0)

    def test_reauthentication_is_rate_limited(self):
        for _ in range(4):
            self.assertEqual(self.request()[0], 200)
        self.assertEqual(self.request()[0], 429)
        self.assertEqual(self.engine.calls, 4)

    def test_origin_host_session_csrf_method_and_query_boundaries(self):
        for fields in ({'Origin': 'https://evil.example'}, {'Host': 'evil.example'},
                       {'Cookie': ''}, {'X-CSRF-Token': 'wrong'}):
            with self.subTest(fields=list(fields)):
                self.assertIn(self.request(headers=fields)[0], (401, 403))
        for method in ('GET', 'PUT', 'DELETE'):
            self.assertEqual(self.request(method=method)[0], 404)
        self.assertEqual(self.request('/api/access-code?expression=anything')[0], 404)
        self.assertEqual(self.engine.calls, 0)

    def test_logout_during_control_request_discards_response(self):
        def revoked():
            self.server.sessions.clear()
            return CODE
        self.engine.reveal_access_code = revoked
        status, _, body = self.request()
        self.assertEqual(status, 401)
        self.assertNotIn(CODE, json.dumps(body))

    def test_runtime_failures_are_redacted(self):
        def failed():
            raise RuntimeError(CODE)
        self.engine.reveal_access_code = failed
        status, _, body = self.request()
        self.assertEqual(status, 409)
        self.assertNotIn(CODE, json.dumps(body))

    def test_reauthenticated_owner_receives_uncached_code(self):
        status, headers, body = self.request()
        self.assertEqual(status, 200)
        self.assertEqual(body, {'code': CODE})
        self.assertEqual(headers['Cache-Control'], 'no-store')
        self.assertEqual(self.engine.calls, 1)

    def test_session_revoked_during_password_check_never_contacts_runtime(self):
        original = hashlib.scrypt
        def revoke(*args, **kwargs):
            self.server.sessions.clear()
            return original(*args, **kwargs)
        with mock.patch.object(hashlib, 'scrypt', side_effect=revoke):
            self.assertEqual(self.request()[0], 401)
        self.assertEqual(self.engine.calls, 0)

    def test_protocol_worker_errors_fail_in_test_thread_without_disclosure(self):
        client, peer = socket.socketpair()
        wrapped = mock.MagicMock(wraps=peer)
        wrapped.__exit__.side_effect = lambda *args: peer.close()
        def send_then_fail(data):
            peer.sendall(data)
            raise RuntimeError(CODE)
        wrapped.sendall.side_effect = send_then_fail
        with mock.patch.object(socket, 'socketpair', return_value=(client, wrapped)), \
                mock.patch.object(threading, 'excepthook') as hook:
            with self.assertRaisesRegex(AssertionError, '^fixture worker failed$'):
                self.test_http_to_managed_lifecycle_to_real_protocol_exchange()
            hook.assert_not_called()

    def test_protocol_worker_must_stop_after_timed_join(self):
        with mock.patch.object(threading.Thread, 'is_alive', return_value=True):
            with self.assertRaisesRegex(AssertionError, 'fixture worker did not stop'):
                self.test_http_to_managed_lifecycle_to_real_protocol_exchange()

    def test_http_to_managed_lifecycle_to_real_protocol_exchange(self):
        with tempfile.TemporaryDirectory(prefix='code-http-', dir=os.environ['IMPORTER_TEST_SCRATCH']) as folder:
            root = Path(folder)
            client, peer = socket.socketpair()
            received = []
            errors = []
            def serve():
                try:
                    with peer:
                        header = peer.recv(5, socket.MSG_WAITALL)
                        received.append(peer.recv(int.from_bytes(header[1:], 'little'), socket.MSG_WAITALL))
                        atom = lambda value: int.from_bytes(value.encode(), 'little')
                        payload = runtime._jam((0, (atom('avow'), (0, (atom('noun'), atom(CODE))))))
                        peer.sendall(b'\0' + len(payload).to_bytes(4, 'little') + payload)
                except BaseException as error:
                    # Fail in the test thread, without disclosing error payloads.
                    errors.append(error)
            class FixtureAdapter:
                def reveal_access_code(self, ship_fd, child):
                    return runtime._request_access_code(client)
            engine = runtime.ManagedImporter(root / 'pier', root / 'upload', root / 'control',
                                              runtime_adapter=FixtureAdapter())
            (root / 'pier/ship/.urb').mkdir(parents=True)
            engine.runtime = {'state': 'RUNNING'}
            engine.child = mock.Mock()
            engine.child.poll.return_value = None
            self.server.engine = engine
            worker = threading.Thread(target=serve)
            worker.start()
            try:
                status, headers, body = self.request()
                self.assertEqual(status, 200)
                self.assertEqual(body, {'code': CODE})
                self.assertEqual(headers['Cache-Control'], 'no-store')
                self.assertEqual(len(received), 1)
            finally:
                client.close()
                worker.join(2)
                engine.child = None
                engine.runtime = {'state': 'STOPPED'}
                engine.close()
                self.assertFalse(worker.is_alive(), 'fixture worker did not stop')
                if errors:
                    self.fail('fixture worker failed')


if __name__ == '__main__':
    unittest.main()
