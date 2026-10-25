"""Official serial vectors and synthetic conn fixtures; no Vere execution."""
import os
from pathlib import Path
import socket
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tools/browser-importer'))
import runtime


def atom(text):
    return int.from_bytes(text.encode(), 'little')


def frame(noun):
    data = runtime._jam(noun)
    return b'\0' + len(data).to_bytes(4, 'little') + data


def response(code='sampel-sampel-sampel-sampel'):
    return (0, (atom('avow'), (0, (atom('noun'), atom(code)))))


class ConnCodecTests(unittest.TestCase):
    def test_decoder_rejects_trailing_bytes_bits_depth_and_wide_atoms(self):
        deep = 0
        for _ in range(66):
            deep = (0, deep)
        for data in (b'\x02\0', b'\x82', runtime._jam(deep),
                     runtime._jam(1 << 4096), b'\0' * 4097, b'\x03', b''):
            with self.subTest(length=len(data)):
                with self.assertRaises(ValueError):
                    runtime._cue(data)

    def test_pinned_vere_serial_vectors(self):
        self.assertTrue(callable(getattr(runtime, '_jam', None)), 'scaffold: conn codec missing')
        vectors = [(0, '02'), (1, '0c'), (2, '48'),
                   (atom('fast'), 'c0370b9ba303'), (atom('full'), 'c037ab636303'),
                   ((0, 0), '29'), ((1, 1), '3103'), ((1, 2), '3112'),
                   ((2, 3), '21d1'), ((1, (1, 1)), '71cc'),
                   ((1, (2, 3)), '714834'), (((1, 2), 3), 'c54834'),
                   ((atom('fast'), (atom('full'), atom('fast'))), '01df2c6c8e1ef0cdead8d893'),
                   (((1, 2), ((1, 2), (1, 2))), 'c5c8262701'),
                   (((0, 0), (((0, 0), (1, 1)), (1, 1))), 'a53519f31805')]
        for noun, encoded in vectors:
            with self.subTest(encoded=encoded):
                self.assertEqual(runtime._jam(noun), bytes.fromhex(encoded))
                self.assertEqual(runtime._cue(bytes.fromhex(encoded)), noun)


class ConnTransportTests(unittest.TestCase):
    def exchange(self, payload, *, fragment=False, allow_disconnect=False):
        client, peer = socket.socketpair()
        received = bytearray()
        errors = []
        def serve():
            try:
                header = peer.recv(5, socket.MSG_WAITALL)
                size = int.from_bytes(header[1:], 'little')
                received.extend(peer.recv(size, socket.MSG_WAITALL))
                for data in ([bytes([b]) for b in payload] if fragment else [payload]):
                    peer.sendall(data)
            except BaseException as error:
                # Rejection may close the peer early; no other error is expected.
                if not (allow_disconnect and isinstance(error, (BrokenPipeError, ConnectionResetError))):
                    errors.append(error)
            finally:
                peer.close()
        worker = threading.Thread(target=serve)
        worker.start()
        try:
            result = runtime._request_access_code(client)
            return result, bytes(received)
        finally:
            client.close()
            worker.join(2)
            self.assertFalse(worker.is_alive(), 'fixture worker did not stop')
            if errors:
                self.fail('fixture worker failed')

    def test_unexpected_worker_errors_fail_in_test_thread_without_disclosure(self):
        cases = [(error, allowed) for error in (OSError, RuntimeError, SystemExit)
                 for allowed in (False, True)]
        cases.extend((error, False) for error in (BrokenPipeError, ConnectionResetError))
        for error_type, allowed in cases:
            error = error_type('synthetic private detail')
            with self.subTest(kind=error_type.__name__, allow_disconnect=allowed):
                client, peer = socket.socketpair()
                wrapped = mock.Mock(wraps=peer)
                def send_then_fail(data):
                    peer.sendall(data)
                    raise error
                wrapped.sendall.side_effect = send_then_fail
                with mock.patch.object(socket, 'socketpair', return_value=(client, wrapped)), \
                        mock.patch.object(threading, 'excepthook') as hook:
                    with self.assertRaisesRegex(AssertionError, '^fixture worker failed$'):
                        self.exchange(frame(response()), allow_disconnect=allowed)
                    hook.assert_not_called()

    def test_rejection_allows_only_expected_disconnect_errors(self):
        for error_type in (BrokenPipeError, ConnectionResetError):
            with self.subTest(kind=error_type.__name__):
                client, peer = socket.socketpair()
                wrapped = mock.Mock(wraps=peer)
                def send_then_disconnect(data):
                    peer.sendall(data)
                    raise error_type('synthetic private detail')
                wrapped.sendall.side_effect = send_then_disconnect
                with mock.patch.object(socket, 'socketpair', return_value=(client, wrapped)), \
                        mock.patch.object(threading, 'excepthook') as hook:
                    with self.assertRaises(ValueError):
                        self.exchange(b'\x01' + frame(response())[1:], allow_disconnect=True)
                    hook.assert_not_called()

    def test_worker_must_stop_after_timed_join(self):
        with mock.patch.object(threading.Thread, 'is_alive', return_value=True):
            with self.assertRaises(AssertionError):
                self.exchange(frame(response()))

    def test_rejects_wrong_envelope_tag_id_status_and_code(self):
        good = response()
        variants = [(1, good[1]), (0, (atom('bail'), good[1][1])),
                    (0, (atom('avow'), (1, good[1][1][1]))),
                    (0, (atom('avow'), (0, (atom('tape'), atom('sampel'))))),
                    response('<script>'), response('x' * 300)]
        for noun in variants:
            with self.subTest(kind='invalid envelope'):
                with self.assertRaises(ValueError):
                    self.exchange(frame(noun), allow_disconnect=True)
        with self.assertRaises(ValueError):
            self.exchange(b'\x01' + frame(good)[1:], allow_disconnect=True)

    def test_rejects_oversize_header_without_reading_body(self):
        fake = mock.Mock()
        fake.recv.side_effect = [b'\0' + (4097).to_bytes(4, 'little'), b'']
        with self.assertRaises(ValueError):
            runtime._request_access_code(fake)
        self.assertEqual(fake.recv.call_count, 1)

    def test_total_deadline_bounds_trickle_reads(self):
        fake = mock.Mock()
        fake.recv.return_value = b'\0'
        with mock.patch.object(runtime.time, 'monotonic', side_effect=range(20)):
            with self.assertRaises(TimeoutError):
                runtime._request_access_code(fake)
        self.assertLessEqual(fake.recv.call_count, 5)

    def test_stalled_local_peer_times_out(self):
        client, peer = socket.socketpair()
        started = time.monotonic()
        try:
            with self.assertRaises(TimeoutError):
                runtime._request_access_code(client)
            self.assertLess(time.monotonic() - started, 6.5)
        finally:
            client.close()
            peer.close()

    def test_fixed_documented_code_request_and_fragmented_response(self):
        self.assertTrue(callable(getattr(runtime, '_request_access_code', None)), 'scaffold: conn exchange missing')
        code, request = self.exchange(frame(response()), fragment=True)
        self.assertEqual(code, 'sampel-sampel-sampel-sampel')
        expression = ('=/  m  (strand ,vase)  ;<  our=@p  bind:m  get-our  '
                      ';<  code=@p  bind:m  (scry @p /j/code/(scot %p our))  '
                      '(pure:m !>((crip (slag 1 (scow %p code)))))')
        self.assertEqual(runtime._cue(request), (0, (atom('fyrd'), (atom('base'),
                         (atom('khan-eval'), (atom('noun'), (atom('ted-eval'), atom(expression))))))))


class ManagedCodeTests(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.TemporaryDirectory(prefix='code-', dir=os.environ['IMPORTER_TEST_SCRATCH'])
        root = Path(self.root.name)
        self.adapter = mock.Mock()
        self.adapter.reveal_access_code.return_value = 'sampel-sampel-sampel-sampel'
        self.engine = runtime.ManagedImporter(root / 'pier', root / 'uploads', root / 'control',
                                              runtime_adapter=self.adapter)
        (root / 'pier/ship/.urb').mkdir(parents=True)
        self.engine.runtime = {'state': 'RUNNING'}
        self.engine.child = mock.Mock(pid=1234)
        self.engine.child.poll.return_value = None

    def tearDown(self):
        self.engine.child = None
        self.engine.runtime = {'state': 'STOPPED'}
        self.engine.close()
        self.root.cleanup()

    def test_inactive_closed_closing_and_dead_runtime_never_contact_control(self):
        for state in ('STOPPED', 'STARTING', 'FAULT', 'RECOVERY_REQUIRED'):
            self.engine.runtime = {'state': state}
            with self.subTest(state=state), self.assertRaises(runtime.ImportError):
                self.engine.reveal_access_code()
        self.engine.runtime = {'state': 'RUNNING'}
        for flag in ('_closing', '_closed'):
            setattr(self.engine, flag, True)
            with self.subTest(flag=flag), self.assertRaises(runtime.ImportError):
                self.engine.reveal_access_code()
            setattr(self.engine, flag, False)
        self.engine.child.poll.return_value = 0
        with self.assertRaises(runtime.ImportError):
            self.engine.reveal_access_code()
        self.engine.child = None
        with self.assertRaises(runtime.ImportError):
            self.engine.reveal_access_code()
        self.adapter.reveal_access_code.assert_not_called()

    def test_death_during_read_discards_code_and_failure_is_redacted(self):
        self.engine.child.poll.side_effect = [None, 0]
        with self.assertRaises(runtime.ImportError):
            self.engine.reveal_access_code()
        self.engine.child.poll.side_effect = None
        self.adapter.reveal_access_code.side_effect = ValueError('SYNTHETIC_SECRET')
        with self.assertRaises(runtime.ImportError) as caught:
            self.engine.reveal_access_code()
        self.assertNotIn('SYNTHETIC_SECRET', str(caught.exception))

    def test_active_managed_runtime_code_read_under_lifecycle_lock(self):
        self.assertTrue(callable(getattr(self.engine, 'reveal_access_code', None)), 'scaffold: lifecycle operation missing')
        def read(ship_fd, child):
            self.assertEqual(os.listdir(ship_fd), ['.urb'])
            self.assertIs(child, self.engine.child)
            self.assertTrue(self.engine.mutex._is_owned())
            return 'sampel-sampel-sampel-sampel'
        self.adapter.reveal_access_code.side_effect = read
        self.assertEqual(self.engine.reveal_access_code(), 'sampel-sampel-sampel-sampel')
        self.assertFalse((self.engine.control / 'runtime.json').exists())


class OfficialAdapterCodeTests(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.TemporaryDirectory(prefix='conn-', dir=os.environ['IMPORTER_TEST_SCRATCH'])
        self.pier = Path(self.root.name)
        (self.pier / '.urb').mkdir(mode=0o700)
        self.ship_fd = os.open(self.pier, os.O_RDONLY | os.O_DIRECTORY)
        self.child = mock.Mock(pid=os.getpid())
        self.child.poll.return_value = None
        self.adapter = runtime.OfficialRuntimeAdapter()

    def tearDown(self):
        os.close(self.ship_fd)
        self.root.cleanup()

    def run_fixture(self, peer_pid=None, peer_uid=None):
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        path = str(self.pier / '.urb/conn.sock')
        listener.bind(path)
        listener.listen(1)
        listener.settimeout(2)
        received = []
        errors = []
        accepted = threading.Event()
        real_socket = socket.socket
        pid = self.child.pid if peer_pid is None else peer_pid
        uid = os.geteuid() if peer_uid is None else peer_uid
        class FixtureSocket(real_socket):
            def connect(inner, address):
                self.assertRegex(address, r'^/proc/self/fd/[0-9]+/conn\.sock$')
                super(FixtureSocket, inner).connect(path)
                # Do not let a refusing client close before accept completes.
                self.assertTrue(accepted.wait(3), 'fixture accept did not complete')
            def getsockopt(inner, level, option, size):
                self.assertEqual((level, option, size), (socket.SOL_SOCKET, 17, 12))
                return runtime.struct.pack('3i', pid, uid, os.getegid())
        def serve():
            try:
                connection, _ = listener.accept()
                with connection:
                    connection.settimeout(2)
                    accepted.set()
                    header = connection.recv(5, socket.MSG_WAITALL)
                    if header:
                        received.append(connection.recv(int.from_bytes(header[1:], 'little'), socket.MSG_WAITALL))
                        connection.sendall(frame(response()))
            except BaseException as error:
                # unittest does not fail on uncaught background exceptions.
                errors.append(error)
            finally:
                accepted.set()  # Release connect even when accept itself fails.
        worker = threading.Thread(target=serve)
        worker.start()
        try:
            with mock.patch.object(runtime.sys, 'platform', 'linux'), mock.patch.object(runtime.socket, 'socket', FixtureSocket):
                return self.adapter.reveal_access_code(self.ship_fd, self.child), received
        finally:
            try:
                worker.join(3)
            finally:
                listener.close()
            self.received = received
            self.assertFalse(worker.is_alive(), 'fixture worker did not stop')
            self.assertEqual(errors, [], 'fixture worker failed: ' + repr(errors))

    def test_worker_exception_fails_in_test_thread(self):
        with mock.patch(__name__ + '.frame', side_effect=RuntimeError('synthetic worker failure')):
            with self.assertRaisesRegex(AssertionError, 'synthetic worker failure'):
                try:
                    self.run_fixture()
                except (ValueError, OSError):
                    # A failed client read must not conceal the worker failure.
                    pass

    def test_wrong_peer_pid_refused_before_sending(self):
        with self.assertRaises(ValueError):
            self.run_fixture(peer_pid=self.child.pid + 1)
        self.assertEqual(self.received, [])

    def test_wrong_peer_uid_refused_before_sending(self):
        with self.assertRaises(ValueError):
            self.run_fixture(peer_uid=os.geteuid() + 1)
        self.assertEqual(self.received, [])

    def test_exited_child_after_connect_refused_before_sending(self):
        self.child.poll.side_effect = [None, 0]
        with self.assertRaises(ValueError):
            self.run_fixture()
        self.assertEqual(self.received, [])

    def test_nonlinux_or_dead_child_never_opens_socket(self):
        for platform, exited in [('darwin', None), ('linux', 0)]:
            self.child.poll.return_value = exited
            with self.subTest(platform=platform), mock.patch.object(runtime.sys, 'platform', platform), \
                    mock.patch.object(runtime.socket, 'socket') as connect, \
                    mock.patch.object(runtime, '_request_access_code', return_value='synthetic'):
                with self.assertRaises(ValueError):
                    self.adapter.reveal_access_code(self.ship_fd, self.child)
                connect.assert_not_called()

    def test_non_socket_or_symlink_endpoint_never_opens_socket(self):
        endpoint = self.pier / '.urb/conn.sock'
        endpoint.write_text('synthetic')
        for linked in (False, True):
            if linked:
                endpoint.rename(self.pier / 'other')
                endpoint.symlink_to(self.pier / 'other')
            with self.subTest(linked=linked), mock.patch.object(runtime.sys, 'platform', 'linux'), \
                    mock.patch.object(runtime.socket, 'socket') as connect, \
                    mock.patch.object(runtime, '_request_access_code', return_value='synthetic'):
                with self.assertRaises(ValueError):
                    self.adapter.reveal_access_code(self.ship_fd, self.child)
                connect.assert_not_called()

    def test_descriptor_anchored_socket_to_owned_runtime(self):
        self.assertTrue(callable(getattr(self.adapter, 'reveal_access_code', None)), 'scaffold: official control adapter missing')
        code, received = self.run_fixture()
        self.assertEqual(code, 'sampel-sampel-sampel-sampel')
        self.assertEqual(len(received), 1)


if __name__ == '__main__':
    unittest.main()
