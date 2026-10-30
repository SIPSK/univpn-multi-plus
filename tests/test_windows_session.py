"""Owned random-loopback fake servers only; never touches installed UniVPN RPC."""
from __future__ import annotations

import json
from pathlib import Path
import socket
import struct
import sys
import threading
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import windows_messages as wire
from windows_session import SessionError, WindowsSession

USER = 'offline-fixture-user'
PASSWORD = 'offline-fixture-password'
CODE = 'offline-fixture-token'
PROFILE_NAME = 'offline-fixture-profile'
UNTRUSTED = b'unknown-native-message-text'


def exact(sock, size):
    result = bytearray()
    while len(result) < size:
        part = sock.recv(size - len(result))
        if not part:
            raise EOFError()
        result.extend(part)
    return bytes(result)


def receive(sock):
    header = exact(sock, wire.HEADER.size)
    length = wire.HEADER.unpack(header)[-1]
    if length > wire.MAX_PAYLOAD:
        raise ValueError('fixture framing limit')
    return wire.decode_frame(header + exact(sock, length))


class FakeNative:
    """Implements only the proven request table on two newly allocated ports."""

    def __init__(self, mode='plain', *, fragmented=True):
        self.mode = mode
        self.fragmented = fragmented
        self.stop = threading.Event()
        self.release_prepare = threading.Event()
        self.release_prepare.set()
        self.lock = threading.Lock()
        self.listeners = []
        self.clients = []
        self.threads = []
        self.ops = []
        self.registrations = []
        self.diagnostics = []
        self.prepare_calls = 0
        self.validation_calls = 0
        self.wait_calls = 0
        self.shape_valid = True
        self.failures = []
        self.event_socket = None
        self.helper_listener = self._listen()
        self.backend_listener = self._listen()
        self.service_port = self.helper_listener.getsockname()[1]
        self.backend_port = self.backend_listener.getsockname()[1]

    def _listen(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(('127.0.0.1', 0))
        sock.listen(4)
        sock.settimeout(0.1)
        self.listeners.append(sock)
        return sock

    def __enter__(self):
        for target in (self._helper, self._backend):
            thread = threading.Thread(target=target, daemon=True)
            self.threads.append(thread)
            thread.start()
        return self

    def _accept(self, listener):
        while not self.stop.is_set():
            try:
                sock, _ = listener.accept()
                sock.settimeout(3)
                self.clients.append(sock)
                return sock
            except socket.timeout:
                continue
        raise EOFError()

    def _reply(self, sock, opcode, payload=b'', connection_type=1):
        # Response class intentionally differs: Windows GUI uses opcode.
        frame = wire.Message(4, 2, connection_type, 0, opcode, payload).encode()
        if self.fragmented:
            for part in (frame[:7], frame[7:20], frame[20:]):
                sock.sendall(part)
        else:
            sock.sendall(frame)

    def _helper(self):
        try:
            sock = self._accept(self.helper_listener)
            message = receive(sock)
            self.shape_valid &= (message.source, message.destination, message.connection_type,
                                 message.message_class, message.opcode, len(message.payload)) == (
                                     2, 1, 2, 1, 0x10006, 0x124)
            self._reply(sock, 0x10008, struct.pack('!I', self.backend_port), connection_type=2)
            self.stop.wait(5)
        except (OSError, EOFError):
            pass
        except Exception:
            self.failures.append('fixture helper failed')

    def _backend(self):
        try:
            sync = self._accept(self.backend_listener)
            one = receive(sync)
            self.registrations.append(one.connection_type)
            self.shape_valid &= one.opcode == 0x10006 and not one.payload
            events = self._accept(self.backend_listener)
            self.event_socket = events
            two = receive(events)
            self.registrations.append(two.connection_type)
            self.shape_valid &= two.opcode == 0x10006 and not two.payload
            # No registration ACK is sent.
            if self.mode == 'unknown_event':
                self._reply(events, 0xDEADBEEF, UNTRUSTED, connection_type=2)
            code_count = 0
            while not self.stop.is_set():
                message = receive(sync)
                pair = (message.message_class, message.opcode)
                self.ops.append(pair)
                if pair == (1, 4):
                    self.shape_valid &= len(message.payload) == 0x9d0
                    site_count, selected = struct.unpack_from('<Ii', message.payload, 0x9c8)
                    enabled = struct.unpack_from('<I', message.payload, 0x104)[0]
                    host = message.payload[0x108:0x188].split(b'\0', 1)[0]
                    port = struct.unpack_from('<I', message.payload, 0x188)[0]
                    endpoint = message.payload[4:0x104].split(b'\0', 1)[0]
                    self.shape_valid &= (site_count == 1 and selected == 0 and enabled == 0
                                         and endpoint == host + b':' + str(port).encode('ascii'))
                    if site_count == 0:
                        # Real Windows 0x4ab3c0 has no site task to run and
                        # reports 0x10001 locally, before authentication.
                        self._reply(sync, 0x10001)
                        continue
                    if self.mode == 'oversized':
                        sync.sendall(wire.HEADER.pack(4, 2, 1, 0, 0x10000, wire.MAX_PAYLOAD + 1))
                    else:
                        self._reply(sync, 0x1000B if self.mode == 'special_first' else 0x10000,
                                    bytes(0x1a4))
                elif pair == (1, 18):
                    self.shape_valid &= len(message.payload) == 0x88
                    self._reply(sync, 0x10004)
                elif pair == (3, 5):
                    expected_prefix = (0, 0, 1, 1, 2) if self.mode == 'saved_dynamic' else (0, 0, 0, 1, 2)
                    self.shape_valid &= (len(message.payload) == 0x7bc
                        and struct.unpack_from('<5I', message.payload) == expected_prefix
                        and message.payload[0x514:0x514 + len(USER)] == USER.encode())
                    if self.mode == 'saved_dynamic':
                        self.shape_valid &= (message.payload[0x694:0x714] == bytes(0x80)
                            and message.payload[0x734:0x734 + len(PROFILE_NAME)] == PROFILE_NAME.encode())
                    else:
                        self.shape_valid &= message.payload[0x694:0x694 + len(PASSWORD)] == PASSWORD.encode()
                    if self.mode in ('dynamic', 'repeat_challenge', 'saved_dynamic'):
                        self._reply(sync, 0x3000A)
                    elif self.mode == 'auth_rejected':
                        self._reply(sync, 0x30001, UNTRUSTED)
                    else:
                        words = [0] * 9
                        if self.mode == 'policy':
                            words[4] = 1
                        if self.mode == 'cache_policy':
                            words[5] = 1
                        if self.mode == 'password_notice':
                            words[7] = 1
                        if self.mode == 'password_modifiable':
                            words[6] = 1
                        self._reply(sync, 0x20000,
                                    b'' if self.mode == 'short_auth' else wire.AUTH_RESPONSE.pack(*words))
                elif pair == (3, 17):
                    code_count += 1
                    self.shape_valid &= (len(message.payload) == 0x7bc
                                         and message.payload[:4] == bytes(4)
                                         and message.payload[4:4 + len(CODE)] == CODE.encode()
                                         and message.payload[0x84:] == bytes(0x738))
                    if self.mode == 'repeat_challenge' and code_count == 1:
                        self._reply(sync, 0x3000A)
                    else:
                        self._reply(sync, 0x20000, bytes(32))
                elif pair == (5, 10):
                    self.shape_valid &= message.payload == bytes(12)
                    self._reply(sync, 0x70000)
                elif pair == (5, 20):
                    self._reply(sync, 0x70003)
                elif pair == (3, 8):
                    if self.mode == 'logout_unconfirmed':
                        sync.close()
                        break
                    self._reply(sync, 0xA0000)
                else:
                    self.failures.append('unexpected fixture opcode')
                    break
        except (OSError, EOFError):
            pass
        except Exception:
            self.failures.append('fixture backend failed')

    def prepare(self, profile):
        self.prepare_calls += 1
        self.release_prepare.wait(3)
        return {'service_port': self.service_port, 'install_directory': 'C:\\OfflineFixture\\',
                'login_user_ansi': b'offline-windows-user'}

    def wait_tunnel(self, profile, timeout):
        self.wait_calls += 1
        return self.mode != 'target_not_ready'

    def validate_backend(self, profile, port):
        self.validation_calls += 1
        return self.mode != 'wrong_owner' and port == self.backend_port

    def diagnostic(self, profile_id, phase, opcode, size):
        self.diagnostics.append((profile_id, phase, opcode, size))

    def __exit__(self, *_):
        self.stop.set()
        self.release_prepare.set()
        for sock in self.clients + self.listeners:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            sock.close()
        for thread in self.threads:
            thread.join(1)


class FastSession(WindowsSession):
    CONNECT_TIMEOUT = 1
    FIRST_TIMEOUT = 1
    AUTH_TIMEOUT = 1
    TUNNEL_TIMEOUT = 1
    OTP_TIMEOUT = 3
    TARGET_WAIT_TIMEOUT = 0.2
    CLEANUP_TIMEOUT = 0.3


class SessionTests(unittest.TestCase):
    def make_session(self, native):
        history = []
        session = FastSession({'id': 'fixture-profile', 'index': 9, 'gateway': '192.0.2.1',
                               'port': 443, 'name': 'Offline'}, history.append, native)
        self.addCleanup(session.disconnect)
        return session, history

    def wait_status(self, session, expected, timeout=3):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if session.status_snapshot().get('status') == expected:
                return
            time.sleep(0.01)
        self.fail('expected session state was not reached')

    def assert_safe(self, native, history):
        serialized = json.dumps([history, native.diagnostics], ensure_ascii=False)
        self.assertTrue(all(value not in serialized for value in (USER, PASSWORD, CODE, PROFILE_NAME, UNTRUSTED.decode())))
        self.assertTrue(native.shape_valid)
        self.assertEqual(native.failures, [])

    def test_plain_login_and_owned_disconnect(self):
        with FakeNative() as native:
            session, history = self.make_session(native)
            session.start(USER, PASSWORD)
            self.wait_status(session, 'connected')
            session.disconnect()
            self.assertEqual(session.status_snapshot(), {'status': 'disconnected'})
            self.assertEqual(native.registrations, [1, 2])
            self.assertEqual(native.ops, [(1, 4), (1, 18), (3, 5), (5, 10), (5, 20), (3, 8)])
            self.assertEqual(native.prepare_calls, 1)
            self.assert_safe(native, history)

    def test_dynamic_code_stays_in_same_backend(self):
        with FakeNative('dynamic') as native:
            session, history = self.make_session(native)
            session.start(USER, PASSWORD)
            self.wait_status(session, 'otp')
            self.assertEqual(session.status_snapshot()['challenge'], '动态口令')
            self.assertEqual(native.ops.count((3, 5)), 1)
            session.submit_otp(CODE)
            self.wait_status(session, 'connected')
            with self.assertRaises(SessionError):
                session.submit_otp(CODE)
            session.disconnect()
            self.assertEqual(native.ops.count((3, 17)), 1)
            self.assertEqual(native.prepare_calls, 1)
            self.assert_safe(native, history)

    def test_native_saved_profile_keeps_password_empty_and_supports_dynamic_code(self):
        with FakeNative('saved_dynamic') as native:
            session, history = self.make_session(native)
            session.start_saved(USER, PROFILE_NAME)
            self.wait_status(session, 'otp')
            self.assertEqual(native.ops.count((3, 5)), 1)
            session.submit_otp(CODE)
            self.wait_status(session, 'connected')
            session.disconnect()
            self.assertEqual(native.prepare_calls, 1)
            self.assertEqual(native.ops.count((3, 17)), 1)
            self.assert_safe(native, history)

    def test_saved_profile_codec_rejects_paths_and_oversized_names(self):
        message = wire.decode_frame(wire.saved_profile_login('192.0.2.1:443', USER, PROFILE_NAME))
        self.assertEqual(struct.unpack_from('<5I', message.payload), (0, 0, 1, 1, 2))
        self.assertEqual(message.payload[0x694:0x714], bytes(0x80))
        self.assertTrue(PROFILE_NAME not in repr(message))
        for bad_name in ('', '../profile', 'x\\profile', '.', '..', 'x\x00y', 'x' * 132):
            with self.assertRaises(wire.CodecError):
                wire.saved_profile_login('192.0.2.1:443', USER, bad_name)

    def test_another_challenge_requires_another_user_submission(self):
        with FakeNative('repeat_challenge') as native:
            session, history = self.make_session(native)
            session.start(USER, PASSWORD)
            self.wait_status(session, 'otp')
            session.submit_otp(CODE)
            self.wait_status(session, 'otp')
            time.sleep(0.05)
            self.assertEqual(native.ops.count((3, 17)), 1)
            session.submit_otp(CODE)
            self.wait_status(session, 'connected')
            session.disconnect()
            self.assertEqual(native.ops.count((3, 5)), 1)
            self.assertEqual(native.ops.count((3, 17)), 2)
            self.assert_safe(native, history)

    def test_post_auth_policy_and_expiry_stop_before_tunnel(self):
        for mode in ('policy', 'cache_policy', 'password_notice'):
            with self.subTest(mode=mode), FakeNative(mode) as native:
                session, history = self.make_session(native)
                session.start(USER, PASSWORD)
                self.wait_status(session, 'error')
                self.assertNotIn((5, 10), native.ops)
                self.assertIn((3, 8), native.ops)
                self.assertEqual(native.prepare_calls, 1)
                self.assert_safe(native, history)

    def test_password_modifiable_is_not_forced_expiry(self):
        with FakeNative('password_modifiable') as native:
            session, history = self.make_session(native)
            session.start(USER, PASSWORD)
            self.wait_status(session, 'connected')
            session.disconnect()
            self.assert_safe(native, history)

    def test_malformed_and_special_replies_fail_closed(self):
        for mode in ('oversized', 'special_first', 'short_auth', 'auth_rejected'):
            with self.subTest(mode=mode), FakeNative(mode) as native:
                session, history = self.make_session(native)
                session.start(USER, PASSWORD)
                self.wait_status(session, 'error')
                self.assertNotIn((5, 10), native.ops)
                self.assertLessEqual(native.ops.count((3, 5)), 1)
                self.assertEqual(native.prepare_calls, 1)
                self.assert_safe(native, history)

    def test_disconnect_waiting_for_code_does_not_send_code_or_password_again(self):
        with FakeNative('dynamic') as native:
            session, history = self.make_session(native)
            session.start(USER, PASSWORD)
            self.wait_status(session, 'otp')
            session.disconnect()
            self.assertEqual(session.status_snapshot()['status'], 'disconnected')
            self.assertEqual(native.ops.count((3, 5)), 1)
            self.assertNotIn((3, 17), native.ops)
            self.assertNotIn((5, 10), native.ops)
            self.assert_safe(native, history)

    def test_start_is_async_and_cancelled_prepare_sends_no_rpc(self):
        with FakeNative() as native:
            native.release_prepare.clear()
            session, history = self.make_session(native)
            started = time.monotonic()
            session.start(USER, PASSWORD)
            self.assertLess(time.monotonic() - started, 0.3)
            with self.assertRaises(SessionError):
                session.start(USER, PASSWORD)
            closer = threading.Thread(target=session.disconnect)
            closer.start()
            time.sleep(0.03)
            native.release_prepare.set()
            closer.join(2)
            self.wait_status(session, 'disconnected')
            self.assertEqual(native.ops, [])
            self.assertEqual(native.registrations, [])
            self.assert_safe(native, history)

    def test_unknown_async_payload_is_not_interpreted_or_exposed(self):
        with FakeNative('unknown_event') as native:
            session, history = self.make_session(native)
            session.start(USER, PASSWORD)
            self.wait_status(session, 'connected')
            self.assertTrue(any(row[2] == 0xDEADBEEF for row in native.diagnostics))
            session.disconnect()
            self.assert_safe(native, history)

    def test_tunnel_reply_requires_environment_readiness(self):
        with FakeNative('target_not_ready') as native:
            session, history = self.make_session(native)
            session.start(USER, PASSWORD)
            self.wait_status(session, 'error')
            self.assertFalse(any(row['status'] == 'connected' for row in history))
            self.assertIn((5, 20), native.ops)
            self.assert_safe(native, history)

    def test_unstarted_disconnect_and_bad_input_are_local(self):
        with FakeNative() as native:
            session, history = self.make_session(native)
            with self.assertRaises(SessionError):
                session.start(USER, 'x' * 128)
            with self.assertRaises(SessionError):
                session.submit_otp(CODE)
            session.disconnect()
            self.assertEqual(native.prepare_calls, 0)
            self.assertEqual(native.ops, [])
            self.assert_safe(native, history)

    def test_closed_session_rejects_normal_and_saved_start_before_prepare(self):
        with FakeNative() as native:
            session, history = self.make_session(native)
            session.disconnect()
            with self.assertRaises(SessionError):
                session.start(USER, PASSWORD)
            with self.assertRaises(SessionError):
                session.start_saved(USER, PROFILE_NAME)
            self.assertEqual(session.status_snapshot()['status'], 'disconnected')
            self.assertEqual(native.prepare_calls, 0)
            self.assertEqual(native.registrations, [])
            self.assert_safe(native, history)

    def test_delayed_start_cancelled_before_entry_never_prepares(self):
        with FakeNative() as native:
            entered, release = threading.Event(), threading.Event()
            history, rejected = [], []

            class DelayedStart(FastSession):
                def start(self, username, password):
                    entered.set()
                    release.wait(2)
                    return super().start(username, password)

            session = DelayedStart({'id': 'fixture-profile', 'index': 9, 'gateway': '192.0.2.1',
                                    'port': 443}, history.append, native)
            self.addCleanup(session.disconnect)

            def start_later():
                try:
                    session.start(USER, PASSWORD)
                except SessionError:
                    rejected.append(True)

            starter = threading.Thread(target=start_later)
            starter.start()
            self.assertTrue(entered.wait(1))
            session.disconnect()
            release.set()
            starter.join(1)
            self.assertFalse(starter.is_alive())
            self.assertEqual(rejected, [True])
            self.assertEqual(native.prepare_calls, 0)
            self.assertEqual(native.registrations, [])
            self.assertEqual(session.status_snapshot()['status'], 'disconnected')
            self.assert_safe(native, history)

    def test_cancelled_worker_checks_before_environment_prepare(self):
        with FakeNative() as native:
            entered, release = threading.Event(), threading.Event()
            history, failures = [], []

            class DelayedWorker(FastSession):
                def _bootstrap(self):
                    entered.set()
                    release.wait(2)
                    return super()._bootstrap()

            session = DelayedWorker({'id': 'fixture-profile', 'index': 9, 'gateway': '192.0.2.1',
                                     'port': 443}, history.append, native)
            self.addCleanup(session.disconnect)
            session.start(USER, PASSWORD)
            self.assertTrue(entered.wait(1))

            def cancel():
                try:
                    session.disconnect()
                except SessionError:
                    failures.append(True)

            closer = threading.Thread(target=cancel)
            closer.start()
            deadline = time.monotonic() + 1
            while not session._stop.is_set() and time.monotonic() < deadline:
                time.sleep(0.005)
            self.assertTrue(session._stop.is_set())
            release.set()
            closer.join(1)
            self.assertFalse(closer.is_alive())
            self.assertEqual(failures, [])
            self.assertEqual(native.prepare_calls, 0)
            self.assertEqual(native.registrations, [])
            self.assertEqual(session.status_snapshot()['status'], 'disconnected')
            self.assert_safe(native, history)

    def test_disconnect_between_worker_registration_and_start_is_local(self):
        with FakeNative() as native:
            entered, release = threading.Event(), threading.Event()
            history, rejected, failures = [], [], []

            def notify(event):
                history.append(event)
                if event['status'] == 'authenticating':
                    entered.set()
                    release.wait(2)

            session = FastSession({'id': 'fixture-profile', 'index': 9, 'gateway': '192.0.2.1',
                                   'port': 443}, notify, native)
            self.addCleanup(session.disconnect)

            def start_later():
                try:
                    session.start(USER, PASSWORD)
                except SessionError:
                    rejected.append(True)
                except Exception:
                    failures.append(True)

            starter = threading.Thread(target=start_later)
            starter.start()
            self.assertTrue(entered.wait(1))
            try:
                session.disconnect()
            except Exception:
                failures.append(True)
            release.set()
            starter.join(1)
            self.assertFalse(starter.is_alive())
            self.assertEqual(failures, [])
            self.assertEqual(rejected, [True])
            self.assertEqual(native.prepare_calls, 0)
            self.assertEqual(native.registrations, [])
            self.assertEqual(session.status_snapshot()['status'], 'disconnected')
            self.assert_safe(native, history)

    def test_bootstrap_failure_releases_optional_owned_anchor(self):
        with FakeNative('wrong_owner') as native:
            released = []
            native.release_anchor = released.append
            session, history = self.make_session(native)
            session.start(USER, PASSWORD)
            self.wait_status(session, 'error')
            self.assertEqual(released, ['fixture-profile'])
            self.assertEqual(native.registrations, [])
            self.assert_safe(native, history)

    def test_unexpected_channel_cleanup_failure_still_releases_anchor(self):
        with FakeNative() as native:
            released = []
            native.release_anchor = released.append
            session, history = self.make_session(native)

            def fail():
                raise RuntimeError('fixture non-sensitive cleanup failure')

            session._cleanup_owned_channels = fail
            self.assertFalse(session._cleanup())
            self.assertEqual(released, ['fixture-profile'])
            self.assertEqual(native.prepare_calls, 0)
            self.assert_safe(native, history)

    def test_unconfirmed_logout_is_not_reported_as_disconnected(self):
        with FakeNative('logout_unconfirmed') as native:
            history = []
            session = FastSession({'id': 'fixture-profile', 'index': 9, 'gateway': '192.0.2.1',
                                   'port': 443}, history.append, native)
            session.start(USER, PASSWORD)
            self.wait_status(session, 'connected')
            with self.assertRaises(SessionError):
                session.disconnect()
            self.assertEqual(session.status_snapshot()['status'], 'error')
            self.assert_safe(native, history)

    def test_wrong_backend_owner_is_rejected_before_registration(self):
        with FakeNative('wrong_owner') as native:
            session, history = self.make_session(native)
            session.start(USER, PASSWORD)
            self.wait_status(session, 'error')
            self.assertEqual(native.validation_calls, 1)
            self.assertEqual(native.registrations, [])
            self.assertEqual(native.ops, [])
            self.assert_safe(native, history)

    def test_event_channel_loss_fails_the_owned_session(self):
        with FakeNative() as native:
            session, history = self.make_session(native)
            session.start(USER, PASSWORD)
            self.wait_status(session, 'connected')
            native.event_socket.shutdown(socket.SHUT_RDWR)
            native.event_socket.close()
            self.wait_status(session, 'error')
            self.assertIn((5, 20), native.ops)
            self.assertIn((3, 8), native.ops)
            self.assert_safe(native, history)


if __name__ == '__main__':
    unittest.main()
