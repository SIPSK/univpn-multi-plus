"""Exercise the real loopback HTTP handler using fake native sessions only.

Each test owns a temporary Manager, a random local port and a server thread.
No installed client, adapter, native RPC connection or real session is used.
"""
from __future__ import annotations

import contextlib
from http.cookies import SimpleCookie
import http.client
import io
import json
from pathlib import Path
import socket
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core import AppError, Manager  # noqa: E402
from server import APP_ID, Handler, LocalServer, MAX_BODY  # noqa: E402
from test_core_preferences import MemoryStore, FakeStartup  # noqa: E402

UNSET = object()
PASSWORD = "test-only-password-7ac9-not-a-real-secret"
OTP = "test-only-dynamic-token-836728"
USERNAME = "test-only-account"


class FakeSession:
    def __init__(self, bridge, profile, notify):
        self.bridge = bridge
        self.profile = profile
        self.notify = notify
        self.start_arguments = None
        self.otp_argument = None
        self.disconnected = False

    def start(self, username, password):
        self.start_arguments = (username, password)
        if self.bridge.fail_start:
            raise RuntimeError("native exception contains " + password)
        self.notify({"status": "otp", "challenge": {"kind": "dynamic"}})

    def submit_otp(self, code):
        self.otp_argument = code
        if self.bridge.fail_otp:
            raise RuntimeError("native exception contains " + code)
        self.notify({"status": "authenticated"})

    def disconnect(self):
        self.disconnected = True
        self.notify({"status": "disconnected"})


class FakeBridge:
    available = True

    def __init__(self):
        self.next_index = 3
        self.sessions = []
        self.fail_start = False
        self.fail_otp = False
        self.external_disconnects = []
        self.environment_checks = 0

    def check_environment(self):
        self.environment_checks += 1
        return {"ok": True, "phase": "complete", "exitCode": 0}

    def create_instance(self):
        index = self.next_index
        self.next_index += 1
        return index

    def session(self, profile, notify):
        session = FakeSession(self, profile, notify)
        self.sessions.append(session)
        return session

    def disconnect_external(self, profile):
        self.external_disconnects.append(profile["id"])


class HttpSecurityTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="vpn-http-test-")
        self.runtime = Path(self.directory.name)
        self.bridge = FakeBridge()
        self.store = MemoryStore()
        self.startup = FakeStartup()
        self.manager = Manager(self.runtime, bridge=self.bridge, inspect=False,
                               credentials=self.store, startup=self.startup)
        self.manager.profiles = [
            {"id": "alpha", "name": "Test", "gateway": "192.0.2.10", "port": 443, "index": 1, "autoConnect": False},
            {"id": "beta", "name": "", "gateway": "192.0.2.20", "port": 49999, "index": 2, "autoConnect": False},
        ]
        self.manager.inventory = {"installed": True, "records": [{"index": 2, "status": "Ready", "tapGuid": "beta-tap"}]}
        self.manager._save()
        self.stdout = io.StringIO()
        self.stderr = io.StringIO()
        self.output_stack = contextlib.ExitStack()
        self.output_stack.enter_context(contextlib.redirect_stdout(self.stdout))
        self.output_stack.enter_context(contextlib.redirect_stderr(self.stderr))
        self.server = LocalServer(self.runtime, self.manager, port=0)
        self.thread = threading.Thread(
            target=self.server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True
        )
        self.thread.start()

    def tearDown(self):
        if self.thread.is_alive():
            self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)
        self.manager.close()
        self.output_stack.close()
        self.directory.cleanup()

    def request(self, method, target, *, authorized=True, value=UNSET, raw=None, headers=None):
        supplied = dict(headers or {})
        if authorized:
            supplied.setdefault("X-VPN-Token", self.server.token)
        if value is not UNSET:
            if raw is not None:
                raise ValueError("Use either a JSON value or raw body")
            raw = json.dumps(value, ensure_ascii=False).encode("utf-8")
            supplied.setdefault("Content-Type", "application/json")
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=3)
        try:
            connection.request(method, target, body=raw, headers=supplied)
            response = connection.getresponse()
            return response.status, dict(response.getheaders()), response.read()
        finally:
            connection.close()

    def json_request(self, method, target, **kwargs):
        status, headers, body = self.request(method, target, **kwargs)
        return status, headers, json.loads(body)

    def assert_no_secrets(self, *values):
        files = "\n".join(p.read_text("utf-8") for p in self.runtime.glob("*") if p.is_file())
        material = "\n".join(
            [files, json.dumps(self.manager.state(), ensure_ascii=False), self.stdout.getvalue(), self.stderr.getvalue()]
            + [v.decode("utf-8", errors="replace") if isinstance(v, bytes) else str(v) for v in values]
        )
        for secret in (PASSWORD, OTP, USERNAME):
            self.assertNotIn(secret, material)

    def test_bind_and_static_response_security_headers(self):
        self.assertEqual(self.server.server_address[0], "127.0.0.1")
        status, headers, body = self.request("GET", "/", authorized=False)
        self.assertEqual(status, 200)
        self.assertNotIn(self.server.token.encode(), body)
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertEqual(headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(headers["Referrer-Policy"], "no-referrer")
        self.assertEqual(headers["X-Frame-Options"], "DENY")
        self.assertIn("frame-ancestors 'none'", headers["Content-Security-Policy"])
        self.assertIn("script-src 'self'", headers["Content-Security-Policy"])
        self.assertNotIn("Access-Control-Allow-Origin", headers)

    def test_health_exposes_only_public_information(self):
        status, _, value = self.json_request("GET", "/api/health", authorized=False)
        self.assertEqual(status, 200)
        self.assertEqual(value["app"], APP_ID)
        self.assertNotIn("token", value)
        self.assertNotIn("profiles", value)

    def test_state_and_all_mutations_require_token(self):
        requests = [
            ("GET", "/api/state"), ("GET", "/api/notifications"), ("GET", "/api/environment"), ("POST", "/api/session"),
            ("POST", "/api/profiles"), ("POST", "/api/profiles/alpha/connect"),
            ("POST", "/api/profiles/alpha/expand-connect"),
            ("POST", "/api/profiles/alpha/otp"), ("POST", "/api/profiles/alpha/disconnect"),
            ("PATCH", "/api/profiles/alpha"), ("DELETE", "/api/profiles/alpha"),
            ("DELETE", "/api/profiles/alpha/credential"),
            ("POST", "/api/settings"), ("POST", "/api/auto-connect"),
            ("POST", "/api/shutdown"),
        ]
        for method, target in requests:
            with self.subTest(method=method, target=target):
                status, _, body = self.request(method, target, authorized=False, value={} if method != "GET" else UNSET)
                self.assertEqual(status, 401)
                self.assertNotIn(self.server.token.encode(), body)
        self.assertEqual(len(self.manager.profiles), 2)
        self.assertEqual(self.bridge.sessions, [])
        self.assertTrue(self.thread.is_alive())

    def test_wrong_token_rejected(self):
        status, _, _ = self.request("GET", "/api/state", authorized=False, headers={"X-VPN-Token": "wrong"})
        self.assertEqual(status, 401)

    def test_early_unauthorized_delete_with_delayed_body_returns_401_without_tcp_reset(self):
        raw = json.dumps({'username': USERNAME, 'password': PASSWORD, 'code': OTP}).encode('utf-8')
        received = []
        with patch.object(Handler, '_body', side_effect=AssertionError('unauthorized JSON parsing')), \
                patch.object(self.manager, 'remove') as remove:
            for _ in range(4):
                connection = http.client.HTTPConnection('127.0.0.1', self.server.server_port, timeout=3)
                try:
                    connection.putrequest('DELETE', '/api/profiles/alpha')
                    connection.putheader('Content-Type', 'application/json')
                    connection.putheader('Content-Length', str(len(raw)))
                    connection.endheaders()
                    # Reproduce the Windows race: headers cause rejection,
                    # then body arrives before the client consumes the 401.
                    time.sleep(0.02)
                    connection.send(raw)
                    response = connection.getresponse()
                    self.assertEqual(response.status, 401)
                    self.assertEqual(response.getheader('Connection'), 'close')
                    received.append(response.read())
                finally:
                    connection.close()
            remove.assert_not_called()
        self.assertEqual(len(self.manager.profiles), 2)
        self.assertEqual(self.bridge.sessions, [])
        self.assertEqual(self.bridge.external_disconnects, [])
        self.assert_no_secrets(*received)

    def test_rejected_body_discard_is_bounded_and_does_not_read_chunked_or_oversized_data(self):
        from email.message import Message

        class RawBody:
            def read(self, length):
                raise AssertionError('an unbounded or already parsed body must not be read')

        class Connection:
            def settimeout(self, timeout):
                raise AssertionError('no wait is needed for an unsupported body')

        for fields in ({'Content-Length': str(MAX_BODY + 1)}, {'Content-Length': '-1'},
                       {'Content-Length': 'invalid'}, {'Content-Length': '2', 'Transfer-Encoding': 'chunked'}):
            handler = object.__new__(Handler)
            handler.headers = Message()
            for key, value in fields.items():
                handler.headers[key] = value
            handler.connection, handler.rfile = Connection(), RawBody()
            handler._request_body_consumed = False
            handler._drain_rejected_body()
        handler.headers = Message()
        handler.headers['Content-Length'] = '2'
        handler._request_body_consumed = True
        handler._drain_rejected_body()

    def test_rejection_does_not_wait_indefinitely_for_a_missing_small_body(self):
        completed = threading.Event()
        original = Handler._drain_rejected_body
        durations = []

        def record(handler):
            started = time.monotonic()
            try:
                return original(handler)
            finally:
                durations.append(time.monotonic() - started)
                completed.set()

        connection = socket.create_connection(('127.0.0.1', self.server.server_port), timeout=2)
        try:
            with patch.object(Handler, '_drain_rejected_body', record):
                request = ('DELETE /api/profiles/alpha HTTP/1.1\r\nHost: 127.0.0.1:'
                           + str(self.server.server_port) + '\r\nContent-Type: application/json\r\n'
                           + 'Content-Length: 2\r\n\r\n').encode('ascii')
                connection.sendall(request)
                response = connection.recv(4096)
                self.assertTrue(response.startswith(b'HTTP/1.1 401 '))
                self.assertTrue(completed.wait(1.5))
                self.assertLess(durations[0], 1.0)
        finally:
            connection.close()
        self.assertEqual(self.bridge.sessions, [])

    def test_rejected_body_deadline_is_total_even_if_bytes_keep_arriving(self):
        from email.message import Message

        class Trickle:
            received = 0

            def read1(self, length):
                self.received += 1
                if self.received > 10:
                    raise AssertionError('discard continued without a total deadline')
                return b'x'

        class Connection:
            timeouts = []

            def settimeout(self, timeout):
                self.timeouts.append(timeout)

        handler = object.__new__(Handler)
        handler.headers = Message()
        handler.headers['Content-Length'] = str(MAX_BODY)
        handler._request_body_consumed = False
        handler.rfile, handler.connection = Trickle(), Connection()
        ticks = iter((0.0, 0.04, 0.08, 0.12))
        with patch('server.time.monotonic', side_effect=lambda: next(ticks)):
            handler._drain_rejected_body()
        self.assertGreater(handler.rfile.received, 0)
        self.assertLess(handler.rfile.received, MAX_BODY)
        self.assertTrue(all(0 < value <= 0.1 for value in handler.connection.timeouts))

    def test_host_boundary_applies_to_reads_and_writes(self):
        hosts = ["evil.example", "localhost:" + str(self.server.server_port), "127.0.0.1:1", "127.0.0.1:80@evil.example"]
        for host in hosts:
            for method, target in [("GET", "/api/state"), ("POST", "/api/session")]:
                with self.subTest(host=host, method=method):
                    status, _, _ = self.request(method, target, headers={"Host": host}, value={} if method == "POST" else UNSET)
                    self.assertEqual(status, 403)

    def test_missing_host_is_rejected(self):
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=3)
        try:
            connection.putrequest("GET", "/api/state", skip_host=True)
            connection.putheader("X-VPN-Token", self.server.token)
            connection.endheaders()
            response = connection.getresponse()
            self.assertEqual(response.status, 403)
            response.read()
        finally:
            connection.close()

    def test_origin_boundary(self):
        for origin in ["http://evil.example", "null", "http://127.0.0.1:1", self.server.origin.replace("http:", "https:")]:
            with self.subTest(origin=origin):
                status, _, _ = self.request("POST", "/api/session", headers={"Origin": origin}, value={})
                self.assertEqual(status, 403)
        status, _, _ = self.request("POST", "/api/session", headers={"Origin": self.server.origin}, value={})
        self.assertEqual(status, 200)

    def test_fetch_metadata_boundary(self):
        for site in ["cross-site", "same-site", "unexpected"]:
            with self.subTest(site=site):
                status, _, _ = self.request("GET", "/api/state", headers={"Sec-Fetch-Site": site})
                self.assertEqual(status, 403)
        for site in ["same-origin", "none"]:
            with self.subTest(site=site):
                status, _, _ = self.request("GET", "/api/state", headers={"Sec-Fetch-Site": site})
                self.assertEqual(status, 200)

    def test_cookie_bootstrap_restores_page_refresh(self):
        status, headers, _ = self.json_request("POST", "/api/session", value={})
        self.assertEqual(status, 200)
        cookie = SimpleCookie(headers["Set-Cookie"])["vpn_session"]
        self.assertTrue(cookie["httponly"])
        self.assertEqual(cookie["samesite"], "Strict")
        self.assertEqual(cookie["path"], "/")
        status, response_headers, data = self.json_request(
            "GET", "/api/bootstrap", authorized=False,
            headers={"Cookie": f"vpn_session={cookie.value}", "Origin": self.server.origin, "Sec-Fetch-Site": "same-origin", "Sec-Fetch-Dest": "empty"},
        )
        self.assertEqual(status, 200)
        self.assertEqual(data["token"], self.server.token)
        self.assertEqual(response_headers["Cache-Control"], "no-store")
        status, _, _ = self.request("GET", "/api/state", authorized=False, headers={"X-VPN-Token": data["token"]})
        self.assertEqual(status, 200)

    def test_bootstrap_requires_cookie_and_rejects_navigation(self):
        for cookie in [None, "vpn_session=wrong", "unrelated=valid"]:
            with self.subTest(cookie=cookie):
                headers = {} if cookie is None else {"Cookie": cookie}
                status, _, body = self.request("GET", "/api/bootstrap", headers=headers)
                self.assertEqual(status, 401)
                self.assertNotIn(self.server.token.encode(), body)
        status, _, _ = self.request(
            "GET", "/api/bootstrap", authorized=False,
            headers={"Cookie": f"vpn_session={self.server.browser_session}", "Sec-Fetch-Dest": "document"},
        )
        self.assertEqual(status, 403)

    def test_unknown_and_traversal_paths_do_not_expose_files(self):
        for target in ["/server.py", "/core.py", "/profiles.json", "/session.token", "/../core.py", "/%2e%2e/core.py", "/%2e%2e%5ccore.py", "/api/profiles/../state", "/api/profiles/alpha%2f..%2fstate"]:
            with self.subTest(target=target):
                method = "POST" if target.startswith("/api/profiles/") else "GET"
                status, _, body = self.request(method, target, value={} if method == "POST" else UNSET)
                self.assertEqual(status, 404)
                self.assertNotIn(self.server.token.encode(), body)
                self.assertNotIn(b'"gateway"', body)

    def test_query_strings_cannot_carry_authentication_data(self):
        for method, target in [("GET", "/api/state?password=" + PASSWORD), ("POST", "/api/session?code=" + OTP)]:
            with self.subTest(method=method):
                status, _, body = self.request(method, target, value={} if method == "POST" else UNSET)
                self.assertEqual(status, 400)
                self.assert_no_secrets(body)

    def test_oversized_negative_and_chunked_requests_are_rejected(self):
        cases = [
            (b"", {"Content-Length": str(MAX_BODY + 1)}, 413),
            (b"", {"Content-Length": "-1"}, 413),
            (b"", {"Content-Length": "invalid"}, 400),
            (b"0\r\n\r\n", {"Transfer-Encoding": "chunked"}, 413),
        ]
        for raw, headers, expected in cases:
            with self.subTest(headers=headers):
                status, _, _ = self.request("POST", "/api/session", raw=raw, headers=headers)
                self.assertEqual(status, expected)

    def test_non_json_and_invalid_json_are_rejected(self):
        cases = [
            (b"{}", "text/plain", 415),
            (b"{", "application/json", 400),
            (b"\xff", "application/json", 400),
            (b"[]", "application/json", 400),
            (b"null", "application/json", 400),
            (b'"scalar"', "application/json", 400),
        ]
        for raw, content_type, expected in cases:
            with self.subTest(content_type=content_type, raw=raw):
                status, _, _ = self.request("POST", "/api/session", raw=raw, headers={"Content-Type": content_type})
                self.assertEqual(status, expected)

    def test_credentials_and_dynamic_code_never_enter_public_state_files_or_logs(self):
        status, _, first = self.request("POST", "/api/profiles/alpha/connect", value={"username": USERNAME, "password": PASSWORD})
        self.assertEqual(status, 200)
        self.assertEqual(self.bridge.sessions[0].start_arguments, (USERNAME, PASSWORD))
        status, _, state_before = self.request("GET", "/api/state")
        self.assertEqual(status, 200)
        status, _, second = self.request("POST", "/api/profiles/alpha/otp", value={"code": OTP})
        self.assertEqual(status, 200)
        self.assertEqual(self.bridge.sessions[0].otp_argument, OTP)
        status, _, state_after = self.request("GET", "/api/state")
        self.assertEqual(status, 200)
        self.assert_no_secrets(first, second, state_before, state_after)
        persisted = json.loads(self.manager.path.read_text("utf-8"))
        self.assertTrue(all(set(item) == {"id", "name", "gateway", "port", "index", "autoConnect", "useLegacyCredential"} for item in persisted))
        self.assertTrue(all(type(item["useLegacyCredential"]) is bool for item in persisted))

    def test_extra_secret_fields_are_not_persisted_on_profile_create(self):
        status, _, body = self.request("POST", "/api/profiles", value={
            "name": "Test third", "gateway": "vpn.example.test", "port": 443,
            "username": USERNAME, "password": PASSWORD, "code": OTP,
        })
        self.assertEqual(status, 201)
        self.assert_no_secrets(body)

    def test_native_exceptions_do_not_reflect_password_or_code(self):
        self.bridge.fail_start = True
        status, _, body = self.request("POST", "/api/profiles/alpha/connect", value={"username": USERNAME, "password": PASSWORD})
        self.assertEqual(status, 409)
        self.assert_no_secrets(body)
        self.bridge.fail_start = False
        self.manager.sessions.clear()
        self.manager.events.clear()
        status, _, _ = self.request("POST", "/api/profiles/alpha/connect", value={"username": USERNAME, "password": PASSWORD})
        self.assertEqual(status, 200)
        self.bridge.fail_otp = True
        status, _, body = self.request("POST", "/api/profiles/alpha/otp", value={"code": OTP})
        self.assertEqual(status, 409)
        self.assert_no_secrets(body)

    def test_shutdown_is_blocked_for_every_owned_active_state(self):
        session = FakeSession(self.bridge, self.manager.profiles[0], lambda event: None)
        self.manager.sessions["alpha"] = session
        for active in ["connected", "starting", "authenticating", "otp", "authenticated", "disconnecting"]:
            with self.subTest(status=active):
                self.manager.events["alpha"] = {"status": active}
                status, _, _ = self.request("POST", "/api/shutdown", value={})
                self.assertEqual(status, 409)
                self.assertTrue(self.thread.is_alive())
                status, _, _ = self.request("GET", "/api/health", authorized=False)
                self.assertEqual(status, 200)
        self.assertFalse(session.disconnected)

    def test_shutdown_with_only_external_connection_never_disconnects_it(self):
        self.manager.inventory = {
            "installed": True,
            "adapters": [{"guid": "external-test-adapter", "up": True, "addresses": ["192.0.2.50"]}],
            "peers": [{"process": "UniVPNCS", "gateway": "192.0.2.10", "port": 443}],
        }
        self.assertEqual(self.manager.state()["profiles"][0]["status"], "connected")
        self.assertEqual(self.manager.sessions, {})
        status, _, _ = self.request("POST", "/api/shutdown", value={})
        self.assertEqual(status, 200)
        self.thread.join(timeout=3)
        self.assertFalse(self.thread.is_alive())
        self.assertEqual(self.bridge.external_disconnects, [])
        self.assertEqual(self.bridge.sessions, [])
        self.assertTrue(self.manager.inventory["adapters"][0]["up"])

    def test_options_does_not_enable_cors(self):
        status, headers, _ = self.request("OPTIONS", "/api/state", authorized=False, headers={"Origin": "http://evil.example"})
        self.assertEqual(status, 403)
        self.assertNotIn("Access-Control-Allow-Origin", headers)

    def test_malformed_token_is_a_controlled_authentication_rejection(self):
        # Header values can legally contain these Latin-1 bytes; they must not
        # cause an unhandled compare_digest TypeError or a server traceback.
        status, _, body = self.request("GET", "/api/state", authorized=False, headers={"X-VPN-Token": "bad-\u0080"})
        self.assertEqual(status, 401)
        self.assertNotIn(b"Traceback", body)
        self.assertNotIn("Traceback", self.stderr.getvalue())

    def test_notifications_are_token_authorized_nonsecret_and_vault_free(self):
        self.manager._event("alpha", {"status": "otp", "challenge": PASSWORD})
        with patch.object(self.store, "read", side_effect=AssertionError("Vault must not be read")), \
             patch.object(self.startup, "get_enabled", side_effect=AssertionError("Startup must not be read")):
            status, _, value = self.json_request("GET", "/api/notifications")
        self.assertEqual(status, 200)
        self.assertEqual(set(value), {"profiles"})
        self.assertEqual(value["profiles"][0], {"id": "alpha", "status": "otp", "challengeId": 1})
        self.assertTrue(all(set(p) == {"id", "status", "challengeId"} for p in value["profiles"]))
        text = json.dumps(value) + self.stdout.getvalue() + self.stderr.getvalue()
        for secret in (PASSWORD, OTP, USERNAME, "192.0.2.10", '"challenge":', "gateway"):
            self.assertNotIn(secret, text)
        for headers in ({"Origin": "http://evil.example"}, {"Host": "evil.example"}, {"Sec-Fetch-Site": "cross-site"}):
            with self.subTest(headers=headers):
                status, _, _ = self.request("GET", "/api/notifications", headers=headers)
                self.assertEqual(status, 403)

    def test_saved_login_and_forget_use_memory_vault_without_public_secret_material(self):
        status, _, body = self.request("POST", "/api/profiles/alpha/connect", value={
            "username": USERNAME, "password": PASSWORD, "remember": True, "autoConnect": True,
        })
        self.assertEqual(status, 200)
        self.assertEqual(self.store.saves, [])
        self.assert_no_secrets(body)
        status, _, body = self.request("POST", "/api/profiles/alpha/otp", value={"code": OTP})
        self.assertEqual(status, 200)
        self.assertEqual(self.store.saves, ["alpha"])
        self.assertTrue(self.manager.state()["profiles"][0]["hasSavedCredential"])
        self.assert_no_secrets(body)
        status, _, body = self.request("DELETE", "/api/profiles/alpha/credential", value={})
        self.assertEqual(status, 200)
        profile = self.manager.state()["profiles"][0]
        self.assertFalse(profile["hasSavedCredential"])
        self.assertFalse(profile["autoConnect"])
        self.assertIn("alpha", self.manager.sessions)
        self.assert_no_secrets(body)

    def test_preference_routes_are_independent_do_not_connect_and_keep_origin_boundary(self):
        for target, body in [("/api/settings", {"startup": True}), ("/api/auto-connect", {"enabled": True})]:
            with self.subTest(target=target):
                status, _, _ = self.request("POST", target, value=body, headers={"Origin": "http://evil.example"})
                self.assertEqual(status, 403)
        self.assertFalse(self.startup.enabled)
        self.assertTrue(all(not p["autoConnect"] for p in self.manager.profiles))
        status, _, _ = self.request("POST", "/api/settings", value={"startup": True})
        self.assertEqual(status, 200)
        self.assertTrue(self.startup.enabled)
        self.assertTrue(all(not p["autoConnect"] for p in self.manager.profiles))
        status, _, _ = self.request("POST", "/api/auto-connect", value={"enabled": True})
        self.assertEqual(status, 200)
        self.assertTrue(all(p["autoConnect"] for p in self.manager.profiles))
        self.assertTrue(self.startup.enabled)
        original = dict(self.manager.profiles[0])
        status, _, _ = self.request("PATCH", "/api/profiles/alpha", value={"autoConnect": False})
        self.assertEqual(status, 200)
        self.assertEqual(self.manager.profiles[0], {**original, "autoConnect": False})
        self.assertEqual(self.bridge.sessions, [])
        self.assertEqual(self.bridge.external_disconnects, [])
        self.assert_no_secrets()

    def test_environment_route_requires_token_and_request_boundaries_before_fake_probe(self):
        status, _, _ = self.request("GET", "/api/environment", authorized=False)
        self.assertEqual(status, 401)
        for headers in ({"Host": "evil.example"}, {"Origin": "http://evil.example"}, {"Sec-Fetch-Site": "cross-site"}):
            with self.subTest(headers=headers):
                status, _, _ = self.request("GET", "/api/environment", headers=headers)
                self.assertEqual(status, 403)
        self.assertEqual(self.bridge.environment_checks, 0)
        status, _, data = self.json_request("GET", "/api/environment")
        self.assertEqual(status, 200)
        self.assertEqual(data, {"ok": True, "phase": "complete", "exitCode": 0})
        self.assertEqual(self.bridge.environment_checks, 1)
        self.assertEqual(self.bridge.sessions, [])
        self.assertEqual(self.bridge.external_disconnects, [])
        self.assert_no_secrets(json.dumps(data))

    def test_private_source_links_never_enter_public_state_or_static_routes(self):
        filename = 'private-source-identity.ini'
        source_id = 'a' * 64
        self.manager.source_links['alpha'] = {'sourceId': source_id, 'sourceIndex': 1, 'sourceName': filename}
        self.manager._save_sources()
        status, _, body = self.request('GET', '/api/state')
        self.assertEqual(status, 200)
        for private in (filename, source_id, 'sourceId', 'sourceIndex', 'sourceName'):
            self.assertNotIn(private.encode(), body)
            self.assertNotIn(private, self.manager.path.read_text('utf-8'))
        status, _, body = self.request('GET', '/source-links.json')
        self.assertEqual(status, 404)
        self.assertNotIn(filename.encode(), body)

    def test_expansion_route_requires_boundaries_before_any_manager_action(self):
        with patch.object(self.manager, "expand_connect", return_value={"ok": True}, create=True) as expand:
            for authorized, headers in [(False, {}), (True, {"Origin": "http://evil.example"}),
                                        (True, {"Host": "evil.example"}), (True, {"Sec-Fetch-Site": "cross-site"})]:
                status, _, _ = self.request("POST", "/api/profiles/alpha/expand-connect",
                                            value={}, authorized=authorized, headers=headers)
                self.assertIn(status, {401, 403})
            expand.assert_not_called()
            status, _, data = self.json_request("POST", "/api/profiles/alpha/expand-connect", value={})
            self.assertEqual((status, data), (200, {"ok": True}))
            expand.assert_called_once_with("alpha", {})
        self.assertEqual(self.bridge.sessions, [])
        self.assertEqual(self.bridge.external_disconnects, [])

    def test_structured_flow_errors_expose_only_fixed_codes_and_public_ids(self):
        error = AppError("需要新增连接", 409)
        error.code = "expansion_required"
        error.details = {"profileIds": ["alpha", "beta"], "failedProfileIds": ["alpha"],
                         "password": PASSWORD, "username": USERNAME, "sourceName": "private.ini"}
        with patch.object(self.manager, "connect", side_effect=error):
            status, _, data = self.json_request("POST", "/api/profiles/alpha/connect", value={})
        self.assertEqual(status, 409)
        self.assertEqual(data, {"error": "需要新增连接", "code": "expansion_required",
                                "details": {"profileIds": ["alpha", "beta"], "failedProfileIds": ["alpha"]}})
        self.assert_no_secrets(json.dumps(data))
        for code, details in [("unknown-private-code", {"profileIds": ["alpha"]}),
                              ("credentials_required", {"profileIds": ["alpha", "bad/id"]}),
                              ("credentials_required", {"profileIds": "alpha"})]:
            error.code, error.details = code, details
            with patch.object(self.manager, "connect", side_effect=error):
                status, _, data = self.json_request("POST", "/api/profiles/alpha/connect", value={})
            self.assertEqual(status, 409)
            self.assertNotIn("details", data)
            self.assertEqual(data.get("code"), code if code in {"credentials_required"} else None)

    def test_expansion_native_exception_never_renders_submitted_credentials(self):
        with patch.object(self.manager, "expand_connect", side_effect=RuntimeError(PASSWORD), create=True):
            status, _, data = self.json_request("POST", "/api/profiles/alpha/expand-connect",
                                               value={"username": USERNAME, "password": PASSWORD})
        self.assertEqual(status, 500)
        self.assert_no_secrets(json.dumps(data))

    def test_stale_endpoint_revision_rejects_login_and_expansion_before_native_actions(self):
        status, _, state = self.json_request('GET', '/api/state')
        self.assertEqual(status, 200)
        revision = state['profiles'][0]['networkVersion']
        self.assertRegex(revision, r'^[a-f0-9]{64}$')
        self.manager.edit('alpha', {'gateway': '192.0.2.99'})
        for action in ('connect', 'expand-connect'):
            with self.subTest(action=action):
                status, _, data = self.json_request('POST', '/api/profiles/alpha/' + action, value={
                    'networkVersion': revision, 'username': USERNAME, 'password': PASSWORD, 'remember': True,
                })
                self.assertEqual(status, 409)
                self.assertEqual(data.get('code'), 'credentials_required')
                self.assert_no_secrets(json.dumps(data))
        self.assertEqual(self.bridge.sessions, [])
        self.assertEqual(self.bridge.external_disconnects, [])
        self.assertEqual(self.bridge.next_index, 3)
        self.assertNotIn('networkVersion', self.manager.path.read_text('utf-8'))


if __name__ == "__main__":
    unittest.main(verbosity=2)
