"""Native remembered-reference integration using synthetic metadata only.

No vendor configuration, AppData, native RPC, Windows vault or Run key is read.
"""
from __future__ import annotations

import contextlib
from dataclasses import dataclass
import http.client
import io
import json
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from core import AppError, Manager, PUBLIC_PROFILE_KEYS
from server import LocalServer
from test_core_preferences import MemoryStore, MemoryCredential, FakeStartup

PRIVATE_USER = "synthetic-private-native-account"
PRIVATE_PROFILE = "synthetic-private-native-profile-reference"
VAULT_USER = "synthetic-private-vault-account"
VAULT_PASSWORD = "synthetic-private-vault-password"


@dataclass(frozen=True, slots=True, repr=False)
class FakeLegacyRef:
    username: str
    profile_name: str


class FakeSession:
    def __init__(self, profile, notify):
        self.profile = dict(profile)
        self.notify = notify
        self.normal = []
        self.saved = []
        self.disconnects = 0
        self.fail_saved = False

    def start(self, username, password):
        self.normal.append((username, password))
        self.notify({"status": "otp", "challenge": "动态口令"})

    def start_saved(self, username, profile_name):
        self.saved.append((username, profile_name))
        if self.fail_saved:
            raise RuntimeError(username + profile_name)
        self.notify({"status": "otp", "challenge": "动态口令"})

    def disconnect(self):
        self.disconnects += 1
        self.notify({"status": "disconnected"})


class FakeBridge:
    available = True

    def __init__(self):
        self.references = {("192.0.2.10", 443): FakeLegacyRef(PRIVATE_USER, PRIVATE_PROFILE)}
        self.lookups = []
        self.imports = []
        self.import_calls = 0
        self.sessions = []
        self.vendor_changes = []
        self.fail_lookup = self.fail_saved = False

    def legacy_reference(self, profile):
        self.lookups.append((profile["id"], profile["gateway"], profile["port"]))
        if self.fail_lookup:
            raise RuntimeError(PRIVATE_USER + PRIVATE_PROFILE)
        return self.references.get((profile["gateway"], profile["port"]))

    def remembered_profiles(self, inventory):
        self.import_calls += 1
        return self.imports

    def session(self, profile, notify):
        session = FakeSession(profile, notify)
        session.fail_saved = self.fail_saved
        self.sessions.append(session)
        return session


class LegacyCoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="vpn-legacy-fake-test-")
        self.addCleanup(self.tmp.cleanup)
        self.runtime = Path(self.tmp.name)
        self.bridge = FakeBridge()
        self.store = MemoryStore()
        self.startup = FakeStartup()
        self.manager = Manager(self.runtime, bridge=self.bridge, inspect=False,
                               credentials=self.store, startup=self.startup)
        self.addCleanup(self.manager.close)
        self.manager.profiles = [{"id": "alpha", "name": "", "gateway": "192.0.2.10", "port": 443,
                                  "index": 1, "autoConnect": False, "useLegacyCredential": True}]
        self.manager.inventory = {"installed": True}
        self.manager._save()

    def assert_private(self, *extra):
        text = json.dumps(self.manager.state(), ensure_ascii=False) + self.manager.path.read_text("utf-8")
        text += "".join(str(value) for value in extra)
        for private in (PRIVATE_USER, PRIVATE_PROFILE, VAULT_USER, VAULT_PASSWORD):
            self.assertNotIn(private, text)
        for row in json.loads(self.manager.path.read_text("utf-8")):
            self.assertEqual(set(row), PUBLIC_PROFILE_KEYS)
        self.assertNotIn("legacyReference", text)
        self.assertNotIn("profile_name", text)
        self.assertNotIn('"username"', text)
        self.assertNotIn('"password"', text)

    def test_reference_repr_has_no_private_metadata(self):
        reference = next(iter(self.bridge.references.values()))
        self.assertNotIn(PRIVATE_USER, repr(reference))
        self.assertNotIn(PRIVATE_PROFILE, repr(reference))
        self.assertFalse(hasattr(reference, "password"))

    def test_state_and_real_http_expose_only_presence_not_private_reference(self):
        server = LocalServer(self.runtime, self.manager, port=0)
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": .01}, daemon=True)
        thread.start()
        output = io.StringIO()
        try:
            with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
                connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=3)
                try:
                    connection.request("GET", "/api/state", headers={"X-VPN-Token": server.token})
                    response = connection.getresponse()
                    self.assertEqual(response.status, 200)
                    body = response.read().decode("utf-8")
                finally:
                    connection.close()
            profile = json.loads(body)["profiles"][0]
            self.assertTrue(profile["hasSavedCredential"])
            self.assert_private(body, output.getvalue())
        finally:
            server.shutdown()
            server.server_close()
            thread.join(3)
        self.assertFalse(thread.is_alive())

    def test_empty_connect_prefers_vault_without_resolving_native_reference(self):
        self.store.values["alpha"] = MemoryCredential(VAULT_USER, VAULT_PASSWORD)
        self.manager.connect("alpha", {})
        session = self.bridge.sessions[0]
        self.assertEqual(session.normal, [(VAULT_USER, VAULT_PASSWORD)])
        self.assertEqual(session.saved, [])
        self.assertEqual(self.bridge.lookups, [])
        self.assertEqual(self.store.saves, [])
        self.assertEqual(self.manager._pending_credentials, {})
        self.assert_private()

    def test_empty_connect_falls_back_to_native_reference_without_plaintext_password_or_vault_write(self):
        self.manager.connect("alpha", {"remember": True, "autoConnect": True})
        session = self.bridge.sessions[0]
        self.assertEqual(session.saved, [(PRIVATE_USER, PRIVATE_PROFILE)])
        self.assertEqual(session.normal, [])
        self.assertEqual(self.store.saves, [])
        self.assertEqual(self.store.values, {})
        self.assertEqual(self.manager._pending_credentials, {})
        session.notify({"status": "authenticated"})
        self.assertEqual(self.store.saves, [])
        self.assertTrue(self.manager.profiles[0]["autoConnect"])
        self.assert_private()

    def test_native_fallback_works_without_a_manager_vault(self):
        self.manager.credentials = None
        self.manager.connect("alpha", {})
        self.assertEqual(self.bridge.sessions[0].saved, [(PRIVATE_USER, PRIVATE_PROFILE)])
        self.assert_private()

    def test_gateway_edit_cancels_old_automatic_flag_even_without_a_manager_vault(self):
        self.manager.credentials = None
        self.manager.profiles[0]["autoConnect"] = True
        original_references = dict(self.bridge.references)
        self.manager.edit("alpha", {"gateway": "192.0.2.99"})
        self.assertFalse(self.manager.profiles[0]["autoConnect"])
        self.assertEqual(self.bridge.references, original_references)
        with self.assertRaises(AppError):
            self.manager.connect("alpha", {})
        self.assertEqual(self.bridge.sessions, [])

    def test_explicit_login_does_not_resolve_or_use_native_reference(self):
        self.manager.connect("alpha", {"username": VAULT_USER, "password": VAULT_PASSWORD})
        self.assertEqual(self.bridge.lookups, [])
        self.assertEqual(self.bridge.sessions[0].normal, [(VAULT_USER, VAULT_PASSWORD)])
        self.assertEqual(self.bridge.sessions[0].saved, [])
        self.assert_private()

    def test_native_reference_resolution_errors_are_generic_without_partial_session(self):
        self.bridge.fail_lookup = True
        with self.assertRaises(AppError) as caught:
            self.manager.connect("alpha", {})
        self.assertEqual(caught.exception.status, 409)
        self.assertEqual(self.bridge.sessions, [])
        self.assertEqual(self.manager.sessions, {})
        self.assert_private(str(caught.exception))

    def test_native_saved_start_errors_are_generic_and_leave_no_pending_secret(self):
        self.bridge.fail_saved = True
        with self.assertRaises(AppError) as caught:
            self.manager.connect("alpha", {})
        self.assertEqual(caught.exception.status, 409)
        self.assertEqual(self.manager.sessions, {})
        self.assertEqual(self.manager._pending_credentials, {})
        self.assertEqual(self.store.saves, [])
        self.assert_private(str(caught.exception))

    def test_forget_revokes_both_sources_and_auto_without_reading_or_mutating_vendor(self):
        self.store.values["alpha"] = MemoryCredential(VAULT_USER, VAULT_PASSWORD)
        self.manager.profiles[0]["autoConnect"] = True
        original_references = dict(self.bridge.references)
        self.manager.forget_credential("alpha")
        self.assertFalse(self.manager.profiles[0]["useLegacyCredential"])
        self.assertFalse(self.manager.profiles[0]["autoConnect"])
        self.assertEqual(self.store.values, {})
        self.assertEqual(self.store.deletes, ["alpha"])
        self.assertEqual(self.bridge.references, original_references)
        self.assertEqual(self.bridge.vendor_changes, [])
        self.assertEqual(self.bridge.lookups, [])
        self.assertFalse(self.manager.state()["profiles"][0]["hasSavedCredential"])
        with self.assertRaises(AppError):
            self.manager.connect("alpha", {})
        self.assertEqual(self.bridge.lookups, [])
        self.assertEqual(self.bridge.sessions, [])
        self.assert_private()

    def test_forget_permission_stays_revoked_after_reload_and_import(self):
        self.manager.forget_credential("alpha")
        other = Manager(self.runtime, bridge=self.bridge, inspect=False, credentials=self.store, startup=self.startup)
        self.addCleanup(other.close)
        self.bridge.imports = [{"index": 1, "gateway": "192.0.2.10", "port": 443}]
        other._import_existing()
        self.assertEqual(len(other.profiles), 1)
        self.assertFalse(other.profiles[0]["useLegacyCredential"])
        self.assertFalse(other.state()["profiles"][0]["hasSavedCredential"])
        self.assertEqual(self.bridge.lookups, [])

    def test_import_preserves_existing_assignment_and_new_rows_always_disable_auto(self):
        existing = dict(self.manager.profiles[0])
        self.bridge.imports = [
            {"index": 1, "gateway": "192.0.2.99", "port": 444, "name": "overwrite"},
            {"index": 2, "gateway": "192.0.2.20", "port": 49999, "name": "", "autoConnect": True,
             "username": PRIVATE_USER, "legacyReference": PRIVATE_PROFILE},
        ]
        self.manager._import_existing()
        self.assertEqual(self.manager.profiles[0], existing)
        imported = self.manager.profiles[1]
        self.assertEqual(imported["index"], 2)
        self.assertFalse(imported["autoConnect"])
        self.assertTrue(imported["useLegacyCredential"])
        self.assertNotIn("username", imported)
        self.assertEqual(self.bridge.sessions, [])
        self.assertEqual(self.store.saves, [])
        self.assertEqual(self.startup.sets, [])
        self.manager._import_existing()
        self.assertEqual(len(self.manager.profiles), 2)
        self.assert_private()

    def test_import_does_not_change_an_existing_user_selected_auto_flag(self):
        self.manager.profiles[0]["autoConnect"] = True
        self.bridge.imports = [{"index": 1, "gateway": "192.0.2.99", "port": 443}]
        self.manager._import_existing()
        self.assertTrue(self.manager.profiles[0]["autoConnect"])
        self.assertEqual(self.manager.profiles[0]["gateway"], "192.0.2.10")

    def test_notifications_never_resolve_native_reference_or_vault(self):
        self.manager._event("alpha", {"status": "otp", "challenge": PRIVATE_PROFILE})
        with patch.object(self.store, "read", side_effect=AssertionError("vault read")), \
             patch.object(self.bridge, "legacy_reference", side_effect=AssertionError("native reference read")), \
             patch.object(self.startup, "get_enabled", side_effect=AssertionError("startup read")):
            result = self.manager.notifications()
        self.assertEqual(result, {"profiles": [{"id": "alpha", "status": "otp", "challengeId": 1}]})

    def test_endpoint_edit_cannot_redirect_credentials_while_either_source_is_resolved(self):
        for source in ("vault", "native"):
            with self.subTest(source=source):
                self.manager.sessions.clear()
                self.manager.events.clear()
                self.bridge.sessions.clear()
                self.store.values.clear()
                entered, release, edit_done = threading.Event(), threading.Event(), threading.Event()
                errors = []
                edits = []
                original = self.store.read if source == "vault" else self.bridge.legacy_reference
                if source == "vault":
                    self.store.values["alpha"] = MemoryCredential(VAULT_USER, VAULT_PASSWORD)
                def blocking(value):
                    entered.set()
                    if not release.wait(3):
                        raise RuntimeError("fixture release timed out")
                    return original(value)
                def connect():
                    try:
                        self.manager.connect("alpha", {})
                    except Exception as exc:
                        errors.append(type(exc).__name__)
                def edit():
                    try:
                        self.manager.edit("alpha", {"gateway": "192.0.2.99"})
                    except AppError as exc:
                        edits.append(exc.status)
                    finally:
                        edit_done.set()
                target, attribute = (self.store, "read") if source == "vault" else (self.bridge, "legacy_reference")
                with patch.object(target, attribute, side_effect=blocking):
                    connector = threading.Thread(target=connect)
                    editor = threading.Thread(target=edit)
                    connector.start()
                    try:
                        self.assertTrue(entered.wait(2))
                        editor.start()
                        self.assertFalse(edit_done.wait(.05))
                    finally:
                        release.set()
                        connector.join(3)
                        if editor.ident is not None:
                            editor.join(3)
                self.assertFalse(connector.is_alive())
                self.assertFalse(editor.is_alive())
                self.assertEqual(errors, [])
                self.assertEqual(edits, [409])
                self.assertEqual(self.manager.profiles[0]["gateway"], "192.0.2.10")
                session = self.bridge.sessions[0]
                self.assertEqual(session.profile["gateway"], "192.0.2.10")
                self.assertEqual(len(session.normal if source == "vault" else session.saved), 1)
                self.assertEqual(session.saved if source == "vault" else session.normal, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
