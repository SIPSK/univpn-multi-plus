"""Credential/automatic-login lifecycle with memory doubles, never Windows APIs."""
from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from core import AppError, Manager, PUBLIC_PROFILE_KEYS

USER = "offline-preferences-user"
PASSWORD = "offline-preferences-password"
CODE = "offline-preferences-dynamic-token"


@dataclass(repr=False)
class MemoryCredential:
    username: str
    password: str


class MemoryStore:
    def __init__(self):
        self.values = {}
        self.saves = []
        self.deletes = []
        self.reads = []
        self.fail_read = self.fail_save = self.fail_delete = False

    def read(self, key):
        self.reads.append(key)
        if self.fail_read:
            raise RuntimeError(PASSWORD)
        return self.values.get(key)

    def save(self, key, username, password):
        if self.fail_save:
            raise RuntimeError(password)
        self.saves.append(key)
        self.values[key] = MemoryCredential(username, password)

    def delete(self, key):
        if self.fail_delete:
            raise RuntimeError(PASSWORD)
        self.deletes.append(key)
        self.values.pop(key, None)


class FakeStartup:
    def __init__(self):
        self.enabled = False
        self.sets = []
        self.reads = 0
        self.fail = False

    def get_enabled(self):
        self.reads += 1
        return self.enabled

    def set_enabled(self, value):
        if self.fail:
            raise RuntimeError(PASSWORD)
        self.sets.append(value)
        self.enabled = value


class FakeSession:
    def __init__(self, bridge, profile, notify):
        self.bridge = bridge
        self.profile = profile
        self.notify = notify
        self.starts = []
        self.codes = []
        self.disconnects = 0

    def start(self, username, password):
        self.starts.append((username, password))
        if self.profile["id"] in self.bridge.fail_start:
            raise RuntimeError(password)
        self.notify({"status": "otp", "challenge": "动态口令"})

    def submit_otp(self, code):
        self.codes.append(code)
        self.notify({"status": "authenticated"})

    def disconnect(self):
        self.disconnects += 1
        self.notify({"status": "disconnected"})


class FakeBridge:
    available = True

    def __init__(self):
        self.sessions = []
        self.fail_start = set()
        self.external_disconnects = []

    def session(self, profile, notify):
        result = FakeSession(self, profile, notify)
        self.sessions.append(result)
        return result

    def disconnect_external(self, profile):
        self.external_disconnects.append(profile["id"])


class CorePreferenceTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="vpn-core-memory-test-")
        self.addCleanup(self.directory.cleanup)
        self.store = MemoryStore()
        self.startup = FakeStartup()
        self.bridge = FakeBridge()
        self.manager = Manager(Path(self.directory.name), bridge=self.bridge, inspect=False,
                               credentials=self.store, startup=self.startup)
        self.addCleanup(self.manager.close)
        self.manager.profiles = [
            {"id": "alpha", "name": "", "gateway": "192.0.2.10", "port": 443, "index": 1, "autoConnect": False},
            {"id": "beta", "name": "", "gateway": "192.0.2.20", "port": 49999, "index": 2, "autoConnect": False},
        ]
        self.manager.inventory = {"installed": True, "records": [{"index": 2, "status": "Ready", "tapGuid": "beta-tap"}]}
        self.manager._save()

    def login(self, **options):
        self.manager.connect("alpha", {"username": USER, "password": PASSWORD, **options})
        return self.bridge.sessions[-1]

    def selected(self, key="alpha"):
        return next(p for p in self.manager.profiles if p["id"] == key)

    def public(self, key="alpha"):
        return next(p for p in self.manager.state()["profiles"] if p["id"] == key)

    def observe(self, *, peer=True):
        self.manager.inventory = {
            "installed": True, "records": [{"index": 2, "tapGuid": "beta-tap"}],
            "adapters": [{"guid": "alpha-tap", "up": True, "addresses": ["192.0.2.60"]}],
            "peers": ([{"process": "UniVPNCS", "gateway": "192.0.2.10", "port": 443}] if peer else []),
        }

    def automatic(self):
        with patch.object(self.manager._stop, "wait", return_value=False):
            self.manager._auto_connect_once()

    def assert_public_private(self):
        text = self.manager.path.read_text("utf-8") + json.dumps(self.manager.state(), ensure_ascii=False)
        for value in (USER, PASSWORD, CODE):
            self.assertNotIn(value, text)
        self.assertTrue(all(set(p) == PUBLIC_PROFILE_KEYS for p in json.loads(self.manager.path.read_text("utf-8"))))

    def test_inspect_false_constructs_no_real_dependencies_or_workers(self):
        with patch("core.subprocess.run", side_effect=AssertionError("Real process forbidden")), \
             patch("core.threading.Thread", side_effect=AssertionError("Worker forbidden")), \
             patch("credential_store.CredentialStore", side_effect=AssertionError("Vault forbidden")), \
             patch("startup.Startup", side_effect=AssertionError("Registry forbidden")):
            other = Manager(Path(self.directory.name) / "isolated", bridge=self.bridge, inspect=False)
            self.assertIsNone(other.credentials)
            self.assertIsNone(other.startup)
            self.assertEqual(other.sessions, {})
            other.close()

    def test_defaults_are_disabled_and_private(self):
        state = self.manager.state()
        self.assertFalse(state["settings"]["startup"])
        for profile in state["profiles"]:
            self.assertFalse(profile["autoConnect"])
            self.assertFalse(profile["hasSavedCredential"])
            self.assertFalse(profile["canDisconnect"])
            self.assertEqual(profile["challengeId"], 0)
        self.assert_public_private()

    def test_save_only_after_authenticated_never_during_challenge_or_tunnel_events(self):
        session = self.login(remember=True)
        self.assertEqual(self.store.saves, [])
        for status in ("starting", "otp", "connected"):
            session.notify({"status": status})
            self.assertEqual(self.store.saves, [])
        session.notify({"status": "authenticated"})
        self.assertEqual(self.store.saves, ["alpha"])
        self.assertEqual(self.store.values["alpha"].password, PASSWORD)
        self.assertNotIn("alpha", self.manager._pending_credentials)
        session.notify({"status": "authenticated"})
        self.assertEqual(self.store.saves, ["alpha"])
        self.assert_public_private()

    def test_no_explicit_save_keeps_credential_out_of_store(self):
        session = self.login()
        session.submit_otp(CODE)
        self.assertEqual(self.store.saves, [])
        self.assertEqual(self.manager._pending_credentials, {})
        self.assert_public_private()

    def test_automatic_login_implies_remember_but_waits_for_authentication(self):
        session = self.login(autoConnect=True, remember=False)
        self.assertTrue(self.selected()["autoConnect"])
        self.assertEqual(self.store.saves, [])
        session.submit_otp(CODE)
        self.assertEqual(self.store.saves, ["alpha"])
        self.assert_public_private()

    def test_terminal_authentication_failures_discard_pending_password(self):
        for status in ("error", "disconnected"):
            with self.subTest(status=status):
                self.manager.sessions.clear()
                self.manager.events.clear()
                session = self.login(remember=True)
                session.notify({"status": status, "error": "认证未完成"})
                self.assertNotIn("alpha", self.manager._pending_credentials)
                session.notify({"status": "authenticated"})
                self.assertEqual(self.store.saves, [])

    def test_synchronous_native_failure_is_sanitized_and_discards_pending(self):
        self.bridge.fail_start.add("alpha")
        with self.assertRaises(AppError) as caught:
            self.login(remember=True, autoConnect=True)
        self.assertEqual(caught.exception.status, 409)
        self.assertNotIn(PASSWORD, str(caught.exception))
        self.assertEqual(self.manager._pending_credentials, {})
        self.assertNotIn("alpha", self.manager.sessions)
        self.assertEqual(self.store.saves, [])
        self.assert_public_private()

    def test_vault_failure_is_safe_and_drops_pending_after_successful_authentication(self):
        self.store.fail_save = True
        session = self.login(remember=True)
        session.submit_otp(CODE)
        self.assertEqual(self.manager._pending_credentials, {})
        self.assertFalse(self.public()["hasSavedCredential"])
        self.assertIn("密码未能保存", self.public()["error"])
        self.assert_public_private()

    def test_saved_connect_uses_vault_without_returning_or_resaving_secret(self):
        self.store.values["alpha"] = MemoryCredential(USER, PASSWORD)
        self.manager.connect("alpha", {})
        session = self.bridge.sessions[0]
        self.assertEqual(session.starts, [(USER, PASSWORD)])
        self.assertEqual(self.manager._pending_credentials, {})
        session.submit_otp(CODE)
        self.assertEqual(self.store.saves, [])
        self.assertTrue(self.public()["hasSavedCredential"])
        self.assert_public_private()

    def test_missing_or_unreadable_vault_never_starts_native_authentication(self):
        for fail in (False, True):
            with self.subTest(fail_read=fail):
                self.store.fail_read = fail
                with self.assertRaises(AppError) as caught:
                    self.manager.connect("alpha", {})
                self.assertEqual(caught.exception.status, 409)
                self.assertNotIn(PASSWORD, str(caught.exception))
        self.assertEqual(self.bridge.sessions, [])

    def test_forget_clears_saved_and_pending_password_and_automatic_without_disconnect(self):
        self.store.values["alpha"] = MemoryCredential(USER, PASSWORD)
        session = self.login(remember=True, autoConnect=True)
        self.manager.forget_credential("alpha")
        self.assertNotIn("alpha", self.store.values)
        self.assertNotIn("alpha", self.manager._pending_credentials)
        self.assertFalse(self.selected()["autoConnect"])
        self.assertEqual(session.disconnects, 0)
        session.notify({"status": "authenticated"})
        self.assertEqual(self.store.saves, [])
        self.assert_public_private()

    def test_gateway_and_port_changes_delete_old_credentials_and_cancel_automatic(self):
        for change in ({"gateway": "192.0.2.99"}, {"port": 5443}):
            with self.subTest(change=change):
                self.store.values["alpha"] = MemoryCredential(USER, PASSWORD)
                self.selected()["autoConnect"] = True
                self.manager.edit("alpha", change)
                self.assertNotIn("alpha", self.store.values)
                self.assertFalse(self.selected()["autoConnect"])
        self.assertEqual(self.store.deletes, ["alpha", "alpha"])

    def test_failed_old_credential_deletion_preserves_original_endpoint_and_preferences(self):
        self.store.values["alpha"] = MemoryCredential(USER, PASSWORD)
        self.selected()["autoConnect"] = True
        original = dict(self.selected())
        self.store.fail_delete = True
        with self.assertRaises(AppError) as caught:
            self.manager.edit("alpha", {"gateway": "192.0.2.77"})
        self.assertEqual(caught.exception.status, 409)
        self.assertEqual(self.selected(), original)
        self.assertNotIn(PASSWORD, str(caught.exception))

    def test_partial_automatic_and_name_edits_preserve_endpoint_and_credential(self):
        self.store.values["alpha"] = MemoryCredential(USER, PASSWORD)
        original_endpoint = (self.selected()["gateway"], self.selected()["port"])
        self.manager.edit("alpha", {"autoConnect": True})
        self.manager.edit("alpha", {"name": "可选名称"})
        self.assertEqual((self.selected()["gateway"], self.selected()["port"]), original_endpoint)
        self.assertTrue(self.selected()["autoConnect"])
        self.assertEqual(self.store.deletes, [])
        self.assertEqual(self.store.values["alpha"].password, PASSWORD)

    def test_bulk_changes_only_same_per_profile_flags_without_login_or_startup(self):
        for enabled in (True, False):
            self.manager.set_automatic({"enabled": enabled})
            self.assertTrue(all(p["autoConnect"] is enabled for p in self.manager.profiles))
            self.assertEqual(self.bridge.sessions, [])
            self.assertEqual(self.store.reads, [])
            self.assertEqual(self.startup.sets, [])
            self.assertFalse(self.startup.enabled)
        self.assert_public_private()

    def test_startup_is_independent_and_never_connects_or_changes_profile_flags(self):
        for enabled in (True, False):
            self.manager.settings({"startup": enabled})
            self.assertEqual(self.manager.state()["settings"]["startup"], enabled)
            self.assertTrue(all(not p["autoConnect"] for p in self.manager.profiles))
            self.assertEqual(self.bridge.sessions, [])
        self.assertEqual(self.startup.sets, [True, False])

    def test_startup_errors_are_sanitized_without_plaintext_fallback(self):
        self.startup.fail = True
        with self.assertRaises(AppError) as caught:
            self.manager.settings({"startup": True})
        self.assertEqual(caught.exception.status, 409)
        self.assertNotIn(PASSWORD, str(caught.exception))
        self.assertFalse(self.startup.enabled)
        self.assert_public_private()

    def test_preferences_require_actual_booleans(self):
        for value in (1, 0, "true", None, [], {}):
            with self.subTest(value=value):
                for call in (lambda: self.manager.edit("alpha", {"autoConnect": value}),
                             lambda: self.manager.set_automatic({"enabled": value}),
                             lambda: self.manager.settings({"startup": value})):
                    with self.assertRaises(AppError):
                        call()
        self.assertEqual(self.startup.sets, [])

    def test_automatic_attempts_each_selected_profile_once_and_pauses_for_dynamic_token(self):
        self.manager.set_automatic({"enabled": True})
        self.store.values["alpha"] = MemoryCredential(USER, PASSWORD)
        self.store.values["beta"] = MemoryCredential(USER, PASSWORD)
        self.automatic()
        self.automatic()
        self.assertEqual([s.profile["id"] for s in self.bridge.sessions], ["alpha", "beta"])
        self.assertTrue(all(len(s.starts) == 1 and not s.codes for s in self.bridge.sessions))
        self.assertTrue(all(p["status"] == "otp" for p in self.manager.state()["profiles"]))
        self.assertEqual(self.manager._pending_credentials, {})

    def test_automatic_does_not_retry_failures_or_abort_other_profiles(self):
        self.manager.set_automatic({"enabled": True})
        self.store.values.update({key: MemoryCredential(USER, PASSWORD) for key in ("alpha", "beta")})
        self.bridge.fail_start.add("alpha")
        self.automatic()
        self.automatic()
        self.assertEqual([s.profile["id"] for s in self.bridge.sessions], ["alpha", "beta"])
        self.assertEqual(self.public("alpha")["status"], "error")
        self.assertEqual(self.public("beta")["status"], "otp")
        self.assert_public_private()

    def test_automatic_without_saved_credential_keeps_flag_without_attempt(self):
        self.manager.edit("alpha", {"autoConnect": True})
        self.automatic()
        self.assertTrue(self.selected()["autoConnect"])
        self.assertEqual(self.bridge.sessions, [])
        self.assertEqual(self.public()["status"], "disconnected")

    def test_automatic_preserves_an_existing_interactive_dynamic_challenge(self):
        self.store.values["alpha"] = MemoryCredential(USER, PASSWORD)
        session = self.login(remember=True, autoConnect=True)
        before = dict(self.manager.events["alpha"])
        self.automatic()
        self.assertEqual(self.manager.events["alpha"], before)
        self.assertEqual(self.bridge.sessions, [session])
        self.assertIn("alpha", self.manager._pending_credentials)

    def test_automatic_snapshot_removal_does_not_abort_remaining_profiles(self):
        self.manager.set_automatic({"enabled": True})
        self.store.values.update({key: MemoryCredential(USER, PASSWORD) for key in ("alpha", "beta")})
        original = self.manager._has_credential
        def remove_alpha(key):
            if key == "alpha":
                self.manager.remove(key)
                return True
            return original(key)
        with patch.object(self.manager, "_has_credential", side_effect=remove_alpha):
            self.automatic()
        self.assertEqual([s.profile["id"] for s in self.bridge.sessions], ["beta"])
        self.assertNotIn("alpha", self.manager.events)

    def test_automatic_vault_read_race_cannot_overwrite_a_new_interactive_challenge(self):
        self.manager.edit("alpha", {"autoConnect": True})
        def interactive_login(key):
            self.login(remember=True, autoConnect=True)
            return False
        with patch.object(self.manager, "_has_credential", side_effect=interactive_login):
            self.automatic()
        self.assertEqual(self.manager.events["alpha"]["status"], "otp")
        self.assertIn("alpha", self.manager._pending_credentials)

    def test_automatic_cancel_during_vault_read_never_starts_connection(self):
        self.manager.edit("alpha", {"autoConnect": True})
        self.store.values["alpha"] = MemoryCredential(USER, PASSWORD)
        def cancel_automatic(key):
            self.manager.edit(key, {"autoConnect": False})
            return True
        with patch.object(self.manager, "_has_credential", side_effect=cancel_automatic):
            self.automatic()
        self.assertEqual(self.bridge.sessions, [])
        self.assertFalse(self.selected()["autoConnect"])

    def test_existing_external_connection_is_observed_but_not_auto_reconnected(self):
        self.observe()
        self.manager.edit("alpha", {"autoConnect": True})
        self.store.values["alpha"] = MemoryCredential(USER, PASSWORD)
        self.automatic()
        self.assertEqual(self.bridge.sessions, [])
        self.assertTrue(self.manager.can_shutdown())

    def test_residual_tap_never_promotes_authenticated_or_starting_before_tunnel_event(self):
        session = self.login()
        self.observe()
        for status in ("authenticated", "starting"):
            session.notify({"status": status})
            self.assertEqual(self.public()["status"], "starting")
            self.assertTrue(self.public()["canDisconnect"])
        session.notify({"status": "connected"})
        self.assertEqual(self.public()["status"], "connected")

    def test_owned_connected_requires_current_tap_and_remains_disconnectable_when_lost(self):
        session = self.login()
        session.notify({"status": "connected"})
        self.observe(peer=False)
        self.assertEqual(self.public()["status"], "connected")
        self.manager.inventory["adapters"] = []
        self.assertEqual(self.public()["status"], "error")
        self.assertTrue(self.public()["canDisconnect"])
        self.assertIn("连接状态未确认", self.public()["error"])
        self.assertEqual(self.manager.events["alpha"]["status"], "connected")
        self.assertFalse(self.manager.can_shutdown())
        self.manager.disconnect("alpha")
        self.assertEqual(session.disconnects, 1)
        self.assertTrue(self.manager.can_shutdown())

    def test_failed_inventory_refresh_does_not_leave_owned_connected_forever(self):
        session = self.login()
        self.observe()
        session.notify({"status": "connected"})
        self.assertEqual(self.public()["status"], "connected")
        self.manager.inventory_error = "无法读取 VPN 状态"
        self.assertEqual(self.public()["status"], "error")
        self.assertTrue(self.public()["canDisconnect"])

    def test_external_requires_both_adapter_and_matching_endpoint_peer(self):
        self.observe(peer=False)
        self.assertEqual(self.public()["status"], "disconnected")
        self.observe()
        self.assertEqual(self.public()["status"], "connected")
        self.manager.inventory["peers"][0]["port"] = 5443
        self.assertEqual(self.public()["status"], "disconnected")

    def test_failed_external_disconnect_keeps_observed_connected_and_operation_error(self):
        self.observe()
        with patch.object(self.bridge, "disconnect_external", side_effect=RuntimeError(PASSWORD)):
            with self.assertRaises(AppError) as caught:
                self.manager.disconnect("alpha")
        self.assertEqual(caught.exception.status, 409)
        # Current handoff protection does not call an external killer. An old
        # failed-operation event still must not hide a confirmed live tunnel.
        self.manager._event("alpha", {"status": "error", "error": "断开尚未确认"})
        profile = self.public()
        self.assertEqual(profile["status"], "connected")
        self.assertIn("断开尚未确认", profile["error"])
        self.assertFalse(profile["canDisconnect"])
        self.assertEqual(self.manager.events["alpha"]["status"], "error")
        self.assertEqual(self.manager.notifications()["profiles"][0]["status"], "connected")
        self.assertTrue(self.manager.can_shutdown())
        self.assert_public_private()

    def test_external_operation_error_needs_both_current_tap_and_matching_peer_to_show_online(self):
        self.manager._event("alpha", {"status": "error", "error": "断开尚未确认"})
        self.observe(peer=False)
        self.assertEqual(self.public()["status"], "error")
        self.observe()
        self.manager.inventory["adapters"] = []
        self.assertEqual(self.public()["status"], "error")
        self.observe()
        self.manager.inventory_error = "无法读取 VPN 状态"
        self.assertEqual(self.public()["status"], "error")

    def test_owned_authentication_error_is_not_hidden_by_a_residual_external_tap(self):
        session = self.login()
        self.observe()
        session.notify({"status": "error", "error": "认证尚未完成"})
        self.assertEqual(self.public()["status"], "error")
        self.assertEqual(self.public()["error"], "认证尚未完成")
        self.assertTrue(self.public()["canDisconnect"])

    def test_confirmed_external_disconnect_becomes_disconnected_without_success_error(self):
        self.observe()
        self.manager._event("alpha", {"status": "error", "error": "旧断开错误"})
        self.manager.inventory["adapters"] = []
        self.manager.inventory["peers"] = []
        def confirmed_disconnect(profile):
            self.manager.inventory["adapters"] = []
            self.manager.inventory["peers"] = []
        with patch.object(self.bridge, "disconnect_external", side_effect=confirmed_disconnect):
            self.manager.disconnect("alpha")
        self.assertEqual(self.public()["status"], "disconnected")
        self.assertNotIn("error", self.public())

    def test_failed_owned_session_requires_explicit_disconnect_before_relogin(self):
        session = self.login()
        session.notify({"status": "error", "error": "断开尚未确认"})
        self.assertTrue(self.public()["canDisconnect"])
        self.assertFalse(self.manager.can_shutdown())
        with self.assertRaises(AppError) as caught:
            self.login()
        self.assertEqual(caught.exception.status, 409)
        self.assertEqual(self.bridge.sessions, [session])
        self.manager.disconnect("alpha")
        self.login()
        self.assertEqual(len(self.bridge.sessions), 2)

    def test_notifications_are_exact_nonsecret_shape_and_never_read_vault_or_startup(self):
        session = self.login(remember=True)
        first = self.manager.notifications()
        self.assertEqual(first["profiles"][0], {"id": "alpha", "status": "otp", "challengeId": 1})
        session.notify({"status": "otp", "challenge": PASSWORD})
        self.assertEqual(self.manager.notifications()["profiles"][0]["challengeId"], 2)
        self.assertEqual(self.public()["challengeId"], 2)
        with patch.object(self.store, "read", side_effect=AssertionError("Vault read forbidden")), \
             patch.object(self.startup, "get_enabled", side_effect=AssertionError("Startup read forbidden")), \
             patch.object(self.manager, "state", side_effect=AssertionError("Full state forbidden")):
            notification = self.manager.notifications()
        self.assertEqual(set(notification), {"profiles"})
        self.assertTrue(all(set(p) == {"id", "status", "challengeId"} for p in notification["profiles"]))
        text = json.dumps(notification)
        for value in (USER, PASSWORD, CODE, "192.0.2.10", '"challenge":', "username", "gateway"):
            self.assertNotIn(value, text)

    def test_close_discards_pending_secret_without_disconnecting_any_native_session(self):
        session = self.login(remember=True)
        self.manager.close()
        self.assertEqual(self.manager._pending_credentials, {})
        self.assertEqual(session.disconnects, 0)
        self.assertEqual(self.bridge.external_disconnects, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
