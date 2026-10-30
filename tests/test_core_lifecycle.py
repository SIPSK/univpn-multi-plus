"""Generation and native-slot leases with deliberately delayed fake methods."""
from __future__ import annotations

import threading
import unittest
from unittest.mock import patch

from core import AppError
import test_core_multi as fixtures
Session, USER = fixtures.Session, fixtures.USER


class LifecycleTests(unittest.TestCase):
    setUp = fixtures.MultiConfigurationTests.setUp
    add = fixtures.MultiConfigurationTests.add
    profile = fixtures.MultiConfigurationTests.profile
    public = fixtures.MultiConfigurationTests.public
    manual = fixtures.MultiConfigurationTests.manual
    import_all = fixtures.MultiConfigurationTests.import_all
    def launch(self, callback):
        failures = []
        def run():
            try:
                callback()
            except AppError as exc:
                failures.append(exc.status)
            except Exception as exc:
                failures.append(type(exc).__name__)
        thread = threading.Thread(target=run, daemon=True)
        thread.start()
        return thread, failures

    def test_old_delayed_start_and_exception_never_overwrite_a_new_generation(self):
        key = self.add()
        entered, release = threading.Event(), threading.Event()
        original = self.bridge.session
        previous = []
        class Delayed(Session):
            def start(inner, username, password):
                entered.set()
                if not release.wait(3):
                    raise RuntimeError('fixture timeout')
                for status in ('authenticated', 'otp', 'connected', 'disconnected', 'error'):
                    inner.notify({'status': status, 'error': 'stale event'})
                raise RuntimeError('stale start failure')
        def create(profile, notify):
            if not previous:
                result = Delayed(profile, notify)
                previous.append(result)
                self.bridge.sessions.append(result)
                return result
            return original(profile, notify)
        with patch.object(self.bridge, 'session', side_effect=create):
            thread, failures = self.launch(lambda: self.manual(key, remember=True))
            try:
                self.assertTrue(entered.wait(2))
                self.manager.disconnect(key)
                self.manager.edit(key, {'gateway': '192.0.2.99'})
                self.manager.connect(key, {'username': USER, 'password': 'new-fixture-password', 'remember': True})
                current = self.manager.sessions[key]
                before = dict(self.manager.events[key])
                challenge = self.manager._challenge_ids[key]
            finally:
                release.set()
                thread.join(3)
        self.assertFalse(thread.is_alive())
        self.assertEqual(failures, [409])
        self.assertIs(self.manager.sessions[key], current)
        self.assertEqual(self.manager.events[key], before)
        self.assertEqual(self.manager._challenge_ids[key], challenge)
        self.assertEqual(self.manager._pending_credentials[key], (USER, 'new-fixture-password'))
        self.assertEqual(self.store.saves, [])
        self.assertEqual(current.profile['gateway'], '192.0.2.99')

    def test_late_callback_after_remove_cannot_recreate_events_or_save_credentials(self):
        key = self.add()
        self.manual(key, remember=True)
        old = self.bridge.sessions[-1]
        self.manager.disconnect(key)
        self.manager.remove(key)
        old.notify({'status': 'authenticated'})
        old.notify({'status': 'otp'})
        self.assertNotIn(key, self.manager.events)
        self.assertNotIn(key, self.manager._challenge_ids)
        self.assertEqual(self.store.saves, [])

    def test_external_disconnect_reserves_profile_and_slot_until_completion(self):
        first, second = self.add(), self.add('192.0.2.20')
        self.profile(first)['index'] = 1
        entered, release = threading.Event(), threading.Event()
        hit = []
        def delayed(profile):
            entered.set()
            if not release.wait(3):
                raise RuntimeError('fixture timeout')
            hit.append(profile['index'])
        with patch.object(self.bridge, 'disconnect_external', side_effect=delayed):
            thread, failures = self.launch(lambda: self.manager.disconnect(first))
            try:
                self.assertTrue(entered.wait(2))
                self.assertTrue(self.manager._slot_busy(1))
                self.assertFalse(self.manager.can_shutdown())
                for action in (lambda: self.manual(first), lambda: self.manager.edit(first, {'name': 'new'}),
                               lambda: self.manager.remove(first), lambda: self.manager.disconnect(first)):
                    with self.assertRaises(AppError):
                        action()
                self.manual(second)
                self.assertEqual(self.profile(second)['index'], 2)
                replacement = self.manager.sessions[second]
                self.assertEqual(self.profile(first)['index'], 1)
            finally:
                release.set()
                thread.join(3)
        self.assertFalse(thread.is_alive())
        self.assertEqual(failures, [])
        self.assertEqual(hit, [1])
        self.assertIs(self.manager.sessions[second], replacement)
        self.assertEqual(self.manager.events[first]['status'], 'disconnected')
        self.assertEqual(self.manager._disconnecting, {})

    def test_disconnect_without_another_slot_never_releases_lease_or_creates(self):
        first, second = self.add(), self.add('192.0.2.20')
        self.profile(first)['index'] = 1
        self.manager.inventory = {'installed': True}
        entered, release = threading.Event(), threading.Event()
        def delayed(profile):
            entered.set()
            release.wait(3)
        with patch.object(self.bridge, 'disconnect_external', side_effect=delayed):
            thread, failures = self.launch(lambda: self.manager.disconnect(first))
            try:
                self.assertTrue(entered.wait(2))
                with self.assertRaises(AppError):
                    self.manual(second)
                self.assertEqual(self.bridge.creates, 0)
                self.assertEqual(self.profile(first)['index'], 1)
                self.assertEqual(self.profile(second)['index'], 0)
            finally:
                release.set()
                thread.join(3)
        self.assertEqual(failures, [])

    def test_expired_disconnect_completion_cannot_pop_replacement_session(self):
        key = self.add()
        self.profile(key)['index'] = 1
        entered, release = threading.Event(), threading.Event()
        def delayed(profile):
            entered.set()
            release.wait(3)
        with patch.object(self.bridge, 'disconnect_external', side_effect=delayed):
            thread, failures = self.launch(lambda: self.manager.disconnect(key))
            try:
                self.assertTrue(entered.wait(2))
                replacement = Session(self.profile(key), lambda event: None)
                with self.manager.lock:
                    self.manager.sessions[key] = replacement
                    self.manager._attempts[key] = object()
                    self.manager.events[key] = {'status': 'otp'}
            finally:
                release.set()
                thread.join(3)
        self.assertEqual(failures, [409])
        self.assertIs(self.manager.sessions[key], replacement)
        self.assertEqual(self.manager.events[key], {'status': 'otp'})

    def test_first_handoff_keeps_import_and_list_but_never_authenticates_or_kills_external_client(self):
        self.manager.inventory['processes'] = [{'name': 'UniVPN', 'pid': 12345}]
        keys = self.import_all()
        self.assertEqual(len(self.manager.profiles), 4)
        self.assertTrue(self.manager.state()['handoffRequired'])
        self.assertIn('原客户端', self.manager.state()['error'])
        for action in (lambda: self.manager.connect(keys['a'], {}), lambda: self.manual(keys['a'])):
            with self.assertRaises(AppError):
                action()
        self.profile(keys['a'])['index'] = 1
        with self.assertRaises(AppError):
            self.manager.disconnect(keys['a'])
        self.assertEqual(self.bridge.sessions, [])
        self.assertEqual(self.bridge.external_disconnects, [])
        self.assertEqual(self.bridge.creates, 0)
        self.manager.inventory['processes'] = []
        self.assertFalse(self.manager.state()['handoffRequired'])
        self.manager.connect(keys['a'], {})
        self.assertEqual(self.public(keys['a'])['status'], 'otp')

    def test_daily_owned_session_disconnect_is_allowed_while_external_handoff_remains(self):
        first, second = self.add(), self.add('192.0.2.20')
        self.manual(first)
        owned = self.manager.sessions[first]
        self.manager.inventory['processes'] = [{'name': 'UVP002', 'pid': 12345}]
        self.assertTrue(self.manager.state()['handoffRequired'])
        with self.assertRaises(AppError):
            self.manual(second)
        self.manager.disconnect(first)
        self.assertEqual(owned.disconnects, 1)
        self.assertNotIn(first, self.manager.sessions)
        self.assertEqual(self.bridge.external_disconnects, [])


if __name__ == '__main__':
    unittest.main(verbosity=2)
