"""Confirmed native expansion with fake backends and temporary data only."""
from copy import deepcopy
import json
import threading
import unittest
from unittest.mock import patch

from core import AppError
import test_core_multi as fixture


class OwnedSession(fixture.Session):
    def __init__(self, bridge, profile, notify):
        super().__init__(profile, notify)
        self.bridge = bridge

    def start(self, username, password):
        self.normal.append((username, password))
        if self.profile['id'] in self.bridge.fail_start:
            raise RuntimeError('private-fixture-password')
        if self.profile['id'] in self.bridge.pause_otp:
            self.notify({'status': 'otp', 'challenge': '动态口令'})
            return
        self.notify({'status': 'authenticated'})
        self.bridge.online(self.profile)
        self.notify({'status': 'connected'})

    def disconnect(self):
        self.disconnects += 1
        if self.profile['id'] in self.bridge.fail_disconnect:
            raise RuntimeError('private-fixture-password')
        self.bridge.offline(self.profile)
        self.notify({'status': 'disconnected'})


class ExpansionTests(unittest.TestCase):
    setUp = fixture.MultiConfigurationTests.setUp
    add = fixture.MultiConfigurationTests.add
    profile = fixture.MultiConfigurationTests.profile
    public = fixture.MultiConfigurationTests.public
    manual = fixture.MultiConfigurationTests.manual

    def ready(self):
        self.bridge.fail_disconnect, self.bridge.fail_start, self.bridge.pause_otp = set(), set(), set()
        self.bridge.quiesced = []
        self.bridge._inventory = lambda: deepcopy(self.manager.inventory)
        def backend(profile):
            return 'UniVPNCS' if profile['index'] == 1 else f"UVP{profile['index']:03d}CS"
        def online(profile):
            inventory = self.manager.inventory
            name, index = backend(profile), profile['index']
            guid = 'original' if index == 1 else f'tap-{index}'
            inventory.setdefault('adapters', []).append({'guid': guid, 'up': True, 'addresses': ['192.0.2.200']})
            inventory.setdefault('peers', []).append({'process': name, 'gateway': profile['gateway'], 'port': profile['port']})
            inventory.setdefault('processes', []).append({'name': name, 'pid': index + 1000})
        def offline(profile):
            inventory = self.manager.inventory
            name, index = backend(profile), profile['index']
            guid = 'original' if index == 1 else f'tap-{index}'
            inventory['adapters'] = [a for a in inventory.get('adapters', []) if a['guid'] != guid]
            inventory['peers'] = [p for p in inventory.get('peers', []) if p['process'] != name]
        def quiesce(profile):
            # Assert core first observes all tunnels down, while the idle owned
            # backend workers still exist. No external backend is terminated.
            self.assertEqual(self.manager.inventory.get('peers', []), [])
            self.assertEqual(self.manager.inventory.get('adapters', []), [])
            self.bridge.quiesced.append(profile['id'])
            self.manager.inventory['processes'] = [p for p in self.manager.inventory.get('processes', []) if p['name'] != backend(profile)]
        def session(profile, notify):
            value = OwnedSession(self.bridge, profile, notify)
            self.bridge.sessions.append(value)
            return value
        self.bridge.online, self.bridge.offline = online, offline
        self.bridge.session, self.bridge.quiesce_owned = session, quiesce
        first, second, target = self.add(), self.add('192.0.2.20'), self.add('192.0.2.30')
        self.manual(first, remember=True)
        self.manual(second, remember=True)
        self.assertEqual([self.public(k)['status'] for k in (first, second)], ['connected', 'connected'])
        return first, second, target

    def assert_untouched(self):
        self.assertEqual(self.bridge.creates, 0)
        self.assertEqual(self.bridge.quiesced, [])
        self.assertEqual([s.disconnects for s in self.bridge.sessions], [0, 0])
        self.assertEqual(self.bridge.external_disconnects, [])

    def test_first_connect_requires_confirmation_and_cancel_has_no_side_effect(self):
        first, second, target = self.ready()
        with self.assertRaises(AppError) as caught:
            self.manual(target)
        self.assertEqual(caught.exception.code, 'expansion_required')
        self.assertEqual(set(caught.exception.details['profileIds']), {first, second})
        self.assert_untouched()
        self.assertEqual(self.profile(target)['index'], 0)

    def test_confirm_disconnects_quiesces_creates_and_restores_exactly_once(self):
        first, second, target = self.ready()
        original_source = fixture.source('x', '192.0.2.30')
        self.manager.source_links[target] = self.manager._source_link(original_source)
        self.manager.deleted_sources.add('tombstone')
        self.manager._save_sources()
        result = self.manager.expand_connect(target, {'username': fixture.USER, 'password': fixture.PASSWORD, 'remember': True})
        self.assertTrue(result['ok'])
        self.assertEqual([self.profile(k)['index'] for k in (first, second, target)], [1, 2, 3])
        self.assertEqual(self.bridge.creates, 1)
        self.assertEqual(self.bridge.quiesced, [first, second])
        self.assertEqual([s.disconnects for s in self.bridge.sessions[:2]], [1, 1])
        self.assertEqual([s.profile['id'] for s in self.bridge.sessions], [first, second, first, second, target])
        self.assertTrue(all(len(s.normal) == 1 and not s.saved for s in self.bridge.sessions))
        self.assertEqual(self.manager.source_links[target]['sourceId'], 'x' * 64)
        self.assertEqual(self.manager.deleted_sources, {'tombstone'})
        self.assertEqual(self.bridge.external_disconnects, [])
        self.assertFalse(self.manager.state()['expansion']['inProgress'])

    def test_missing_target_credentials_keeps_new_slot_and_then_accepts_manual_login(self):
        first, second, target = self.ready()
        with self.assertRaises(AppError) as caught:
            self.manager.expand_connect(target, {})
        self.assertEqual(caught.exception.code, 'credentials_required')
        self.assertEqual(self.profile(target)['index'], 3)
        self.assertEqual(self.bridge.creates, 1)
        self.assertEqual(set(self.manager.sessions), {first, second})
        self.manual(target, remember=True)
        self.assertEqual(self.profile(target)['index'], 3)
        self.assertEqual(self.bridge.creates, 1)
        self.assertEqual(set(self.manager.sessions), {first, second, target})

    def test_source_one_cache_never_crosses_into_assigned_clone_three(self):
        _, _, target = self.ready()
        self.bridge.sources = [fixture.source('x', '192.0.2.30')]
        self.manager.source_links[target] = self.manager._source_link(self.bridge.sources[0])
        with self.assertRaises(AppError) as caught:
            self.manager.expand_connect(target, {})
        self.assertEqual(caught.exception.code, 'credentials_required')
        self.assertEqual(self.profile(target)['index'], 3)
        self.assertTrue(all(not s.saved for s in self.bridge.sessions))
        target_lookups = [(p, source) for p, source in self.bridge.lookups if p['id'] == target]
        self.assertTrue(target_lookups)
        self.assertTrue(all(p['index'] == 3 and source is None for p, source in target_lookups))

    def test_target_own_saved_password_starts_on_new_slot(self):
        first, second, target = self.ready()
        self.store.values[target] = fixture.MemoryCredential(fixture.USER, fixture.PASSWORD)
        self.manager.expand_connect(target, {})
        self.assertEqual(set(self.manager.sessions), {first, second, target})
        self.assertEqual(self.bridge.sessions[-1].normal, [(fixture.USER, fixture.PASSWORD)])
        self.assertEqual(self.profile(target)['index'], 3)

    def test_creator_failure_restores_saved_once_without_retries_or_credential_leaks(self):
        first, second, target = self.ready()
        def fail():
            self.bridge.creates += 1
            raise RuntimeError('private-fixture-password')
        with patch.object(self.bridge, 'create_instance', side_effect=fail):
            with self.assertRaises(AppError) as caught:
                self.manager.expand_connect(target, {'username': fixture.USER, 'password': fixture.PASSWORD})
        self.assertEqual(self.bridge.creates, 1)
        self.assertEqual([s.profile['id'] for s in self.bridge.sessions], [first, second, first, second])
        self.assertEqual(self.profile(target)['index'], 0)
        self.assertNotIn('private-fixture-password', str(caught.exception))
        material = json.dumps(self.manager.state()) + self.manager.path.read_text('utf-8')
        self.assertNotIn(fixture.PASSWORD, material)
        self.assertFalse(self.manager.state()['expansion']['inProgress'])

    def test_second_disconnect_failure_stops_without_create_and_restores_only_first(self):
        first, second, target = self.ready()
        self.bridge.fail_disconnect.add(second)
        with self.assertRaises(AppError):
            self.manager.expand_connect(target, {})
        self.assertEqual(self.bridge.creates, 0)
        self.assertEqual(self.bridge.quiesced, [])
        self.assertEqual([s.profile['id'] for s in self.bridge.sessions], [first, second, first])
        self.assertIs(self.manager.sessions[second], self.bridge.sessions[1])
        self.assertEqual(self.bridge.external_disconnects, [])

    def test_quiesce_failure_never_creates_and_still_restores_both(self):
        first, second, target = self.ready()
        with patch.object(self.bridge, 'quiesce_owned', side_effect=RuntimeError('fixture')):
            with self.assertRaises(AppError):
                self.manager.expand_connect(target, {})
        self.assertEqual(self.bridge.creates, 0)
        self.assertEqual([s.profile['id'] for s in self.bridge.sessions], [first, second, first, second])

    def test_restore_failure_is_safe_and_attempted_only_once_then_target_can_start(self):
        first, second, target = self.ready()
        self.bridge.fail_start.add(first)
        result = self.manager.expand_connect(target, {'username': fixture.USER, 'password': fixture.PASSWORD})
        self.assertEqual(result['failedProfileIds'], [first])
        self.assertEqual([s.profile['id'] for s in self.bridge.sessions], [first, second, first, second, target])
        self.assertNotIn(first, self.manager.sessions)
        self.assertIn(target, self.manager.sessions)

    def test_restore_dynamic_token_pauses_without_waiting_or_resending_password(self):
        first, second, target = self.ready()
        self.bridge.pause_otp.add(first)
        self.manager.expand_connect(target, {'username': fixture.USER, 'password': fixture.PASSWORD})
        self.assertEqual(self.public(first)['status'], 'otp')
        self.assertEqual(self.manager._challenge_ids[first], 1)
        self.assertEqual([s.profile['id'] for s in self.bridge.sessions], [first, second, first, second, target])

    def test_unsaved_or_pending_owned_connection_is_not_interrupted(self):
        first, _, target = self.ready()
        self.store.values.pop(first)
        with self.assertRaises(AppError) as caught:
            self.manager.expand_connect(target, {})
        self.assertIn('保存', str(caught.exception))
        self.assert_untouched()
        self.store.values[first] = fixture.MemoryCredential(fixture.USER, fixture.PASSWORD)
        self.manager.events[first] = {'status': 'otp'}
        with self.assertRaises(AppError):
            self.manager.expand_connect(target, {})
        self.assert_untouched()

    def test_external_unknown_peer_process_or_metadata_refuses_before_disconnect(self):
        _, _, target = self.ready()
        original = deepcopy(self.manager.inventory)
        for field, addition in [('peers', {'process': 'mystery', 'gateway': '192.0.2.55', 'port': 443}),
                                ('processes', {'name': 'UVP009CS', 'pid': 2000})]:
            self.manager.inventory = deepcopy(original)
            self.manager.inventory.setdefault(field, []).append(addition)
            with self.assertRaises(AppError):
                self.manager.expand_connect(target, {})
            self.assert_untouched()
        self.manager.inventory = {**original, 'metadataUnknown': True}
        with self.assertRaises(AppError):
            self.manager.expand_connect(target, {})
        self.assert_untouched()

    def test_capacity_appeared_after_confirmation_does_not_interrupt_existing_connections(self):
        first, second, target = self.ready()
        self.manager.inventory['records'].append({'index': 3, 'status': 'Ready', 'tapGuid': 'tap-3'})
        self.manager.expand_connect(target, {'username': fixture.USER, 'password': fixture.PASSWORD})
        self.assertEqual(self.profile(target)['index'], 3)
        self.assertEqual([s.disconnects for s in self.bridge.sessions[:2]], [0, 0])
        self.assertEqual(self.bridge.creates, 0)
        self.assertEqual(set(self.manager.sessions), {first, second, target})

    def test_duplicate_owned_backend_or_extra_same_backend_peer_refuses_before_any_action(self):
        _, _, target = self.ready()
        original = deepcopy(self.manager.inventory)
        for field, addition in [('processes', {'name': 'UniVPNCS', 'pid': 9001}),
                                ('peers', {'process': 'UniVPNCS', 'gateway': '192.0.2.111', 'port': 443}),
                                ('peers', {'process': 'UniVPNCS', 'gateway': '192.0.2.10', 'port': 49999})]:
            self.manager.inventory = deepcopy(original)
            self.manager.inventory[field].append(addition)
            with self.assertRaises(AppError):
                self.manager.expand_connect(target, {})
            self.assert_untouched()

    def test_native_backend_ownership_must_be_positive_and_fail_closed(self):
        _, _, target = self.ready()
        self.bridge.owns_backend = lambda profile, row: False
        with self.assertRaises(AppError):
            self.manager.expand_connect(target, {})
        self.assert_untouched()
        def fail(profile, row):
            raise RuntimeError('private-fixture-password')
        self.bridge.owns_backend = fail
        with self.assertRaises(AppError) as caught:
            self.manager.expand_connect(target, {})
        self.assertNotIn('private-fixture-password', str(caught.exception))
        self.assert_untouched()

    def test_precisely_owned_anchor_is_allowed_but_cleared_before_driver_creation(self):
        _, _, target = self.ready()
        anchor = {'name': 'UniVPN', 'pid': 9900, 'created': 'fixture-birth'}
        self.manager.inventory['processes'].append(anchor)
        self.bridge.is_owned_anchor = lambda row: row == anchor
        original = self.bridge.quiesce_owned
        def quiesce(profile):
            original(profile)
            self.manager.inventory['processes'] = [row for row in self.manager.inventory['processes'] if row != anchor]
        with patch.object(self.bridge, 'quiesce_owned', side_effect=quiesce):
            with self.assertRaises(AppError) as caught:
                self.manager.expand_connect(target, {})
        self.assertEqual(caught.exception.code, 'credentials_required')
        self.assertEqual(self.bridge.creates, 1)
        self.assertEqual(self.profile(target)['index'], 3)

    def test_incomplete_inventory_never_interrupts_even_when_cached_online_rows_exist(self):
        _, _, target = self.ready()
        del self.manager.inventory['records']
        with self.assertRaises(AppError):
            self.manager.expand_connect(target, {})
        self.assert_untouched()

    def test_assigned_new_slot_advertises_only_target_credentials(self):
        _, _, target = self.ready()
        self.bridge.sources = [fixture.source('x', '192.0.2.30')]
        self.manager.source_links[target] = self.manager._source_link(self.bridge.sources[0])
        with self.assertRaises(AppError):
            self.manager.expand_connect(target, {})
        self.assertEqual(self.profile(target)['index'], 3)
        self.assertFalse(self.public(target)['hasSavedCredential'])
        self.assertNotIn('error', self.public(target))

    def test_malformed_manual_body_never_interrupts_existing_connections(self):
        _, _, target = self.ready()
        for body in ({'username': 'fixture', 'password': ''}, {'password': 'fixture'}, {'remember': 'yes'},
                     {'autoConnect': []}, {'username': 'bad\x00user', 'password': 'fixture'}):
            with self.assertRaises(AppError):
                self.manager.expand_connect(target, body)
            self.assert_untouched()

    def test_plain_idle_connect_also_creates_outside_global_lock(self):
        reserved = self.add('192.0.2.10')
        target = self.add('192.0.2.20')
        self.profile(reserved)['index'] = 1
        self.manager.inventory['records'] = []
        entered, release = threading.Event(), threading.Event()
        original = self.bridge.create_instance
        failures = []
        def creator():
            entered.set()
            if not release.wait(3):
                raise RuntimeError('fixture timeout')
            return original()
        def connect():
            try:
                self.manual(target)
            except Exception as exc:
                failures.append(type(exc).__name__)
        with patch.object(self.bridge, 'create_instance', side_effect=creator):
            thread = threading.Thread(target=connect, daemon=True)
            thread.start()
            try:
                self.assertTrue(entered.wait(2))
                self.assertTrue(self.manager.state()['expansion']['inProgress'])
                self.assertEqual(len(self.manager.notifications()['profiles']), 2)
                self.assertFalse(self.manager.can_shutdown())
            finally:
                release.set()
                thread.join(4)
        self.assertFalse(thread.is_alive())
        self.assertEqual(failures, [])
        self.assertEqual(self.bridge.creates, 1)
        self.assertEqual(self.profile(reserved)['index'], 1)
        self.assertEqual(self.profile(target)['index'], 2)

    def test_add_provisions_outside_global_lock_without_authenticating(self):
        reserved = self.add()
        self.profile(reserved)['index'] = 1
        self.manager.inventory['records'] = []
        entered, release = threading.Event(), threading.Event()
        original = self.bridge.create_instance
        results = []
        def creator():
            entered.set()
            if not release.wait(3):
                raise RuntimeError('fixture timeout')
            return original()
        with patch.object(self.bridge, 'create_instance', side_effect=creator):
            thread = threading.Thread(target=lambda: results.append(self.manager.add({'gateway': '192.0.2.20', 'port': 443})), daemon=True)
            thread.start()
            try:
                self.assertTrue(entered.wait(2))
                state = self.manager.state()
                self.assertTrue(state['expansion']['inProgress'])
                self.assertEqual(len(state['profiles']), 2)
                self.assertEqual(self.manager.sessions, {})
            finally:
                release.set()
                thread.join(4)
        self.assertFalse(thread.is_alive())
        self.assertEqual(self.bridge.creates, 1)
        self.assertEqual(len(results), 1)
        self.assertNotIn('notice', results[0])
        self.assertEqual(self.profile(results[0]['id'])['index'], 2)
        self.assertEqual(self.bridge.sessions, [])

    def test_unconfirmed_idle_creation_race_never_turns_into_tunnel_disconnect(self):
        first, second, target = self.ready()
        with self.assertRaises(AppError) as caught:
            self.manager.expand_connect(target, {}, _idle_only=True)
        self.assertEqual(caught.exception.code, 'expansion_required')
        self.assert_untouched()
        self.assertEqual(set(self.manager.sessions), {first, second})

    def test_auto_missing_saved_result_cannot_overwrite_expansion_started_during_read(self):
        target = self.add()
        self.profile(target)['autoConnect'] = True
        operation = {'token': object(), 'profileId': target}
        def no_saved(key):
            self.assertEqual(key, target)
            self.manager._expansion = operation
            return False
        try:
            with patch.object(self.manager, '_has_credential', side_effect=no_saved), patch.object(self.manager._stop, 'wait', return_value=False):
                self.manager._auto_connect_once()
            self.assertNotIn(target, self.manager.events)
            self.assertEqual(self.bridge.creates, 0)
            self.assertEqual(self.bridge.sessions, [])
        finally:
            self.manager._expansion = None

    def test_plain_creation_continuation_rejects_endpoint_edit_before_any_authentication(self):
        reserved, target = self.add(), self.add('192.0.2.20')
        self.profile(reserved)['index'] = 1
        self.manager.inventory['records'] = []
        original = self.manager.expand_connect
        before = self.public(target)['networkVersion']
        def redirected(key, values, **options):
            self.assertEqual(values['networkVersion'], before)
            self.manager.edit(key, {'gateway': '192.0.2.199'})
            return original(key, values, **options)
        with patch.object(self.manager, 'expand_connect', side_effect=redirected):
            with self.assertRaises(AppError) as caught:
                self.manual(target)
        self.assertEqual(caught.exception.code, 'credentials_required')
        self.assertEqual(self.bridge.sessions, [])
        self.assertEqual(self.bridge.creates, 0)
        self.assertNotEqual(self.public(target)['networkVersion'], before)

    def test_confirmation_from_old_endpoint_does_not_disconnect_or_send_password_to_new_gateway(self):
        _, _, target = self.ready()
        values = {'username': fixture.USER, 'password': fixture.PASSWORD, 'networkVersion': self.public(target)['networkVersion']}
        with self.assertRaises(AppError) as caught:
            self.manager.connect(target, values)
        self.assertEqual(caught.exception.code, 'expansion_required')
        self.manager.edit(target, {'gateway': '192.0.2.199'})
        with self.assertRaises(AppError) as caught:
            self.manager.expand_connect(target, values)
        self.assertEqual(caught.exception.code, 'credentials_required')
        self.assert_untouched()
        self.assertNotIn(target, self.manager.sessions)

    def test_stale_login_form_network_version_is_checked_before_saved_read_or_authentication(self):
        _, _, target = self.ready()
        old = self.public(target)['networkVersion']
        self.manager.edit(target, {'port': 49999})
        self.store.reads.clear()
        for values in ({'networkVersion': old}, {'username': fixture.USER, 'password': fixture.PASSWORD, 'networkVersion': old}):
            with self.assertRaises(AppError) as caught:
                self.manager.connect(target, values)
            self.assertEqual(caught.exception.code, 'credentials_required')
            self.assert_untouched()
        self.assertEqual(self.store.reads, [])

    def test_network_revision_depends_only_on_public_id_and_endpoint(self):
        target = self.add()
        before = self.public(target)['networkVersion']
        self.assertRegex(before, r'^[0-9a-f]{64}$')
        self.manager.edit(target, {'name': 'public alias', 'autoConnect': True})
        self.profile(target)['index'] = 2
        self.manager.source_links[target] = self.manager._source_link(fixture.source('x'))
        self.assertEqual(self.public(target)['networkVersion'], before)
        self.manager.edit(target, {'gateway': '192.0.2.188'})
        self.assertNotEqual(self.public(target)['networkVersion'], before)
        self.assertNotIn('networkVersion', self.manager.path.read_text('utf-8'))
        notification = self.manager.notifications()['profiles'][0]
        self.assertEqual(set(notification), {'id', 'status', 'challengeId'})

    def test_creator_runs_without_global_lock_and_blocks_writes_but_allows_reads_and_otp(self):
        first, _, target = self.ready()
        entered, release = threading.Event(), threading.Event()
        original = self.bridge.create_instance
        results = []
        def creator():
            entered.set()
            if not release.wait(3):
                raise RuntimeError('fixture timeout')
            return original()
        def run():
            try:
                results.append(self.manager.expand_connect(target, {}))
            except AppError as exc:
                results.append(exc.code)
        with patch.object(self.bridge, 'create_instance', side_effect=creator):
            thread = threading.Thread(target=run, daemon=True)
            thread.start()
            try:
                self.assertTrue(entered.wait(2))
                self.assertTrue(self.manager.state()['expansion']['inProgress'])
                self.assertEqual(set(self.manager.notifications()), {'profiles'})
                self.assertFalse(self.manager.can_shutdown())
                actions = [lambda: self.manager.connect(target, {}), lambda: self.manager.disconnect(first),
                           lambda: self.manager.edit(target, {'name': 'new'}), lambda: self.manager.remove(target),
                           lambda: self.manager.forget_credential(first), lambda: self.manager.set_automatic({'enabled': True}),
                           lambda: self.manager.add({'gateway': '192.0.2.99', 'port': 443}),
                           lambda: self.manager.settings({'startup': True}), lambda: self.manager.expand_connect(target, {})]
                for action in actions:
                    with self.assertRaises(AppError) as caught:
                        action()
                    self.assertEqual(caught.exception.code, 'expansion_in_progress')
                # Reaching normal OTP validation proves expansion does not block
                # this user-only authentication endpoint globally.
                with self.assertRaises(AppError) as caught:
                    self.manager.otp(first, {'code': 'fixture-code'})
                self.assertIsNone(caught.exception.code)
            finally:
                release.set()
                thread.join(4)
        self.assertFalse(thread.is_alive())
        self.assertEqual(results, ['credentials_required'])
        self.assertFalse(self.manager.state()['expansion']['inProgress'])


if __name__ == '__main__':
    unittest.main()
