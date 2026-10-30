"""Multiple saved configurations on leased native slots; synthetic data only."""
from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from core import AppError, Manager
from test_core_preferences import MemoryStore, MemoryCredential, FakeStartup

USER = 'multi-fixture-account'
PASSWORD = 'multi-fixture-password'


@dataclass(frozen=True, repr=False)
class NativeReference:
    username: str
    profile_name: str


class Session:
    def __init__(self, profile, notify):
        self.profile, self.notify = dict(profile), notify
        self.normal, self.saved = [], []
        self.disconnects = 0

    def start(self, username, password):
        self.normal.append((username, password))
        self.notify({'status': 'otp', 'challenge': '动态口令'})

    def start_saved(self, username, name):
        self.saved.append((username, name))
        self.notify({'status': 'otp', 'challenge': '动态口令'})

    def disconnect(self):
        self.disconnects += 1
        self.notify({'status': 'disconnected'})


class Bridge:
    available = True

    def __init__(self):
        self.sources = []
        self.sessions, self.lookups = [], []
        self.creates = 0
        self.external_disconnects = []
        self.manager = None

    def remembered_sources(self, inventory):
        return deepcopy(self.sources)

    def legacy_reference(self, profile, *, source=None):
        self.lookups.append((dict(profile), deepcopy(source)))
        if source is None:
            return None
        row = next((r for r in self.sources if r['sourceId'] == source['sourceId']), None)
        if row and (profile['gateway'], profile['port'], profile['index']) == (row['gateway'], row['port'], row['sourceIndex']):
            return NativeReference(USER, 'private-reference-' + row['sourceId'])
        return None

    def session(self, profile, notify):
        result = Session(profile, notify)
        self.sessions.append(result)
        return result

    def create_instance(self):
        self.creates += 1
        current = self.manager._available_indexes()
        index = max(current | {1}) + 1
        self.manager.inventory.setdefault('records', []).append({'index': index, 'status': 'Ready', 'tapGuid': f'tap-{index}'})
        return index

    def disconnect_external(self, profile):
        self.external_disconnects.append(dict(profile))


def source(letter, gateway='192.0.2.10', *, index=1, name='重复'):
    return {'sourceId': letter * 64, 'sourceIndex': index, 'sourceName': f'private-{letter}.ini',
            'gateway': gateway, 'port': 443, 'name': name}


class MultiConfigurationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='vpn-multi-fixture-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.bridge, self.store, self.startup = Bridge(), MemoryStore(), FakeStartup()
        self.manager = Manager(self.root, bridge=self.bridge, credentials=self.store,
                               startup=self.startup, inspect=False)
        self.addCleanup(self.manager.close)
        self.bridge.manager = self.manager
        self.manager.inventory = {'installed': True, 'records': [{'index': 2, 'status': 'Ready', 'tapGuid': 'tap-2'}]}

    def add(self, gateway='192.0.2.10', name=''):
        # Most tests need an unassigned configuration, as imported/online-added
        # entries are. Explicit eager-add coverage calls Manager.add directly.
        with patch.object(self.manager, '_can_allocate_idle', return_value=False):
            result = self.manager.add({'gateway': gateway, 'port': 443, 'name': name})
        return result['id']

    def profile(self, key):
        return self.manager._profile(key)

    def public(self, key):
        return next(row for row in self.manager.state()['profiles'] if row['id'] == key)

    def manual(self, key, **options):
        return self.manager.connect(key, {'username': USER, 'password': PASSWORD, **options})

    def import_all(self):
        self.bridge.sources = [source('a'), source('b', '192.0.2.20'), source('c'), source('d', '192.0.2.30', index=2)]
        self.manager._import_existing()
        return {link['sourceId'][0]: key for key, link in self.manager.source_links.items()}

    def automatic(self):
        with patch.object(self.manager._stop, 'wait', return_value=False):
            self.manager._auto_connect_once()

    def assert_private(self):
        material = json.dumps(self.manager.state(), ensure_ascii=False) + self.manager.path.read_text('utf-8')
        for field in ('sourceId', 'sourceIndex', 'sourceName', 'private-', 'username', USER, PASSWORD):
            self.assertNotIn(field, material)

    def test_add_is_metadata_only_even_with_no_bridge_or_while_other_vpn_is_live(self):
        self.manager.inventory['adapters'] = [{'guid': 'original', 'up': True, 'addresses': ['192.0.2.99']}]
        self.manager.bridge = None
        first, second = self.add(), self.add()
        self.assertNotEqual(first, second)
        self.assertEqual([p['index'] for p in self.manager.profiles], [0, 0])
        self.assertEqual(self.bridge.creates, 0)
        self.assertEqual(self.bridge.external_disconnects, [])

    def test_multiple_unassigned_indexes_load_but_positive_indexes_remain_unique(self):
        self.add()
        self.add()
        loaded = Manager(self.root, bridge=self.bridge, inspect=False)
        self.addCleanup(loaded.close)
        self.assertEqual([p['index'] for p in loaded.profiles], [0, 0])
        rows = json.loads(self.manager.path.read_text('utf-8'))
        for row in rows:
            row['index'] = 1
        original = json.dumps(rows)
        self.manager.path.write_text(original, 'utf-8')
        with self.assertRaises(AppError):
            Manager(self.root, bridge=self.bridge, inspect=False)
        self.assertEqual(self.manager.path.read_text('utf-8'), original)

    def test_all_physical_sources_survive_name_and_endpoint_collisions(self):
        keys = self.import_all()
        self.assertEqual(set(keys), {'a', 'b', 'c', 'd'})
        self.assertEqual(len(self.manager.profiles), 4)
        self.assertTrue(all(p['index'] == 0 and not p['autoConnect'] for p in self.manager.profiles))
        self.assertNotEqual(keys['a'], keys['c'])
        self.assertEqual((self.profile(keys['a'])['name'], self.profile(keys['a'])['gateway']),
                         (self.profile(keys['c'])['name'], self.profile(keys['c'])['gateway']))
        self.assertEqual(self.bridge.creates, 0)
        self.assertEqual(self.bridge.sessions, [])
        self.assert_private()

    def test_more_than_one_hundred_sources_are_not_silently_truncated(self):
        self.bridge.sources = [{**source('a'), 'sourceId': f'configuration-{n}', 'sourceName': f'private-{n}.ini'} for n in range(101)]
        self.manager._import_existing()
        self.assertEqual(len(self.manager.profiles), 101)
        self.assertEqual(len(self.manager.source_links), 101)
        self.assertEqual(self.bridge.creates, 0)

    def test_import_limit_is_explicit_and_preserves_existing_rows(self):
        existing = self.add('192.0.2.99', name='用户配置')
        self.bridge.sources = [source('a'), source('b'), source('c'), source('d')]
        with patch('core.MAX_PROFILES', 3):
            self.manager._import_existing()
        self.assertEqual(len(self.manager.profiles), 3)
        self.assertEqual(self.profile(existing)['name'], '用户配置')
        self.assertIn('未能全部导入', self.manager.state()['error'])
        self.assertEqual(self.bridge.creates, 0)
        self.manager._import_existing()
        self.assertEqual(len(self.manager.profiles), 5)
        self.assertEqual(self.manager.state()['error'], '')

    def test_import_is_idempotent_and_roundtrips_private_links_without_overwriting_custom_names(self):
        self.import_all()
        identifiers = [p['id'] for p in self.manager.profiles]
        self.manager.profiles[0]['name'] = '用户名称'
        self.manager._save()
        self.manager._import_existing()
        self.assertEqual([p['id'] for p in self.manager.profiles], identifiers)
        self.assertEqual(self.manager.profiles[0]['name'], '用户名称')
        loaded = Manager(self.root, bridge=self.bridge, credentials=self.store, inspect=False)
        self.addCleanup(loaded.close)
        loaded._import_existing()
        self.assertEqual([p['id'] for p in loaded.profiles], identifiers)
        self.assertEqual(loaded.source_links, self.manager.source_links)
        self.assert_private()

    def test_same_source_identity_normalizes_cached_lookup_metadata_without_touching_user_profile(self):
        canonical = {**source('a'), 'sourceName': '规范原生缓存名.ini', 'name': '候选原名称'}
        self.bridge.sources = [canonical]
        self.manager._import_existing()
        key = self.manager.profiles[0]['id']
        self.profile(key).update(name='用户自定义名称', gateway='192.0.2.99', port=5443,
                                 autoConnect=True, useLegacyCredential=False)
        self.manager.source_links[key] = {'sourceId': canonical['sourceId'], 'sourceIndex': 2,
                                          'sourceName': '旧编码字段锟斤拷.ini'}
        self.manager.deleted_sources.add('b' * 64)
        self.manager._save_sources()
        self.manager._save()
        before = deepcopy(self.manager.profiles)

        loaded = Manager(self.root, bridge=self.bridge, credentials=self.store, startup=self.startup, inspect=False)
        self.addCleanup(loaded.close)
        loaded._import_existing()
        self.assertEqual(loaded.profiles, before)
        self.assertEqual(loaded.source_links[key], {'sourceId': canonical['sourceId'], 'sourceIndex': 1,
                                                    'sourceName': canonical['sourceName']})
        self.assertEqual(loaded.deleted_sources, {'b' * 64})
        saved = json.loads(loaded.source_path.read_text('utf-8'))
        self.assertEqual(saved['links'][key], loaded.source_links[key])
        self.assertEqual(saved['deleted'], ['b' * 64])
        for private in ('sourceId', 'sourceIndex', 'sourceName', canonical['sourceName'], canonical['sourceId']):
            self.assertNotIn(private, loaded.path.read_text('utf-8'))
            self.assertNotIn(private, json.dumps(loaded.state(), ensure_ascii=False))

        again = Manager(self.root, bridge=self.bridge, credentials=self.store, startup=self.startup, inspect=False)
        self.addCleanup(again.close)
        with patch.object(again, '_save_sources', side_effect=AssertionError('Repeated import must be a no-op')), \
             patch.object(again, '_save', side_effect=AssertionError('User metadata must not be rewritten')):
            again._import_existing()
        self.assertEqual(again.profiles, before)
        self.assertEqual(again.source_links, loaded.source_links)
        self.assertEqual(self.bridge.creates, 0)
        self.assertEqual(self.bridge.sessions, [])

    def test_lookup_metadata_refresh_never_bypasses_source_tombstone(self):
        self.bridge.sources = [source('a')]
        self.manager._import_existing()
        key = self.manager.profiles[0]['id']
        stale = {**self.manager.source_links[key], 'sourceName': '旧缓存字段.ini'}
        self.manager.source_links[key] = dict(stale)
        self.manager.deleted_sources.add(stale['sourceId'])
        self.manager._save_sources()
        self.manager._import_existing()
        self.assertEqual(self.manager.source_links[key], stale)
        self.assertEqual(len(self.manager.profiles), 1)
        self.assertIn(stale['sourceId'], self.manager.deleted_sources)

    def test_lookup_refresh_requires_same_file_identity_even_when_name_and_endpoint_match(self):
        self.bridge.sources = [source('a')]
        self.manager._import_existing()
        original_id = self.manager.profiles[0]['id']
        original_link = dict(self.manager.source_links[original_id])
        self.bridge.sources = [{**source('b'), 'sourceName': original_link['sourceName']}]
        self.manager._import_existing()
        self.assertEqual(self.manager.source_links[original_id], original_link)
        self.assertEqual(len(self.manager.profiles), 2)
        self.assertEqual({v['sourceId'] for v in self.manager.source_links.values()}, {'a' * 64, 'b' * 64})

    def test_visible_old_name_can_equal_source_stem_without_exposing_source_structure(self):
        self.bridge.sources = [{**source('a'), 'sourceName': '旧配置名称', 'name': '旧配置名称'}]
        self.manager._import_existing()
        public = self.manager.state()['profiles'][0]
        self.assertEqual(public['name'], '旧配置名称')
        self.assertTrue(public['hasSavedCredential'])
        self.assertNotIn('sourceId', public)
        self.assertNotIn('sourceIndex', public)
        self.assertNotIn('sourceName', public)
        text = json.dumps(public, ensure_ascii=False)
        self.assertNotIn('a' * 64, text)
        self.assertNotIn(USER, text)
        self.assertNotIn('private-reference', text)

    def test_long_original_display_name_is_preserved_without_truncation(self):
        name = '旧配置名称' * 20
        self.bridge.sources = [{**source('a'), 'name': name}]
        self.manager._import_existing()
        self.assertEqual(self.manager.profiles[0]['name'], name)
        self.assertEqual(self.manager.state()['profiles'][0]['name'], name)

    def test_unique_existing_positive_assignment_gets_link_without_replacing_preferences(self):
        key = self.add(name='用户名称')
        self.profile(key).update(index=1, autoConnect=True)
        self.manager._save()
        self.bridge.sources = [source('a')]
        self.manager._import_existing()
        self.assertEqual(len(self.manager.profiles), 1)
        self.assertEqual(self.profile(key)['name'], '用户名称')
        self.assertTrue(self.profile(key)['autoConnect'])
        self.assertEqual(self.manager.source_links[key]['sourceId'], 'a' * 64)

    def test_first_unique_link_inherits_old_visible_name_only_when_existing_name_is_empty(self):
        key = self.add()
        self.profile(key)['index'] = 1
        self.bridge.sources = [source('a', name='原配置名称')]
        self.manager._import_existing()
        self.assertEqual(self.profile(key)['name'], '原配置名称')
        self.manager.edit(key, {'name': ''})
        self.manager._import_existing()
        self.assertEqual(self.profile(key)['name'], '')

    def test_ambiguous_existing_endpoint_is_never_guessed_and_all_sources_are_new_rows(self):
        key = self.add(name='已记忆')
        self.profile(key)['index'] = 1
        self.bridge.sources = [source('a'), source('b')]
        self.manager._import_existing()
        self.assertNotIn(key, self.manager.source_links)
        self.assertEqual(self.profile(key)['index'], 1)
        self.assertEqual(len(self.manager.profiles), 3)
        self.assertEqual(sum(p['index'] == 0 for p in self.manager.profiles), 2)

    def test_existing_two_positive_rows_remain_while_all_other_sources_import_unassigned(self):
        first, second = self.add(name='原1'), self.add('192.0.2.30', name='原2')
        self.profile(first)['index'], self.profile(second)['index'] = 1, 2
        keys = self.import_all()
        self.assertEqual((self.profile(first)['index'], self.profile(second)['index']), (1, 2))
        self.assertEqual(keys['d'], second)
        self.assertEqual(len(self.manager.profiles), 5)
        self.assertEqual([p['name'] for p in self.manager.profiles[:2]], ['原1', '原2'])

    def test_delete_tombstone_prevents_restart_resurrection_without_affecting_same_endpoint_source(self):
        keys = self.import_all()
        self.manager.remove(keys['a'])
        self.assertIn('a' * 64, self.manager.deleted_sources)
        self.assertIn(keys['c'], [p['id'] for p in self.manager.profiles])
        loaded = Manager(self.root, bridge=self.bridge, credentials=self.store, inspect=False)
        self.addCleanup(loaded.close)
        loaded._import_existing()
        self.assertEqual(len(loaded.profiles), 3)
        self.assertNotIn('a' * 64, {v['sourceId'] for v in loaded.source_links.values()})
        self.assertEqual(len(self.bridge.sources), 4)
        self.assertEqual(self.bridge.external_disconnects, [])

    def test_malformed_private_source_file_is_preserved_and_refused(self):
        self.add()
        original = '{"links":{"bad":{"sourceId":"a","sourceIndex":1,"sourceName":"../escape.ini"}},"deleted":[]}'
        self.manager.source_path.write_text(original, 'utf-8')
        with self.assertRaises(AppError):
            Manager(self.root, bridge=self.bridge, inspect=False)
        self.assertEqual(self.manager.source_path.read_text('utf-8'), original)

    def test_unsafe_source_names_are_skipped_without_hidden_creation(self):
        self.bridge.sources = [{**source('a'), 'sourceName': '../escape.ini'}, {**source('b'), 'sourceName': 'C:other.ini'}, source('c')]
        self.manager._import_existing()
        self.assertEqual(len(self.manager.profiles), 1)
        self.assertEqual(self.bridge.creates, 0)
        self.assertEqual(next(iter(self.manager.source_links.values()))['sourceId'], 'c' * 64)

    def test_manual_login_preserves_an_inactive_assignment_and_uses_an_unreserved_slot(self):
        old = self.add('192.0.2.20')
        self.profile(old)['index'] = 1
        new = self.add()
        self.manual(new)
        self.assertEqual(self.profile(old)['index'], 1)
        self.assertEqual(self.profile(new)['index'], 2)
        self.assertEqual(self.bridge.sessions[0].profile['id'], new)
        self.assertEqual(self.bridge.sessions[0].normal, [(USER, PASSWORD)])
        self.assertEqual(self.bridge.creates, 0)

    def test_owned_slot_is_not_reassigned_and_next_manual_login_uses_another_ready_slot(self):
        first, second = self.add(), self.add('192.0.2.20')
        self.manual(first)
        self.manual(second)
        self.assertEqual((self.profile(first)['index'], self.profile(second)['index']), (1, 2))
        self.assertEqual(len(self.manager.sessions), 2)
        self.assertEqual(self.bridge.external_disconnects, [])

    def test_external_live_slot_requires_handoff_without_touching_any_slot(self):
        old, new = self.add('192.0.2.20'), self.add()
        self.profile(old)['index'] = 1
        self.manager.inventory.update(adapters=[{'guid': 'original', 'up': True, 'addresses': ['192.0.2.90']}],
                                      peers=[{'process': 'UniVPNCS', 'gateway': '192.0.2.20', 'port': 443}])
        with self.assertRaises(AppError) as caught:
            self.manual(new)
        self.assertIn('原客户端', str(caught.exception))
        self.assertEqual(self.profile(new)['index'], 0)
        self.assertEqual(self.public(old)['status'], 'connected')
        self.assertEqual(self.bridge.external_disconnects, [])

    def test_manual_without_available_slot_creates_only_when_all_native_resources_are_idle(self):
        key = self.add()
        self.manager.inventory = {'installed': False}
        self.manual(key)
        self.assertEqual(self.bridge.creates, 1)
        self.assertEqual(self.profile(key)['index'], 2)
        self.assertEqual(self.bridge.sessions[0].profile['index'], 2)

    def test_manual_capacity_exhaustion_never_stops_connections_or_calls_create(self):
        first, second, third = self.add(), self.add('192.0.2.20'), self.add('192.0.2.30')
        self.manual(first)
        self.manual(second)
        with self.assertRaises(AppError) as caught:
            self.manual(third)
        self.assertEqual(caught.exception.status, 409)
        self.assertEqual(self.profile(third)['index'], 0)
        self.assertEqual(self.bridge.creates, 0)
        self.assertEqual(self.bridge.external_disconnects, [])

    def test_idle_vendor_process_still_prevents_driver_creation(self):
        key = self.add()
        self.manager.inventory = {'installed': False, 'processes': [{'name': 'UniVPN', 'pid': 12345}]}
        with self.assertRaises(AppError):
            self.manual(key)
        self.assertEqual(self.bridge.creates, 0)

    def test_unclaimed_external_backend_peer_blocks_slot_even_without_any_profile_owner(self):
        first, second = self.add(), self.add('192.0.2.20')
        self.manual(first)
        self.manager.inventory['peers'] = [{'process': 'UVP002CS', 'gateway': '192.0.2.99', 'port': 5443}]
        self.assertFalse(any(p['index'] == 2 for p in self.manager.profiles))
        with self.assertRaises(AppError):
            self.manual(second)
        self.assertEqual(self.profile(second)['index'], 0)
        self.assertEqual(self.bridge.creates, 0)
        self.assertEqual(self.bridge.external_disconnects, [])

    def test_unknown_external_peer_blocks_driver_creation_even_if_its_record_is_missing(self):
        key = self.add()
        self.manager.inventory = {'installed': False, 'peers': [{'process': 'UVP009CS', 'gateway': '192.0.2.99', 'port': 443}]}
        with self.assertRaises(AppError):
            self.manual(key)
        self.assertEqual(self.bridge.creates, 0)

    def test_unknown_or_failed_inventory_never_allocates_or_creates(self):
        key = self.add()
        for value in ({}, {'installed': True, 'metadataUnknown': True}, {'installed': True, 'records': None},
                      {'installed': True, 'adapters': [None]}):
            with self.subTest(inventory=value):
                self.manager.inventory = value
                with self.assertRaises(AppError):
                    self.manual(key)
                self.assertEqual(self.profile(key)['index'], 0)
        self.manager.inventory = {'installed': True}
        self.manager.inventory_error = '无法读取 VPN 状态'
        with self.assertRaises(AppError):
            self.manual(key)
        self.assertEqual(self.bridge.creates, 0)
        self.assertEqual(self.bridge.sessions, [])

    def test_unknown_inventory_on_existing_positive_profile_is_controlled_without_stale_online(self):
        key = self.add()
        self.profile(key)['index'] = 1
        self.manager.inventory = {'installed': True, 'records': None}
        self.assertEqual(self.public(key)['status'], 'disconnected')
        with self.assertRaises(AppError) as caught:
            self.manual(key)
        self.assertEqual(caught.exception.status, 409)
        self.assertEqual(self.bridge.creates, 0)

    def test_legacy_reference_lookup_on_index_zero_uses_private_source_and_executes_that_same_slot(self):
        keys = self.import_all()
        self.manager.connect(keys['d'], {})
        lookup, link = self.bridge.lookups[-1]
        self.assertEqual(lookup['index'], 2)
        self.assertEqual(link['sourceIndex'], 2)
        session = self.bridge.sessions[-1]
        self.assertEqual(session.profile['index'], 2)
        self.assertEqual(session.normal, [])
        self.assertTrue(session.saved)
        self.assertEqual(self.store.saves, [])
        self.assertEqual(self.manager._pending_credentials, {})
        self.assert_private()

    def test_legacy_source_slot_conflict_never_sends_source_one_reference_to_free_clone_two(self):
        keys = self.import_all()
        old = self.add('192.0.2.99')
        self.manual(old)
        with self.assertRaises(AppError) as caught:
            self.manager.connect(keys['a'], {})
        self.assertEqual(caught.exception.code, 'credentials_required')
        self.assertEqual(self.profile(keys['a'])['index'], 2)
        self.assertEqual(len(self.bridge.sessions), 1)
        self.assertEqual(self.bridge.sessions[0].saved, [])
        self.assertEqual(self.bridge.creates, 0)

    def test_manual_relogin_can_use_clone_then_own_vault_reconnects_without_cross_native_reference(self):
        keys = self.import_all()
        old = self.add('192.0.2.99')
        self.manual(old)
        self.manual(keys['a'], remember=True)
        session = self.bridge.sessions[-1]
        self.assertEqual(session.profile['index'], 2)
        self.assertEqual(session.saved, [])
        session.notify({'status': 'authenticated'})
        self.manager.disconnect(keys['a'])
        self.bridge.lookups.clear()
        self.manager.connect(keys['a'], {})
        self.assertEqual(self.bridge.sessions[-1].normal, [(USER, PASSWORD)])
        self.assertEqual(self.bridge.sessions[-1].profile['index'], 2)
        self.assertEqual(self.bridge.lookups, [])

    def test_legacy_only_missing_source_never_creates_a_different_slot(self):
        keys = self.import_all()
        self.manager.inventory = {'installed': False, 'records': [{'index': 2, 'status': 'Ready'}]}
        with self.assertRaises(AppError):
            self.manager.connect(keys['a'], {})
        self.assertEqual(self.bridge.creates, 0)
        self.assertEqual(self.bridge.sessions, [])

    def test_same_source_auto_profiles_attempt_once_and_pause_only_the_first_dynamic_challenge(self):
        keys = self.import_all()
        self.profile(keys['a'])['autoConnect'] = self.profile(keys['c'])['autoConnect'] = True
        self.automatic()
        self.automatic()
        self.assertEqual(len(self.bridge.sessions), 1)
        self.assertEqual(self.public(keys['a'])['status'], 'otp')
        self.assertEqual(self.public(keys['c'])['status'], 'error')
        self.assertEqual(self.profile(keys['c'])['index'], 2)
        self.assertEqual(self.bridge.creates, 0)

    def test_auto_unassigned_vault_profile_can_lease_prepared_slot_without_creating(self):
        key = self.add()
        self.profile(key)['autoConnect'] = True
        self.store.values[key] = MemoryCredential(USER, PASSWORD)
        self.automatic()
        self.assertEqual(self.profile(key)['index'], 1)
        self.assertEqual(self.public(key)['status'], 'otp')
        self.assertEqual(self.bridge.creates, 0)

    def test_auto_unprepared_slot_only_reports_manual_preparation_without_creating(self):
        key = self.add()
        self.profile(key)['autoConnect'] = True
        self.store.values[key] = MemoryCredential(USER, PASSWORD)
        self.manager.inventory = {'installed': False}
        self.automatic()
        self.assertIn('手动连接一次', self.public(key)['error'])
        self.assertEqual(self.profile(key)['index'], 0)
        self.assertEqual(self.bridge.creates, 0)
        self.assertEqual(self.bridge.sessions, [])

    def test_unbound_rows_never_all_appear_connected_from_a_shared_endpoint(self):
        keys = self.import_all()
        self.manager.inventory.update(adapters=[{'guid': 'original', 'up': True, 'addresses': ['192.0.2.90']}],
                                      peers=[{'process': 'UniVPNCS', 'gateway': '192.0.2.10', 'port': 443}])
        self.assertFalse(self.manager._connected(self.profile(keys['a'])))
        self.assertFalse(self.manager._connected(self.profile(keys['c'])))
        self.assertTrue(all(p['status'] == 'disconnected' for p in self.manager.state()['profiles']))
        self.profile(keys['a'])['index'] = 1
        self.assertEqual(self.public(keys['a'])['status'], 'connected')
        self.assertEqual(self.public(keys['c'])['status'], 'disconnected')

    def test_unbound_disconnect_is_rejected_without_native_calls(self):
        key = self.add()
        with self.assertRaises(AppError) as caught:
            self.manager.disconnect(key)
        self.assertEqual(caught.exception.status, 409)
        self.assertEqual(self.bridge.external_disconnects, [])

    def test_forget_disables_both_credential_sources_and_auto_without_touching_vendor(self):
        keys = self.import_all()
        self.profile(keys['a'])['autoConnect'] = True
        before = deepcopy(self.bridge.sources)
        self.manager.forget_credential(keys['a'])
        self.bridge.lookups.clear()
        self.assertFalse(self.public(keys['a'])['hasSavedCredential'])
        self.assertTrue(all(lookup[0]['id'] != keys['a'] for lookup in self.bridge.lookups))
        self.assertFalse(self.profile(keys['a'])['autoConnect'])
        self.assertEqual(self.bridge.sources, before)
        self.assertIn(keys['a'], self.manager.source_links)

    def test_gateway_edit_clears_old_vault_legacy_link_and_auto_before_next_login(self):
        keys = self.import_all()
        key = keys['a']
        self.profile(key)['autoConnect'] = True
        self.store.values[key] = MemoryCredential(USER, PASSWORD)
        self.manager.edit(key, {'gateway': '192.0.2.100'})
        self.assertNotIn(key, self.store.values)
        self.assertNotIn(key, self.manager.source_links)
        self.assertFalse(self.profile(key)['autoConnect'])
        self.assertFalse(self.profile(key)['useLegacyCredential'])
        self.bridge.lookups.clear()
        with self.assertRaises(AppError):
            self.manager.connect(key, {})
        self.assertEqual(self.bridge.lookups, [])
        self.assertEqual(len(self.bridge.sources), 4)

    def test_notifications_never_resolve_private_source_or_vault(self):
        self.import_all()
        with patch.object(self.bridge, 'legacy_reference', side_effect=AssertionError('native reference read')), \
             patch.object(self.store, 'read', side_effect=AssertionError('vault read')):
            result = self.manager.notifications()
        self.assertTrue(all(set(row) == {'id', 'status', 'challengeId'} for row in result['profiles']))
        self.assertNotIn('source', json.dumps(result))

    def test_fresh_single_environment_explicit_add_grows_to_two_three_four(self):
        self.manager.inventory = {'installed': True}
        keys = [self.manager.add({'gateway': f'192.0.2.{10 + n}', 'port': 443})['id'] for n in range(4)]
        self.assertEqual([self.profile(key)['index'] for key in keys], [1, 2, 3, 4])
        self.assertEqual(self.bridge.creates, 3)
        self.assertEqual(self.bridge.sessions, [])
        self.assertEqual(self.bridge.external_disconnects, [])

    def test_reserved_inactive_original_is_not_stolen_and_manual_connection_creates_second(self):
        self.manager.inventory = {'installed': True}
        old, new = self.add('192.0.2.20'), self.add()
        self.profile(old)['index'] = 1
        self.manual(new)
        self.assertEqual(self.profile(old)['index'], 1)
        self.assertEqual(self.profile(new)['index'], 2)
        self.assertEqual(self.bridge.creates, 1)

    def test_online_explicit_add_keeps_configuration_unassigned_and_never_calls_creator(self):
        self.manager.inventory.update(processes=[{'name': 'UniVPN', 'pid': 12345}],
                                      peers=[{'process': 'UniVPNCS', 'gateway': '192.0.2.10', 'port': 443}])
        result = self.manager.add({'name': '保留配置', 'gateway': '192.0.2.50', 'port': 443})
        self.assertEqual(self.profile(result['id'])['index'], 0)
        self.assertEqual(self.profile(result['id'])['name'], '保留配置')
        self.assertIn('配置已保存', result['notice'])
        self.assertIn('退出原客户端', result['notice'])
        self.assertEqual(self.bridge.creates, 0)
        self.assertEqual(self.bridge.external_disconnects, [])

    def test_creation_failure_during_explicit_add_keeps_entry_and_manual_retry_is_explicit(self):
        self.manager.inventory = {'installed': True}
        first = self.manager.add({'gateway': '192.0.2.10', 'port': 443})['id']
        creator = self.bridge.create_instance
        def fail():
            self.bridge.creates += 1
            raise RuntimeError('synthetic helper failure')
        with patch.object(self.bridge, 'create_instance', side_effect=fail):
            result = self.manager.add({'gateway': '192.0.2.20', 'port': 443, 'name': '记住新配置'})
        second = result['id']
        self.assertEqual(self.profile(first)['index'], 1)
        self.assertEqual(self.profile(second)['index'], 0)
        self.assertEqual(self.profile(second)['name'], '记住新配置')
        self.assertIn('配置已保存', result['notice'])
        self.assertEqual(self.bridge.creates, 1)
        self.manual(second)
        self.assertEqual(self.profile(first)['index'], 1)
        self.assertEqual(self.profile(second)['index'], 2)
        self.assertEqual(self.bridge.creates, 2)

    def test_uncertain_created_environment_is_reused_on_manual_retry_without_duplicate_creation(self):
        self.manager.inventory = {'installed': True}
        self.manager.add({'gateway': '192.0.2.10', 'port': 443})
        creator = self.bridge.create_instance
        def uncertain():
            creator()
            raise AppError('synthetic result unconfirmed', 409)
        with patch.object(self.bridge, 'create_instance', side_effect=uncertain):
            result = self.manager.add({'gateway': '192.0.2.20', 'port': 443})
        self.assertEqual(self.profile(result['id'])['index'], 0)
        self.assertEqual(self.bridge.creates, 1)
        self.manual(result['id'])
        self.assertEqual(self.profile(result['id'])['index'], 2)
        self.assertEqual(self.bridge.creates, 1)

    def test_imported_source_survives_manual_creator_failure_without_retry(self):
        keys = self.import_all()
        self.manager.inventory = {'installed': True}
        self.manager.connect(keys['a'], {})
        self.manager.disconnect(keys['a'])
        before = dict(self.manager.source_links[keys['b']])
        def fail():
            self.bridge.creates += 1
            raise RuntimeError('synthetic helper failure')
        with patch.object(self.bridge, 'create_instance', side_effect=fail):
            with self.assertRaises(AppError) as caught:
                self.manual(keys['b'])
        self.assertEqual(caught.exception.status, 409)
        self.assertEqual(self.bridge.creates, 1)
        self.assertEqual(self.profile(keys['b'])['index'], 0)
        self.assertEqual(self.manager.source_links[keys['b']], before)

    def test_source_provenance_does_not_take_another_offline_profiles_reserved_slot(self):
        keys = self.import_all()
        self.manager.connect(keys['a'], {})
        self.manager.disconnect(keys['a'])
        with self.assertRaises(AppError) as caught:
            self.manager.connect(keys['b'], {})
        self.assertEqual(caught.exception.code, 'credentials_required')
        self.assertEqual(self.profile(keys['a'])['index'], 1)
        self.assertEqual(self.profile(keys['b'])['index'], 2)
        self.assertEqual(self.bridge.sessions[-1].profile['index'], 1)
        self.assertTrue(self.bridge.sessions[-1].saved)
        self.assertEqual(self.bridge.creates, 0)

    def test_fresh_import_binds_original_only_for_one_unique_live_endpoint(self):
        self.manager.inventory = {'installed': True,
                                  'peers': [{'process': 'UniVPNCS', 'gateway': '192.0.2.20', 'port': 443}]}
        self.bridge.sources = [source('a'), source('b', '192.0.2.20'), source('c', '192.0.2.30')]
        self.manager._import_existing()
        keys = {link['sourceId'][0]: key for key, link in self.manager.source_links.items()}
        self.assertEqual([self.profile(keys[c])['index'] for c in 'abc'], [0, 1, 0])
        self.assertEqual(self.bridge.creates, 0)
        self.assertEqual(self.bridge.sessions, [])

    def test_fresh_import_does_not_guess_duplicate_live_endpoint_or_bind_offline_sources(self):
        self.manager.inventory = {'installed': True,
                                  'peers': [{'process': 'UniVPNCS', 'gateway': '192.0.2.10', 'port': 443}]}
        self.bridge.sources = [source('a'), source('b'), source('c', '192.0.2.30')]
        self.manager._import_existing()
        self.assertTrue(all(p['index'] == 0 for p in self.manager.profiles))
        self.manager.inventory['peers'] = []
        self.manager._import_existing()
        self.assertTrue(all(p['index'] == 0 for p in self.manager.profiles))
        self.assertEqual(self.bridge.creates, 0)

    def test_only_exact_owned_anchor_metadata_is_excluded_from_handoff(self):
        row = {'name': 'UniVPN', 'pid': 1234501, 'created': 'fixture-birth', 'session': 8}
        self.manager.inventory['processes'] = [row]
        self.bridge.is_owned_anchor = lambda candidate: candidate == row
        self.assertFalse(self.manager.state()['handoffRequired'])
        self.manager.inventory['processes'] = [{**row, 'pid': 1234502}]
        self.assertTrue(self.manager.state()['handoffRequired'])
        self.manager.inventory['processes'] = [{**row, 'created': 'different-birth'}]
        self.assertTrue(self.manager.state()['handoffRequired'])
        self.bridge.is_owned_anchor = lambda candidate: (_ for _ in ()).throw(RuntimeError('unconfirmed'))
        self.assertTrue(self.manager.state()['handoffRequired'])
        self.assertNotIn('created', json.dumps(self.manager.state()))


if __name__ == '__main__':
    unittest.main(verbosity=2)
