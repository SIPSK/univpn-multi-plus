"""Pure fixtures for the privileged bridge. No native action is executed."""
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import json
import threading
import time
import unittest
from unittest.mock import Mock, patch

from core import AppError
from native import NativeBridge


class BridgeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.bridge = NativeBridge.__new__(NativeBridge)
        self.bridge.available = True
        self.bridge.source = Path(self.tmp.name)
        self.bridge.runtime_dir = Path(self.tmp.name)
        self.bridge._lock = threading.RLock()
        self.bridge._prepared = {}
        self.bridge._diagnostics = []
        self.bridge._action_diagnostics = []
        self.bridge._anchors = {}
        self.bridge._anchor_history = {}
        self.bridge._backed_up = set()

    def result_fixture(self, value):
        directory = self.bridge.source / '.univpn-multi/manager-results'
        directory.mkdir(parents=True, exist_ok=True)
        (directory / ('a' * 32 + '.json')).write_text(json.dumps(value), 'utf-8')

    def test_action_uses_fixed_script_and_index_and_never_shell(self):
        self.result_fixture({'ok': True, 'index': 2})
        with patch('native.secrets.token_hex', return_value='a' * 32), patch('native.subprocess.run', return_value=SimpleNamespace(returncode=0)) as run:
            self.assertEqual(self.bridge._action('CreateInstance', 1)['index'], 2)
        args, options = run.call_args
        command = args[0]
        self.assertEqual(command[command.index('-Mode') + 1], 'CreateInstance')
        self.assertEqual(command[command.index('-Index') + 1], '1')
        self.assertEqual(Path(command[command.index('-File') + 1]).name, 'native-action.ps1')
        self.assertNotIn('shell', options)
        with patch('native.subprocess.run') as run:
            for mode, index in [('Remove', 1), ('Disconnect', True), ('Disconnect', 0), ('Disconnect', 1000)]:
                with self.assertRaises(AppError):
                    self.bridge._action(mode, index)
            run.assert_not_called()

    def test_action_refuses_ambiguous_or_unsuccessful_results(self):
        values = [[], {'ok': 1, 'index': 2}, {'ok': False, 'index': 2},
                  {'ok': True, 'index': True}, {'ok': True, 'index': 1}, {'ok': True, 'index': 1000}]
        with patch('native.secrets.token_hex', return_value='a' * 32), patch('native.subprocess.run', return_value=SimpleNamespace(returncode=0)):
            for value in values:
                self.result_fixture(value)
                with self.subTest(value=value), self.assertRaises(AppError):
                    self.bridge._action('CreateInstance', 1)
            self.result_fixture({'ok': True, 'index': 3})
            with self.assertRaises(AppError):
                self.bridge._action('Disconnect', 2)

    def test_readonly_environment_probe_returns_only_safe_fixed_metadata(self):
        result = SimpleNamespace(returncode=0, stdout=json.dumps({'ok': True, 'phase': 'complete',
                                'username': 'offline-private-fixture'}).encode())
        with patch('native.subprocess.run', return_value=result) as run:
            self.assertEqual(self.bridge.check_environment(), {'ok': True, 'phase': 'complete', 'exitCode': 0})
        command = run.call_args.args[0]
        self.assertEqual(command[command.index('-Mode') + 1], 'Probe')
        self.assertNotIn('offline-private-fixture', (self.bridge.runtime_dir / 'native-actions.json').read_text())
        with patch('native.subprocess.run', return_value=SimpleNamespace(returncode=5, stdout=b'offline-private-fixture')):
            public = self.bridge.check_environment()
        self.assertFalse(public['ok'])
        self.assertEqual(public['exitCode'], 5)
        self.assertNotIn('offline-private-fixture', json.dumps(public))

    def test_legacy_reference_may_only_execute_on_its_source_slot(self):
        source = {'sourceIndex': 1, 'sourceName': 'offline-fixture'}
        with patch('vendor_config.legacy_reference', return_value='private-reference') as lookup:
            unbound = {'id': 'p', 'index': 0, 'gateway': '192.0.2.1', 'port': 443}
            self.assertEqual(self.bridge.legacy_reference(unbound, source=source), 'private-reference')
            self.assertEqual(lookup.call_args.args[0]['index'], 1)
            self.assertEqual(lookup.call_args.kwargs, {'sourceName': 'offline-fixture'})
            lookup.reset_mock()
            self.assertIsNone(self.bridge.legacy_reference({**unbound, 'index': 2}, source=source))
            self.assertIsNone(self.bridge.legacy_reference(unbound, source={'sourceIndex': 1}))
            self.assertIsNone(self.bridge.legacy_reference(unbound))
            lookup.assert_not_called()

    def test_saved_alias_fallback_requires_unique_source_and_exact_origin(self):
        profile = {'id': 'p', 'index': 1, 'gateway': '192.0.2.1', 'port': 443}
        source = {'sourceId': 'stable-id', 'sourceIndex': 1, 'sourceName': 'display-name'}
        candidate = {**source, 'gateway': profile['gateway'], 'port': 443, 'name': 'public-display'}
        with patch('vendor_config.legacy_reference', side_effect=[None, 'private-reference']) as lookup, patch('vendor_config.source_candidates', return_value=[candidate]):
            self.assertEqual(self.bridge.legacy_reference(profile, source=source), 'private-reference')
            self.assertEqual(lookup.call_count, 2)
            self.assertEqual(lookup.call_args.kwargs, {})
        for rows in ([candidate, {**candidate, 'sourceId': 'other'}],
                     [{**candidate, 'sourceId': 'renamed-source'}],
                     []):
            with self.subTest(rows=rows), patch('vendor_config.legacy_reference', return_value=None) as lookup, patch('vendor_config.source_candidates', return_value=rows):
                self.assertIsNone(self.bridge.legacy_reference(profile, source=source))
                self.assertEqual(lookup.call_count, 1)
        # The filename-derived ID is authoritative across older stored-name
        # encodings; the private cache alias is not a display-name key.
        with patch('vendor_config.legacy_reference', side_effect=[None, 'private-reference']), patch('vendor_config.source_candidates', return_value=[{**candidate, 'sourceName': 'canonical-name'}]):
            self.assertEqual(self.bridge.legacy_reference(profile, source=source), 'private-reference')

    def test_prepare_uses_suspended_user_anchor_without_terminating_idle_backend(self):
        from datetime import datetime, timezone
        anchor = SimpleNamespace(pid=500, session=1, created_timestamp=time.time(), close=Mock())
        service = {'pid': 100, 'session': 0}
        idle = {'processes': [{'name': 'UniVPNCS', 'pid': 200, 'parent': 100, 'session': 0}], 'peers': [], 'adapters': []}
        self.bridge._paths = Mock(return_value=('UniVPN', self.bridge.source, self.bridge.source))
        self.bridge._inventory = Mock(return_value=idle)
        self.bridge._verified_service = Mock(return_value=service)
        self.bridge._action = Mock(side_effect=AssertionError('must not stop a process'))
        profile = {'id': 'p', 'index': 1}
        with patch('native._windows_identity', return_value=(b'fixture', 1)), patch('native.snapshot_config'), patch('session_anchor.UserSessionAnchor', return_value=anchor):
            prepared = self.bridge.prepare(profile)
        self.assertEqual(prepared['service_port'], 29190)
        self.bridge._action.assert_not_called()
        ui = {'name': 'UniVPN', 'pid': 500, 'session': 1, 'created': datetime.fromtimestamp(anchor.created_timestamp, timezone.utc).isoformat()}
        self.assertTrue(self.bridge.is_owned_anchor(ui))
        self.assertFalse(self.bridge.is_owned_anchor({**ui, 'created': '2000-01-01T00:00:00+00:00'}))
        valid = {'processes': [ui, {'name': 'UniVPNCS', 'pid': 201, 'parent': 100, 'session': 1, 'created': datetime.now(timezone.utc).isoformat()}],
                 'listeners': [{'address': '127.0.0.1', 'port': 35000, 'pid': 201}]}
        self.bridge._inventory = Mock(return_value=valid)
        self.assertTrue(self.bridge.validate_backend(profile, 35000))
        anchor.close.assert_not_called()
        self.assertIn('p', self.bridge._anchors)
        self.bridge.release_anchor('p')
        anchor.close.assert_called_once()
        self.assertFalse(self.bridge._anchors)
        self.assertTrue(self.bridge.is_owned_anchor(ui))  # cached metadata only

    def test_idle_preflight_rejects_active_or_foreign_backend(self):
        profile = {'id': 'p', 'index': 1}
        for inventory in ({'processes': [{'name': 'UniVPN', 'pid': 99}]},
                          {'peers': [{'process': 'UniVPNCS'}]},
                          {'adapters': [{'guid': 't', 'up': True, 'addresses': ['192.0.2.1']}]},
                          {'processes': [{'name': 'UniVPNCS', 'parent': 99, 'session': 0}]},
                          {'processes': [{'name': 'UniVPNCS', 'parent': 100, 'session': 2}]},
                          {'processes': [{'name': 'UniVPNCS', 'parent': 100, 'session': 0}] * 2}):
            with self.subTest(inventory=inventory), self.assertRaises(AppError):
                self.bridge._assert_idle_target(profile, inventory, {'pid': 100, 'session': 0}, 1)

    def test_creation_does_not_disconnect_a_live_tap_or_client(self):
        for inventory in ({'processes': [{'name': 'UniVPNCS'}]}, {'adapters': [{'up': True}]}):
            self.bridge._inventory = Mock(return_value=inventory)
            self.bridge._action = Mock()
            with self.subTest(inventory=inventory), self.assertRaises(AppError):
                self.bridge.create_instance()
            self.bridge._action.assert_not_called()

    def test_quiesce_requires_exact_owned_backend_and_offline_tunnels(self):
        profile = {'id': 'p', 'index': 1}
        created = '2026-10-30T01:02:03.1234567+00:00'
        prepared = {'backend_pid': 201, 'backend_created': created, 'service_pid': 100, 'session': 1}
        row = {'name': 'UniVPNCS', 'pid': 201, 'parent': 100, 'session': 1, 'created': created}
        idle = {'installed': True, 'processes': [row], 'adapters': [], 'peers': []}
        self.bridge._prepared['p'] = dict(prepared)
        self.bridge._paths = Mock(return_value=('UniVPN', self.bridge.source, self.bridge.source))
        self.bridge._verified_service = Mock(return_value={'pid': 100})
        self.bridge._action = Mock(return_value={'ok': True, 'index': 1})
        invalid = [
            {**idle, 'adapters': [{'up': True}]}, {**idle, 'peers': [{'process': 'UniVPNCS'}]},
            {**idle, 'metadataUnknown': True},
            {**idle, 'processes': [row, {'name': 'UniVPN'}]},
            {**idle, 'processes': [row, row]},
            *[{**idle, 'processes': [{**row, **changes}]} for changes in
                ({'pid': 202}, {'created': '2026-10-30T01:02:04+00:00'}, {'parent': 101}, {'session': 2})],
        ]
        for inventory in invalid:
            self.bridge._inventory = Mock(return_value=inventory)
            with self.subTest(inventory=inventory), self.assertRaises(AppError):
                self.bridge.quiesce_owned(profile)
            self.bridge._action.assert_not_called()
        self.bridge._inventory = Mock(side_effect=[idle, {**idle, 'processes': []}])
        self.bridge.quiesce_owned(profile)
        self.bridge._action.assert_called_once_with('QuiesceOwned', 1, expected_pid=201,
                                                    expected_created_us=13437795723123456)
        self.assertNotIn('p', self.bridge._prepared)

    def test_quiesce_does_not_touch_unowned_or_still_anchored_process(self):
        profile = {'id': 'p', 'index': 1}
        self.bridge._paths = Mock()
        self.bridge._inventory = Mock(return_value={'installed': True, 'processes': [{'name': 'UniVPNCS'}]})
        self.bridge._verified_service = Mock(return_value={'pid': 100})
        self.bridge._action = Mock()
        with self.assertRaises(AppError):
            self.bridge.quiesce_owned(profile)
        self.bridge._anchors['p'] = object()
        with self.assertRaises(AppError):
            self.bridge.quiesce_owned(profile)
        self.bridge._action.assert_not_called()

    def test_quiesce_action_carries_only_validated_numeric_process_identity(self):
        self.result_fixture({'ok': True, 'index': 1})
        with patch('native.secrets.token_hex', return_value='a' * 32), patch('native.subprocess.run', return_value=SimpleNamespace(returncode=0)) as run:
            for pid, created in [(None, None), (True, 100), (200, True), (0, 100), (200, -1)]:
                with self.subTest(pid=pid, created=created), self.assertRaises(AppError):
                    self.bridge._action('QuiesceOwned', 1, expected_pid=pid, expected_created_us=created)
            run.assert_not_called()
            self.bridge._action('QuiesceOwned', 1, expected_pid=200, expected_created_us=13406259723123456)
            command = run.call_args.args[0]
            self.assertIsNone(run.call_args.kwargs['timeout'])
            self.assertEqual(command[command.index('-ExpectedPid') + 1], '200')
            self.assertEqual(command[command.index('-ExpectedCreatedUs') + 1], '13406259723123456')

    def test_backend_ownership_uses_birth_parent_and_session_not_only_name(self):
        profile = {'id': 'p', 'index': 1}
        prepared = {'backend_pid': 201, 'backend_created': '2026-10-30T01:02:03.1234567Z', 'service_pid': 100, 'session': 1}
        row = {'name': 'UniVPNCS', 'pid': 201, 'created': prepared['backend_created'], 'parent': 100, 'session': 1}
        self.assertFalse(self.bridge.owns_backend(profile, row))
        self.bridge._prepared['p'] = prepared
        self.assertTrue(self.bridge.owns_backend(profile, row))
        for change in ({'name': 'UVP002CS'}, {'pid': 202}, {'parent': 101}, {'session': 2}, {'created': 'other'}):
            with self.subTest(change=change):
                self.assertFalse(self.bridge.owns_backend(profile, {**row, **change}))

    def test_creation_requires_new_unique_ready_record_and_verified_files(self):
        self.bridge._inventory = Mock(side_effect=[{'records': [{'index': 2}]}, {'records': [{'index': 3, 'status': 'Ready'}]}])
        self.bridge._action = Mock(return_value={'ok': True, 'index': 3})
        self.bridge._paths = Mock()
        self.assertEqual(self.bridge.create_instance(), 3)
        self.bridge._paths.assert_called_once_with(3)
        self.bridge._inventory = Mock(return_value={'records': [{'index': 2, 'status': 'Ready'}]})
        self.bridge._action = Mock(return_value={'ok': True, 'index': 2})
        with self.assertRaises(AppError):
            self.bridge.create_instance()

    def test_backend_requires_new_child_in_same_session_and_unique_loopback_listener(self):
        self.bridge._prepared['p'] = {'service_pid': 100, 'session': 1, 'prepared_at': time.time() - 1}
        self.bridge._verified_service = Mock(return_value={'pid': 100})
        from datetime import datetime, timezone
        valid = {'processes': [{'name': 'UniVPNCS', 'pid': 200, 'parent': 100, 'session': 1, 'created': datetime.now(timezone.utc).isoformat()}],
                 'listeners': [{'port': 35000, 'address': '127.0.0.1', 'pid': 200}]}
        self.bridge._inventory = Mock(return_value=valid)
        self.assertTrue(self.bridge.validate_backend({'id': 'p', 'index': 1}, 35000))
        for field, value in [('parent', 999), ('session', 3), ('created', '2000-01-01T00:00:00+00:00')]:
            changed = {**valid, 'processes': [{**valid['processes'][0], field: value}]}
            self.bridge._inventory = Mock(return_value=changed)
            with self.subTest(field=field):
                self.assertFalse(self.bridge.validate_backend({'id': 'p', 'index': 1}, 35000))
        self.bridge._inventory = Mock(return_value={**valid, 'listeners': valid['listeners'] * 2})
        self.assertFalse(self.bridge.validate_backend({'id': 'p', 'index': 1}, 35000))
        self.bridge._inventory = Mock(return_value={**valid, 'listeners': [{**valid['listeners'][0], 'address': '0.0.0.0'}]})
        self.assertFalse(self.bridge.validate_backend({'id': 'p', 'index': 1}, 35000))


if __name__ == '__main__':
    unittest.main()
