"""Synthetic legacy network profiles only; no real AppData or credentials."""
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from vendor_config import (load_candidates, parse_network_profile, legacy_reference,
                           SavedReference, source_candidates, network_candidates)


class VendorConfigTests(unittest.TestCase):
    def test_only_network_fields_leave_the_parser(self):
        source = b'[GLOBAL]\nGatewayAddress = 192.0.2.10\nGatewayPort=41024\nDescription=Example\nUserName=fixture-account\nPassword=fixture-password\nProfileInfo=opaque-fixture\n'
        self.assertEqual(parse_network_profile(source, 1),
                         {'gateway': '192.0.2.10', 'port': 41024, 'name': 'Example', 'index': 1})

    def test_original_and_clone_candidates_are_not_silently_selected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for product in ('UniVPN', 'UVP002'):
                (root / product / 'config').mkdir(parents=True)
                # These must never be opened.
                (root / product / 'key.ini').write_bytes(b'do-not-open')
                (root / product / 'sysconfig.ini').write_bytes(b'do-not-open')
            (root / 'UniVPN/config/a.ini').write_bytes(b'[GLOBAL]\nGatewayAddress=192.0.2.1\nGatewayPort=443\n')
            (root / 'UniVPN/config/b.ini').write_bytes(b'[GLOBAL]\nGatewayAddress=192.0.2.2\nGatewayPort=49999\n')
            (root / 'UVP002/config/c.ini').write_bytes(b'[GLOBAL]\nGatewayAddress=vpn.example.test\nGatewayPort=41024\n')
            original_open = Path.open
            opened = []

            def checked_open(path, *args, **kwargs):
                opened.append(path.name)
                if path.name in ('key.ini', 'sysconfig.ini'):
                    raise AssertionError('forbidden credential container access')
                return original_open(path, *args, **kwargs)

            with patch.object(Path, 'open', checked_open):
                rows = load_candidates(root)
            self.assertEqual(len(rows), 3)
            self.assertEqual([row['index'] for row in rows], [1, 1, 2])
            self.assertEqual(set(opened), {'a.ini', 'b.ini', 'c.ini'})

    def test_encoding_quotes_and_plain_description(self):
        source = '[GLOBAL]\nGatewayAddress="vpn.example.test"\nGatewayPort="443"\nDescription=测试\n'
        for encoding in ('utf-8-sig', 'utf-16', 'gb18030'):
            with self.subTest(encoding=encoding):
                self.assertEqual(parse_network_profile(source.encode(encoding), 2)['name'], '测试')

    def test_opaque_invalid_or_ambiguous_profiles_are_ignored(self):
        invalid = [b'opaque-ciphertext-no-schema', b'[GLOBAL]\nGatewayAddress=https://vpn.example/\nGatewayPort=443\n',
                   b'[GLOBAL]\nGatewayAddress=192.0.2.1\nGatewayPort=0\n',
                   b'[GLOBAL]\nGatewayAddress=192.0.2.1\nGatewayPort=443\nGatewayPort=444\n',
                   b'[GLOBAL]\nGatewayAddress=192.0.2.1\nGatewayPort=443\n[GLOBAL]\n',
                   b'[DEFAULT]\nGatewayAddress=192.0.2.1\nGatewayPort=443\n[GLOBAL]\n',
                   b'\x00\xff\x00', b'x' * 65537]
        for source in invalid:
            self.assertIsNone(parse_network_profile(source, 1))

    def test_only_explicit_valid_indices_are_scanned(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for product in ('UniVPN', 'UVP002'):
                (root / product / 'config').mkdir(parents=True)
                (root / product / 'config' / 'fixture.ini').write_bytes(b'[GLOBAL]\nGatewayAddress=192.0.2.1\nGatewayPort=443\n')
            self.assertEqual([row['index'] for row in load_candidates(root, indices=(2,))], [2])
        for value in ((0,), ('../',), (True,), (1000,)):
            with self.assertRaises(ValueError):
                load_candidates('.', indices=value)

    def test_reparse_product_root_is_not_opened(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'UniVPN/config').mkdir(parents=True)
            (root / 'UniVPN/config/fixture.ini').write_bytes(b'[GLOBAL]\nGatewayAddress=192.0.2.1\nGatewayPort=443\n')
            from vendor_config import _ordinary
            with patch('vendor_config._ordinary', side_effect=lambda path, directory: False if path == root / 'UniVPN' else _ordinary(path, directory=directory)):
                self.assertEqual(load_candidates(root), [])

    def reference_fixture(self, entries, profile=None, source_name=None):
        profile = profile or {'index': 1, 'gateway': '192.0.2.1', 'port': 443}
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'UniVPN').mkdir()
            (root / 'UniVPN/sysconfig.ini').write_bytes(b'fixture-api-values-are-injected')
            calls = []

            def private_key(path, section, key, *, metadata=None):
                calls.append((section, key))
                if key not in {'LastLoginAddr', 'RemPwd', 'ProfileName', 'ProfileUser'}:
                    raise AssertionError('forbidden private payload read')
                return entries.get(section, {}).get(key, '')

            metadata = {section: {'ProfileName': values.get('ProfileName', '').encode('gbk')}
                        for section, values in entries.items()}
            with patch('vendor_config._private_ini_value', side_effect=private_key), \
                    patch('vendor_config._private_ini_metadata', return_value=metadata):
                result = legacy_reference(profile, root, sourceName=source_name)
            return result, calls

    def test_private_saved_reference_has_no_password_and_a_redacted_repr(self):
        entries = {'Session0': {'LastLoginAddr': '192.0.2.1:443', 'RemPwd': '1',
                                'ProfileName': 'fixture-profile', 'ProfileUser': 'fixture-account'}}
        result, calls = self.reference_fixture(entries)
        self.assertIsInstance(result, SavedReference)
        self.assertEqual(result.username, 'fixture-account')
        self.assertEqual(result.profile_name, 'fixture-profile')
        self.assertEqual(set(vars(result)), {'username', 'profile_name'})
        self.assertEqual(repr(result), 'SavedReference(<private>)')
        self.assertTrue(all(key in {'LastLoginAddr', 'RemPwd', 'ProfileName', 'ProfileUser'} for _, key in calls))

    def test_legacy_reference_requires_saved_flag_and_unique_matching_identity(self):
        ordinary = {'LastLoginAddr': '192.0.2.1:443', 'RemPwd': '1',
                    'ProfileName': 'fixture-profile', 'ProfileUser': 'fixture-account'}
        result, _ = self.reference_fixture({'Session0': ordinary, 'Session1': {**ordinary, 'ProfileUser': 'different-fixture'}})
        self.assertIsNone(result)
        for change in ({'RemPwd': '0'}, {'RemPwd': '3'}, {'LastLoginAddr': 'https://192.0.2.1:443'},
                       {'ProfileName': '../x'}, {'ProfileUser': ''}, {'ProfileUser': '未知编码'},
                       {'ProfileName': 'x' * 132}):
            with self.subTest(change=next(iter(change))):
                result, _ = self.reference_fixture({'Session0': {**ordinary, **change}})
                self.assertIsNone(result)

    def test_nonmatching_endpoint_does_not_read_private_identity(self):
        result, calls = self.reference_fixture({'Session0': {'LastLoginAddr': '192.0.2.99:443'}})
        self.assertIsNone(result)
        self.assertTrue(all(key == 'LastLoginAddr' for _, key in calls))

    def test_private_byte_schema_gbk_profile_name_and_no_cipher_field(self):
        from vendor_config import _private_ini_metadata
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'UniVPN').mkdir()
            name = '测试连接'
            source = (b'[Session0]\nLastLoginAddr=192.0.2.1:443\nRemPwd=1\nProfileName='
                      + name.encode('gbk') + b'\nProfileUser=fixture-account\nProfileInfo=ignored-ciphertext=never-parse\n')
            path = root / 'UniVPN/sysconfig.ini'
            path.write_bytes(source)
            metadata = _private_ini_metadata(path)
            self.assertEqual(set(metadata['Session0']), {'LastLoginAddr', 'RemPwd', 'ProfileName', 'ProfileUser'})
            reference = legacy_reference({'index': 1, 'gateway': '192.0.2.1', 'port': 443}, root)
            self.assertIsNotNone(reference)
            self.assertEqual(reference.profile_name, name)
            self.assertEqual(repr(reference), 'SavedReference(<private>)')

    def test_duplicate_saved_sessions_are_ambiguous_even_if_identical(self):
        ordinary = {'LastLoginAddr': '192.0.2.1:443', 'RemPwd': '1',
                    'ProfileName': 'fixture-profile', 'ProfileUser': 'fixture-account'}
        result, _ = self.reference_fixture({'Session0': ordinary, 'Session1': ordinary})
        self.assertIsNone(result)

    def test_source_identity_preserves_same_names_and_filename_fallback(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for product in ('UniVPN', 'UVP002'):
                (root / product / 'config').mkdir(parents=True)
            content = '[GLOBAL]\nGatewayAddress=192.0.2.1\nGatewayPort=443\nDescription=同名\nProfileUser=not-a-network-field\n'
            for filename in ('first.ini', 'second.ini'):
                (root / 'UniVPN/config' / filename).write_text(content, encoding='utf-8')
            (root / 'UVP002/config/first.ini').write_text(content, encoding='utf-8')
            (root / 'UniVPN/config/原名称.ini').write_bytes(b'[GLOBAL]\nGatewayAddress=192.0.2.2\nGatewayPort=444\n')
            rows = source_candidates((1, 2), root)
            self.assertEqual(len(rows), 4)
            self.assertEqual(len({row['sourceId'] for row in rows}), 4)
            self.assertTrue(all(set(row) == {'sourceId', 'sourceIndex', 'sourceName', 'name', 'gateway', 'port'} for row in rows))
            self.assertEqual(sum(row['name'] == '同名' for row in rows), 3)
            self.assertTrue(any(row['sourceName'] == '原名称' and row['name'] == '原名称' for row in rows))
            self.assertEqual(rows, source_candidates((1, 2), root))
            first = next(row for row in rows if row['sourceIndex'] == 1 and row['sourceName'] == 'first')
            (root / 'UniVPN/config/first.ini').write_text(content.replace('同名', '新描述'), encoding='utf-8')
            updated = next(row for row in source_candidates((1,), root) if row['sourceName'] == 'first')
            self.assertEqual(first['sourceId'], updated['sourceId'])
            self.assertEqual(updated['name'], '新描述')
            public = network_candidates((1, 2), root)
            self.assertTrue(all(set(row) == {'gateway', 'port', 'name', 'index'} for row in public))
            self.assertEqual(len(public), 4)

    def test_every_valid_source_is_returned_without_a_silent_hundred_file_cap(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            directory = root / 'UniVPN/config'
            directory.mkdir(parents=True)
            for number in range(101):
                (directory / f'fixture-{number:03d}.ini').write_bytes(b'[GLOBAL]\nGatewayAddress=192.0.2.1\nGatewayPort=443\nDescription=same-name\n')
            rows = source_candidates((1,), root)
            self.assertEqual(len(rows), 101)
            self.assertEqual(len({row['sourceId'] for row in rows}), 101)

    def test_exact_source_name_selects_one_of_same_endpoint_saved_profiles(self):
        ordinary = {'LastLoginAddr': '192.0.2.1:443', 'RemPwd': '1',
                    'ProfileName': 'first', 'ProfileUser': 'first-fixture-account'}
        entries = {'Session0': ordinary, 'Session1': {**ordinary, 'ProfileName': 'second',
                                                   'ProfileUser': 'second-fixture-account'}}
        result, _ = self.reference_fixture(entries, source_name='second')
        self.assertIsNotNone(result)
        self.assertEqual(result.profile_name, 'second')
        self.assertEqual(result.username, 'second-fixture-account')
        result, calls = self.reference_fixture(entries, source_name='absent')
        self.assertIsNone(result)
        self.assertTrue(all(key != 'ProfileUser' for _, key in calls))
        for name in ('../first', 'x\\first', '', '😀'):
            with self.subTest(name_kind='invalid'):
                result, _ = self.reference_fixture(entries, source_name=name)
                self.assertIsNone(result)

    def test_exact_source_name_keeps_endpoint_and_duplicate_safety_gates(self):
        ordinary = {'LastLoginAddr': '192.0.2.1:443', 'RemPwd': '1',
                    'ProfileName': 'first', 'ProfileUser': 'first-fixture-account'}
        result, _ = self.reference_fixture({'Session0': ordinary, 'Session1': ordinary}, source_name='first')
        self.assertIsNone(result)
        result, _ = self.reference_fixture({'Session0': {**ordinary, 'LastLoginAddr': '192.0.2.2:443'}}, source_name='first')
        self.assertIsNone(result)
        result, _ = self.reference_fixture({'Session0': {**ordinary, 'RemPwd': '0'}}, source_name='first')
        self.assertIsNone(result)

    def test_logical_source_name_accepts_full_ini_filename_but_preserves_wire_identity(self):
        for cached_name in ('fixture.ini', 'fixture.INI', 'fixture.InI'):
            with self.subTest(extension=cached_name.rsplit('.', 1)[1]):
                ordinary = {'LastLoginAddr': '192.0.2.1:443', 'RemPwd': '1',
                            'ProfileName': cached_name, 'ProfileUser': 'fixture-account'}
                result, _ = self.reference_fixture({'Session0': ordinary}, source_name='fixture')
                self.assertIsNotNone(result)
                self.assertEqual(result.profile_name, cached_name)
        ordinary['ProfileName'] = 'Fixture.ini'
        result, _ = self.reference_fixture({'Session0': ordinary}, source_name='fixture')
        self.assertIsNone(result)

    def test_filename_compatibility_does_not_merge_ambiguous_cache_names(self):
        ordinary = {'LastLoginAddr': '192.0.2.1:443', 'RemPwd': '1',
                    'ProfileName': 'fixture', 'ProfileUser': 'fixture-account'}
        result, _ = self.reference_fixture({'Session0': ordinary,
                                           'Session1': {**ordinary, 'ProfileName': 'fixture.ini'}},
                                          source_name='fixture')
        self.assertIsNone(result)

    def test_other_endpoint_same_native_lookup_name_is_rejected(self):
        ordinary = {'LastLoginAddr': '192.0.2.1:443', 'RemPwd': '1',
                    'ProfileName': 'fixture.ini', 'ProfileUser': 'fixture-account'}
        other = {**ordinary, 'LastLoginAddr': '192.0.2.2:443'}
        for source_name in (None, 'fixture'):
            result, _ = self.reference_fixture({'Session0': other, 'Session1': ordinary}, source_name=source_name)
            self.assertIsNone(result)
            result, _ = self.reference_fixture({'Session0': {**other, 'RemPwd': '0'}, 'Session1': ordinary},
                                              source_name=source_name)
            self.assertIsNone(result)

    def test_gbk_and_utf8_filename_bytes_preserve_native_gbk_roundtrip(self):
        from windows_messages import saved_profile_login
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'UniVPN').mkdir()
            path = root / 'UniVPN/sysconfig.ini'
            for encoding in ('gbk', 'utf-8'):
                with self.subTest(encoding=encoding):
                    raw_name = '测试连接.INI'.encode(encoding)
                    source = (b'[Session0]\nLastLoginAddr=192.0.2.1:443\nRemPwd=1\nProfileName='
                              + raw_name + b'\nProfileUser=fixture-account\nProfileInfo=unread-fixture\n')
                    path.write_bytes(source)
                    reference = legacy_reference({'index': 1, 'gateway': '192.0.2.1', 'port': 443},
                                                 root, sourceName='测试连接')
                    self.assertIsNotNone(reference)
                    self.assertEqual(reference.profile_name.encode('gbk'), raw_name)
                    frame = saved_profile_login('192.0.2.1:443', reference.username, reference.profile_name)
                    wire_name = frame[24 + 0x734:].split(b'\0', 1)[0].decode('utf-8')
                    self.assertEqual(wire_name.encode('gbk'), raw_name)
                    self.assertEqual(path.read_bytes(), source)


if __name__ == '__main__':
    unittest.main()
