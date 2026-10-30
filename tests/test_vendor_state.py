from pathlib import Path
from tempfile import TemporaryDirectory
import os
import stat
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from vendor_state import snapshot_config, SnapshotError, _private_directory


def directory_sddl(path, value=None):
    """Read/change ACLs on these synthetic temporary test folders only."""
    import ctypes
    from ctypes import wintypes
    api = ctypes.WinDLL('advapi32', use_last_error=True)
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    pointer = ctypes.c_void_p
    kernel.LocalFree.argtypes = [pointer]
    api.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(pointer), pointer]
    api.SetFileSecurityW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, pointer]
    api.GetNamedSecurityInfoW.argtypes = [wintypes.LPWSTR, ctypes.c_int, wintypes.DWORD, pointer, pointer, pointer, pointer, ctypes.POINTER(pointer)]
    api.ConvertSecurityDescriptorToStringSecurityDescriptorW.argtypes = [pointer, wintypes.DWORD, wintypes.DWORD, ctypes.POINTER(wintypes.LPWSTR), pointer]
    descriptor = pointer()
    text = wintypes.LPWSTR()
    try:
        if value is not None:
            if not api.ConvertStringSecurityDescriptorToSecurityDescriptorW(value, 1, ctypes.byref(descriptor), None):
                raise ctypes.WinError(ctypes.get_last_error())
            if not api.SetFileSecurityW(str(path), 0x80000004, descriptor):
                raise ctypes.WinError(ctypes.get_last_error())
            return
        code = api.GetNamedSecurityInfoW(str(path), 1, 4, None, None, None, None, ctypes.byref(descriptor))
        if code:
            raise ctypes.WinError(code)
        if not api.ConvertSecurityDescriptorToStringSecurityDescriptorW(descriptor, 1, 4, ctypes.byref(text), None):
            raise ctypes.WinError(ctypes.get_last_error())
        return text.value
    finally:
        if text:
            kernel.LocalFree(text)
        if descriptor:
            kernel.LocalFree(descriptor)


class ReadHook:
    def __init__(self, file, hook):
        self.file, self.hook = file, hook

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return self.file.__exit__(*args)

    def fileno(self):
        return self.file.fileno()

    def read(self, size):
        result = self.file.read(size)
        self.hook()
        return result


class SnapshotTests(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.runtime = self.root / 'runtime'
        self.runtime.mkdir()
        self.appdata = self.root / 'appdata'
        self.appdata.mkdir()

    def test_opaque_copy_preserves_original_excludes_logs_and_keeps_both_snapshots(self):
        source = self.appdata / 'UniVPN'
        (source / 'config').mkdir(parents=True)
        (source / 'log').mkdir()
        values = {'key.ini': b'opaque\x00\xffkey', 'sysconfig.ini': b'opaque settings', 'config/old.ini': b'opaque encrypted profile'}
        for name, data in values.items():
            (source / name).write_bytes(data)
        (source / 'log/private.log').write_bytes(b'excluded')
        first = snapshot_config(self.runtime, 1, appdata=self.appdata)
        second = snapshot_config(self.runtime, 1, appdata=self.appdata)
        self.assertNotEqual(first, second)
        self.assertFalse((first / 'log').exists())
        for name, data in values.items():
            self.assertEqual((source / name).read_bytes(), data)
            self.assertEqual((first / name).read_bytes(), data)
        self.assertTrue((first / 'complete').is_file())

    def test_absent_config_is_noop_and_index_is_strict(self):
        self.assertIsNone(snapshot_config(self.runtime, 2, appdata=self.appdata))
        self.assertEqual(list(self.runtime.iterdir()), [])
        for index in (0, 1000, True, '1'):
            with self.assertRaises(SnapshotError):
                snapshot_config(self.runtime, index, appdata=self.appdata)

    def test_oversize_source_is_refused_before_copy(self):
        source = self.appdata / 'UniVPN'
        source.mkdir()
        (source / 'key.ini').write_bytes(b'x' * (2**20 + 1))
        with self.assertRaises(SnapshotError):
            snapshot_config(self.runtime, 1, appdata=self.appdata)
        self.assertEqual(list(self.runtime.iterdir()), [])

    def source(self):
        source = self.appdata / 'UniVPN'
        source.mkdir()
        path = source / 'key.ini'
        path.write_bytes(b'synthetic opaque value')
        return path

    def assert_no_complete(self):
        self.assertEqual(list(self.runtime.rglob('complete')), [])

    @unittest.skipUnless(os.name == 'nt', 'Windows ACL contract')
    def test_existing_weak_protected_acl_is_replaced_before_any_source_read(self):
        path = self.source()
        backups = self.runtime / 'vendor-backups'
        backups.mkdir()
        directory_sddl(backups, 'D:P(A;OICI;FA;;;WD)')
        self.assertIn(';;;WD)', directory_sddl(backups))
        original = Path.open
        observed = []
        def inspect_open(current, *args, **kwargs):
            if current == path:
                acl = directory_sddl(backups)
                self.assertTrue(acl.startswith('D:P'))
                self.assertNotIn(';;;WD)', acl)
                self.assertNotIn(';;;BU)', acl)
                self.assertNotIn(';;;AU)', acl)
                self.assertEqual(acl.count('(A;'), 3)
                observed.append(True)
            return original(current, *args, **kwargs)
        with patch.object(Path, 'open', inspect_open):
            target = snapshot_config(self.runtime, 1, appdata=self.appdata)
        self.assertEqual(observed, [True])
        self.assertTrue((target / 'complete').is_file())
        self.assertNotIn(';;;WD)', directory_sddl(target))

    def test_private_directory_failure_happens_before_source_file_is_opened(self):
        path = self.source()
        original = Path.open
        opened = []
        def inspect_open(current, *args, **kwargs):
            if current == path:
                opened.append(current)
            return original(current, *args, **kwargs)
        with patch('vendor_state._private_directory', side_effect=SnapshotError('blocked')), patch.object(Path, 'open', inspect_open):
            with self.assertRaises(SnapshotError):
                snapshot_config(self.runtime, 1, appdata=self.appdata)
        self.assertEqual(opened, [])
        self.assert_no_complete()

    def test_source_reparse_attribute_is_refused_without_reading(self):
        path = self.source()
        original = Path.lstat
        def inspect_lstat(current, *args, **kwargs):
            if current == path:
                return SimpleNamespace(st_mode=stat.S_IFREG, st_file_attributes=0x400)
            return original(current, *args, **kwargs)
        with patch.object(Path, 'lstat', inspect_lstat):
            with self.assertRaises(SnapshotError):
                snapshot_config(self.runtime, 1, appdata=self.appdata)
        self.assert_no_complete()

    def test_backup_reparse_attribute_is_refused_before_reading(self):
        self.source()
        backups = self.runtime / 'vendor-backups'
        backups.mkdir()
        original = Path.lstat
        def inspect_lstat(current, *args, **kwargs):
            if current == backups:
                return SimpleNamespace(st_mode=stat.S_IFDIR, st_file_attributes=0x400)
            return original(current, *args, **kwargs)
        with patch.object(Path, 'lstat', inspect_lstat):
            with self.assertRaises(SnapshotError):
                snapshot_config(self.runtime, 1, appdata=self.appdata)
        self.assert_no_complete()

    def test_replacement_with_same_size_and_timestamp_is_refused_by_file_identity(self):
        path = self.source()
        info = path.stat()
        original = Path.open
        replaced = []
        def replace_then_open(current, *args, **kwargs):
            if current == path and args and args[0] == 'rb' and not replaced:
                path.rename(path.with_suffix('.original'))
                with original(path, 'wb') as writer:
                    writer.write(b'x' * info.st_size)
                os.utime(path, ns=(info.st_atime_ns, info.st_mtime_ns))
                replaced.append(True)
            return original(current, *args, **kwargs)
        with patch.object(Path, 'open', replace_then_open):
            with self.assertRaises(SnapshotError):
                snapshot_config(self.runtime, 1, appdata=self.appdata)
        self.assertEqual(replaced, [True])
        self.assert_no_complete()

    def test_mtime_change_during_read_fails_without_complete(self):
        path = self.source()
        info = path.stat()
        original = Path.open
        def read_then_change(current, *args, **kwargs):
            file = original(current, *args, **kwargs)
            if current == path and args and args[0] == 'rb':
                return ReadHook(file, lambda: os.utime(path, ns=(info.st_atime_ns, info.st_mtime_ns + 1000000)))
            return file
        with patch.object(Path, 'open', read_then_change):
            with self.assertRaises(SnapshotError):
                snapshot_config(self.runtime, 1, appdata=self.appdata)
        self.assert_no_complete()

    def test_earlier_file_changed_during_later_copy_fails_final_batch_check(self):
        path = self.source()
        second = path.parent / 'sysconfig.ini'
        second.write_bytes(b'synthetic second file')
        info = path.stat()
        original = Path.open
        def read_then_change(current, *args, **kwargs):
            file = original(current, *args, **kwargs)
            if current == second and args and args[0] == 'rb':
                return ReadHook(file, lambda: os.utime(path, ns=(info.st_atime_ns, info.st_mtime_ns + 1000000)))
            return file
        with patch.object(Path, 'open', read_then_change):
            with self.assertRaises(SnapshotError):
                snapshot_config(self.runtime, 1, appdata=self.appdata)
        self.assert_no_complete()

    def test_native_clone_product_path_is_exact_and_original_vendor_is_unchanged(self):
        source = self.appdata / 'UVP002'
        source.mkdir()
        (source / 'key.ini').write_bytes(b'clone synthetic opaque')
        target = snapshot_config(self.runtime, 2, appdata=self.appdata)
        self.assertTrue(target.name.startswith('UVP002-'))
        self.assertEqual((source / 'key.ini').read_bytes(), b'clone synthetic opaque')
        self.assertEqual((target / 'key.ini').read_bytes(), b'clone synthetic opaque')


if __name__ == '__main__':
    unittest.main()
