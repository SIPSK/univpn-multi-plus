"""Frozen-resource leases on synthetic files; no vendor script is executed."""
from __future__ import annotations

import errno
import os
from pathlib import Path
import shutil
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from resource_lease import RESOURCE_DIRECTORIES, RESOURCE_FILES, ResourceLease, ResourceLeaseError


SHELL = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32/WindowsPowerShell/v1.0/powershell.exe"
SCRIPT_TEXT = "# Synthetic resource fixture; parse/read only.\nthrow 'RESOURCE_FIXTURE_MUST_NOT_EXECUTE'\n"


class SourceResourceLeaseTests(unittest.TestCase):
    def test_source_mode_never_acquires_or_requires_resource_files(self):
        with TemporaryDirectory(prefix="univpn-source-lease-") as temporary:
            missing = Path(temporary) / "absent-resources"
            with patch("resource_lease._kernel_api", side_effect=AssertionError("native acquisition forbidden")), \
                 patch.object(Path, "stat", side_effect=AssertionError("resource filesystem access forbidden")), \
                 patch.object(Path, "open", side_effect=AssertionError("resource filesystem access forbidden")):
                with patch.object(sys, "frozen", False, create=True):
                    with ResourceLease(missing) as lease:
                        self.assertFalse(lease.enabled)
                    lease.close()
                with patch.object(sys, "frozen", True, create=True):
                    with ResourceLease(missing, frozen=False) as lease:
                        self.assertFalse(lease.enabled)
                    lease.close()
            self.assertFalse(missing.exists())


@unittest.skipUnless(os.name == "nt", "Windows file-sharing semantics")
class WindowsResourceLeaseTests(unittest.TestCase):
    def setUp(self):
        self.temporary = TemporaryDirectory(prefix="univpn-resource-lease-")
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name).resolve()
        self.root = self.base / "synthetic resources"
        self.root.mkdir()
        self.contents = {}
        for relative in RESOURCE_FILES:
            target = self.root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            data = SCRIPT_TEXT.encode("utf-8") if target.suffix == ".ps1" else ("synthetic " + relative + "\n").encode("utf-8")
            target.write_bytes(data)
            self.contents[relative] = data

    def remove_fixture(self, path):
        resolved = path.resolve()
        self.assertTrue(resolved.is_relative_to(self.base), "delete must remain within this test's temporary directory")
        self.assertNotEqual(resolved, self.base)
        shutil.rmtree(path)

    def assert_denied(self, operation):
        with self.assertRaises(OSError) as caught:
            operation()
        # CPython's CRT-backed open/write maps sharing denial to EACCES and
        # does not preserve winerror; unlink/rename keep the native code.
        winerror = getattr(caught.exception, "winerror", None)
        if winerror is None:
            self.assertIsInstance(caught.exception, PermissionError)
            self.assertEqual(caught.exception.errno, errno.EACCES)
        else:
            self.assertIn(winerror, {5, 32, 33})

    @staticmethod
    def truncate(path):
        with path.open("wb"):
            pass

    def assert_unchanged(self):
        for relative, data in self.contents.items():
            self.assertEqual((self.root / relative).read_bytes(), data)

    def assert_failed_entry_released_all_pins(self, lease):
        # Verify before an explicit close, which could otherwise hide a leak
        # in __enter__'s failure cleanup.
        for relative in RESOURCE_FILES:
            path = self.root / relative
            if path.is_file():
                path.write_bytes(b"writable after failed entry\n")
        moved = self.root.with_name("released resources")
        self.root.rename(moved)
        self.remove_fixture(moved)
        lease.close()
        lease.close()

    def test_all_eight_resources_reject_write_truncate_unlink_and_rename_until_close(self):
        self.assertEqual(len(RESOURCE_FILES), 8)
        with ResourceLease(self.root, frozen=True):
            for relative in RESOURCE_FILES:
                path = self.root / relative
                for action, operation in (
                    ("overwrite", lambda p=path: p.write_bytes(b"forbidden overwrite")),
                    ("truncate", lambda p=path: self.truncate(p)),
                    ("unlink", lambda p=path: p.unlink()),
                    ("rename", lambda p=path: p.rename(p.with_name(p.name + ".moved"))),
                ):
                    with self.subTest(resource=relative, action=action):
                        self.assert_denied(operation)
                        self.assertEqual(path.read_bytes(), self.contents[relative])
        # All four operations become possible after the owning handles close.
        for relative in RESOURCE_FILES:
            path = self.root / relative
            path.write_bytes(b"allowed overwrite")
            self.truncate(path)
            self.assertEqual(path.read_bytes(), b"")
            moved = path.with_name(path.name + ".moved")
            path.rename(moved)
            moved.unlink()
        self.remove_fixture(self.root)

    def test_root_and_each_resource_directory_cannot_be_renamed_or_recursively_removed(self):
        self.assertEqual(set(RESOURCE_DIRECTORIES), {".", "web", "tools", "vendor"})
        with ResourceLease(self.root, frozen=True):
            for relative in RESOURCE_DIRECTORIES:
                directory = self.root / relative
                with self.subTest(directory=relative, action="rename"):
                    self.assert_denied(lambda p=directory: p.rename(p.with_name(p.name + ".moved")))
                with self.subTest(directory=relative, action="rmtree"):
                    self.assert_denied(lambda p=directory: self.remove_fixture(p))
                self.assert_unchanged()
        moved = self.root.with_name("released directory tree")
        self.root.rename(moved)
        self.remove_fixture(moved)

    def test_normal_readers_and_windows_powershell_ast_parser_can_read_locked_resources(self):
        self.assertTrue(SHELL.is_file(), "Windows PowerShell is required for this Windows regression")
        command = (
            "$tokens=$null; $parseErrors=$null; "
            "$ast=[System.Management.Automation.Language.Parser]::ParseFile("
            "$env:UNIVPN_RESOURCE_FIXTURE,[ref]$tokens,[ref]$parseErrors); "
            "if($parseErrors.Count -ne 0){exit 3}; "
            "$text=[System.IO.File]::ReadAllText($env:UNIVPN_RESOURCE_FIXTURE); "
            "if(-not $text.Contains('RESOURCE_FIXTURE_MUST_NOT_EXECUTE')){exit 4}; "
            "[Console]::WriteLine('parsed-only')"
        )
        with ResourceLease(self.root, frozen=True):
            self.assert_unchanged()
            for relative in (name for name in RESOURCE_FILES if name.endswith(".ps1")):
                environment = os.environ.copy()
                environment["UNIVPN_RESOURCE_FIXTURE"] = str(self.root / relative)
                completed = subprocess.run(
                    [str(SHELL), "-NoProfile", "-NonInteractive", "-Command", command],
                    capture_output=True, timeout=15, env=environment,
                    creationflags=subprocess.CREATE_NO_WINDOW,
                )
                with self.subTest(resource=relative):
                    self.assertEqual(completed.returncode, 0, completed.stderr.decode("utf-8", "replace"))
                    self.assertEqual(completed.stdout.decode("utf-8-sig").strip(), "parsed-only")
            self.assert_unchanged()

    def test_close_is_idempotent_and_reentry_failure_does_not_drop_existing_pins(self):
        lease = ResourceLease(self.root, frozen=True)
        with lease:
            with self.assertRaises(ResourceLeaseError):
                lease.__enter__()
            self.assert_denied(lambda: (self.root / RESOURCE_FILES[0]).unlink())
            lease.close()
            lease.close()
            (self.root / RESOURCE_FILES[0]).write_bytes(b"released during context")
        lease.close()
        self.remove_fixture(self.root)

    def test_context_body_exception_releases_resources(self):
        lease = ResourceLease(self.root, frozen=True)
        with self.assertRaisesRegex(RuntimeError, "synthetic body failure"):
            with lease:
                raise RuntimeError("synthetic body failure")
        self.assert_failed_entry_released_all_pins(lease)

    def test_distinct_nested_leases_share_reads_and_outer_lease_remains_after_inner_closes(self):
        target = self.root / "web/index.html"
        with ResourceLease(self.root, frozen=True):
            with ResourceLease(self.root, frozen=True):
                self.assertEqual(target.read_bytes(), self.contents["web/index.html"])
                self.assert_denied(target.unlink)
            self.assert_denied(target.unlink)
            self.assert_denied(lambda: self.root.rename(self.base / "renamed while outer active"))
        target.write_bytes(b"writable after both contexts")
        moved = self.base / "nested leases released"
        self.root.rename(moved)
        self.remove_fixture(moved)

    def test_missing_asset_midway_releases_all_earlier_file_and_directory_handles(self):
        (self.root / RESOURCE_FILES[len(RESOURCE_FILES) // 2]).unlink()
        lease = ResourceLease(self.root, frozen=True)
        with self.assertRaises(ResourceLeaseError):
            lease.__enter__()
        self.assert_failed_entry_released_all_pins(lease)

    def test_invalid_directory_type_releases_both_root_and_rejected_file_handle(self):
        self.remove_fixture(self.root / "web")
        (self.root / "web").write_bytes(b"regular file instead of resource directory")
        lease = ResourceLease(self.root, frozen=True)
        with self.assertRaises(ResourceLeaseError):
            lease.__enter__()
        (self.root / "web").unlink()
        self.assert_failed_entry_released_all_pins(lease)

    def test_default_frozen_mode_uses_real_windows_leases(self):
        with patch.object(sys, "frozen", True, create=True):
            with ResourceLease(self.root) as lease:
                self.assertTrue(lease.enabled)
                self.assert_denied(lambda: (self.root / RESOURCE_FILES[0]).unlink())
        self.remove_fixture(self.root)

    def test_file_reparse_point_is_rejected_without_following_its_target(self):
        target = self.base / "synthetic outside target.txt"
        target.write_bytes(b"outside fixture must stay intact")
        resource = self.root / RESOURCE_FILES[len(RESOURCE_FILES) // 2]
        resource.unlink()
        try:
            resource.symlink_to(target)
        except OSError as exc:
            if getattr(exc, "winerror", None) in {1, 50, 1314}:
                self.skipTest("unprivileged file symlinks unavailable; all primary Windows locking checks still run")
            raise
        lease = ResourceLease(self.root, frozen=True)
        with self.assertRaises(ResourceLeaseError):
            lease.__enter__()
        self.assertEqual(target.read_bytes(), b"outside fixture must stay intact")
        # Unlink the reparse entry, never write through it during cleanup.
        resource.unlink()
        self.assert_failed_entry_released_all_pins(lease)
        self.assertEqual(target.read_bytes(), b"outside fixture must stay intact")


if __name__ == "__main__":
    unittest.main()
