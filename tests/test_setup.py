import ctypes
import hashlib
import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import Mock, patch

import setup


class SetupTests(unittest.TestCase):
    def test_supported_build_skips_installer_and_idle_gate(self):
        forbidden = Mock(side_effect=AssertionError("must not run"))
        setup.ensure_supported_client(Path("unused"), check=lambda: {"ready": True},
                                      inventory=forbidden, installer=forbidden)
        forbidden.assert_not_called()

    def test_active_client_or_tap_refuses_before_installation(self):
        for state in ({"processes": [{"name": "UVP002"}], "adapters": []},
                      {"processes": [], "adapters": [{"up": True}]},
                      {"error": "synthetic unavailable"}):
            forbidden = Mock(side_effect=AssertionError("must not run"))
            with self.assertRaises(setup.SetupError):
                setup.ensure_supported_client(Path("unused"), check=lambda: {"ready": False},
                                              inventory=lambda: state, installer=forbidden)
            forbidden.assert_not_called()

    def test_install_is_one_interactive_attempt_then_exact_recheck(self):
        for after in (True, False):
            check = Mock(side_effect=[{"ready": False}, {"ready": after}])
            installer = Mock()
            inventory = Mock(return_value={"processes": [], "adapters": []})
            with patch.object(setup, "verify_official_files", return_value={setup.OFFICIAL_EXE: Path("synthetic-installer")}):
                if after:
                    setup.ensure_supported_client(Path("unused"), check=check, inventory=inventory,
                                                  installer=installer)
                else:
                    with self.assertRaises(setup.SetupError):
                        setup.ensure_supported_client(Path("unused"), check=check, inventory=inventory,
                                                      installer=installer)
            self.assertEqual(check.call_count, 2)
            self.assertEqual(inventory.call_count, 2)
            installer.assert_called_once_with(Path("synthetic-installer"))

    def test_missing_or_invalid_metadata_arrays_never_open_installer(self):
        for state in ({}, {"processes": []}, {"adapters": []}, {"processes": {}, "adapters": []},
                      {"processes": [], "adapters": [{}]}):
            installer = Mock()
            with self.assertRaises(setup.SetupError):
                setup.ensure_supported_client(Path("unused"), check=lambda: {"ready": False},
                                              inventory=lambda: state, installer=installer)
            installer.assert_not_called()

    def test_modified_official_bundle_is_refused(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "official").mkdir()
            for name in setup.OFFICIAL_HASHES:
                (root / "official" / name).write_bytes(b"synthetic modified file")
            with self.assertRaises(setup.SetupError):
                setup.verify_official_files(root)

    def package(self, root):
        hashes = {}
        for name in setup.APP_FILES:
            if name == "package-manifest.json":
                continue
            data = ("synthetic-" + name).encode()
            (root / name).write_bytes(data)
            hashes[name] = hashlib.sha256(data).hexdigest()
        (root / "package-manifest.json").write_text(json.dumps({"app": "univpn-native-manager",
            "distribution": "manager-only", "files": hashes}), "utf-8")

    def test_manager_copy_is_whitelisted_and_runtime_preserved(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            package = root / "package"
            package.mkdir()
            self.package(package)
            for name in ("profiles.json", "session.token", "key.ini"):
                (package / name).write_bytes(b"synthetic excluded")
            runtime = root / "runtime"
            runtime.mkdir()
            (runtime / "profiles.json").write_bytes(b"synthetic existing profiles")
            target = setup.install_manager(package, runtime / "App")
            self.assertEqual(target, runtime / "App/UniVPNManager.exe")
            self.assertEqual({item.name for item in target.parent.iterdir()}, set(setup.APP_FILES))
            self.assertEqual((runtime / "profiles.json").read_bytes(), b"synthetic existing profiles")
            self.assertFalse((runtime / "App/session.token").exists())
            self.assertFalse((runtime / "App/key.ini").exists())

    def test_changed_manager_is_refused_before_copy(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.package(root)
            (root / "UniVPNManager.exe").write_bytes(b"synthetic changed")
            with self.assertRaises(setup.SetupError):
                setup.install_manager(root, root / "not-created/App")
            self.assertFalse((root / "not-created").exists())

    @unittest.skipUnless(os.name == "nt" and ctypes.sizeof(ctypes.c_void_p) == 8, "Win64 layout")
    def test_shell_structure_matches_win64_layout(self):
        self.assertEqual(ctypes.sizeof(setup._SHELLEXECUTEINFOW), 112)


if __name__ == "__main__":
    unittest.main()
