"""Probe guards use synthetic preflight, with all mutation entrypoints poisoned."""
import json
import os
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory
import unittest


ROOT = Path(__file__).resolve().parents[1]
SHELL = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32/WindowsPowerShell/v1.0/powershell.exe"


@unittest.skipUnless(os.name == "nt" and SHELL.is_file(), "Windows PowerShell guard fixtures")
class ProbeTests(unittest.TestCase):
    def run_probe(self, *, source_failure=False, platform_failure=False, identity_failure=False, mode="Probe",
                  empty_module_path=False):
        script = (ROOT / "tools/native-action.ps1").read_text("utf-8-sig")
        marker = "$resultDirectory = $null"
        self.assertEqual(script.count(marker), 1)
        source = "throw [InvalidOperationException]::new('synthetic preflight failure')" if source_failure else "return 'C:\\Synthetic\\UniVPN'"
        spies = "function Assert-OfficialSource([string]$Path) { " + source + " }\n"
        for name in ("Start-Process", "Ensure-ResultDirectory", "Save-Result", "Get-ProtectedCreationScript",
                     "New-Item", "New-Service", "Start-Service", "Stop-Service", "Stop-Process"):
            spies += "function " + name + " { throw [InvalidOperationException]::new('forbidden mutation reached') }\n"
        script = script.replace(marker, spies + marker)
        if platform_failure:
            condition = "if ([IntPtr]::Size -ne 8 -or -not [Environment]::Is64BitOperatingSystem)"
            self.assertEqual(script.count(condition), 1)
            script = script.replace(condition, "if ($true)")
        if identity_failure:
            identity = "$identity = [Security.Principal.WindowsIdentity]::GetCurrent()"
            self.assertEqual(script.count(identity), 1)
            script = script.replace(identity, "throw [InvalidOperationException]::new('synthetic identity failure')")
        with TemporaryDirectory(prefix="univpn-probe-guard-") as temporary:
            fixture = Path(temporary) / "probe-fixture.ps1"
            fixture.write_text(script, "utf-8-sig")
            environment = os.environ.copy()
            if empty_module_path:
                environment["PSModulePath"] = ""
            completed = subprocess.run([str(SHELL), "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(fixture),
                                        "-Mode", mode, "-Index", "1", "-SourceDirectory", r"C:\Synthetic\UniVPN",
                                        "-Nonce", "0" * 32], capture_output=True, timeout=15,
                                       env=environment, creationflags=subprocess.CREATE_NO_WINDOW)
        output = completed.stdout.decode("utf-8-sig").strip()
        return completed.returncode, json.loads(output) if output else None

    def test_probe_exits_before_every_privileged_or_mutating_entrypoint(self):
        code, value = self.run_probe()
        self.assertEqual(code, 0)
        self.assertEqual(set(value), {"ok", "phase", "isAdministrator", "bitness", "languageMode"})
        self.assertIs(value["ok"], True)
        self.assertEqual(value["phase"], "complete")
        self.assertIs(type(value["isAdministrator"]), bool)
        self.assertEqual(value["bitness"], 64)
        self.assertIn(value["languageMode"], {"FullLanguage", "ConstrainedLanguage", "RestrictedLanguage", "NoLanguage"})

    def test_probe_failure_fields_are_a_fixed_phase_and_numeric_hresult(self):
        for keyword, phase in (("source_failure", "source_preflight"), ("platform_failure", "platform"),
                               ("identity_failure", "identity")):
            code, value = self.run_probe(**{keyword: True})
            self.assertEqual(code, 1)
            self.assertEqual(set(value), {"ok", "phase", "errorCode", "languageMode"})
            self.assertIs(value["ok"], False)
            self.assertEqual(value["phase"], phase)
            self.assertIs(type(value["errorCode"]), int)

    def test_probe_mode_is_case_normalized_and_unknown_mode_cannot_disconnect(self):
        code, value = self.run_probe(mode="probe")
        self.assertEqual(code, 0)
        self.assertEqual(value["phase"], "complete")
        code, value = self.run_probe(mode="UnsupportedMode")
        self.assertNotEqual(code, 0)
        self.assertIsNone(value)

    def test_probe_loads_only_system_manifests_without_module_search_path(self):
        code, value = self.run_probe(empty_module_path=True)
        self.assertEqual(code, 0)
        self.assertEqual(value["phase"], "complete")

    def test_quiesce_without_owned_process_identity_stops_before_elevation(self):
        code, value = self.run_probe(mode="QuiesceOwned")
        self.assertEqual(code, 1)
        self.assertFalse(value["ok"])
        self.assertEqual(value["mode"], "QuiesceOwned")
        self.assertEqual(value["phase"], "source_preflight")


if __name__ == "__main__":
    unittest.main()
