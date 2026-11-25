"""Run the synthetic PowerShell readiness regression through unittest discovery."""
import os
from pathlib import Path
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(os.name == "nt", "Windows PowerShell regression")
class VendorRuntimeTests(unittest.TestCase):
    def test_fresh_and_loaded_ready_metadata_selects_the_correct_images(self):
        shell = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32/WindowsPowerShell/v1.0/powershell.exe"
        self.assertTrue(shell.is_file())
        result = subprocess.run(
            [str(shell), "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
             "-File", str(ROOT / "tests/test_assert_ready_instance.ps1")],
            cwd=ROOT, capture_output=True, timeout=30,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        output = result.stdout.decode("utf-8", "replace")
        self.assertEqual(result.returncode, 0, output + result.stderr.decode("utf-8", "replace"))
        self.assertIn("assertions passed. Synthetic records only.", output)


if __name__ == "__main__":
    unittest.main()
