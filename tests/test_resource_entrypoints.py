"""Resource lifetimes at public entry points, without starting a manager."""
from contextlib import ExitStack
import io
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

import launcher
from resource_lease import ResourceLeaseError
import server


class ResourceEntrypointTests(unittest.TestCase):
    def setUp(self):
        self.active = False
        self.closed = 0
        owner = self

        class Lease:
            def __init__(self, root):
                self.root = root

            def __enter__(self):
                owner.assertFalse(owner.active)
                owner.active = True
                return self

            def __exit__(self, *_):
                owner.assertTrue(owner.active)
                owner.active = False
                owner.closed += 1

        self.lease = Lease

    def during_lease(self, *args, **kwargs):
        self.assertTrue(self.active)
        return 0

    def test_all_launcher_modes_hold_resources_until_their_operation_returns(self):
        with TemporaryDirectory() as temporary, ExitStack() as stack:
            stack.enter_context(patch.object(launcher, "ResourceLease", self.lease))
            stack.enter_context(patch.object(launcher, "run_launcher", side_effect=self.during_lease))
            stack.enter_context(patch.object(launcher, "stop_manager", side_effect=self.during_lease))
            stack.enter_context(patch.object(launcher, "check_client", side_effect=self.during_lease))
            stack.enter_context(patch("setup.run_setup", side_effect=self.during_lease))
            stack.enter_context(patch.object(server, "main", side_effect=self.during_lease))
            for options in ([], ["--no-browser"], ["--stop"], ["--setup"], ["--check-client"], ["--serve"]):
                with self.subTest(options=options):
                    self.assertEqual(launcher.main(["--runtime-dir", temporary, *options]), 0)
                    self.assertFalse(self.active)
            self.assertEqual(self.closed, 6)

    def test_help_and_operation_exception_release_launcher_resources(self):
        with patch.object(launcher, "ResourceLease", self.lease):
            with patch("sys.stdout", io.StringIO()), self.assertRaises(SystemExit):
                launcher.main(["--help"])
            self.assertFalse(self.active)
            with patch.object(launcher, "_main", side_effect=RuntimeError("synthetic")):
                with self.assertRaisesRegex(RuntimeError, "synthetic"):
                    launcher.main([])
            self.assertFalse(self.active)
            self.assertEqual(self.closed, 2)

    def test_resource_initialization_failure_never_dispatches_launcher(self):
        with patch.object(launcher, "ResourceLease", side_effect=ResourceLeaseError("synthetic")), \
                patch.object(launcher, "_main") as dispatch, patch.object(launcher, "notify") as notify:
            self.assertEqual(launcher.main([]), 1)
        dispatch.assert_not_called()
        notify.assert_called_once()
        self.assertNotIn("synthetic", notify.call_args.args[0])

    def test_direct_server_entrypoint_holds_resources_and_releases_on_exception(self):
        with patch.object(server, "ResourceLease", self.lease):
            with patch.object(server, "_serve", side_effect=self.during_lease):
                self.assertEqual(server.main([]), 0)
            with patch.object(server, "_serve", side_effect=RuntimeError("synthetic")):
                with self.assertRaisesRegex(RuntimeError, "synthetic"):
                    server.main([])
        self.assertFalse(self.active)
        self.assertEqual(self.closed, 2)


if __name__ == "__main__":
    unittest.main()
