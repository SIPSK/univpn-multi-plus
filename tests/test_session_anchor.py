"""No native process is started: every lifecycle call uses a fake WinAPI."""
import ctypes
import os
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import session_anchor as anchor
_REAL_API = anchor._WinAPI


class FakeAPI:
    def __init__(self):
        self.calls = []
        self.created = anchor._Created(True, 101, 202, 303)
        self.target_session = self.caller_session = 1
        self.target_pid = 303
        self.timestamp = 1700000000.0
        self.exited = False
        self.termination_ok = True
        self.wait_after_terminate = anchor.WAIT_OBJECT_0
        self.close_fail = set()
        self.assign_ok = True
        self.job_creation_ok = True

    def create_job(self):
        self.calls.append(('job', 404))
        if not self.job_creation_ok:
            raise anchor.AnchorError('fixture failure')
        return 404

    def assign_job(self, job, process):
        self.calls.append(('assign', job, process))
        return self.assign_ok

    def create_suspended(self, path):
        self.calls.append(('create', path))
        return self.created

    def process_id(self, handle):
        self.calls.append(('process_id', handle))
        return self.target_pid

    def process_session(self, pid):
        self.calls.append(('session', pid))
        return self.target_session

    def current_session(self):
        return self.caller_session

    def creation_timestamp(self, handle):
        self.calls.append(('created', handle))
        return self.timestamp

    def wait(self, handle, milliseconds):
        self.calls.append(('wait', handle, milliseconds))
        return anchor.WAIT_OBJECT_0 if self.exited else anchor.WAIT_TIMEOUT

    def terminate(self, handle):
        self.calls.append(('terminate', handle))
        if self.termination_ok:
            self.exited = self.wait_after_terminate == anchor.WAIT_OBJECT_0
        return self.termination_ok

    def close_handle(self, handle):
        self.calls.append(('close', handle))
        if handle == 404 and handle not in self.close_fail and self.assign_ok:
            self.exited = True
        return handle not in self.close_fail


class AnchorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='vpn-anchor-fixture-')
        self.addCleanup(self.tmp.cleanup)
        self.exe = Path(self.tmp.name) / 'UVP009.exe'
        self.exe.write_bytes(b'offline fake executable; never executed')
        self.api = FakeAPI()
        self.patch_api = patch.object(anchor, '_WinAPI', return_value=self.api)
        self.patch_api.start()
        self.addCleanup(self.patch_api.stop)

    def create(self):
        item = anchor.UserSessionAnchor(self.exe)
        self.addCleanup(item.close)
        return item

    def test_owns_one_handle_and_never_exposes_a_resume_api(self):
        item = self.create()
        self.assertEqual((item.pid, item.session, item.created_timestamp), (303, 1, 1700000000.0))
        self.assertIn(('close', 202), self.api.calls)
        self.assertNotIn(('close', 101), self.api.calls)
        self.assertFalse(hasattr(self.api, 'resume'))
        self.assertIn(item, anchor._live)
        item.close()
        self.assertEqual([row for row in self.api.calls if row[0] == 'terminate'], [('terminate', 101)])
        self.assertEqual([row for row in self.api.calls if row[0] == 'close'], [('close', 202), ('close', 101), ('close', 404)])
        before = list(self.api.calls)
        item.close()
        self.assertEqual(before, self.api.calls)
        self.assertNotIn(item, anchor._live)

    def test_failed_create_closes_all_returned_handles_without_termination(self):
        self.api.created = anchor._Created(False, 101, 202, 0)
        with self.assertRaises(anchor.AnchorError):
            anchor.UserSessionAnchor(self.exe)
        self.assertEqual([row for row in self.api.calls if row[0] == 'close'], [('close', 202), ('close', 101), ('close', 404)])
        self.assertFalse(any(row[0] == 'terminate' for row in self.api.calls))

    def test_create_failure_with_zero_handles_does_not_close_unowned_handles(self):
        self.api.created = anchor._Created(False, None, None, 0)
        with self.assertRaises(anchor.AnchorError):
            anchor.UserSessionAnchor(self.exe)
        self.assertEqual([row[0] for row in self.api.calls], ['job', 'create', 'close'])

    def test_session_mismatch_terminates_only_created_handle(self):
        self.api.target_session = 2
        with self.assertRaises(anchor.AnchorError):
            anchor.UserSessionAnchor(self.exe)
        self.assertIn(('terminate', 101), self.api.calls)
        self.assertEqual({row[1] for row in self.api.calls if row[0] == 'close'}, {101, 202, 404})

    def test_pid_mismatch_terminates_by_owned_handle_not_reported_pid(self):
        self.api.target_pid = 999
        with self.assertRaises(anchor.AnchorError):
            anchor.UserSessionAnchor(self.exe)
        self.assertEqual([row for row in self.api.calls if row[0] == 'terminate'], [('terminate', 101)])

    def test_invalid_creation_metadata_cleans_up(self):
        self.api.timestamp = -1
        with self.assertRaises(anchor.AnchorError):
            anchor.UserSessionAnchor(self.exe)
        self.assertIn(('terminate', 101), self.api.calls)

    def test_failed_termination_retains_handle_for_explicit_retry(self):
        item = self.create()
        self.api.termination_ok = False
        self.api.close_fail.add(404)
        with self.assertRaises(anchor.AnchorError):
            item.close()
        self.assertEqual(item._process, 101)
        self.assertNotIn(('close', 101), self.api.calls)
        self.assertIn(item, anchor._live)
        self.api.termination_ok = True
        self.api.close_fail.clear()
        item.close()
        self.assertIsNone(item._process)
        self.assertNotIn(item, anchor._live)

    def test_job_close_is_an_owned_fallback_if_termination_fails(self):
        item = self.create()
        self.api.termination_ok = False
        item.close()
        self.assertEqual([row for row in self.api.calls if row[0] == 'terminate'], [('terminate', 101)])
        self.assertIn(('close', 404), self.api.calls)
        self.assertIsNone(item._process)

    def test_job_assignment_failure_terminates_child_and_closes_every_handle(self):
        self.api.assign_ok = False
        with self.assertRaises(anchor.AnchorError):
            anchor.UserSessionAnchor(self.exe)
        self.assertIn(('terminate', 101), self.api.calls)
        self.assertEqual({row[1] for row in self.api.calls if row[0] == 'close'}, {101, 202, 404})

    def test_job_creation_failure_never_creates_child(self):
        self.api.job_creation_ok = False
        with self.assertRaises(anchor.AnchorError):
            anchor.UserSessionAnchor(self.exe)
        self.assertEqual(self.api.calls, [('job', 404)])

    def test_already_exited_process_closes_handle_without_terminating(self):
        item = self.create()
        self.api.exited = True
        item.close()
        self.assertFalse(any(row[0] == 'terminate' for row in self.api.calls))
        self.assertIn(('close', 101), self.api.calls)

    def test_concurrent_close_terminates_and_closes_once(self):
        item = self.create()
        threads = [threading.Thread(target=item.close) for _ in range(5)]
        for thread in threads: thread.start()
        for thread in threads: thread.join(1)
        self.assertTrue(all(not thread.is_alive() for thread in threads))
        self.assertEqual([row for row in self.api.calls if row[0] == 'terminate'], [('terminate', 101)])
        self.assertEqual(self.api.calls.count(('close', 101)), 1)

    def test_relative_missing_and_non_executable_paths_are_rejected_before_create(self):
        for path in (Path('UVP009.exe'), self.exe.parent / 'missing.exe', self.exe.with_suffix('.txt')):
            with self.subTest(path=path.name), self.assertRaises(anchor.AnchorError):
                anchor.UserSessionAnchor(path)
        self.assertEqual(self.api.calls, [])

    def test_real_wrapper_passes_only_suspended_flags_and_no_inherited_handles(self):
        received = {}

        class Kernel:
            def CreateProcessW(self, application, command, process_security, thread_security,
                               inherit, flags, environment, directory, startup_ptr, info_ptr):
                startup = ctypes.cast(startup_ptr, ctypes.POINTER(anchor.STARTUPINFOW)).contents
                received.update(application=application, command=command.value, process_security=process_security,
                                thread_security=thread_security, inherit=inherit, flags=flags,
                                environment=environment, directory=directory, startup_size=startup.cb,
                                startup_flags=startup.dwFlags)
                info = ctypes.cast(info_ptr, ctypes.POINTER(anchor.PROCESS_INFORMATION)).contents
                info.hProcess, info.hThread, info.dwProcessId = 101, 202, 303
                return True

        api = object.__new__(_REAL_API)
        api.kernel = Kernel()
        result = api.create_suspended(self.exe)
        self.assertEqual(result, anchor._Created(True, 101, 202, 303))
        self.assertEqual(received, {
            'application': str(self.exe), 'command': '"' + str(self.exe) + '"',
            'process_security': None, 'thread_security': None, 'inherit': False,
            'flags': 0x08000004, 'environment': None, 'directory': str(self.exe.parent),
            'startup_size': ctypes.sizeof(anchor.STARTUPINFOW), 'startup_flags': 0,
        })

    def test_real_wrapper_creates_an_unnamed_kill_on_close_job(self):
        received = []

        class Kernel:
            def CreateJobObjectW(self, security, name):
                received.append(('create', security, name))
                return 404

            def SetInformationJobObject(self, job, kind, ptr, size):
                limits = ctypes.cast(ptr, ctypes.POINTER(anchor.JOBOBJECT_EXTENDED_LIMIT_INFORMATION)).contents
                received.append(('limit', job, kind, size, limits.BasicLimitInformation.LimitFlags))
                return True

        api = object.__new__(_REAL_API)
        api.kernel = Kernel()
        self.assertEqual(api.create_job(), 404)
        self.assertEqual(received, [('create', None, None),
                                   ('limit', 404, 9, ctypes.sizeof(anchor.JOBOBJECT_EXTENDED_LIMIT_INFORMATION), 0x2000)])

    @unittest.skipUnless(os.name == 'nt' and ctypes.sizeof(ctypes.c_void_p) == 8, 'Win64 ABI')
    def test_windows_structure_layout_and_suspended_creation_flags(self):
        self.assertEqual(ctypes.sizeof(anchor.STARTUPINFOW), 104)
        self.assertEqual(ctypes.sizeof(anchor.PROCESS_INFORMATION), 24)
        self.assertEqual(ctypes.sizeof(anchor.JOBOBJECT_BASIC_LIMIT_INFORMATION), 64)
        self.assertEqual(ctypes.sizeof(anchor.JOBOBJECT_EXTENDED_LIMIT_INFORMATION), 144)
        self.assertEqual(anchor.CREATE_SUSPENDED | anchor.CREATE_NO_WINDOW, 0x08000004)


if __name__ == '__main__':
    unittest.main()
