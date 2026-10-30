"""Own a never-resumed native UI process solely as a Windows token source.

The caller verifies the installed vendor binary's hash and instance first.
No RPC, GUI code, configuration, credentials, command arguments, or window
automation is used here. Every termination uses our CreateProcessW handle.
"""
from __future__ import annotations

import atexit
import ctypes
from ctypes import wintypes
from dataclasses import dataclass
import os
from pathlib import Path
import stat
import threading

CREATE_SUSPENDED = 0x00000004
CREATE_NO_WINDOW = 0x08000000
WAIT_OBJECT_0 = 0
WAIT_TIMEOUT = 258
WAIT_FAILED = 0xFFFFFFFF
FILE_ATTRIBUTE_REPARSE_POINT = 0x400
JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x2000
_live = set()
_live_lock = threading.RLock()


class AnchorError(RuntimeError):
    """A fixed, credential-free error suitable for the bridge's safe boundary."""


class STARTUPINFOW(ctypes.Structure):
    _fields_ = [
        ('cb', wintypes.DWORD), ('lpReserved', wintypes.LPWSTR),
        ('lpDesktop', wintypes.LPWSTR), ('lpTitle', wintypes.LPWSTR),
        ('dwX', wintypes.DWORD), ('dwY', wintypes.DWORD),
        ('dwXSize', wintypes.DWORD), ('dwYSize', wintypes.DWORD),
        ('dwXCountChars', wintypes.DWORD), ('dwYCountChars', wintypes.DWORD),
        ('dwFillAttribute', wintypes.DWORD), ('dwFlags', wintypes.DWORD),
        ('wShowWindow', wintypes.WORD), ('cbReserved2', wintypes.WORD),
        ('lpReserved2', ctypes.POINTER(wintypes.BYTE)),
        ('hStdInput', wintypes.HANDLE), ('hStdOutput', wintypes.HANDLE),
        ('hStdError', wintypes.HANDLE),
    ]


class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [('hProcess', wintypes.HANDLE), ('hThread', wintypes.HANDLE),
                ('dwProcessId', wintypes.DWORD), ('dwThreadId', wintypes.DWORD)]


class JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
    _fields_ = [
        ('PerProcessUserTimeLimit', ctypes.c_longlong), ('PerJobUserTimeLimit', ctypes.c_longlong),
        ('LimitFlags', wintypes.DWORD), ('MinimumWorkingSetSize', ctypes.c_size_t),
        ('MaximumWorkingSetSize', ctypes.c_size_t), ('ActiveProcessLimit', wintypes.DWORD),
        ('Affinity', ctypes.c_size_t), ('PriorityClass', wintypes.DWORD),
        ('SchedulingClass', wintypes.DWORD),
    ]


class IO_COUNTERS(ctypes.Structure):
    _fields_ = [(name, ctypes.c_ulonglong) for name in (
        'ReadOperationCount', 'WriteOperationCount', 'OtherOperationCount',
        'ReadTransferCount', 'WriteTransferCount', 'OtherTransferCount')]


class JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
    _fields_ = [
        ('BasicLimitInformation', JOBOBJECT_BASIC_LIMIT_INFORMATION), ('IoInfo', IO_COUNTERS),
        ('ProcessMemoryLimit', ctypes.c_size_t), ('JobMemoryLimit', ctypes.c_size_t),
        ('PeakProcessMemoryUsed', ctypes.c_size_t), ('PeakJobMemoryUsed', ctypes.c_size_t),
    ]


@dataclass(frozen=True)
class _Created:
    ok: bool
    process: int | None
    thread: int | None
    pid: int


class _WinAPI:
    def __init__(self):
        if os.name != 'nt':
            raise AnchorError('此功能仅支持 Windows')
        kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        self.kernel = kernel
        kernel.CreateProcessW.argtypes = [
            wintypes.LPCWSTR, wintypes.LPWSTR, ctypes.c_void_p, ctypes.c_void_p,
            wintypes.BOOL, wintypes.DWORD, ctypes.c_void_p, wintypes.LPCWSTR,
            ctypes.POINTER(STARTUPINFOW), ctypes.POINTER(PROCESS_INFORMATION),
        ]
        kernel.CreateProcessW.restype = wintypes.BOOL
        kernel.GetCurrentProcessId.argtypes = []
        kernel.GetCurrentProcessId.restype = wintypes.DWORD
        kernel.GetProcessId.argtypes = [wintypes.HANDLE]
        kernel.GetProcessId.restype = wintypes.DWORD
        kernel.ProcessIdToSessionId.argtypes = [wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
        kernel.ProcessIdToSessionId.restype = wintypes.BOOL
        kernel.GetProcessTimes.argtypes = [wintypes.HANDLE] + [ctypes.POINTER(wintypes.FILETIME)] * 4
        kernel.GetProcessTimes.restype = wintypes.BOOL
        kernel.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
        kernel.TerminateProcess.restype = wintypes.BOOL
        kernel.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        kernel.WaitForSingleObject.restype = wintypes.DWORD
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel.CloseHandle.restype = wintypes.BOOL
        kernel.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
        kernel.CreateJobObjectW.restype = wintypes.HANDLE
        kernel.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
        kernel.SetInformationJobObject.restype = wintypes.BOOL
        kernel.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
        kernel.AssignProcessToJobObject.restype = wintypes.BOOL
        # ResumeThread is deliberately never loaded or exposed.

    def create_job(self):
        job = self.kernel.CreateJobObjectW(None, None)
        if not job:
            raise AnchorError('无法创建临时进程保护')
        limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        if not self.kernel.SetInformationJobObject(job, 9, ctypes.byref(limits), ctypes.sizeof(limits)):
            self.kernel.CloseHandle(job)
            raise AnchorError('无法设置临时进程保护')
        return job

    def assign_job(self, job, process):
        # Nested jobs are supported on the target Windows 10/11 builds. Do
        # not add BREAKAWAY flags or bypass a parent job's restrictions.
        return bool(self.kernel.AssignProcessToJobObject(job, process))

    def create_suspended(self, executable):
        info, startup = PROCESS_INFORMATION(), STARTUPINFOW()
        startup.cb = ctypes.sizeof(STARTUPINFOW)
        command = ctypes.create_unicode_buffer('"' + str(executable) + '"')
        ok = self.kernel.CreateProcessW(
            str(executable), command, None, None, False,
            CREATE_SUSPENDED | CREATE_NO_WINDOW, None, str(executable.parent),
            ctypes.byref(startup), ctypes.byref(info),
        )
        return _Created(bool(ok), info.hProcess, info.hThread, int(info.dwProcessId))

    def process_id(self, handle):
        return int(self.kernel.GetProcessId(handle))

    def process_session(self, pid):
        session = wintypes.DWORD()
        if not self.kernel.ProcessIdToSessionId(pid, ctypes.byref(session)):
            raise AnchorError('无法确认临时进程的用户会话')
        return int(session.value)

    def current_session(self):
        return self.process_session(self.kernel.GetCurrentProcessId())

    def creation_timestamp(self, handle):
        created, exited, kernel, user = (wintypes.FILETIME() for _ in range(4))
        if not self.kernel.GetProcessTimes(handle, ctypes.byref(created), ctypes.byref(exited),
                                           ctypes.byref(kernel), ctypes.byref(user)):
            raise AnchorError('无法确认临时进程的创建时间')
        return ((int(created.dwHighDateTime) << 32) | int(created.dwLowDateTime)) / 10_000_000 - 11644473600

    def terminate(self, handle):
        return bool(self.kernel.TerminateProcess(handle, 1))

    def wait(self, handle, milliseconds):
        return int(self.kernel.WaitForSingleObject(handle, milliseconds))

    def close_handle(self, handle):
        return bool(self.kernel.CloseHandle(handle))


def _checked_executable(executable):
    path = Path(executable)
    if not path.is_absolute() or path.suffix.casefold() != '.exe':
        raise AnchorError('原生程序路径无效')
    try:
        supplied = path.lstat()
        if stat.S_ISLNK(supplied.st_mode) or getattr(supplied, 'st_file_attributes', 0) & FILE_ATTRIBUTE_REPARSE_POINT:
            raise ValueError()
        # The bridge separately verifies clone aliases. Resolve an already
        # verified alias to the physical directory before process creation.
        path = path.resolve(strict=True)
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & FILE_ATTRIBUTE_REPARSE_POINT:
            raise ValueError()
        if '"' in str(path) or '\x00' in str(path):
            raise ValueError()
    except (OSError, ValueError):
        raise AnchorError('原生程序文件无法确认') from None
    return path


class UserSessionAnchor:
    """One suspended same-user/session process; close only its owned handle.

    close() is idempotent after confirmed termination. A termination failure
    retains the owned handle for an explicit retry; no PID-based fallback is
    permitted. A module registry also keeps failed constructor cleanup alive
    for best-effort process-exit cleanup.
    """
    def __init__(self, executable: Path):
        self._lock = threading.RLock()
        self._api = _WinAPI()
        self._process = self._thread = self._job = None
        self.pid = 0
        self.session = None
        self.created_timestamp = None
        self._closed = False
        path = _checked_executable(executable)
        self._job = self._api.create_job()
        try:
            created = self._api.create_suspended(path)
        except Exception:
            self._close_handles()
            raise AnchorError('无法创建临时原生用户上下文') from None
        self._process, self._thread, self.pid = created.process, created.thread, created.pid
        if not created.ok:
            # Failed CreateProcessW has no running child. Close any returned
            # output handles without enumerating or targeting a process ID.
            self._close_handles()
            self._closed = True
            raise AnchorError('无法创建临时原生用户上下文')
        with _live_lock:
            _live.add(self)
        try:
            if not self._process or not self._thread or self.pid <= 0 or self._api.process_id(self._process) != self.pid:
                raise AnchorError('临时原生进程归属无法确认')
            if not self._api.assign_job(self._job, self._process):
                raise AnchorError('无法保护临时原生进程')
            self.session = self._api.process_session(self.pid)
            if self.session != self._api.current_session():
                raise AnchorError('临时原生进程的用户会话不匹配')
            self.created_timestamp = self._api.creation_timestamp(self._process)
            if self.created_timestamp <= 0:
                raise AnchorError('临时原生进程的创建时间无效')
            # Keeping no primary-thread handle makes accidental resume
            # unavailable to callers. The primary thread remains suspended.
            self._close_thread()
        except Exception:
            try:
                self.close()
            except Exception:
                raise AnchorError('临时原生进程结束未确认，请重试清理') from None
            raise AnchorError('无法准备原生用户上下文') from None

    def _close_thread(self):
        if self._thread is not None:
            if not self._api.close_handle(self._thread):
                raise AnchorError('无法关闭临时线程句柄')
            self._thread = None

    def _close_handles(self):
        error = False
        for field in ('_thread', '_process', '_job'):
            handle = getattr(self, field)
            if handle is not None:
                if self._api.close_handle(handle):
                    setattr(self, field, None)
                else:
                    error = True
        if error:
            raise AnchorError('无法关闭临时进程句柄')

    def close(self):
        with self._lock:
            if self._closed:
                return
            if self._process is not None:
                exited = self._api.wait(self._process, 0)
                if exited != WAIT_OBJECT_0:
                    if not self._api.terminate(self._process):
                        if self._api.wait(self._process, 0) != WAIT_OBJECT_0:
                            # Closing only our unnamed job kills only the
                            # process that we assigned while still suspended.
                            if self._job is None or not self._api.close_handle(self._job):
                                raise AnchorError('临时原生进程结束未确认，请重试清理')
                            self._job = None
                    if self._api.wait(self._process, 2000) != WAIT_OBJECT_0:
                        raise AnchorError('临时原生进程仍在结束，请重试清理')
            self._close_handles()
            self._closed = True
            with _live_lock:
                _live.discard(self)

    def __enter__(self):
        return self

    def __exit__(self, *ignored):
        self.close()


def _close_live():
    with _live_lock:
        anchors = list(_live)
    for anchor in anchors:
        try:
            anchor.close()
        except Exception:
            pass


atexit.register(_close_live)
