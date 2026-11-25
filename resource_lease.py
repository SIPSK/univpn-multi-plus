"""Keep frozen, read-only resources available for this process's lifetime."""
from __future__ import annotations

import ctypes
from ctypes import wintypes
import os
from pathlib import Path
import sys


RESOURCE_FILES = (
    "web/index.html", "web/app.js", "web/style.css",
    "tools/inspect.ps1", "tools/native-action.ps1",
    "vendor/UniVPN-Multi.ps1", "vendor/LICENSE.univpn-multi",
    "vendor/setup-selfcheck.json",
)
RESOURCE_DIRECTORIES = (".", "web", "tools", "vendor")

GENERIC_READ = 0x80000000
FILE_SHARE_READ = 0x00000001
OPEN_EXISTING = 3
FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
FILE_ATTRIBUTE_DIRECTORY = 0x00000010
FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value


class ResourceLeaseError(OSError):
    pass


class _FileInformation(ctypes.Structure):
    _fields_ = [
        ("attributes", wintypes.DWORD),
        ("creation", wintypes.FILETIME),
        ("access", wintypes.FILETIME),
        ("write", wintypes.FILETIME),
        ("volume", wintypes.DWORD),
        ("size_high", wintypes.DWORD),
        ("size_low", wintypes.DWORD),
        ("links", wintypes.DWORD),
        ("index_high", wintypes.DWORD),
        ("index_low", wintypes.DWORD),
    ]


def _kernel_api():
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                  ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    kernel.CreateFileW.restype = wintypes.HANDLE
    kernel.GetFileInformationByHandle.argtypes = [wintypes.HANDLE, ctypes.POINTER(_FileInformation)]
    kernel.GetFileInformationByHandle.restype = wintypes.BOOL
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.CloseHandle.restype = wintypes.BOOL
    return kernel


class ResourceLease:
    """Deny writes, deletes and renames while allowing native readers.

    Each frozen launcher/server owns its own handles, including independently
    extracted one-file children. Source runs keep normal editable resources.
    """

    def __init__(self, root: Path, *, frozen: bool | None = None):
        self.root = Path(root).absolute()
        self.enabled = bool(getattr(sys, "frozen", False)) if frozen is None else frozen
        self._kernel = None
        self._handles = []

    def _open(self, relative: str, *, directory: bool):
        flags = FILE_FLAG_OPEN_REPARSE_POINT
        if directory:
            flags |= FILE_FLAG_BACKUP_SEMANTICS
        handle = self._kernel.CreateFileW(str(self.root / relative), GENERIC_READ,
                                          FILE_SHARE_READ, None, OPEN_EXISTING, flags, None)
        if handle in (None, 0, INVALID_HANDLE_VALUE):
            raise ResourceLeaseError("无法保护打包资源：" + relative)
        self._handles.append(handle)
        information = _FileInformation()
        if not self._kernel.GetFileInformationByHandle(handle, ctypes.byref(information)):
            raise ResourceLeaseError("无法核对打包资源：" + relative)
        attributes = information.attributes
        if attributes & FILE_ATTRIBUTE_REPARSE_POINT or bool(attributes & FILE_ATTRIBUTE_DIRECTORY) != directory:
            raise ResourceLeaseError("打包资源类型无效：" + relative)

    def __enter__(self):
        if not self.enabled:
            return self
        if os.name != "nt":
            raise ResourceLeaseError("打包资源保护需要 Windows")
        if self._handles:
            raise ResourceLeaseError("打包资源已被保护")
        self._kernel = _kernel_api()
        try:
            # Pin directories too: renaming an otherwise intact web/ directory
            # would invalidate the absolute paths used by the running server.
            for relative in RESOURCE_DIRECTORIES:
                self._open(relative, directory=True)
            for relative in RESOURCE_FILES:
                self._open(relative, directory=False)
        except BaseException:
            self.close()
            raise
        return self

    def close(self):
        handles, self._handles = self._handles, []
        failed = False
        for handle in reversed(handles):
            if not self._kernel.CloseHandle(handle):
                failed = True
        if failed:
            raise ResourceLeaseError("无法释放打包资源句柄")

    def __exit__(self, *_):
        self.close()
