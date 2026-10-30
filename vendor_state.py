"""Opaque private snapshots before taking over a vendor instance.

No file is parsed, no password/key value is returned, and no old file is written.
The caller supplies the already ACL-protected manager runtime directory.
"""
from __future__ import annotations

from contextlib import contextmanager, ExitStack
import os
from pathlib import Path
import secrets
import stat
import time


class SnapshotError(RuntimeError):
    pass


def _identity(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)


def _regular(path: Path, *, directory=False):
    value = path.lstat()
    if stat.S_ISLNK(value.st_mode) or getattr(value, 'st_file_attributes', 0) & 0x400:
        raise SnapshotError('原配置包含链接，备份未完成')
    if not (stat.S_ISDIR(value.st_mode) if directory else stat.S_ISREG(value.st_mode)):
        raise SnapshotError('原配置类型不受支持，备份未完成')
    return value


@contextmanager
def _private_directory(path: Path):
    """Pin this directory and replace weak/inherited permissions before copying."""
    before = _regular(path, directory=True)
    if os.name != 'nt':
        descriptor = os.open(path, os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0) | getattr(os, 'O_NOFOLLOW', 0))
        try:
            opened = os.fstat(descriptor)
            if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino) or opened.st_uid not in {os.getuid(), 0}:
                raise SnapshotError('备份目录归属无效')
            os.fchmod(descriptor, 0o700)
            yield
        finally:
            os.close(descriptor)
        return

    import ctypes
    from ctypes import wintypes
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    advapi = ctypes.WinDLL('advapi32', use_last_error=True)
    pointer = ctypes.c_void_p
    kernel.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, pointer,
                                  wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    kernel.CreateFileW.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    kernel.LocalFree.argtypes = [pointer]
    kernel.GetFileInformationByHandleEx.argtypes = [wintypes.HANDLE, ctypes.c_int, pointer, wintypes.DWORD]
    advapi.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    advapi.GetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, pointer, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    advapi.ConvertSidToStringSidW.argtypes = [pointer, ctypes.POINTER(wintypes.LPWSTR)]
    advapi.GetSecurityInfo.argtypes = [wintypes.HANDLE, ctypes.c_int, wintypes.DWORD, ctypes.POINTER(pointer), pointer, pointer, pointer, ctypes.POINTER(pointer)]
    advapi.SetSecurityInfo.argtypes = [wintypes.HANDLE, ctypes.c_int, wintypes.DWORD, pointer, pointer, pointer, pointer]
    advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(pointer), pointer]
    advapi.GetSecurityDescriptorDacl.argtypes = [pointer, ctypes.POINTER(wintypes.BOOL), ctypes.POINTER(pointer), ctypes.POINTER(wintypes.BOOL)]

    class Attributes(ctypes.Structure):
        _fields_ = [('attributes', wintypes.DWORD), ('reparse_tag', wintypes.DWORD)]

    handle = kernel.CreateFileW(str(path), 0x00060080, 3, None, 3, 0x02200000, None)
    if handle == ctypes.c_void_p(-1).value:
        raise SnapshotError('无法保护备份目录')
    token = wintypes.HANDLE()
    owner_descriptor = pointer()
    private_descriptor = pointer()

    def sid_text(sid):
        output = wintypes.LPWSTR()
        if not advapi.ConvertSidToStringSidW(sid, ctypes.byref(output)):
            raise SnapshotError('无法确认备份目录归属')
        try:
            return output.value
        finally:
            kernel.LocalFree(output)

    def check_attributes():
        info = Attributes()
        if not kernel.GetFileInformationByHandleEx(handle, 9, ctypes.byref(info), ctypes.sizeof(info)) or not info.attributes & 0x10 or info.attributes & 0x400:
            raise SnapshotError('备份目录包含链接或类型无效')

    try:
        check_attributes()
        if not advapi.OpenProcessToken(kernel.GetCurrentProcess(), 8, ctypes.byref(token)):
            raise SnapshotError('无法保护备份目录')
        size = wintypes.DWORD()
        advapi.GetTokenInformation(token, 1, None, 0, ctypes.byref(size))
        if not size.value:
            raise SnapshotError('无法确认备份目录归属')
        buffer = ctypes.create_string_buffer(size.value)
        if not advapi.GetTokenInformation(token, 1, buffer, size, ctypes.byref(size)):
            raise SnapshotError('无法确认备份目录归属')
        user = sid_text(ctypes.cast(buffer, ctypes.POINTER(pointer))[0])
        owner = pointer()
        if advapi.GetSecurityInfo(handle, 1, 1, ctypes.byref(owner), None, None, None, ctypes.byref(owner_descriptor)):
            raise SnapshotError('无法确认备份目录归属')
        if sid_text(owner) not in {user, 'S-1-5-18', 'S-1-5-32-544'}:
            raise SnapshotError('备份目录归属无效')
        sddl = f'D:P(A;OICI;FA;;;{user})(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)'
        if not advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, ctypes.byref(private_descriptor), None):
            raise SnapshotError('无法保护备份目录')
        present, defaulted = wintypes.BOOL(), wintypes.BOOL()
        dacl = pointer()
        if not advapi.GetSecurityDescriptorDacl(private_descriptor, ctypes.byref(present), ctypes.byref(dacl), ctypes.byref(defaulted)) or not present.value or not dacl.value:
            raise SnapshotError('无法保护备份目录')
        if advapi.SetSecurityInfo(handle, 1, 0x80000004, None, None, dacl, None):
            raise SnapshotError('无法保护备份目录')
        check_attributes()
        yield
    finally:
        if token:
            kernel.CloseHandle(token)
        if owner_descriptor:
            kernel.LocalFree(owner_descriptor)
        if private_descriptor:
            kernel.LocalFree(private_descriptor)
        kernel.CloseHandle(handle)


def snapshot_config(runtime_dir: Path, index: int, *, appdata: Path | None = None):
    if type(index) is not int or not 1 <= index <= 999:
        raise SnapshotError('原生连接编号无效')
    base = appdata if appdata is not None else Path(os.environ['APPDATA'])
    product = 'UniVPN' if index == 1 else f'UVP{index:03d}'
    source = base / product
    if not os.path.lexists(source):
        return None
    _regular(source, directory=True)
    files = [source / name for name in ('key.ini', 'sysconfig.ini') if os.path.lexists(source / name)]
    config = source / 'config'
    if os.path.lexists(config):
        _regular(config, directory=True)
        files += sorted(config.glob('*.ini'))
    if len(files) > 1000:
        raise SnapshotError('原配置数量超出备份范围')
    infos = [(path, _regular(path)) for path in files]
    if any(info.st_size > 2**20 for _, info in infos) or sum(info.st_size for _, info in infos) > 16 * 2**20:
        raise SnapshotError('原配置大小超出备份范围')
    if not files:
        return None
    parent = runtime_dir / 'vendor-backups'
    try:
        _regular(runtime_dir, directory=True)
        with ExitStack() as locks:
            locks.enter_context(_private_directory(runtime_dir))
            parent.mkdir(exist_ok=True)
            locks.enter_context(_private_directory(parent))
            target = parent / f'{product}-{time.time_ns()}-{secrets.token_hex(8)}'
            target.mkdir()
            locks.enter_context(_private_directory(target))
            pinned = {target}
            for path, info in infos:
                relative = path.relative_to(source)
                destination = target / relative
                destination.parent.mkdir(exist_ok=True)
                if destination.parent not in pinned:
                    locks.enter_context(_private_directory(destination.parent))
                    pinned.add(destination.parent)
                with path.open('rb') as reader:
                    if _identity(os.fstat(reader.fileno())) != _identity(info):
                        raise SnapshotError('原配置正在变化，备份未完成')
                    # Size and identity are checked before reading any bytes.
                    data = reader.read(2**20 + 1)
                    if len(data) != info.st_size or _identity(os.fstat(reader.fileno())) != _identity(info):
                        raise SnapshotError('原配置正在变化，备份未完成')
                    with destination.open('xb') as writer:
                        writer.write(data)
                    del data
                if _identity(_regular(path)) != _identity(info):
                    raise SnapshotError('原配置正在变化，备份未完成')
            # Earlier files may have changed while a later file was copied.
            if any(_identity(_regular(path)) != _identity(info) for path, info in infos):
                raise SnapshotError('原配置正在变化，备份未完成')
            with (target / 'complete').open('xb') as marker:
                marker.write(b'1')
    except OSError:
        raise SnapshotError('原配置备份未完成，现有文件已保留') from None
    return target
