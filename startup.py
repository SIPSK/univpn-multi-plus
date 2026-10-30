"""Explicit current-user Windows-logon startup; constructing this never writes.

HKCU Run is used only after set_enabled(True). No machine key, task, service,
automatic registration, or dependency on PyInstaller's extraction path exists.
https://learn.microsoft.com/windows/win32/setupapi/run-and-runonce-registry-keys
"""
from __future__ import annotations

import ntpath
import os
from pathlib import Path
import sys
import tempfile


RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
VALUE_NAME = "UniVPNManager"


class StartupError(RuntimeError):
    pass


class _WindowsRunKey:
    def __init__(self):
        if os.name != "nt":
            raise StartupError("登录启动设置需要 Windows")
        import winreg
        self.registry = winreg

    def read(self) -> str | None:
        registry = self.registry
        try:
            with registry.OpenKey(registry.HKEY_CURRENT_USER, RUN_KEY, 0, registry.KEY_QUERY_VALUE) as key:
                value, kind = registry.QueryValueEx(key, VALUE_NAME)
                return value if kind == registry.REG_SZ and isinstance(value, str) else None
        except FileNotFoundError:
            return None
        except OSError:
            raise StartupError("无法读取当前用户的登录启动设置") from None

    def write(self, command: str) -> None:
        registry = self.registry
        try:
            with registry.CreateKeyEx(registry.HKEY_CURRENT_USER, RUN_KEY, 0, registry.KEY_SET_VALUE) as key:
                registry.SetValueEx(key, VALUE_NAME, 0, registry.REG_SZ, command)
        except OSError:
            raise StartupError("无法保存当前用户的登录启动设置") from None

    def delete(self) -> None:
        registry = self.registry
        try:
            with registry.OpenKey(registry.HKEY_CURRENT_USER, RUN_KEY, 0, registry.KEY_SET_VALUE) as key:
                registry.DeleteValue(key, VALUE_NAME)
        except FileNotFoundError:
            pass
        except OSError:
            raise StartupError("无法关闭当前用户的登录启动设置") from None


def _path(value: str | Path) -> str:
    text = str(value)
    if not text or any(character in text for character in ('"', "\x00", "\r", "\n")):
        raise StartupError("启动路径无效")
    drive, tail = ntpath.splitdrive(text)
    if (not ntpath.isabs(text) or len(drive) != 2 or drive[1:] != ":"
            or not tail.startswith(("\\", "/")) or text.startswith(("\\\\", "//"))):
        raise StartupError("请将管理器保存到本机固定目录后再启用登录启动")
    normalized = ntpath.normpath(text)
    if any(part.casefold().startswith("_mei") for part in normalized.replace("/", "\\").split("\\")):
        raise StartupError("临时解包目录不能用于登录启动")
    # User-facing installs may live in Program Files, LocalAppData, or a chosen
    # local folder. The temporary extraction/download-open area is not stable.
    temporary = ntpath.normcase(ntpath.normpath(tempfile.gettempdir()))
    candidate = ntpath.normcase(normalized)
    try:
        if ntpath.commonpath([candidate, temporary]) == temporary:
            raise StartupError("请先把管理器移到固定目录，再启用登录启动")
    except ValueError:
        pass  # Different drives cannot be inside the temporary directory.
    return normalized


def build_command(executable: str | Path, launcher: str | Path | None = None) -> str:
    executable_path = _path(executable)
    if not executable_path.casefold().endswith(".exe"):
        raise StartupError("登录启动需要有效的 Windows 程序路径")
    parts = ['"' + executable_path + '"']
    if launcher is not None:
        launcher_path = _path(launcher)
        if not launcher_path.casefold().endswith(".py"):
            raise StartupError("启动器路径无效")
        parts.append('"' + launcher_path + '"')
    parts.append("--no-browser")
    command = " ".join(parts)
    if len(command.encode("utf-16-le")) // 2 > 260:
        raise StartupError("启动路径过长，请先把管理器移到较短的固定目录")
    return command


class Startup:
    """Only set_enabled writes. backend is an explicit in-memory test seam."""
    def __init__(self, *, backend=None, executable: str | Path | None = None,
                 launcher: str | Path | None = None):
        self._backend = _WindowsRunKey() if backend is None else backend
        explicit_executable = executable is not None
        if executable is None:
            if getattr(sys, "frozen", False):
                # __file__/_MEIPASS are temporary; sys.executable is the installed EXE.
                executable = Path(sys.executable).resolve()
            else:
                executable = Path(sys.executable).resolve().with_name("pythonw.exe")
                launcher = Path(__file__).resolve().parent / "launcher.py"
        self.command = build_command(executable, launcher)
        if backend is None or not explicit_executable:
            if not Path(executable).is_file() or (launcher is not None and not Path(launcher).is_file()):
                raise StartupError("未找到固定位置的管理器启动程序，请先完成解压安装")

    def get_enabled(self) -> bool:
        return self._backend.read() == self.command

    def set_enabled(self, enabled: bool) -> None:
        if type(enabled) is not bool:
            raise StartupError("登录启动设置无效")
        if enabled:
            self._backend.write(self.command)
        else:
            self._backend.delete()
