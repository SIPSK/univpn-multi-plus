"""Explicit Complete-package setup. Official installation remains interactive.

This module never uninstalls, clicks vendor UI, supplies credentials, changes
startup settings, or retries an installation. Only a fixed file whitelist is
copied into the current user's stable App directory.
"""
from __future__ import annotations

import ctypes
from ctypes import wintypes
import hashlib
import json
import os
from pathlib import Path
import platform
import secrets
import shutil
import stat
import subprocess
import sys

from native_preflight import check_client, observe_inventory, SUPPORTED_BUILD

OFFICIAL_EXE = "univpn-win-full-10781.19.0.1214.exe"
OFFICIAL_HASHES = {
    OFFICIAL_EXE: "c2923a695fbf1375fbe2985253aa3fd48f6b8012f9caacf6026edd9d9edf8921",
    OFFICIAL_EXE + ".cms": "4519e66c0f8309addbd1369ab1b8cc40f341e3339f2b0084ab1999468c45bd55",
    OFFICIAL_EXE + ".crl": "8a0990b1f7900a6fc0b6770aaa97531a0af44eb5a2094e241009e832289524b6",
}
APP_FILES = ("UniVPNManager.exe", "Start.bat", "Stop.bat", "Setup.bat", "Check-client.bat",
             "LICENSE.univpn-multi", "LICENSE", "THIRD_PARTY_NOTICES.md",
             "README.txt", "README.zh.md", "package-manifest.json")


class SetupError(RuntimeError):
    pass


class SetupCancelled(SetupError):
    pass


def _plain(path: Path, *, directory=False):
    info = path.lstat()
    if (stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400
            or not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))):
        raise SetupError("安装文件或目录包含不受支持的链接，请完整解压安装包后重试")


def _sha(path: Path) -> str:
    _plain(path)
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def verify_official_files(package_dir: Path) -> dict[str, Path]:
    directory = package_dir / "official"
    try:
        _plain(directory, directory=True)
        result = {}
        for name, expected in OFFICIAL_HASHES.items():
            path = directory / name
            if _sha(path) != expected:
                raise SetupError("官方安装文件校验未通过，安装尚未开始")
            result[name] = path
        return result
    except OSError:
        raise SetupError("请使用完整解压的 Complete 包；官方安装文件缺失，安装尚未开始") from None


def _idle(inventory) -> None:
    state = inventory()
    if (not isinstance(state, dict) or state.get("error") or not isinstance(state.get("processes"), list)
            or not isinstance(state.get("adapters"), list)
            or any(not isinstance(item, dict) or type(item.get("up")) is not bool for item in state["adapters"])):
        raise SetupError("无法确认 VPN 状态，安装尚未开始。请检查客户端后重新运行 Setup")
    if state.get("processes") or any(item.get("up") for item in state.get("adapters", [])):
        raise SetupError("请先断开全部 VPN 并退出原客户端，再重新运行 Setup。安装尚未开始")


class _SHELLEXECUTEINFOW(ctypes.Structure):
    _fields_ = [("cbSize", wintypes.DWORD), ("fMask", wintypes.ULONG), ("hwnd", wintypes.HWND),
                ("lpVerb", wintypes.LPCWSTR), ("lpFile", wintypes.LPCWSTR), ("lpParameters", wintypes.LPCWSTR),
                ("lpDirectory", wintypes.LPCWSTR), ("nShow", ctypes.c_int), ("hInstApp", wintypes.HINSTANCE),
                ("lpIDList", ctypes.c_void_p), ("lpClass", wintypes.LPCWSTR), ("hkeyClass", wintypes.HKEY),
                ("dwHotKey", wintypes.DWORD), ("hIcon", wintypes.HANDLE), ("hProcess", wintypes.HANDLE)]


def run_official_installer(path: Path) -> None:
    """Launch the unmodified installer UI and wait for its process, without flags."""
    if path.name != OFFICIAL_EXE or _sha(path) != OFFICIAL_HASHES[OFFICIAL_EXE]:
        raise SetupError("官方安装器校验未通过，安装尚未开始")
    shell = ctypes.WinDLL("shell32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    ole = ctypes.WinDLL("ole32", use_last_error=True)
    shell.ShellExecuteExW.argtypes = [ctypes.POINTER(_SHELLEXECUTEINFOW)]
    shell.ShellExecuteExW.restype = wintypes.BOOL
    kernel.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel.WaitForSingleObject.restype = wintypes.DWORD
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    ole.CoInitializeEx.argtypes = [ctypes.c_void_p, wintypes.DWORD]
    ole.CoInitializeEx.restype = ctypes.c_long
    initialized = ole.CoInitializeEx(None, 0x02 | 0x04)
    if initialized not in (0, 1):
        raise SetupError("无法打开官方安装界面，现有客户端已保留")
    operation = _SHELLEXECUTEINFOW()
    operation.cbSize, operation.fMask = ctypes.sizeof(operation), 0x40 | 0x100
    operation.lpVerb, operation.lpFile = "open", str(path)
    operation.lpDirectory, operation.nShow = str(path.parent), 1
    try:
        if not shell.ShellExecuteExW(ctypes.byref(operation)):
            if ctypes.get_last_error() == 1223:
                raise SetupCancelled("已取消官方安装，现有客户端已保留")
            raise SetupError("无法打开官方安装界面，现有客户端已保留")
        if not operation.hProcess:
            raise SetupError("无法确认官方安装是否结束，请完成或关闭安装界面后重新运行 Setup")
        while True:
            result = kernel.WaitForSingleObject(operation.hProcess, 500)
            if result == 0:
                break
            if result != 258:
                raise SetupError("无法确认官方安装状态，请完成或关闭安装界面后重新运行 Setup")
    finally:
        if operation.hProcess:
            kernel.CloseHandle(operation.hProcess)
        ole.CoUninitialize()


def ensure_supported_client(package_dir: Path, *, check=check_client, inventory=observe_inventory,
                            installer=run_official_installer) -> None:
    if check().get("ready"):
        return  # Existing supported build may keep all of its current VPNs online.
    _idle(inventory)
    official = verify_official_files(package_dir)
    _idle(inventory)  # Recheck after hashing; never stop a client for setup.
    installer(official[OFFICIAL_EXE])
    if not check().get("ready"):
        raise SetupError("官方客户端尚未通过精确构建检查，未启动管理器。请完成或关闭安装界面后重新运行 Setup")


def verify_manager_files(package_dir: Path) -> dict:
    try:
        _plain(package_dir, directory=True)
        manifest_path = package_dir / "package-manifest.json"
        _plain(manifest_path)
        if manifest_path.stat().st_size > 262144:
            raise SetupError("管理器安装清单无效")
        manifest = json.loads(manifest_path.read_text("utf-8-sig"))
        hashes = manifest["files"]
        if manifest.get("app") != "univpn-native-manager" or not isinstance(hashes, dict):
            raise SetupError("管理器安装清单无效")
        for name in APP_FILES:
            _plain(package_dir / name)
            if name != "package-manifest.json" and _sha(package_dir / name) != hashes.get(name):
                raise SetupError("管理器安装文件校验未通过，请重新完整解压安装包")
        if manifest.get("distribution") == "complete":
            verify_official_files(package_dir)
        return manifest
    except (OSError, ValueError, KeyError, TypeError):
        raise SetupError("管理器安装文件不完整，请重新完整解压安装包") from None


def _copy_file(source: Path, destination: Path) -> None:
    _plain(source)
    _plain(destination.parent, directory=True)
    if destination.exists():
        _plain(destination)
    pending = destination.with_name(destination.name + ".pending-" + secrets.token_hex(8))
    try:
        with source.open("rb") as reader, pending.open("xb") as writer:
            shutil.copyfileobj(reader, writer)
        if _sha(source) != _sha(pending):
            raise SetupError("管理器复制校验未通过，未启动新后台")
        os.replace(pending, destination)
    finally:
        pending.unlink(missing_ok=True)


def install_manager(package_dir: Path, app_dir: Path) -> Path:
    manifest = verify_manager_files(package_dir)
    if package_dir.resolve() == app_dir.resolve():
        return app_dir / "UniVPNManager.exe"
    # Reuse the same private runtime ACL implementation as the HTTP service.
    from server import protect_runtime
    protect_runtime(app_dir.parent)
    if app_dir.exists():
        _plain(app_dir, directory=True)
    protect_runtime(app_dir)
    try:
        # EXE first: an active old executable must fail before replacing helpers.
        for name in APP_FILES:
            _copy_file(package_dir / name, app_dir / name)
        if manifest.get("distribution") == "complete":
            official = app_dir / "official"
            if official.exists():
                _plain(official, directory=True)
            protect_runtime(official)
            for name in OFFICIAL_HASHES:
                _copy_file(package_dir / "official" / name, official / name)
    except OSError:
        raise SetupError("管理器部署未完成。若旧管理器仍在运行，请先在网页断开 VPN 并安全退出，再重新运行 Setup") from None
    verify_manager_files(app_dir)
    return app_dir / "UniVPNManager.exe"


def launch_installed(path: Path) -> None:
    environment = os.environ.copy()
    environment["PYINSTALLER_RESET_ENVIRONMENT"] = "1"
    subprocess.Popen([str(path)], cwd=str(path.parent), env=environment,
                     stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                     creationflags=subprocess.CREATE_NO_WINDOW, close_fds=True)


def run_setup() -> int:
    try:
        if os.name != "nt" or sys.maxsize <= 2**32 or platform.machine().lower() not in {"amd64", "x86_64"}:
            raise SetupError("此安装包需要 Windows x64")
        if not getattr(sys, "frozen", False):
            raise SetupError("请完整解压安装包后运行 Setup.bat")
        package_dir = Path(sys.executable).resolve().parent
        verify_manager_files(package_dir)
        ensure_supported_client(package_dir)
        local = os.environ.get("LOCALAPPDATA")
        if not local:
            raise SetupError("无法确认当前用户的安装目录")
        app_dir = Path(local).resolve() / "UniVPNManager" / "App"
        executable = install_manager(package_dir, app_dir)
        launch_installed(executable)
        return 0
    except (SetupError, OSError) as error:
        text = str(error) if isinstance(error, SetupError) else "安装未完成，现有客户端和用户配置已保留"
        ctypes.windll.user32.MessageBoxW(None, text, "UniVPN Manager 安装", 0x40)
        return 1
