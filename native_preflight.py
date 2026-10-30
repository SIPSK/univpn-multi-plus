"""Read-only discovery of the one supported official Windows client build.

This module does not open vendor RPC, read AppData, inspect vendor logs, install
anything, or touch existing VPN processes.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys


SUPPORTED_BUILD = "10781.19.0.1214"
SOURCE_HASHES = {
    "UniVPN.exe": "24f90f30309ad4bcd6c2e81adf39e44a690c648d13455194971c01a08ad0d0b1",
    "promote/UniVPNPromoteService.exe": "e038021b055e659430876a7e270c6ef8e8f32346155c3197cc6e539477141b10",
    "serviceclient/UniVPNCS.exe": "cf07de7e0ffeb470859a5df8cbc33915ef642b407c7b42627ced94f5e166ec39",
}
ROOT = Path(__file__).resolve().parent


def _registry_directories() -> list[Path]:
    import winreg
    directories: list[Path] = []
    for view in (winreg.KEY_WOW64_32KEY, winreg.KEY_WOW64_64KEY):
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", 0,
                                winreg.KEY_READ | view) as uninstall:
                for index in range(min(winreg.QueryInfoKey(uninstall)[0], 5000)):
                    try:
                        key_name = winreg.EnumKey(uninstall, index)
                        with winreg.OpenKey(uninstall, key_name) as entry:
                            name = str(winreg.QueryValueEx(entry, "DisplayName")[0])
                            if not (name.casefold() == "univpn" or name.casefold().startswith("univpn ")):
                                continue
                            try:
                                location = str(winreg.QueryValueEx(entry, "InstallLocation")[0]).strip().strip('"')
                                if location:
                                    directories.append(Path(os.path.expandvars(location)))
                            except OSError:
                                pass
                            try:
                                icon = str(winreg.QueryValueEx(entry, "DisplayIcon")[0]).strip()
                                if icon.startswith('"'):
                                    icon = icon.split('"', 2)[1]
                                else:
                                    icon = icon.rsplit(",", 1)[0].strip()
                                if Path(icon).name.casefold() == "univpn.exe":
                                    directories.append(Path(os.path.expandvars(icon)).parent)
                            except OSError:
                                pass
                    except OSError:
                        continue
        except (OSError, ValueError, RuntimeError):
            continue
    return directories


def discover_directories() -> list[Path]:
    if os.name != "nt":
        return []
    candidates: list[Path] = []
    for variable in ("ProgramFiles(x86)", "ProgramFiles"):
        if os.environ.get(variable):
            candidates.append(Path(os.environ[variable]) / "UniVPN")
    candidates.extend(_registry_directories())
    seen: set[str] = set()
    result: list[Path] = []
    for candidate in candidates:
        try:
            resolved = candidate.resolve()
        except (OSError, ValueError, RuntimeError):
            continue
        key = str(resolved).casefold()
        if key not in seen:
            seen.add(key)
            result.append(resolved)
    return result


def check_client(source_directory: str | Path | None = None) -> dict:
    result = {"ready": False, "source_directory": "", "reason": "需要 Windows x64"}
    if sys.platform != "win32" or sys.maxsize <= 2**32 or platform.machine().casefold() not in {"amd64", "x86_64"}:
        return result
    try:
        candidates = [Path(source_directory).resolve()] if source_directory is not None else discover_directories()
    except (OSError, ValueError, RuntimeError):
        result["reason"] = "客户端目录无效，已有客户端已保留"
        return result
    found = False
    for source in candidates:
        if not (source / "UniVPN.exe").is_file():
            continue
        found = True
        result["source_directory"] = str(source)
        try:
            for name, expected in SOURCE_HASHES.items():
                with (source / name).open("rb") as stream:
                    if hashlib.file_digest(stream, "sha256").hexdigest() != expected:
                        raise ValueError()
        except (OSError, ValueError):
            result["reason"] = "现有客户端不符合官方 " + SUPPORTED_BUILD + " 的精确构建，已保留且不会覆盖"
            continue
        # ready describes build verification only. Privileged actions perform
        # their own protected-path/ACL/ownership/instance checks after UAC.
        return {"ready": True, "source_directory": str(source), "reason": "仅通过官方精确构建检查；特权操作仍需独立校验路径和权限"}
    if not found:
        result["reason"] = "未找到官方 UniVPN " + SUPPORTED_BUILD + "，请先查看官方版本下载说明"
    return result


def observe_inventory() -> dict:
    """Reuse the existing metadata-only inspector, never the vendor config/logs."""
    if os.name != "nt":
        return {"installed": False, "records": [], "adapters": [], "processes": [], "error": "需要 Windows"}
    command = [str(Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32/WindowsPowerShell/v1.0/powershell.exe"),
               "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(ROOT / "tools/inspect.ps1")]
    try:
        completed = subprocess.run(command, capture_output=True, timeout=25, creationflags=subprocess.CREATE_NO_WINDOW)
        if completed.returncode or len(completed.stdout) > 2**20:
            raise ValueError()
        value = json.loads(completed.stdout.decode("utf-8-sig"))
        if not isinstance(value, dict):
            raise ValueError()
        return {key: value[key] for key in ("installed", "sourceDirectory", "records", "adapters", "processes", "services", "peers", "listeners") if key in value}
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return {"installed": False, "records": [], "adapters": [], "processes": [], "error": "无法读取 VPN 元数据"}
