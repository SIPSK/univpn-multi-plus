"""Build a Windows x64 one-file manager and a clean redistributable ZIP.

Run with the project build venv. No dependency installation, elevation, driver
changes, VPN login, or client replacement is performed by this script.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import struct
import subprocess
import sys
import zipfile


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from setup import OFFICIAL_HASHES
from core import VERSION

SUPPORTED_BUILD = "10781.19.0.1214"
SOURCE_HASHES = {
    "UniVPN.exe": "24f90f30309ad4bcd6c2e81adf39e44a690c648d13455194971c01a08ad0d0b1",
    "promote/UniVPNPromoteService.exe": "e038021b055e659430876a7e270c6ef8e8f32346155c3197cc6e539477141b10",
    "serviceclient/UniVPNCS.exe": "cf07de7e0ffeb470859a5df8cbc33915ef642b407c7b42627ced94f5e166ec39",
}
REQUIRED = ("launcher.py", "tray.py", "server.py", "core.py", "Start.bat", "Stop.bat",
            "Setup.bat", "setup.py", "vendor_state.py", "vendor_config.py", "README.zh.md", "README.md",
            "LICENSE", "THIRD_PARTY_NOTICES.md",
            "native.py", "windows_messages.py", "windows_session.py", "session_anchor.py", "native_preflight.py", "credential_store.py", "startup.py",
            "web/index.html", "web/app.js", "web/style.css", "tools/inspect.ps1", "tools/native-action.ps1",
            "vendor/UniVPN-Multi.ps1", "vendor/LICENSE.univpn-multi", "vendor/setup-selfcheck.json")


def digest(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def preflight(*, official_source: Path | None = None, distribution: str = "manager-only") -> dict:
    if distribution not in {"manager-only", "complete", "both"}:
        raise SystemExit("Unknown distribution")
    if sys.platform != "win32" or struct.calcsize("P") != 8 or platform.machine().lower() not in {"amd64", "x86_64"}:
        raise SystemExit("Build requires Windows x64 and a 64-bit Python interpreter.")
    missing = [name for name in REQUIRED if not (ROOT / name).is_file()]
    if missing:
        raise SystemExit("Missing package inputs: " + ", ".join(missing))
    script = (ROOT / "vendor/UniVPN-Multi.ps1").read_text("utf-8-sig")
    if any(value not in script for value in SOURCE_HASHES.values()):
        raise SystemExit("Vendor preflight does not contain the supported exact-build hashes.")
    vendor_hash = digest(ROOT / "vendor/UniVPN-Multi.ps1")
    if vendor_hash not in (ROOT / "tools/native-action.ps1").read_text("utf-8-sig"):
        raise SystemExit("Bundled creation script does not match the privileged helper's reviewed SHA256 pin.")
    diagnostic = json.loads((ROOT / "vendor/setup-selfcheck.json").read_text("utf-8"))
    if diagnostic.get("bundledCreationScriptSHA256") != vendor_hash:
        raise SystemExit("Read-only setup diagnostics do not match the reviewed creation script.")
    if distribution != "manager-only":
        directory = official_source if official_source is not None else ROOT / "official"
        for name, expected in OFFICIAL_HASHES.items():
            official = directory / name
            if not official.is_file() or digest(official) != expected:
                raise SystemExit("The fixed official EXE/CMS/CRL files are missing or changed. Pass --official-source with a directory containing the reviewed files; no download or replacement was attempted.")
    try:
        pyinstaller = importlib.metadata.version("pyinstaller")
    except importlib.metadata.PackageNotFoundError:
        raise SystemExit("Install PyInstaller in .build-venv from official PyPI first.") from None
    components = {name: digest(ROOT / name) for name in (*REQUIRED, "tools/build_package.py")}
    snapshot = hashlib.sha256(json.dumps(components, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
    return {"app": "univpn-native-manager", "version": VERSION, "releaseStage": "prerelease",
            "nativeLoginValidation": "two-concurrent-verified-third-instance-created-business-login-pending", "platform": "windows-x64", "python": platform.python_version(),
            "pyinstaller": pyinstaller, "supportedUniVPNBuild": SUPPORTED_BUILD,
            "officialSourceSHA256": SOURCE_HASHES, "bundledCreationScriptSHA256": vendor_hash,
            "officialInstallerFiles": OFFICIAL_HASHES, "sourceSnapshotSHA256": snapshot,
            "sourceComponents": components}


def build(*, check_only: bool = False, official_source: Path | None = None, distribution: str = "manager-only") -> Path | None:
    manifest = preflight(official_source=official_source, distribution=distribution)
    directory = official_source if official_source is not None else ROOT / "official"
    if check_only:
        print(json.dumps(manifest, indent=2))
        return None
    build_dir = ROOT / "build" / "package"
    dist = ROOT / "dist"
    build_dir.mkdir(parents=True, exist_ok=True)
    dist.mkdir(parents=True, exist_ok=True)
    command = [sys.executable, "-m", "PyInstaller", "--noconfirm", "--clean", "--onefile", "--windowed",
               "--noupx", "--name", "UniVPNManager", "--distpath", str(dist), "--workpath", str(build_dir / "work"),
               "--specpath", str(build_dir), "--paths", str(ROOT)]
    for name in ("web", "vendor", "tools"):
        source = ROOT / name
        # Explicit files only: never capture research, Python envs or runtime secrets.
        patterns = {"web": ("index.html", "app.js", "style.css"),
                    "vendor": ("UniVPN-Multi.ps1", "LICENSE.univpn-multi", "setup-selfcheck.json"),
                    "tools": ("inspect.ps1", "native-action.ps1")}[name]
        seen: set[Path] = set()
        for pattern in patterns:
            for file in sorted(source.glob(pattern)):
                if file.is_file() and file not in seen:
                    seen.add(file)
                    target = file.parent.relative_to(ROOT).as_posix()
                    command += ["--add-data", str(file) + os.pathsep + target]
    command.append(str(ROOT / "launcher.py"))
    subprocess.run(command, cwd=ROOT, check=True)
    executable = dist / "UniVPNManager.exe"
    def wrapper(argument=""):
        suffix = " " + argument if argument else ""
        return ('@echo off\r\nsetlocal\r\n'
                'if exist "%LOCALAPPDATA%\\UniVPNManager\\App\\UniVPNManager.exe" (\r\n'
                '  start "" "%LOCALAPPDATA%\\UniVPNManager\\App\\UniVPNManager.exe"' + suffix + '\r\n'
                '  exit /b 0\r\n)\r\n'
                'start "" "%~dp0UniVPNManager.exe"' + suffix + '\r\n').encode("ascii")

    archives = []
    for complete in ((False, True) if distribution == "both" else (distribution == "complete",)):
        readme = (
            "UniVPN Manager " + VERSION + " 预发布版\r\n\r\n"
            "基于 UsernameFull/univpn-multi 的独立扩展：https://github.com/UsernameFull/univpn-multi\r\n"
            "上游 MIT 许可证及原作者署名见 LICENSE.univpn-multi；官方客户端遵循其原许可。\r\n\r\n"
            "首次使用：完整解压后运行 Setup.bat。之后用 Start.bat 打开统一网页。\r\n"
            "程序安装到 %LOCALAPPDATA%\\UniVPNManager\\App；原有运行数据和凭据不会被复制或打包。\r\n"
            "已有受支持构建时跳过官方安装，可以保留在线 VPN。\r\n"
            + ("Complete 包附带原样官方 EXE、CMS 和 CRL，全部按固定 SHA256 校验。\r\n" if complete else
               "此轻量包不附带官方客户端；未安装指定构建时请使用 Complete 包。\r\n") +
            "需要安装或切换版本时，请先断开 VPN 并退出客户端。安装界面由你操作。\r\n"
            "替换时请选择保留用户配置、保留 TAP 驱动；本工具不会自动卸载或代选复选框。\r\n"
            "依赖官方 UniVPN " + SUPPORTED_BUILD + " 指定构建及其原程序、服务和驱动。\r\n"
            "账号、密码和验证码仅在本地输入。记住密码、每条自动连接、登录启动均需自己选择。\r\n"
            "关闭网页不会断开 VPN；退出托盘或 Stop.bat 前请先在网页断开连接。\r\n"
            "当前为预发布版：双 VPN 登录与动态口令、第三实例创建已验证；三、四条业务隧道并发及全新电脑安装尚待实测。\r\n"
            "无需 Docker、WSL 或另装 Python。不要分享 %LOCALAPPDATA%\\UniVPNManager 运行目录。\r\n"
        ).encode("utf-8-sig")
        files = {"Start.bat": wrapper(), "Stop.bat": wrapper("--stop"),
                 "Setup.bat": (ROOT / "Setup.bat").read_bytes(), "Check-client.bat": wrapper("--check-client"),
                 "LICENSE.univpn-multi": (ROOT / "vendor/LICENSE.univpn-multi").read_bytes(),
                 "LICENSE": (ROOT / "LICENSE").read_bytes(),
                 "THIRD_PARTY_NOTICES.md": (ROOT / "THIRD_PARTY_NOTICES.md").read_bytes(),
                 "README.zh.md": (ROOT / "README.zh.md").read_bytes(), "README.txt": readme}
        packaged_manifest = {**manifest, "distribution": "complete" if complete else "manager-only",
                             "files": {"UniVPNManager.exe": digest(executable),
                                       **{name: hashlib.sha256(data).hexdigest() for name, data in files.items()}}}
        label = "-Complete" if complete else ""
        archive = dist / f"UniVPNManager-{VERSION}-prerelease{label}-windows-x64.zip"
        with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as package:
            package.write(executable, "UniVPNManager.exe")
            for name, data in files.items():
                package.writestr(name, data)
            package.writestr("package-manifest.json", json.dumps(packaged_manifest, ensure_ascii=False, indent=2) + "\n")
            if complete:
                for name in OFFICIAL_HASHES:
                    package.write(directory / name, "official/" + name)
        (dist / (archive.name + ".sha256")).write_text(digest(archive) + "  " + archive.name + "\n", "ascii")
        print("Built " + str(archive))
        archives.append(archive)
    return archives[-1]


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="Validate build inputs without invoking PyInstaller")
    parser.add_argument("--distribution", choices=("manager-only", "complete", "both"), default="manager-only",
                        help="Manager-only builds require no official installer files (default)")
    parser.add_argument("--official-source", type=Path, help="Directory containing the pinned official EXE, CMS and CRL for Complete builds")
    args = parser.parse_args()
    build(check_only=args.check, official_source=args.official_source, distribution=args.distribution)
