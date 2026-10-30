"""Hidden local launcher. Stopping the manager never force-kills a VPN owner."""
from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import threading
import time
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import (OpenerDirector, HTTPHandler, HTTPDefaultErrorHandler, UnknownHandler,
                            HTTPErrorProcessor, HTTPRedirectHandler, ProxyHandler, Request)

from native_preflight import SUPPORTED_BUILD, check_client as inspect_client


APP_NAME = "UniVPN Manager"
APP_ID = "univpn-native-manager"
DOWNLOAD_HELP = "https://www.leagsoft.com/doc/article/103107.html"
ROOT = Path(__file__).resolve().parent


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *_args, **_kwargs):
        return None


def loopback_opener():
    # build_opener implicitly adds HTTPSHandler and initializes OpenSSL even
    # though every manager request is HTTP on 127.0.0.1. Only add the handlers
    # used here. HTTPS and redirects remain unsupported.
    opener = OpenerDirector()
    for handler in (ProxyHandler({}), HTTPHandler(), UnknownHandler(), HTTPDefaultErrorHandler(),
                    HTTPErrorProcessor(), _NoRedirect()):
        opener.add_handler(handler)
    return opener


HTTP = loopback_opener()
TOKEN_PATTERN = re.compile(r"[A-Za-z0-9_-]{32,256}\Z")


def default_runtime_dir() -> Path:
    base = os.environ.get("LOCALAPPDATA")
    return Path(base) / "UniVPNManager" if base else Path.home() / ".univpn-manager"


def notify(message: str, *, error: bool = False) -> None:
    if os.name == "nt":
        ctypes.windll.user32.MessageBoxW(None, message, APP_NAME, 0x40 if not error else 0x10)
    else:
        print(message, file=sys.stderr)


def process_alive(pid: int) -> bool:
    if pid < 1:
        return False
    if os.name != "nt":
        try:
            os.kill(pid, 0)
            return True
        except ProcessLookupError:
            return False
        except PermissionError:
            return True
    from ctypes import wintypes
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel32.WaitForSingleObject.restype = wintypes.DWORD
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    handle = kernel32.OpenProcess(0x00100000, False, pid)  # SYNCHRONIZE, no terminate right.
    if not handle:
        return ctypes.get_last_error() == 5  # Access denied means it may still exist.
    try:
        return kernel32.WaitForSingleObject(handle, 0) == 258
    finally:
        kernel32.CloseHandle(handle)


def runtime_record(runtime_dir: Path) -> dict | None:
    try:
        path = runtime_dir / "runtime.json"
        if path.stat().st_size > 4096:
            return None
        record = json.loads(path.read_text("utf-8-sig"))
        pid, port = record["pid"], record["port"]
        if type(pid) is not int or type(port) is not int or pid < 1 or not 1 <= port <= 65535:
            return None
        return {"pid": pid, "port": port}
    except (OSError, ValueError, TypeError, KeyError):
        return None


def session_token(runtime_dir: Path) -> str:
    path = runtime_dir / "session.token"
    if path.stat().st_size > 512:
        raise ValueError("Invalid session token")
    token = path.read_text("utf-8-sig").strip()
    if not TOKEN_PATTERN.fullmatch(token):
        raise ValueError("Invalid session token")
    return token


def healthy(record: dict | None) -> bool:
    if not record or not process_alive(record["pid"]):
        return False
    try:
        with HTTP.open(f"http://127.0.0.1:{record['port']}/api/health", timeout=1.5) as response:
            value = json.loads(response.read(4096))
            return (response.status == 200 and isinstance(value, dict)
                    and value.get("app") == APP_ID and bool(value.get("version")))
    except (OSError, ValueError, URLError):
        return False


def wait_ready(runtime_dir: Path, *, pid: int | None = None, parent_pid: int | None = None, timeout: float = 25) -> dict | None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        record = runtime_record(runtime_dir)
        if record and (pid is None or record["pid"] == pid) and healthy(record):
            try:
                session_token(runtime_dir)
                return record
            except (OSError, ValueError):
                pass
        if pid is not None and not process_alive(pid):
            return None
        if parent_pid is not None and not process_alive(parent_pid):
            return None
        time.sleep(0.15)
    return None


def open_page(runtime_dir: Path, record: dict) -> None:
    token = session_token(runtime_dir)
    url = f"http://127.0.0.1:{record['port']}/#token={quote(token, safe='')}"
    if os.name == "nt":
        os.startfile(url)
    else:
        import webbrowser
        if not webbrowser.open(url):
            raise OSError("Browser unavailable")


def request_shutdown(runtime_dir: Path, record: dict) -> int:
    if not healthy(record):
        raise OSError("Manager identity could not be verified")
    request = Request(
        f"http://127.0.0.1:{record['port']}/api/shutdown", data=b"{}", method="POST",
        headers={"X-VPN-Token": session_token(runtime_dir), "Content-Type": "application/json"},
    )
    try:
        with HTTP.open(request, timeout=5) as response:
            response.read(4096)
            return response.status
    except HTTPError as error:
        return error.code


def notification_statuses(runtime_dir: Path, record: dict) -> list[dict]:
    """Read only the small status endpoint, never credentials or profile fields."""
    request = Request(
        f"http://127.0.0.1:{record['port']}/api/notifications",
        headers={"X-VPN-Token": session_token(runtime_dir)},
    )
    with HTTP.open(request, timeout=3) as response:
        body = response.read(65537)
        if response.status != 200 or len(body) > 65536:
            raise ValueError("Invalid notification response")
    value = json.loads(body)
    if not isinstance(value, dict) or not isinstance(value.get("profiles"), list) or len(value["profiles"]) > 100:
        raise ValueError("Invalid notification response")
    profiles = []
    for item in value["profiles"]:
        if not isinstance(item, dict):
            continue
        profile_id, status = item.get("id"), item.get("status")
        if (not isinstance(profile_id, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,48}", profile_id)
                or not isinstance(status, str)):
            continue
        public = {"id": profile_id, "status": status}
        challenge = item.get("challengeId")
        if type(challenge) is int and challenge >= 0:
            public["challengeId"] = str(challenge)
        elif isinstance(challenge, str) and re.fullmatch(r"[A-Za-z0-9_-]{1,128}", challenge):
            public["challengeId"] = challenge
        profiles.append(public)
    return profiles


class OTPNotifier:
    """Notify once per public challenge ID, or per OTP edge for older servers."""
    def __init__(self, *, on_notify, on_open, open_browser: bool):
        self.on_notify, self.on_open, self.open_browser = on_notify, on_open, open_browser
        self._last_challenge: dict[str, str] = {}
        self._active: set[str] = set()

    def update(self, profiles: list[dict]):
        current = {item["id"] for item in profiles}
        active: set[str] = set()
        new_challenge = False
        for item in profiles:
            profile_id = item["id"]
            if item["status"] != "otp":
                continue
            active.add(profile_id)
            challenge = item.get("challengeId")
            if challenge is None:
                new_challenge |= profile_id not in self._active
            else:
                new_challenge |= self._last_challenge.get(profile_id) != challenge
                self._last_challenge[profile_id] = challenge
        self._active = active
        self._last_challenge = {key: value for key, value in self._last_challenge.items() if key in current}
        if new_challenge:
            self.on_notify("VPN 需要动态验证码，请在网页完成。")
            if self.open_browser:
                self.on_open()


class LauncherMutex:
    """One launcher/tray per user and runtime directory; OS releases it after a crash."""
    def __init__(self, runtime_dir: Path):
        self.handle = None
        self.owned = False
        if os.name != "nt":
            raise OSError("This launcher supports Windows only")
        from ctypes import wintypes
        self.kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self.kernel32.CreateMutexW.argtypes = [ctypes.c_void_p, wintypes.BOOL, wintypes.LPCWSTR]
        self.kernel32.CreateMutexW.restype = wintypes.HANDLE
        self.kernel32.ReleaseMutex.argtypes = [wintypes.HANDLE]
        self.kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        key = hashlib.sha256(os.path.normcase(str(runtime_dir)).encode("utf-8")).hexdigest()[:24]
        ctypes.set_last_error(0)
        self.handle = self.kernel32.CreateMutexW(None, True, "Local\\UniVPNManager-" + key)
        if not self.handle:
            raise ctypes.WinError(ctypes.get_last_error())
        self.owned = ctypes.get_last_error() != 183

    def close(self):
        if self.handle:
            if self.owned:
                self.kernel32.ReleaseMutex(self.handle)
            self.kernel32.CloseHandle(self.handle)
            self.handle = None


def start_server(runtime_dir: Path) -> subprocess.Popen:
    environment = os.environ.copy()
    if getattr(sys, "frozen", False):
        command = [sys.executable, "--serve", "--runtime-dir", str(runtime_dir)]
        # One-file children need their own extraction lifetime if the tray exits.
        environment["PYINSTALLER_RESET_ENVIRONMENT"] = "1"
    else:
        executable = Path(sys.executable)
        hidden_python = executable.with_name("pythonw.exe")
        if hidden_python.exists():
            executable = hidden_python
        command = [str(executable), str(ROOT / "launcher.py"), "--serve", "--runtime-dir", str(runtime_dir)]
    return subprocess.Popen(
        command, cwd=str(ROOT), stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL, close_fds=True, env=environment, creationflags=subprocess.CREATE_NO_WINDOW,
    )


def stop_manager(runtime_dir: Path) -> int:
    record = runtime_record(runtime_dir)
    if not record or not process_alive(record["pid"]):
        return 0
    try:
        status = request_shutdown(runtime_dir, record)
        if status == 409:
            open_page(runtime_dir, record)
            notify("请先在网页断开 VPN，再退出管理器。后台已保留。")
            return 2
        if status != 200:
            raise OSError("Shutdown refused")
        return 0
    except (OSError, ValueError, URLError):
        notify("暂时无法安全退出管理器，后台已保留。请打开网页检查连接。", error=True)
        return 1


def client_status(source_dir: Path | None = None) -> dict:
    """Read only: never instantiate NativeBridge or open the vendor RPC channel."""
    result = inspect_client(source_dir)
    return {"status": "ready" if result["ready"] else "unsupported", "reason": result["reason"]}


def check_client() -> int:
    result = client_status()
    if result["status"] == "ready":
        notify(result["reason"] + "。可通过 Start.bat 打开管理器。")
        return 0
    notify(result["reason"] + "。\n需要官方 UniVPN " + SUPPORTED_BUILD
           + " 的指定构建。请向管理员获取该构建，或查看即将打开的官方版本下载说明。\n"
           + "管理器不会自动安装、降级或覆盖已有客户端。", error=True)
    try:
        os.startfile(DOWNLOAD_HELP)
    except OSError:
        pass
    return 1


def run_launcher(runtime_dir: Path, *, show_browser: bool = True) -> int:
    from tray import TrayIcon
    mutex = LauncherMutex(runtime_dir)
    try:
        if not mutex.owned:
            record = wait_ready(runtime_dir, timeout=12)
            if not record:
                notify("管理器正在运行，但网页尚未就绪。请稍后再次打开。", error=True)
                return 1
            if show_browser:
                open_page(runtime_dir, record)
            return 0
        record = runtime_record(runtime_dir)
        if record and process_alive(record["pid"]):
            record = wait_ready(runtime_dir, pid=record["pid"], timeout=8)
            if not record:
                notify("后台仍在运行，但暂时无法访问。为保留 VPN 连接，未启动第二个后台。", error=True)
                return 1
        else:
            child = start_server(runtime_dir)
            # A PyInstaller one-file bootloader supervises a second PID, which
            # is the PID written by server.main into runtime.json.
            expected = None if getattr(sys, "frozen", False) else child.pid
            record = wait_ready(runtime_dir, pid=expected, parent_pid=child.pid)
            if not record:
                notify("管理器启动未完成。请检查客户端预检结果；后台未被强制终止。", error=True)
                return 1

        action_lock = threading.Lock()

        def on_open():
            try:
                open_page(runtime_dir, record)
            except (OSError, ValueError):
                notify("无法打开浏览器，请检查默认浏览器设置。", error=True)

        def on_exit():
            if not action_lock.acquire(blocking=False):
                return
            try:
                status = request_shutdown(runtime_dir, record)
                if status == 409:
                    tray.notify("请先在网页断开 VPN，再退出管理器。")
                    on_open()
                elif status == 200:
                    deadline = time.monotonic() + 8
                    while process_alive(record["pid"]) and time.monotonic() < deadline:
                        time.sleep(0.2)
                    if not process_alive(record["pid"]):
                        tray.close()
                    else:
                        tray.notify("正在安全退出，后台完成后托盘会自动关闭。")
                else:
                    tray.notify("暂时无法安全退出，请在网页检查连接。")
            except (OSError, ValueError, URLError):
                if not process_alive(record["pid"]):
                    tray.close()
                else:
                    tray.notify("后台已保留，请打开网页检查连接。")
            finally:
                action_lock.release()

        tray = TrayIcon(on_open=on_open, on_exit=on_exit, tooltip=APP_NAME)
        otp_notifier = OTPNotifier(on_notify=tray.notify, on_open=on_open, open_browser=not show_browser)

        def monitor():
            while not tray.closed.wait(2):
                if not process_alive(record["pid"]):
                    tray.close()
                    return
                try:
                    otp_notifier.update(notification_statuses(runtime_dir, record))
                except (OSError, ValueError, URLError):
                    # A transient read failure does not reset deduplication and
                    # never triggers a login attempt, restart or forced shutdown.
                    pass

        threading.Thread(target=monitor, daemon=True, name="manager-monitor").start()
        if show_browser:
            threading.Thread(target=on_open, daemon=True, name="manager-browser").start()
        tray.run()
        return 0
    finally:
        mutex.close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="UniVPN local web and tray manager")
    parser.add_argument("--runtime-dir", type=Path, default=default_runtime_dir())
    parser.add_argument("--stop", action="store_true")
    parser.add_argument("--check-client", action="store_true", help="Check the installed official exact build; never install or replace it")
    parser.add_argument("--setup", action="store_true", help="Install the manager in the current user's stable App directory")
    parser.add_argument("--serve", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--no-browser", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    runtime_dir = args.runtime_dir.expanduser().resolve()
    if args.serve:
        # A single entry point also lets the frozen EXE host the HTTP process.
        from server import main as serve
        result = serve(["--runtime-dir", str(runtime_dir)])
        return int(result or 0)
    if os.name != "nt":
        notify("此管理器需要 Windows x64。", error=True)
        return 1
    try:
        if args.setup:
            from setup import run_setup
            return run_setup()
        if args.check_client:
            return check_client()
        runtime_dir.mkdir(parents=True, exist_ok=True)
        return stop_manager(runtime_dir) if args.stop else run_launcher(runtime_dir, show_browser=not args.no_browser)
    except (OSError, ValueError):
        notify("无法启动管理器，请检查运行目录和浏览器设置。已有 VPN 连接已保留。", error=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
