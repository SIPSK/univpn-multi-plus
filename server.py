"""Loopback-only web control surface; no credential or request-body logging."""
from __future__ import annotations

import argparse
import ctypes
from ctypes import wintypes
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import mimetypes
import os
from pathlib import Path
import re
import secrets
import signal
import sys
import threading
import time
from urllib.parse import unquote, urlsplit

from core import AppError, Manager, ROOT, VERSION

APP_ID = "univpn-native-manager"
MAX_BODY = 16384
ERROR_CODES = {"expansion_required", "credentials_required", "expansion_in_progress"}
PUBLIC_ID = re.compile(r"[a-zA-Z0-9_-]{1,48}")


def error_payload(error):
    """Expose only fixed flow codes and validated public profile IDs."""
    result = {"error": str(error)}
    code = getattr(error, "code", None)
    if code is not None and code not in ERROR_CODES:
        return result
    if code in ERROR_CODES:
        result["code"] = code
    supplied = getattr(error, "details", None)
    if isinstance(supplied, dict):
        details = {}
        for key in ("profileIds", "failedProfileIds"):
            values = supplied.get(key)
            if isinstance(values, list) and len(values) <= 1000 and all(
                    isinstance(value, str) and PUBLIC_ID.fullmatch(value) for value in values):
                details[key] = values
        if details:
            result["details"] = details
    return result


def protect_runtime(path: Path):
    path.mkdir(parents=True, exist_ok=True)
    if os.name != "nt":
        path.chmod(0o700)
        return
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.LocalFree.argtypes = [wintypes.HLOCAL]
    advapi.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    advapi.GetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    advapi.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)]
    advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p]
    advapi.SetFileSecurityW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, ctypes.c_void_p]
    token = wintypes.HANDLE()
    sid_text = wintypes.LPWSTR()
    descriptor = ctypes.c_void_p()
    try:
        if not advapi.OpenProcessToken(kernel.GetCurrentProcess(), 0x0008, ctypes.byref(token)):
            raise ctypes.WinError(ctypes.get_last_error())
        size = wintypes.DWORD()
        advapi.GetTokenInformation(token, 1, None, 0, ctypes.byref(size))
        buffer = ctypes.create_string_buffer(size.value)
        if not advapi.GetTokenInformation(token, 1, buffer, size, ctypes.byref(size)):
            raise ctypes.WinError(ctypes.get_last_error())
        sid_pointer = ctypes.cast(buffer, ctypes.POINTER(ctypes.c_void_p))[0]
        if not advapi.ConvertSidToStringSidW(sid_pointer, ctypes.byref(sid_text)):
            raise ctypes.WinError(ctypes.get_last_error())
        sddl = f"D:P(A;OICI;FA;;;{sid_text.value})(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
        if not advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, ctypes.byref(descriptor), None):
            raise ctypes.WinError(ctypes.get_last_error())
        if not advapi.SetFileSecurityW(str(path), 0x80000004, descriptor):
            raise ctypes.WinError(ctypes.get_last_error())
    finally:
        if token:
            kernel.CloseHandle(token)
        if sid_text:
            kernel.LocalFree(sid_text)
        if descriptor:
            kernel.LocalFree(descriptor)


class LocalServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False

    def __init__(self, runtime_dir: Path, manager: Manager, port=0):
        super().__init__(("127.0.0.1", port), Handler)
        self.runtime_dir = runtime_dir
        self.manager = manager
        self.token = secrets.token_urlsafe(32)
        self.browser_session = secrets.token_urlsafe(32)
        self.origin = f"http://127.0.0.1:{self.server_port}"
        self.web_root = ROOT / "web"


class Handler(BaseHTTPRequestHandler):
    server: LocalServer
    protocol_version = "HTTP/1.1"

    def log_message(self, *_):
        pass

    def _headers(self, status, content_type, length, *, cookie=False):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(length))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'; form-action 'self'")
        if self.close_connection:
            self.send_header("Connection", "close")
        if cookie:
            self.send_header("Set-Cookie", f"vpn_session={self.server.browser_session}; HttpOnly; SameSite=Strict; Path=/")
        self.end_headers()

    def _json(self, status, data, *, cookie=False):
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self._headers(status, "application/json; charset=utf-8", len(body), cookie=cookie)
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _drain_rejected_body(self):
        """Avoid an unread-body TCP reset after an early HTTP rejection.

        Authentication still precedes body parsing. This discards only a
        bounded raw body, never decodes or logs it, and never waits indefinitely
        for a client which stopped uploading after receiving the rejection.
        """
        if getattr(self, "_request_body_consumed", False) or self.headers.get("Transfer-Encoding"):
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            return
        if not 0 < length <= MAX_BODY:
            return
        try:
            deadline = time.monotonic() + 0.1
            while length:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return
                self.connection.settimeout(remaining)
                chunk = self.rfile.read1(min(length, 4096))
                if not chunk:
                    return
                length -= len(chunk)
        except OSError:
            # The client may already have closed or stopped its upload. No
            # request processing follows this best-effort, bounded discard.
            pass

    def _error_json(self, status, data):
        self.close_connection = True
        try:
            self._json(status, data)
        finally:
            self._drain_rejected_body()

    def _boundary(self):
        if self.client_address[0] != "127.0.0.1":
            raise AppError("拒绝非本机请求", 403)
        if self.headers.get("Host") != self.server.origin.removeprefix("http://"):
            raise AppError("请求地址无效", 403)
        origin = self.headers.get("Origin")
        if origin and origin != self.server.origin:
            raise AppError("请求来源无效", 403)
        fetch_site = self.headers.get("Sec-Fetch-Site")
        if fetch_site and fetch_site not in {"same-origin", "none"}:
            raise AppError("请求来源无效", 403)

    def _authorize(self):
        supplied = self.headers.get("X-VPN-Token", "")
        if not supplied.isascii() or not secrets.compare_digest(supplied, self.server.token):
            raise AppError("请通过启动器打开页面", 401)

    def _bootstrap(self):
        cookie = SimpleCookie()
        try:
            cookie.load(self.headers.get("Cookie", ""))
            supplied = cookie.get("vpn_session")
        except Exception:
            supplied = None
        if not supplied or not supplied.value.isascii() or not secrets.compare_digest(supplied.value, self.server.browser_session):
            raise AppError("请通过启动器打开页面", 401)
        # A top-level navigation from another localhost port is not a bootstrap.
        if self.headers.get("Sec-Fetch-Dest") not in {None, "empty"}:
            raise AppError("请求来源无效", 403)
        return {"token": self.server.token, "version": VERSION}

    def _body(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            raise AppError("请求无效") from None
        if not 0 <= length <= MAX_BODY or self.headers.get("Transfer-Encoding"):
            raise AppError("请求过大或格式无效", 413)
        if length and self.headers.get_content_type() != "application/json":
            raise AppError("请求格式无效", 415)
        self.connection.settimeout(10)
        try:
            raw = self.rfile.read(length) if length else b""
            self._request_body_consumed = True
            data = json.loads(raw.decode("utf-8")) if length else {}
        except (ValueError, UnicodeError):
            raise AppError("请求格式无效") from None
        if not isinstance(data, dict):
            raise AppError("请求格式无效")
        return data

    def do_GET(self):
        self._request_body_consumed = False
        try:
            self._boundary()
            parsed = urlsplit(self.path)
            if parsed.query:
                raise AppError("请勿在地址中传递认证内容")
            path = unquote(parsed.path)
            if path == "/api/health":
                return self._json(200, {"app": APP_ID, "version": VERSION, "ok": True})
            if path == "/api/bootstrap":
                return self._json(200, self._bootstrap())
            if path == "/api/notifications":
                self._authorize()
                return self._json(200, self.server.manager.notifications())
            if path == "/api/environment":
                self._authorize()
                check = getattr(self.server.manager.bridge, "check_environment", None)
                if not callable(check):
                    raise AppError("环境检查暂不可用", 409)
                return self._json(200, check())
            if path.startswith("/api/"):
                self._authorize()
                if path == "/api/state":
                    return self._json(200, self.server.manager.state())
                raise AppError("未找到此接口", 404)
            filename = {"/": "index.html", "/index.html": "index.html", "/app.js": "app.js", "/style.css": "style.css"}.get(path)
            if not filename:
                raise AppError("未找到此页面", 404)
            target = self.server.web_root / filename
            body = target.read_bytes()
            mime = mimetypes.guess_type(filename)[0] or "application/octet-stream"
            self._headers(200, mime + "; charset=utf-8", len(body))
            self.wfile.write(body)
        except AppError as exc:
            self._error_json(exc.status, error_payload(exc))
        except (OSError, ValueError):
            self._error_json(500, {"error": "无法读取页面"})

    def _write(self, method):
        self._request_body_consumed = False
        try:
            self._boundary()
            self._authorize()
            parsed = urlsplit(self.path)
            if parsed.query or len(parsed.path) > 160:
                raise AppError("请求无效")
            path = parsed.path
            body = self._body()
            if method == "POST" and path == "/api/session":
                return self._json(200, {"ok": True}, cookie=True)
            if method == "POST" and path == "/api/shutdown":
                if not self.server.manager.can_shutdown():
                    raise AppError("请先断开 VPN，再退出后台", 409)
                self._json(200, {"ok": True})
                threading.Thread(target=self.server.shutdown, daemon=True).start()
                return
            if method == "POST" and path == "/api/profiles":
                return self._json(201, self.server.manager.add(body))
            if method == "POST" and path == "/api/settings":
                return self._json(200, self.server.manager.settings(body))
            if method == "POST" and path == "/api/auto-connect":
                return self._json(200, self.server.manager.set_automatic(body))
            match = re.fullmatch(r"/api/profiles/([a-zA-Z0-9_-]{1,48})(?:/(connect|expand-connect|otp|disconnect|credential))?", path)
            if not match:
                raise AppError("未找到此接口", 404)
            profile_id, action = match.groups()
            manager = self.server.manager
            if method == "POST" and action == "connect":
                return self._json(200, manager.connect(profile_id, body))
            if method == "POST" and action == "expand-connect":
                return self._json(200, manager.expand_connect(profile_id, body))
            if method == "POST" and action == "otp":
                return self._json(200, manager.otp(profile_id, body))
            if method == "POST" and action == "disconnect":
                return self._json(200, manager.disconnect(profile_id))
            if method == "PATCH" and not action:
                return self._json(200, manager.edit(profile_id, body))
            if method == "DELETE" and not action:
                return self._json(200, manager.remove(profile_id))
            if method == "DELETE" and action == "credential":
                return self._json(200, manager.forget_credential(profile_id))
            raise AppError("请求方法无效", 405)
        except AppError as exc:
            self._error_json(exc.status, error_payload(exc))
        except Exception:
            # Never render native exception messages or submitted credentials.
            self._error_json(500, {"error": "操作失败，连接状态已保留"})

    def do_POST(self):
        self._write("POST")

    def do_PATCH(self):
        self._write("PATCH")

    def do_DELETE(self):
        self._write("DELETE")

    def do_OPTIONS(self):
        self._request_body_consumed = False
        self._error_json(403, {"error": "不接受跨站请求"})


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--runtime-dir", type=Path, default=Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "UniVPNManager")
    parser.add_argument("--port", type=int, default=0)
    args = parser.parse_args(argv)
    runtime = args.runtime_dir.resolve()
    protect_runtime(runtime)
    bridge = None
    try:
        from native import NativeBridge
        bridge = NativeBridge(runtime)
    except ImportError:
        pass
    manager = Manager(runtime, bridge=bridge)
    server = LocalServer(runtime, manager, args.port)
    runtime_file = runtime / "runtime.json"
    token_file = runtime / "session.token"
    runtime_file.write_text(json.dumps({"pid": os.getpid(), "port": server.server_port, "app": APP_ID}), "utf-8")
    token_file.write_text(server.token, "utf-8")
    if os.name != "nt":
        token_file.chmod(0o600)
    try:
        server.serve_forever(poll_interval=0.25)
    finally:
        manager.close()
        server.server_close()
        try:
            if json.loads(runtime_file.read_text("utf-8")).get("pid") == os.getpid():
                runtime_file.unlink(missing_ok=True)
                token_file.unlink(missing_ok=True)
        except (OSError, ValueError):
            pass


if __name__ == "__main__":
    main()
