"""A single Windows notification icon, using only ctypes and the standard library."""
from __future__ import annotations

import ctypes
from ctypes import wintypes
import os
import threading
import time


LRESULT = ctypes.c_ssize_t
WNDPROC = ctypes.WINFUNCTYPE(LRESULT, wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM)


class GUID(ctypes.Structure):
    _fields_ = [("Data1", wintypes.DWORD), ("Data2", wintypes.WORD), ("Data3", wintypes.WORD), ("Data4", ctypes.c_ubyte * 8)]


class NOTIFYICONDATAW(ctypes.Structure):
    _fields_ = [
        ("cbSize", wintypes.DWORD), ("hWnd", wintypes.HWND), ("uID", wintypes.UINT),
        ("uFlags", wintypes.UINT), ("uCallbackMessage", wintypes.UINT), ("hIcon", wintypes.HICON),
        ("szTip", wintypes.WCHAR * 128), ("dwState", wintypes.DWORD), ("dwStateMask", wintypes.DWORD),
        ("szInfo", wintypes.WCHAR * 256), ("uTimeout", wintypes.UINT), ("szInfoTitle", wintypes.WCHAR * 64),
        ("dwInfoFlags", wintypes.DWORD), ("guidItem", GUID), ("hBalloonIcon", wintypes.HICON),
    ]


class WNDCLASSW(ctypes.Structure):
    _fields_ = [
        ("style", wintypes.UINT), ("lpfnWndProc", WNDPROC), ("cbClsExtra", ctypes.c_int),
        ("cbWndExtra", ctypes.c_int), ("hInstance", wintypes.HINSTANCE), ("hIcon", wintypes.HICON),
        ("hCursor", wintypes.HANDLE), ("hbrBackground", wintypes.HBRUSH),
        ("lpszMenuName", wintypes.LPCWSTR), ("lpszClassName", wintypes.LPCWSTR),
    ]


class TrayIcon:
    CALLBACK = 0x8001

    def __init__(self, *, on_open, on_exit, tooltip="UniVPN Manager"):
        if os.name != "nt":
            raise OSError("Windows notification area is unavailable")
        self.on_open, self.on_exit, self.tooltip = on_open, on_exit, tooltip
        self.closed = threading.Event()
        self._close_requested = threading.Event()
        self._last_open = 0.0
        self.hwnd = None
        self.user32 = ctypes.WinDLL("user32", use_last_error=True)
        self.shell32 = ctypes.WinDLL("shell32", use_last_error=True)
        self.kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self._configure_types()
        self.callback = WNDPROC(self._window_proc)  # Keep callback alive for the message loop.
        self.class_name = "UniVPNManagerTray." + str(os.getpid())
        self.taskbar_created = self.user32.RegisterWindowMessageW("TaskbarCreated")
        self.data = NOTIFYICONDATAW()
        self.data.cbSize = ctypes.sizeof(self.data)
        self.data.uID = 1
        self.data.uFlags = 1 | 2 | 4  # MESSAGE, ICON, TIP.
        self.data.uCallbackMessage = self.CALLBACK
        self.data.szTip = tooltip[:127]

    def _configure_types(self):
        u, s, k = self.user32, self.shell32, self.kernel32
        k.GetModuleHandleW.argtypes = [wintypes.LPCWSTR]
        k.GetModuleHandleW.restype = wintypes.HMODULE
        u.RegisterClassW.argtypes = [ctypes.POINTER(WNDCLASSW)]
        u.RegisterClassW.restype = wintypes.ATOM
        u.UnregisterClassW.argtypes = [wintypes.LPCWSTR, wintypes.HINSTANCE]
        u.RegisterWindowMessageW.argtypes = [wintypes.LPCWSTR]
        u.RegisterWindowMessageW.restype = wintypes.UINT
        u.CreateWindowExW.argtypes = [wintypes.DWORD, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD,
                                    ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int,
                                    wintypes.HWND, wintypes.HMENU, wintypes.HINSTANCE, ctypes.c_void_p]
        u.CreateWindowExW.restype = wintypes.HWND
        u.DefWindowProcW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
        u.DefWindowProcW.restype = LRESULT
        u.LoadIconW.argtypes = [wintypes.HINSTANCE, ctypes.c_void_p]
        u.LoadIconW.restype = wintypes.HICON
        u.CreatePopupMenu.restype = wintypes.HMENU
        u.AppendMenuW.argtypes = [wintypes.HMENU, wintypes.UINT, ctypes.c_size_t, wintypes.LPCWSTR]
        u.TrackPopupMenu.argtypes = [wintypes.HMENU, wintypes.UINT, ctypes.c_int, ctypes.c_int,
                                    ctypes.c_int, wintypes.HWND, ctypes.c_void_p]
        u.TrackPopupMenu.restype = wintypes.UINT
        u.DestroyMenu.argtypes = [wintypes.HMENU]
        u.GetCursorPos.argtypes = [ctypes.POINTER(wintypes.POINT)]
        u.SetForegroundWindow.argtypes = [wintypes.HWND]
        u.PostMessageW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
        u.DestroyWindow.argtypes = [wintypes.HWND]
        u.GetMessageW.argtypes = [ctypes.POINTER(wintypes.MSG), wintypes.HWND, wintypes.UINT, wintypes.UINT]
        u.GetMessageW.restype = wintypes.BOOL
        u.TranslateMessage.argtypes = [ctypes.POINTER(wintypes.MSG)]
        u.DispatchMessageW.argtypes = [ctypes.POINTER(wintypes.MSG)]
        u.DispatchMessageW.restype = LRESULT
        s.Shell_NotifyIconW.argtypes = [wintypes.DWORD, ctypes.POINTER(NOTIFYICONDATAW)]
        s.Shell_NotifyIconW.restype = wintypes.BOOL

    def _invoke(self, action):
        threading.Thread(target=action, daemon=True, name="tray-action").start()

    def _menu(self):
        menu = self.user32.CreatePopupMenu()
        if not menu:
            return
        try:
            self.user32.AppendMenuW(menu, 0, 1, "打开")
            self.user32.AppendMenuW(menu, 0, 2, "退出")
            point = wintypes.POINT()
            self.user32.GetCursorPos(ctypes.byref(point))
            self.user32.SetForegroundWindow(self.hwnd)
            selected = self.user32.TrackPopupMenu(menu, 0x0100 | 0x0002, point.x, point.y, 0, self.hwnd, None)
            self.user32.PostMessageW(self.hwnd, 0, 0, 0)
            if selected == 1:
                self._invoke(self.on_open)
            elif selected == 2:
                self._invoke(self.on_exit)
        finally:
            self.user32.DestroyMenu(menu)

    def _window_proc(self, hwnd, message, wparam, lparam):
        if message == self.CALLBACK:
            if lparam in (0x202, 0x203):  # Ignore the duplicate event from a double click.
                now = time.monotonic()
                if now - self._last_open > 0.5:
                    self._last_open = now
                    self._invoke(self.on_open)
            elif lparam in (0x205, 0x007B):
                self._menu()
            return 0
        if message == self.taskbar_created:
            self.shell32.Shell_NotifyIconW(0, ctypes.byref(self.data))
            return 0
        if message == 0x0010:  # WM_CLOSE, posted only after safe shutdown or backend exit.
            self.user32.DestroyWindow(hwnd)
            return 0
        if message == 0x0002:
            self.shell32.Shell_NotifyIconW(2, ctypes.byref(self.data))
            self.closed.set()
            self.user32.PostQuitMessage(0)
            return 0
        return self.user32.DefWindowProcW(hwnd, message, wparam, lparam)

    def notify(self, message: str):
        if self.hwnd and not self.closed.is_set():
            data = NOTIFYICONDATAW()
            data.cbSize = ctypes.sizeof(data)
            data.hWnd, data.uID, data.uFlags = self.hwnd, 1, 0x10
            data.szInfo, data.szInfoTitle = message[:255], self.tooltip[:63]
            data.dwInfoFlags = 1
            self.shell32.Shell_NotifyIconW(1, ctypes.byref(data))

    def close(self):
        self._close_requested.set()
        if self.hwnd:
            self.user32.PostMessageW(self.hwnd, 0x0010, 0, 0)

    def run(self):
        instance = self.kernel32.GetModuleHandleW(None)
        self.data.hIcon = self.user32.LoadIconW(instance, ctypes.c_void_p(1)) or self.user32.LoadIconW(None, ctypes.c_void_p(32512))
        window_class = WNDCLASSW()
        window_class.lpfnWndProc, window_class.hInstance = self.callback, instance
        window_class.lpszClassName, window_class.hIcon = self.class_name, self.data.hIcon
        if not self.user32.RegisterClassW(ctypes.byref(window_class)):
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            self.hwnd = self.user32.CreateWindowExW(0, self.class_name, self.tooltip, 0, 0, 0, 0, 0, None, None, instance, None)
            if not self.hwnd:
                raise ctypes.WinError(ctypes.get_last_error())
            self.data.hWnd = self.hwnd
            if not self.shell32.Shell_NotifyIconW(0, ctypes.byref(self.data)):
                self.user32.DestroyWindow(self.hwnd)
                raise OSError("Cannot add notification icon")
            if self._close_requested.is_set():
                self.close()
            message = wintypes.MSG()
            while True:
                result = self.user32.GetMessageW(ctypes.byref(message), None, 0, 0)
                if result == 0:
                    break
                if result == -1:
                    raise ctypes.WinError(ctypes.get_last_error())
                self.user32.TranslateMessage(ctypes.byref(message))
                self.user32.DispatchMessageW(ctypes.byref(message))
        finally:
            self.shell32.Shell_NotifyIconW(2, ctypes.byref(self.data))
            self.closed.set()
            self.user32.UnregisterClassW(self.class_name, instance)
