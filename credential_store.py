"""Explicitly remembered VPN credentials in the current user's Windows vault.

No enumeration, vendor AppData migration, configuration files, or plaintext
fallback exists. Core must call save only after the user's explicit choice.
Win32 contract: CREDENTIALW and CredWriteW/CredReadW/CredDeleteW/CredFree.
https://learn.microsoft.com/windows/win32/api/wincred/ns-wincred-credentialw
"""
from __future__ import annotations

import ctypes
from ctypes import wintypes
from dataclasses import dataclass
import os
import re
import threading


NAMESPACE = "UniVPNManager/v1/profile"
CRED_TYPE_GENERIC = 1
CRED_PERSIST_LOCAL_MACHINE = 2  # Same Windows user on this computer, across logons.
ERROR_NOT_FOUND = 1168
MAX_BLOB_BYTES = 2560


class CredentialStoreError(RuntimeError):
    def __init__(self, message: str, *, winerror: int | None = None):
        super().__init__(message)
        self.winerror = winerror


@dataclass(frozen=True, slots=True, repr=False)
class Credentials:
    username: str
    password: str

    def __repr__(self):
        return "Credentials(username=<hidden>, password=<hidden>)"

    __str__ = __repr__


class _CREDENTIAL_ATTRIBUTEW(ctypes.Structure):
    _fields_ = [("Keyword", wintypes.LPWSTR), ("Flags", wintypes.DWORD),
                ("ValueSize", wintypes.DWORD), ("Value", ctypes.POINTER(wintypes.BYTE))]


class _CREDENTIALW(ctypes.Structure):
    _fields_ = [
        ("Flags", wintypes.DWORD), ("Type", wintypes.DWORD), ("TargetName", wintypes.LPWSTR),
        ("Comment", wintypes.LPWSTR), ("LastWritten", wintypes.FILETIME),
        ("CredentialBlobSize", wintypes.DWORD), ("CredentialBlob", ctypes.POINTER(wintypes.BYTE)),
        ("Persist", wintypes.DWORD), ("AttributeCount", wintypes.DWORD),
        ("Attributes", ctypes.POINTER(_CREDENTIAL_ATTRIBUTEW)), ("TargetAlias", wintypes.LPWSTR),
        ("UserName", wintypes.LPWSTR),
    ]


def _target(namespace: str, profile_id: str) -> str:
    if not isinstance(profile_id, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,48}", profile_id):
        raise CredentialStoreError("连接标识无效")
    # Credential Manager target names ignore case. ASCII hex keeps distinct
    # profile IDs distinct, even if a caller supplies IDs differing only in case.
    return namespace + "/" + profile_id.encode("ascii").hex()


def _namespace(value: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,127}", value):
        raise CredentialStoreError("凭据命名空间无效")
    return value.rstrip("/")


def _blob(username: str, password: str) -> bytearray:
    if not isinstance(username, str) or not isinstance(password, str) or not username or not password:
        raise CredentialStoreError("请输入账号和密码")
    if "\x00" in username or "\x00" in password:
        raise CredentialStoreError("账号或密码格式无效")
    try:
        if len(username.encode("utf-16-le")) // 2 > 513:
            raise CredentialStoreError("账号过长，无法记住")
        blob = bytearray(password, "utf-16-le")
    except UnicodeError:
        raise CredentialStoreError("账号或密码编码无效") from None
    if len(blob) > MAX_BLOB_BYTES:
        blob[:] = b"\0" * len(blob)
        raise CredentialStoreError("密码过长，无法记住")
    return blob


class CredentialStore:
    """Current-token GenericCredential API. No writes occur during construction."""
    def __init__(self, *, namespace: str = NAMESPACE):
        self.namespace = _namespace(namespace)
        self._lock = threading.RLock()
        if os.name != "nt":
            raise CredentialStoreError("保存账号密码需要 Windows 凭据管理器")
        self._api = ctypes.WinDLL("advapi32", use_last_error=True)
        self._api.CredWriteW.argtypes = [ctypes.POINTER(_CREDENTIALW), wintypes.DWORD]
        self._api.CredWriteW.restype = wintypes.BOOL
        self._api.CredReadW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                       ctypes.POINTER(ctypes.POINTER(_CREDENTIALW))]
        self._api.CredReadW.restype = wintypes.BOOL
        self._api.CredDeleteW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD]
        self._api.CredDeleteW.restype = wintypes.BOOL
        self._api.CredFree.argtypes = [ctypes.c_void_p]
        self._api.CredFree.restype = None

    def _error(self, action: str):
        code = ctypes.get_last_error()
        raise CredentialStoreError(action, winerror=code)

    def save(self, profile_id: str, username: str, password: str) -> None:
        target = _target(self.namespace, profile_id)
        blob = _blob(username, password)
        buffer = (wintypes.BYTE * len(blob)).from_buffer(blob)
        user_buffer = ctypes.create_unicode_buffer(username)
        credential = _CREDENTIALW()
        credential.Type = CRED_TYPE_GENERIC
        credential.TargetName = target
        credential.UserName = ctypes.cast(user_buffer, wintypes.LPWSTR)
        credential.CredentialBlobSize = len(blob)
        credential.CredentialBlob = ctypes.cast(buffer, ctypes.POINTER(wintypes.BYTE))
        credential.Persist = CRED_PERSIST_LOCAL_MACHINE
        try:
            with self._lock:
                if not self._api.CredWriteW(ctypes.byref(credential), 0):
                    self._error("无法保存 Windows 凭据，已有凭据未被转存")
        finally:
            ctypes.memset(ctypes.addressof(buffer), 0, len(blob))
            ctypes.memset(ctypes.addressof(user_buffer), 0, ctypes.sizeof(user_buffer))

    def read(self, profile_id: str) -> Credentials | None:
        target = _target(self.namespace, profile_id)
        with self._lock:
            pointer = ctypes.POINTER(_CREDENTIALW)()
            if not self._api.CredReadW(target, CRED_TYPE_GENERIC, 0, ctypes.byref(pointer)):
                if ctypes.get_last_error() == ERROR_NOT_FOUND:
                    return None
                self._error("无法读取此连接保存的 Windows 凭据")
            wipe_size = 0
            try:
                credential = pointer.contents
                size = credential.CredentialBlobSize
                if credential.Type != CRED_TYPE_GENERIC or not 0 < size <= MAX_BLOB_BYTES or size % 2:
                    raise CredentialStoreError("此连接保存的凭据格式无效，请重新保存")
                if not credential.CredentialBlob:
                    raise CredentialStoreError("此连接保存的凭据格式无效，请重新保存")
                wipe_size = size
                try:
                    password = ctypes.string_at(credential.CredentialBlob, size).decode("utf-16-le")
                    username = credential.UserName or ""
                    validation = _blob(username, password)
                    validation[:] = b"\0" * len(validation)
                except UnicodeError:
                    raise CredentialStoreError("此连接保存的凭据编码无效，请重新保存") from None
                return Credentials(username, password)
            finally:
                if wipe_size:
                    ctypes.memset(pointer.contents.CredentialBlob, 0, wipe_size)
                self._api.CredFree(pointer)

    def delete(self, profile_id: str) -> None:
        target = _target(self.namespace, profile_id)
        with self._lock:
            if not self._api.CredDeleteW(target, CRED_TYPE_GENERIC, 0):
                if ctypes.get_last_error() != ERROR_NOT_FOUND:
                    self._error("无法删除此连接保存的 Windows 凭据")


class MemoryStore:
    """Explicit test double only. Production must never fall back to this store."""
    def __init__(self, *, namespace: str = "UniVPNManager-test"):
        self.namespace = _namespace(namespace)
        self._items: dict[str, Credentials] = {}
        self._lock = threading.RLock()

    def save(self, profile_id: str, username: str, password: str) -> None:
        target = _target(self.namespace, profile_id)
        validation = _blob(username, password)
        validation[:] = b"\0" * len(validation)
        with self._lock:
            self._items[target] = Credentials(username, password)

    def read(self, profile_id: str) -> Credentials | None:
        target = _target(self.namespace, profile_id)
        with self._lock:
            return self._items.get(target)

    def delete(self, profile_id: str) -> None:
        target = _target(self.namespace, profile_id)
        with self._lock:
            self._items.pop(target, None)
