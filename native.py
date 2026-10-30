"""Strictly scoped lifecycle for the pinned upstream multi implementation."""
from __future__ import annotations

import ctypes
from ctypes import wintypes
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import threading
import time

from core import AppError, ROOT, hidden_kwargs, powershell_path
from native_preflight import check_client, observe_inventory
from windows_session import WindowsSession, SessionError
from vendor_state import snapshot_config


def _product(index: int) -> str:
    if type(index) is not int or not 1 <= index <= 999:
        raise AppError("原生连接编号无效")
    return "UniVPN" if index == 1 else f"UVP{index:03d}"


def _windows_identity():
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi.GetUserNameW.argtypes = [wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
    kernel.GetCurrentProcessId.restype = wintypes.DWORD
    kernel.ProcessIdToSessionId.argtypes = [wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    name = ctypes.create_unicode_buffer(256)
    size = wintypes.DWORD(len(name))
    session = wintypes.DWORD()
    if not advapi.GetUserNameW(name, ctypes.byref(size)) or not kernel.ProcessIdToSessionId(kernel.GetCurrentProcessId(), ctypes.byref(session)):
        raise AppError("无法确认当前 Windows 会话", 409)
    return name.value.encode("mbcs"), session.value


def _start_service(name: str):
    """Use only pre-granted start/query rights; never alter service configuration."""
    adv = ctypes.WinDLL("advapi32", use_last_error=True)
    adv.OpenSCManagerW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD]
    adv.OpenSCManagerW.restype = wintypes.HANDLE
    adv.OpenServiceW.argtypes = [wintypes.HANDLE, wintypes.LPCWSTR, wintypes.DWORD]
    adv.OpenServiceW.restype = wintypes.HANDLE
    adv.StartServiceW.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.c_void_p]
    adv.CloseServiceHandle.argtypes = [wintypes.HANDLE]
    scm, service = None, None
    try:
        scm = adv.OpenSCManagerW(None, None, 1)
        if not scm:
            raise OSError(ctypes.get_last_error(), "Service access unavailable")
        service = adv.OpenServiceW(scm, name, 0x14)
        if not service:
            raise OSError(ctypes.get_last_error(), "Service access unavailable")
        if not adv.StartServiceW(service, 0, None):
            error = ctypes.get_last_error()
            if error != 1056:  # already running
                raise OSError(error, "Service start unavailable")
    finally:
        if service:
            adv.CloseServiceHandle(service)
        if scm:
            adv.CloseServiceHandle(scm)


class NativeBridge:
    def __init__(self, runtime_dir: Path):
        self.runtime_dir = runtime_dir
        self.preflight = check_client()
        self.available = bool(self.preflight["ready"])
        self.source = Path(self.preflight["source_directory"]) if self.available else None
        self._lock = threading.RLock()
        self._prepared: dict[str, dict] = {}
        self._diagnostics = []
        self._backed_up: set[int] = set()
        self._action_diagnostics = []
        self._anchors = {}
        self._anchor_history = {}

    def _record_action(self, mode, index, phase, code=None):
        if mode not in {"Disconnect", "EnsureService", "CreateInstance", "QuiesceOwned", "Probe"}:
            return
        with self._lock:
            self._action_diagnostics.append({"time": time.time(), "mode": mode, "index": index,
                                             "phase": phase, "exitCode": code})
            self._action_diagnostics = self._action_diagnostics[-64:]
            target = self.runtime_dir / "native-actions.json"
            pending = target.with_suffix(".tmp")
            try:
                pending.write_text(json.dumps(self._action_diagnostics), "utf-8")
                os.replace(pending, target)
            except OSError:
                pass

    def check_environment(self):
        # This helper mode exits before UAC and before creating a result file,
        # touching a service/process/TAP, or reading any vendor user profile.
        if not self.available or self.source is None:
            return {"ok": False, "phase": "client_build", "error": "需要准备受支持的 UniVPN 客户端"}
        args = [powershell_path(), "-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
                str(ROOT / "tools/native-action.ps1"), "-Mode", "Probe", "-Index", "1",
                "-SourceDirectory", str(self.source), "-Nonce", secrets.token_hex(16)]
        try:
            completed = subprocess.run(args, capture_output=True, timeout=30, **hidden_kwargs())
            if len(completed.stdout) > 8192:
                raise ValueError()
            value = json.loads(completed.stdout.decode("utf-8-sig"))
            if not isinstance(value, dict) or value.get("phase") not in {"platform", "identity", "source_preflight", "complete"}:
                raise ValueError()
            result = {"ok": value.get("ok") is True and completed.returncode == 0,
                      "phase": value["phase"], "exitCode": completed.returncode}
            if type(value.get("errorCode")) is int:
                result["errorCode"] = value["errorCode"]
            language = value.get("languageMode")
            if language in {"FullLanguage", "ConstrainedLanguage", "RestrictedLanguage", "NoLanguage"}:
                result["languageMode"] = language
            self._record_action("Probe", 1, result["phase"], completed.returncode)
            return result
        except (OSError, ValueError, subprocess.TimeoutExpired):
            code = completed.returncode if "completed" in locals() else None
            self._record_action("Probe", 1, "helper_response", code)
            return {"ok": False, "phase": "helper_response", "exitCode": code,
                    "error": "后台组件检查未完成，请重新安装完整包"}

    def _inventory(self):
        result = observe_inventory()
        if not isinstance(result, dict) or not result.get("installed"):
            raise AppError("无法确认原生客户端状态", 409)
        return result

    def _paths(self, index):
        product = _product(index)
        if not self.available or self.source is None:
            raise AppError("未找到受支持的 UniVPN 构建", 409)
        if index == 1:
            return product, self.source, self.source
        record_path = self.source / ".univpn-multi" / f"instance-{index:03d}.json"
        try:
            record = json.loads(record_path.read_text("utf-8-sig"))
            real = self.source.parent / f"UniVPN{index}"
            alias = self.source / ".univpn-multi" / product
            if record["Number"] != index or record["Product"] != product or record["Status"] != "Ready":
                raise ValueError()
            if Path(record["Directory"]) != real or Path(record["Alias"]) != alias or alias.resolve() != real.resolve():
                raise ValueError()
            expected = [f"{product}.exe", f"promote\\{product}PromoteService.exe", f"serviceclient\\{product}CS.exe"]
            files = record["Files"]
            if len(files) != 3:
                raise ValueError()
            for target in expected:
                row = [f for f in files if f["Target"] == target]
                if len(row) != 1 or hashlib.sha256((real / target).read_bytes()).hexdigest() != row[0]["Hash"].lower():
                    raise ValueError()
            return product, real, alias
        except (OSError, ValueError, KeyError, TypeError):
            raise AppError("原生连接的文件校验未通过", 409) from None

    def _action(self, mode, index, *, expected_pid=None, expected_created_us=None):
        _product(index)
        if mode not in {"Disconnect", "EnsureService", "CreateInstance", "QuiesceOwned"}:
            raise AppError("不支持此原生操作", 409)
        if mode == "QuiesceOwned" and (type(expected_pid) is not int or not 1 <= expected_pid <= 0xffffffff
                or type(expected_created_us) is not int or not 0 < expected_created_us < 2**63):
            raise AppError("原生后台归属无法确认，已停止操作", 409)
        if not self.available or self.source is None:
            raise AppError("未找到受支持的 UniVPN 构建", 409)
        nonce = secrets.token_hex(16)
        args = [powershell_path(), "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(ROOT / "tools/native-action.ps1"), "-Mode", mode, "-Index", str(index), "-SourceDirectory", str(self.source), "-Nonce", nonce]
        if mode == "QuiesceOwned":
            args += ["-ExpectedPid", str(expected_pid), "-ExpectedCreatedUs", str(expected_created_us)]
        try:
            # RunAs creates a separate elevated child. Killing its waiting
            # parent on a timeout would leave installation running while core
            # restores tunnels. Keep expansion leased until the action exits;
            # the browser may time out independently without retrying it.
            wait_timeout = None if mode in {"CreateInstance", "QuiesceOwned"} else 120
            completed = subprocess.run(args, capture_output=True, timeout=wait_timeout, **hidden_kwargs())
            self._record_action(mode, index, "helper_exit", completed.returncode)
            result_path = self.source / ".univpn-multi/manager-results" / f"{nonce}.json"
            if result_path.stat().st_size > 8192:
                raise ValueError()
            result = json.loads(result_path.read_text("utf-8-sig"))
            if not isinstance(result, dict):
                raise ValueError()
            actual = result.get("index")
            if completed.returncode or result.get("ok") is not True or type(actual) is not int:
                raise ValueError()
            if mode == "CreateInstance" and not 2 <= actual <= 999:
                raise ValueError()
            if mode != "CreateInstance" and actual != index:
                raise ValueError()
        except (OSError, ValueError, subprocess.TimeoutExpired):
            self._record_action(mode, index, "action_unconfirmed", completed.returncode if "completed" in locals() else None)
            raise AppError("原生操作未完成，请确认系统授权后重试", 409) from None
        return result

    def _verified_service(self, index, inventory):
        product, _, alias = self._paths(index)
        expected = '"' + str(alias / "promote" / f"{product}PromoteService.exe") + '"'
        services = [s for s in inventory.get("services", []) if s.get("name") == product + "Service"]
        if len(services) != 1:
            return None
        service = services[0]
        if service.get("path", "").casefold() != expected.casefold() or service.get("account") != "LocalSystem":
            raise AppError("原生服务归属异常，已停止操作", 409)
        port = 29190 + index - 1
        listeners = [p for p in inventory.get("listeners", []) if p.get("port") == port]
        if service.get("state") != "Running":
            return None
        if len(listeners) != 1 or listeners[0].get("address") != "127.0.0.1" or listeners[0].get("pid") != service.get("pid"):
            raise AppError("原生服务监听校验未通过", 409)
        return service

    @staticmethod
    def _target_adapters(index, inventory):
        records = inventory.get("records", [])
        if index == 1:
            managed = {str(r.get("tapGuid", "")).upper() for r in records}
            return [a for a in inventory.get("adapters", []) if str(a.get("guid", "")).upper() not in managed]
        record = next((r for r in records if r.get("index") == index), {})
        return [a for a in inventory.get("adapters", []) if str(a.get("guid", "")).upper() == str(record.get("tapGuid", "")).upper()]

    def is_owned_anchor(self, row):
        if not isinstance(row, dict):
            return False
        with self._lock:
            marker = self._anchor_history.get(row.get("pid"))
            live = any(anchor.pid == row.get("pid") for anchor in self._anchors.values())
        if not marker or not live and time.time() - marker["recorded"] > 30:
            return False
        try:
            created = datetime.fromisoformat(row["created"]).timestamp()
            return row.get("name") == marker["name"] and row.get("session") == marker["session"] and abs(created - marker["created"]) < .001
        except (KeyError, TypeError, ValueError):
            return False

    def release_anchor(self, profile_id):
        with self._lock:
            anchor = self._anchors.get(profile_id)
            if anchor is not None:
                # close uses only the original process handle, never PID lookup.
                anchor.close()
                if anchor.pid in self._anchor_history:
                    self._anchor_history[anchor.pid]["recorded"] = time.time()
                self._anchors.pop(profile_id, None)

    def _assert_idle_target(self, profile, inventory, service, caller_session):
        product = _product(profile["index"])
        processes = inventory.get("processes", [])
        if any(p.get("name") == product and not self.is_owned_anchor(p) for p in processes):
            raise AppError("请先在原客户端断开并退出，再从网页连接", 409)
        if any(p.get("process") == product + "CS" for p in inventory.get("peers", [])) or any(
                a.get("up") and a.get("addresses") for a in self._target_adapters(profile["index"], inventory)):
            raise AppError("此网关的原连接仍在线，请先断开后再连接", 409)
        backends = [p for p in processes if p.get("name") == product + "CS"]
        if len(backends) > 1:
            raise AppError("原生后台数量异常，已停止连接", 409)
        for backend in backends:
            session = backend.get("session")
            valid_session = type(session) is int and (session == caller_session or session == 0 and type(service.get("session")) is int and service["session"] == 0)
            if backend.get("parent") != service["pid"] or not valid_session:
                raise AppError("原生后台归属无法确认，已停止连接", 409)
        # The original helper bootstrap already replaces the idle same-product
        # CS. Do not separately terminate it or weaken the new-child check.

    def prepare(self, profile):
        """Authorize exactly one target, after the user requests its connection."""
        index = profile["index"]
        product, real, alias = self._paths(index)
        user, caller_session = _windows_identity()
        inventory = self._inventory()
        with self._lock:
            if index not in self._backed_up:
                try:
                    snapshot_config(self.runtime_dir, index)
                except Exception:
                    raise AppError("原配置备份未完成，现有连接已保留", 409) from None
                self._backed_up.add(index)
        service = self._verified_service(index, inventory)
        if not service:
            try:
                _start_service(product + "Service")
            except OSError as exc:
                if getattr(exc, "winerror", None) not in {5, 1060} and getattr(exc, "errno", None) not in {5, 1060}:
                    raise AppError("原生服务无法启动，请检查客户端状态", 409) from None
                self._action("EnsureService", index)
            deadline = time.monotonic() + 12
            while time.monotonic() < deadline:
                inventory = self._inventory()
                service = self._verified_service(index, inventory)
                if service:
                    break
                time.sleep(0.3)
        if not service:
            raise AppError("原生服务未启动", 409)
        inventory = self._inventory()
        service = self._verified_service(index, inventory)
        if not service:
            raise AppError("原生服务状态发生变化，请重试", 409)
        self._assert_idle_target(profile, inventory, service, caller_session)
        from session_anchor import UserSessionAnchor
        with self._lock:
            self.release_anchor(profile["id"])
            anchor = UserSessionAnchor(real / (product + ".exe"))
            if anchor.session != caller_session:
                anchor.close()
                raise AppError("原生用户环境不匹配", 409)
            self._anchors[profile["id"]] = anchor
            self._anchor_history[anchor.pid] = {"name": product, "session": anchor.session,
                                                 "created": anchor.created_timestamp, "recorded": time.time()}
            live_pids = {item.pid for item in self._anchors.values()}
            self._anchor_history = {pid: value for pid, value in self._anchor_history.items() if pid in live_pids or time.time() - value["recorded"] <= 30}
            self._prepared[profile["id"]] = {"service_pid": service["pid"], "session": caller_session, "prepared_at": time.time(), "backend_pid": None, "anchor_pid": anchor.pid}
        return {"service_port": 29190 + index - 1, "install_directory": str(alias) + "\\", "login_user_ansi": user}

    def validate_backend(self, profile, actual_port):
        """Prove the backend is a new child of the already verified helper."""
        # Mirror the original client's lifetime: keep the never-resumed token
        # source until this owned session is cleaned up, including failures.
        return self._validate_backend(profile, actual_port)

    def _validate_backend(self, profile, actual_port):
        if type(actual_port) is not int or not 1 <= actual_port <= 65535:
            return False
        with self._lock:
            prepared = dict(self._prepared.get(profile["id"], {}))
        if not prepared:
            return False
        product = _product(profile["index"])
        deadline = time.monotonic() + 12
        while time.monotonic() < deadline:
            inventory = self._inventory()
            if any(row.get("name") == product and not self.is_owned_anchor(row) for row in inventory.get("processes", [])):
                return False
            if "anchor_pid" in prepared:
                matching_anchors = [row for row in inventory.get("processes", []) if row.get("name") == product
                                    and row.get("pid") == prepared["anchor_pid"] and self.is_owned_anchor(row)]
                if len(matching_anchors) != 1:
                    return False
            service = self._verified_service(profile["index"], inventory)
            if not service or service["pid"] != prepared["service_pid"]:
                return False
            listeners = [row for row in inventory.get("listeners", []) if row.get("port") == actual_port]
            if len(listeners) == 1 and listeners[0].get("address") == "127.0.0.1":
                backend = [row for row in inventory.get("processes", []) if row.get("pid") == listeners[0].get("pid") and row.get("name") == product + "CS"]
                if len(backend) == 1:
                    row = backend[0]
                    created = datetime.fromisoformat(row["created"]).timestamp()
                    if row.get("parent") != service["pid"] or row.get("session") != prepared["session"] or created < prepared["prepared_at"] - 2:
                        return False
                    with self._lock:
                        self._prepared[profile["id"]]["backend_pid"] = row["pid"]
                        self._prepared[profile["id"]]["backend_created"] = row["created"]
                    return True
            elif listeners:
                return False
            time.sleep(0.25)
        return False

    def wait_tunnel(self, profile, timeout=10):
        product = _product(profile["index"])
        gateway_ips = {item[4][0] for item in socket.getaddrinfo(profile["gateway"], profile["port"], socket.AF_INET, socket.SOCK_STREAM)}
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            inventory = self._inventory()
            records = inventory.get("records", [])
            if profile["index"] == 1:
                managed = {str(r.get("tapGuid", "")).upper() for r in records}
                adapters = [a for a in inventory.get("adapters", []) if str(a.get("guid", "")).upper() not in managed]
            else:
                record = next((r for r in records if r.get("index") == profile["index"]), {})
                adapters = [a for a in inventory.get("adapters", []) if str(a.get("guid", "")).upper() == str(record.get("tapGuid", "")).upper()]
            peer = any(p.get("process") == product + "CS" and p.get("gateway") in gateway_ips and p.get("port") == profile["port"] for p in inventory.get("peers", []))
            if len(adapters) == 1 and adapters[0].get("up") and adapters[0].get("addresses") and peer:
                return True
            time.sleep(0.4)
        return False

    def diagnostic(self, profile_id, phase, opcode, size):
        if not isinstance(profile_id, str) or not isinstance(phase, str) or not phase.replace("_", "").isalpha():
            return
        if type(opcode) is not int or type(size) is not int:
            return
        with self._lock:
            self._diagnostics.append({"time": time.time(), "id": profile_id, "phase": phase, "opcode": opcode, "size": size})
            self._diagnostics = self._diagnostics[-128:]
            target = self.runtime_dir / "native-events.json"
            tmp = target.with_suffix(".tmp")
            tmp.write_text(json.dumps(self._diagnostics), "utf-8")
            os.replace(tmp, target)

    def session(self, profile, on_event):
        self._paths(profile["index"])
        return WindowsSession(profile, on_event, self)

    def legacy_reference(self, profile, *, source=None):
        if not self.available:
            return None
        from vendor_config import legacy_reference
        if source is None:
            if not profile.get("index"):
                return None
            _product(profile["index"])
            return legacy_reference(profile)
        if not isinstance(source, dict):
            return None
        source_index = source.get("sourceIndex")
        if type(source_index) is not int or not 1 <= source_index <= 999:
            return None
        source_name = source.get("sourceName")
        if not isinstance(source_name, str) or not source_name:
            return None
        # An opaque password stored by source 1 cannot be read by a backend
        # patched as source 2. An unbound profile may advertise its reference,
        # but core must lease that exact source slot before start_saved.
        if profile.get("index") not in {0, source_index}:
            return None
        lookup = {**profile, "index": source_index}
        reference = legacy_reference(lookup, sourceName=source_name)
        if reference is not None:
            return reference
        # Display/file names and the vendor's private credential-cache name
        # are separate identifiers. A unique source file and unique saved
        # endpoint may safely retain an older cache alias; never guess among
        # multiple configurations or a renamed/stale source identity.
        source_id = source.get("sourceId")
        if not isinstance(source_id, str) or not source_id:
            return None
        try:
            from vendor_config import source_candidates
            candidates = [row for row in source_candidates([source_index])
                          if row["sourceIndex"] == source_index and row["gateway"].casefold() == profile["gateway"].casefold()
                          and row["port"] == profile["port"]]
            if len(candidates) != 1 or candidates[0]["sourceId"] != source_id:
                return None
            return legacy_reference(lookup)
        except (OSError, ValueError, KeyError, TypeError):
            return None

    def remembered_sources(self, inventory):
        if not self.available:
            return []
        from vendor_config import source_candidates
        indexes = [1] + [r["index"] for r in inventory.get("records", [])
                         if r.get("status") == "Ready" and type(r.get("index")) is int and 2 <= r["index"] <= 999]
        return source_candidates(sorted(set(indexes)))

    def remembered_profiles(self, inventory):
        if not self.available:
            return []
        from vendor_config import network_candidates
        indexes = [1] + [r["index"] for r in inventory.get("records", [])
                         if r.get("status") == "Ready" and type(r.get("index")) is int and 2 <= r["index"] <= 999]
        candidates = network_candidates(indexes)
        result = []
        for index in sorted(set(indexes)):
            backend = _product(index) + "CS"
            peers = {(p.get("gateway"), p.get("port")) for p in inventory.get("peers", []) if p.get("process") == backend}
            choices = {(c["gateway"], c["port"]): c for c in candidates if c["index"] == index}
            if len(peers) == 1:
                gateway, port = next(iter(peers))
                result.append(choices.get((gateway, port), {"gateway": gateway, "port": port, "name": "", "index": index}))
            elif len(choices) == 1:
                result.append(next(iter(choices.values())))
            # Multiple saved sites cannot share one live backend. Leave the
            # original files untouched instead of guessing an assignment.
        return result

    def disconnect_external(self, profile):
        self._paths(profile["index"])
        self._action("Disconnect", profile["index"])

    def owns_backend(self, profile, row):
        """Read-only ownership proof for preflight; never infer it from a name."""
        if not isinstance(row, dict):
            return False
        try:
            product = _product(profile["index"])
            with self._lock:
                prepared = dict(self._prepared.get(profile["id"], {}))
            if not prepared.get("backend_pid") or not prepared.get("backend_created"):
                return False
            return (row.get("name") == product + "CS" and row.get("pid") == prepared["backend_pid"]
                    and row.get("created") == prepared["backend_created"]
                    and row.get("parent") == prepared.get("service_pid")
                    and row.get("session") == prepared.get("session"))
        except (AppError, KeyError, TypeError):
            return False

    def quiesce_owned(self, profile):
        """Release only our already logged-out backend before confirmed expansion."""
        product = _product(profile["index"])
        self._paths(profile["index"])
        with self._lock:
            prepared = dict(self._prepared.get(profile["id"], {}))
            if profile["id"] in self._anchors:
                raise AppError("此 VPN 尚未完成断开", 409)
        inventory = self._inventory()
        if inventory.get("metadataUnknown") or any(a.get("up") for a in inventory.get("adapters", [])) or inventory.get("peers"):
            raise AppError("连接尚未全部断开，已保留原生后台", 409)
        if any(row.get("name") == product for row in inventory.get("processes", [])):
            raise AppError("请先退出原客户端，再添加连接", 409)
        backends = [row for row in inventory.get("processes", []) if row.get("name") == product + "CS"]
        if not backends:
            return
        service = self._verified_service(profile["index"], inventory)
        if not prepared.get("backend_pid") or not prepared.get("backend_created") or len(backends) != 1 or not service:
            raise AppError("无法确认空闲后台归属，现有环境已保留", 409)
        row = backends[0]
        if (row.get("pid") != prepared["backend_pid"] or row.get("created") != prepared["backend_created"]
                or row.get("parent") != prepared.get("service_pid") or row.get("parent") != service["pid"]
                or row.get("session") != prepared.get("session")):
            raise AppError("原生后台已发生变化，现有环境已保留", 409)
        try:
            created = datetime.fromisoformat(prepared["backend_created"])
            if created.tzinfo is None:
                raise ValueError()
            delta = created.astimezone(timezone.utc) - datetime(1601, 1, 1, tzinfo=timezone.utc)
            created_us = (delta.days * 86400 + delta.seconds) * 1000000 + delta.microseconds
        except (TypeError, ValueError, OverflowError):
            raise AppError("无法确认空闲后台归属，现有环境已保留", 409) from None
        self._action("QuiesceOwned", profile["index"], expected_pid=row["pid"], expected_created_us=created_us)
        after = self._inventory()
        if any(item.get("name") in {product, product + "CS"} for item in after.get("processes", [])):
            raise AppError("空闲后台退出尚未确认，未创建新连接", 409)
        with self._lock:
            if self._prepared.get(profile["id"]) == prepared:
                self._prepared.pop(profile["id"], None)

    def create_instance(self):
        # The privileged helper rechecks all clients/TAPs before elevation,
        # after elevation, and around the pinned upstream CreateOnly action.
        # It never disconnects another instance to make creation possible.
        inventory = self._inventory()
        if inventory.get("processes") or any(a.get("up") for a in inventory.get("adapters", [])):
            raise AppError("添加前请先断开 VPN 并退出原客户端", 409)
        known = {r.get("index") for r in inventory.get("records", [])}
        result = self._action("CreateInstance", 1)
        index = result["index"]
        if index in known:
            raise AppError("新增连接结果无法确认，请勿重复添加", 409)
        self._paths(index)
        records = [r for r in self._inventory().get("records", []) if r.get("index") == index and r.get("status") == "Ready"]
        if len(records) != 1:
            raise AppError("新增连接尚未通过校验，请勿重复添加", 409)
        return index
