"""Local configuration and state. VPN secrets are never persisted here."""
from __future__ import annotations

import ipaddress
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import socket
import stat
import subprocess
import threading
import time
from typing import Any

VERSION = "0.2.5"
ROOT = Path(__file__).resolve().parent
PUBLIC_PROFILE_KEYS = {"id", "name", "gateway", "port", "index", "autoConnect", "useLegacyCredential"}
MAX_PROFILES = 1000


class AppError(Exception):
    def __init__(self, message: str, status: int = 400, *, code=None, details=None):
        super().__init__(message)
        self.status = status
        self.code = code
        self.details = details


def powershell_path() -> str:
    return str(Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32/WindowsPowerShell/v1.0/powershell.exe")


def hidden_kwargs() -> dict:
    return {"creationflags": subprocess.CREATE_NO_WINDOW} if os.name == "nt" else {}


def validate_network(values: dict[str, Any]) -> dict[str, Any]:
    name = str(values.get("name", "")).strip()
    gateway = str(values.get("gateway", "")).strip()
    if len(name) > 255 or any(ord(c) < 32 for c in name):
        raise AppError("名称格式无效")
    if len(gateway) > 253 or not gateway or any(c in gateway for c in "/\\@?#\r\n\x00"):
        raise AppError("请输入网关地址")
    try:
        address = ipaddress.ip_address(gateway)
        if address.version != 4 or address.is_loopback or address.is_unspecified or address.is_multicast:
            raise AppError("请输入有效的 IPv4 网关或域名")
    except ValueError:
        if not re.fullmatch(r"(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", gateway):
            raise AppError("请输入有效的网关地址")
    port = values.get("port", 443)
    if isinstance(port, bool):
        raise AppError("端口无效")
    try:
        port = int(port)
    except (TypeError, ValueError):
        raise AppError("端口无效") from None
    if not 1 <= port <= 65535:
        raise AppError("端口无效")
    return {"name": name, "gateway": gateway, "port": port}


class Manager:
    def __init__(self, runtime_dir: Path, *, bridge=None, inspect=True, credentials=None, startup=None):
        self.runtime_dir = runtime_dir
        self.runtime_dir.mkdir(parents=True, exist_ok=True)
        self.path = runtime_dir / "profiles.json"
        self.source_path = runtime_dir / "source-links.json"
        self.source_links: dict[str, dict] = {}
        self.deleted_sources: set[str] = set()
        self.lock = threading.RLock()
        self.profiles: list[dict] = []
        self.sessions: dict[str, Any] = {}
        self._attempts: dict[str, object] = {}
        self._disconnecting: dict[str, dict] = {}
        self._expansion = None
        self.events: dict[str, dict] = {}
        self._pending_credentials: dict[str, tuple[str, str]] = {}
        self._warnings: dict[str, str] = {}
        self._challenge_ids: dict[str, int] = {}
        self._automatic_started = False
        self._inspect = bool(inspect)
        self.credentials = credentials
        self.startup = startup
        if inspect and os.name == "nt":
            if self.credentials is None:
                from credential_store import CredentialStore
                self.credentials = CredentialStore()
            if self.startup is None:
                from startup import Startup
                self.startup = Startup()
        self.inventory: dict = {}
        self.inventory_error = ""
        self.import_error = ""
        self._stop = threading.Event()
        self.bridge = bridge
        self._load()
        self._load_sources()
        if inspect and os.name == "nt":
            self.refresh_inventory()
            self._import_existing()
            threading.Thread(target=self._poll, daemon=True, name="vpn-state").start()
            threading.Thread(target=self._auto_connect_once, daemon=True, name="vpn-startup").start()

    def _load(self):
        if not self.path.exists():
            return
        try:
            items = json.loads(self.path.read_text("utf-8"))
            if not isinstance(items, list) or len(items) > MAX_PROFILES:
                raise ValueError()
            seen_ids, seen_indexes = set(), set()
            for item in items:
                public = {k: item[k] for k in PUBLIC_PROFILE_KEYS if k in item}
                if not re.fullmatch(r"[a-zA-Z0-9_-]{1,48}", str(public.get("id", ""))):
                    raise ValueError()
                if type(public.get("index")) is not int or not 0 <= public["index"] <= 999:
                    raise ValueError()
                if public["id"] in seen_ids or (public["index"] and public["index"] in seen_indexes):
                    raise ValueError()
                seen_ids.add(public["id"])
                seen_indexes.add(public["index"])
                automatic = public.get("autoConnect", False)
                if type(automatic) is not bool:
                    raise ValueError()
                public["autoConnect"] = automatic
                legacy = public.get("useLegacyCredential", True)
                if type(legacy) is not bool:
                    raise ValueError()
                public["useLegacyCredential"] = legacy
                network = validate_network(public)
                self.profiles.append({**public, **network})
        except (ValueError, TypeError, KeyError, AppError):
            raise AppError("VPN 配置无法读取，原文件已保留", 500) from None

    def _save(self):
        defaults = {"autoConnect": False, "useLegacyCredential": True}
        public = [{k: item.get(k, defaults.get(k, "")) for k in PUBLIC_PROFILE_KEYS} for item in self.profiles]
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(public, ensure_ascii=False, indent=2), "utf-8")
        os.replace(tmp, self.path)

    @staticmethod
    def _source_link(value):
        if not isinstance(value, dict):
            raise ValueError()
        source_id, index, name = (value.get(k) for k in ("sourceId", "sourceIndex", "sourceName"))
        if not isinstance(source_id, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", source_id):
            raise ValueError()
        if type(index) is not int or not 1 <= index <= 999:
            raise ValueError()
        if not isinstance(name, str) or not 1 <= len(name) <= 255 or name in {".", ".."} or any(c in name for c in "/\\:") or any(ord(c) < 32 for c in name):
            raise ValueError()
        return {"sourceId": source_id, "sourceIndex": index, "sourceName": name}

    def _load_sources(self):
        if not os.path.lexists(self.source_path):
            return
        try:
            info = self.source_path.lstat()
            if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400 or info.st_size > 4 * 2**20:
                raise ValueError()
            data = json.loads(self.source_path.read_text("utf-8"))
            links, deleted = data["links"], data.get("deleted", [])
            if not isinstance(links, dict) or len(links) > MAX_PROFILES or not isinstance(deleted, list) or len(deleted) > 10000:
                raise ValueError()
            if any(not isinstance(key, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", key) for key in deleted):
                raise ValueError()
            known = {p["id"] for p in self.profiles}
            source_ids = set()
            for profile_id, value in links.items():
                link = self._source_link(value)
                if link["sourceId"] in source_ids:
                    raise ValueError()
                source_ids.add(link["sourceId"])
                if profile_id in known:
                    self.source_links[profile_id] = link
            self.deleted_sources = set(deleted)
        except (OSError, ValueError, TypeError, KeyError):
            raise AppError("旧配置关联无法读取，原文件已保留", 500) from None

    def _save_sources(self):
        temporary = self.source_path.with_suffix(".tmp")
        temporary.write_text(json.dumps({"links": self.source_links, "deleted": sorted(self.deleted_sources)}, ensure_ascii=False, indent=2), "utf-8")
        if os.name != "nt":
            temporary.chmod(0o600)
        os.replace(temporary, self.source_path)

    def _poll(self):
        while not self._stop.wait(4):
            self.refresh_inventory()

    def refresh_inventory(self):
        try:
            completed = subprocess.run(
                [powershell_path(), "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(ROOT / "tools/inspect.ps1")],
                capture_output=True, timeout=20, **hidden_kwargs(),
            )
            if completed.returncode:
                raise ValueError()
            raw = completed.stdout
            text = raw.decode("utf-8-sig")
            inventory = json.loads(text)
            with self.lock:
                self.inventory = inventory
                self.inventory_error = "" if inventory.get("installed") else "未找到受支持的 UniVPN 客户端"
        except (ValueError, OSError, subprocess.TimeoutExpired):
            with self.lock:
                self.inventory_error = "无法读取 VPN 状态"

    def _profile(self, profile_id: str) -> dict:
        for item in self.profiles:
            if item["id"] == profile_id:
                return item
        raise AppError("未找到此 VPN", 404)

    @staticmethod
    def _network_version(profile):
        # A public endpoint revision, never an account/source/credential key.
        value = json.dumps([profile["id"], profile["gateway"], profile["port"]], separators=(",", ":"))
        return hashlib.sha256(value.encode("utf-8")).hexdigest()

    def _bind_network(self, profile, values):
        current = self._network_version(profile)
        expected = values.get("networkVersion", current)
        if not isinstance(expected, str) or expected != current:
            raise AppError("网关信息已更改，请重新输入账号和密码", 409, code="credentials_required")
        return {**values, "networkVersion": expected}

    def _import_existing(self):
        # Every physical source is a distinct configuration, including exact
        # name/endpoint duplicates. Its filename identity stays private.
        sources = getattr(self.bridge, "remembered_sources", None)
        if callable(sources):
            try:
                candidates = sources(self.inventory)
            except Exception:
                return
            if not isinstance(candidates, list):
                return
            valid, seen = [], set()
            for row in candidates:
                try:
                    link = self._source_link(row)
                    network = validate_network(row)
                except (ValueError, TypeError, AppError):
                    continue
                if link["sourceId"] not in seen:
                    seen.add(link["sourceId"])
                    valid.append((link, network))
            with self.lock:
                linked = {link["sourceId"] for link in self.source_links.values()}
                changed = False
                self.import_error = ""
                for link, network in valid:
                    source_id = link["sourceId"]
                    if source_id in self.deleted_sources:
                        continue
                    if source_id in linked:
                        # The exact physical-file identity is unchanged. Repair
                        # older cached lookup metadata only; user configuration
                        # fields and the public profile ID remain authoritative.
                        for profile_id, old_link in self.source_links.items():
                            if old_link["sourceId"] == source_id and old_link != link:
                                self.source_links[profile_id] = dict(link)
                                changed = True
                        continue
                    matches = [(other, net) for other, net in valid if other["sourceIndex"] == link["sourceIndex"]
                               and (net["gateway"], net["port"]) == (network["gateway"], network["port"])]
                    existing = next((p for p in self.profiles if p["index"] == link["sourceIndex"]
                                     and p["id"] not in self.source_links
                                     and (p["gateway"], p["port"]) == (network["gateway"], network["port"])), None)
                    if existing is not None and len(matches) == 1:
                        profile_id = existing["id"]
                        if not existing["name"]:
                            existing["name"] = network["name"]
                    else:
                        if len(self.profiles) >= MAX_PROFILES:
                            self.import_error = "旧配置超过 1000 条，未能全部导入；已有配置已保留。"
                            break
                        profile_id = secrets.token_hex(8)
                        self.profiles.append({**network, "id": profile_id, "index": 0,
                                              "autoConnect": False, "useLegacyCredential": True})
                    self.source_links[profile_id] = dict(link)
                    linked.add(source_id)
                    changed = True
                if changed:
                    self._save_sources()
                    self._save()
                # Fresh installs have one original environment. Adopt only an
                # unambiguous currently connected source; offline configs stay
                # unassigned until the user explicitly adds/connects them.
                occupied = {p["index"] for p in self.profiles if p["index"] > 0}
                adopted = False
                if self._inventory_known() and not self.inventory_error:
                    for index in sorted(self._available_indexes() - occupied):
                        if any(operation["index"] == index for operation in self._disconnecting.values()):
                            continue
                        backend = "UniVPNCS" if index == 1 else f"UVP{index:03d}CS"
                        peers = {(p.get("gateway"), p.get("port")) for p in self.inventory.get("peers", [])
                                 if p.get("process") == backend and self._remote_peer(p)}
                        if len(peers) != 1:
                            continue
                        endpoint = next(iter(peers))
                        matches = [link["sourceId"] for link, network in valid if link["sourceIndex"] == index
                                   and (network["gateway"], network["port"]) == endpoint]
                        if len(matches) != 1:
                            continue
                        key = next((key for key, link in self.source_links.items() if link["sourceId"] == matches[0]), None)
                        if key is not None and self._profile(key)["index"] == 0 and key not in self._disconnecting:
                            self._profile(key)["index"] = index
                            adopted = True
                    if adopted:
                        self._save()
            return
        # Compatibility for older bridges: keep existing explicit assignments.
        # The current bridge always provides remembered_sources instead.
        callback = getattr(self.bridge, "remembered_profiles", None)
        if not callable(callback):
            return
        try:
            candidates = callback(self.inventory)
            if not isinstance(candidates, list):
                return
            before = len(self.profiles)
            used = {p["index"] for p in self.profiles}
            for row in candidates[:MAX_PROFILES - before]:
                index = row["index"]
                if type(index) is not int or not 1 <= index <= 999 or index in used:
                    continue
                network = validate_network(row)
                self.profiles.append({**network, "id": secrets.token_hex(8), "index": index,
                                      "autoConnect": False, "useLegacyCredential": True})
                used.add(index)
            if len(self.profiles) != before:
                # _save writes only the public allowlist, never native refs.
                self._save()
        except Exception:
            # A malformed optional vendor profile must not prevent opening the
            # manager. It is left in place for the original client.
            return

    def _legacy_reference(self, profile):
        callback = getattr(self.bridge, "legacy_reference", None)
        if not profile.get("useLegacyCredential", True) or not callable(callback):
            return None
        source = self.source_links.get(profile["id"])
        if source is not None:
            if profile["index"] and profile["index"] != source["sourceIndex"]:
                # A source is configuration provenance, not a runtime lease.
                # Only the assigned backend's own native cache may be reused.
                return callback(profile)
            lookup = {**profile, "index": source["sourceIndex"]}
            return callback(lookup, source=dict(source))
        if profile["index"] == 0:
            return None
        return callback(profile)

    def _has_credential(self, profile_id):
        try:
            if self.credentials is not None:
                value = self.credentials.read(profile_id)
                present = value is not None
                del value
                if present:
                    return True
            reference = self._legacy_reference(self._profile(profile_id))
            present = reference is not None
            del reference
            return present
        except Exception:
            return False

    def _auto_connect_once(self):
        # One attempt per selected profile per manager start. A dynamic-code
        # challenge pauses that individual session; no password is retried.
        with self.lock:
            if self._automatic_started:
                return
            self._automatic_started = True
        if self._stop.wait(1.5):
            return
        with self.lock:
            candidates = [p["id"] for p in self.profiles if p.get("autoConnect", False)]
        for profile_id in candidates:
            if self._stop.is_set():
                return
            with self.lock:
                profile = next((p for p in self.profiles if p["id"] == profile_id), None)
                if self._expansion is not None or profile is None or not profile.get("autoConnect", False) or profile_id in self.sessions or profile_id in self._disconnecting or self._connected(profile):
                    continue
            if not self._has_credential(profile_id):
                with self.lock:
                    profile = next((p for p in self.profiles if p["id"] == profile_id), None)
                    if self._expansion is None and profile is not None and profile.get("autoConnect", False) and profile_id not in self.sessions and profile_id not in self._disconnecting and not self._connected(profile):
                        self._event(profile_id, {"status": "disconnected", "error": "首次连接请保存账号和密码"})
                continue
            try:
                with self.lock:
                    profile = next((p for p in self.profiles if p["id"] == profile_id), None)
                    if self._expansion is not None or profile is None or not profile.get("autoConnect", False) or profile_id in self.sessions or profile_id in self._disconnecting or self._connected(profile):
                        continue
                    self.connect(profile_id, {}, allow_create=False)
            except AppError as exc:
                with self.lock:
                    # A user may start/remove this connection while the vault
                    # is read. Never overwrite an existing interactive session.
                    profile = next((p for p in self.profiles if p["id"] == profile_id), None)
                    if self._expansion is None and profile is not None and profile_id not in self.sessions and profile_id not in self._disconnecting and not self._connected(profile):
                        self._event(profile_id, {"status": "error", "error": str(exc)})

    def _connected(self, profile: dict) -> bool:
        if self.inventory_error or not self._inventory_known() or profile["index"] == 0:
            return False
        records = self.inventory.get("records", [])
        if profile["index"] == 1:
            managed = {str(r.get("tapGuid", "")).upper() for r in records}
            adapters = [a for a in self.inventory.get("adapters", []) if str(a.get("guid", "")).upper() not in managed]
        else:
            record = next((r for r in records if r.get("index") == profile["index"]), {})
            adapters = [a for a in self.inventory.get("adapters", []) if str(a.get("guid", "")).upper() == str(record.get("tapGuid", "")).upper()]
        backend = "UniVPNCS" if profile["index"] == 1 else f"UVP{profile['index']:03d}CS"
        peer_matches = any(p.get("process") == backend and p.get("gateway") == profile["gateway"] and p.get("port") == profile["port"] for p in self.inventory.get("peers", []))
        owned_connected = profile["id"] in self.sessions and self.events.get(profile["id"], {}).get("status") == "connected"
        return len(adapters) == 1 and bool(adapters[0].get("up") and adapters[0].get("addresses")) and (peer_matches or owned_connected)

    def _public_status(self, profile: dict) -> tuple[str, str]:
        event = self.events.get(profile["id"], {})
        status = event.get("status")
        if status is None:
            return ("connected" if self._connected(profile) else "disconnected"), ""
        if status == "authenticated":
            return "starting", ""
        if status == "error" and profile["id"] not in self.sessions and self._connected(profile):
            # A failed management operation does not end the external GUI's
            # tunnel. Keep its observed connection state and the event error.
            return "connected", ""
        if status == "connected" and not self._connected(profile):
            return "error", "连接状态未确认，请断开后重连"
        return status, ""

    def notifications(self) -> dict:
        # Tray polling must never enumerate/read saved credentials, startup
        # configuration, authentication text or endpoint/account information.
        with self.lock:
            return {"profiles": [{"id": p["id"], "status": self._public_status(p)[0],
                                  "challengeId": self._challenge_ids.get(p["id"], 0)}
                                 for p in self.profiles]}

    def state(self) -> dict:
        with self.lock:
            profiles = []
            for item in self.profiles:
                event = self.events.get(item["id"], {})
                status, observation_error = self._public_status(item)
                public = {**{k: item[k] for k in PUBLIC_PROFILE_KEYS if k in item}, "status": status, "autoConnect": item.get("autoConnect", False), "hasSavedCredential": self._has_credential(item["id"]),
                          "canDisconnect": item["id"] in self.sessions, "challengeId": self._challenge_ids.get(item["id"], 0),
                          "networkVersion": self._network_version(item)}
                if observation_error:
                    public["error"] = observation_error
                elif event.get("error"):
                    public["error"] = event["error"]
                elif self._warnings.get(item["id"]):
                    public["error"] = self._warnings[item["id"]]
                if event.get("challenge"):
                    public["challenge"] = event["challenge"]
                profiles.append(public)
            ready = bool(self.bridge and getattr(self.bridge, "available", False))
            try:
                startup_enabled = bool(self.startup and self.startup.get_enabled())
            except Exception:
                startup_enabled = False
            handoff = self._handoff_required()
            return {"version": VERSION, "profiles": profiles, "handoffRequired": handoff,
                    "expansion": {"inProgress": self._expansion is not None,
                                  **({"profileId": self._expansion["profileId"]} if self._expansion else {})},
                    "capabilities": {"nativeAuth": ready, "otp": ready, "saveCredentials": self.credentials is not None, "startup": self.startup is not None,
                                     "environment": callable(getattr(self.bridge, "check_environment", None))},
                    "settings": {"startup": startup_enabled}, "error": self.inventory_error or
                    ("请先在原客户端断开 VPN 并退出，再由网页连接。" if handoff else self.import_error)}

    def add(self, values: dict) -> dict:
        network = validate_network(values)
        needs_creation = False
        with self.lock:
            self._check_expansion()
            if len(self.profiles) >= MAX_PROFILES:
                raise AppError("连接数量已达上限", 409)
            profile = {**network, "id": secrets.token_hex(8), "index": 0,
                       "autoConnect": False, "useLegacyCredential": True}
            self.profiles.append(profile)
            self._save()
            notice = ""
            if self._inspect and os.name == "nt":
                self.refresh_inventory()
            if self._can_allocate_idle():
                try:
                    index = self._choose_index(profile, legacy=False, allow_create=True)
                    self._assign_index(profile["id"], index)
                    self._save()
                except AppError as exc:
                    needs_creation = exc.code == "creation_required"
                    # Creating an environment is optional to remembering the
                    # configuration. Never lose the user's new entry or retry
                    # a privileged helper automatically after an uncertain exit.
                    if not needs_creation:
                        notice = "配置已保存，连接环境创建未完成；全部退出后可再次手动连接。"
                except Exception:
                    notice = "配置已保存，连接环境创建未完成；全部退出后可再次手动连接。"
            else:
                notice = "配置已保存，请先断开所有 VPN 并退出原客户端；首次连接时会自动创建所需环境。"
            if notice:
                self._warnings[profile["id"]] = notice
        if needs_creation:
            try:
                self.expand_connect(profile["id"], {}, _idle_only=True, _provision_only=True)
            except Exception:
                notice = "配置已保存，连接环境创建未完成；全部退出后可再次手动连接。"
                with self.lock:
                    self._warnings[profile["id"]] = notice
        return {"id": profile["id"], **({"notice": notice} if notice else {})}

    def _can_allocate_idle(self):
        return bool(self.bridge and getattr(self.bridge, "available", False) and self._inventory_known()
                    and not self.inventory_error and not self.sessions and not self._disconnecting and not self._expansion
                    and not self.inventory.get("processes")
                    and not any(self._remote_peer(peer) for peer in self.inventory.get("peers", []))
                    and not any(a.get("up") and a.get("addresses") for a in self.inventory.get("adapters", [])))

    def _available_indexes(self):
        indexes = {1} if self.inventory.get("installed") else set()
        indexes.update(row["index"] for row in self.inventory.get("records", [])
                       if row.get("status") == "Ready" and type(row.get("index")) is int and 2 <= row["index"] <= 999)
        return indexes

    def _inventory_known(self):
        return isinstance(self.inventory, dict) and type(self.inventory.get("installed")) is bool and not self.inventory.get("metadataUnknown") and all(
            isinstance(self.inventory.get(key, []), list) and all(isinstance(row, dict) for row in self.inventory.get(key, []))
            for key in ("records", "adapters", "peers", "processes"))

    def _handoff_required(self):
        if not self._inventory_known():
            return False
        owned_anchor = getattr(self.bridge, "is_owned_anchor", None)
        for row in self.inventory.get("processes", []):
            if not re.fullmatch(r"(?:UniVPN|UVP\d{3})(?:\.exe)?", str(row.get("name", "")), re.IGNORECASE):
                continue
            try:
                if callable(owned_anchor) and owned_anchor(row) is True:
                    continue
            except Exception:
                pass
            return True
        owned = {"UniVPNCS" if p["index"] == 1 else f"UVP{p['index']:03d}CS"
                 for p in self.profiles if p["id"] in self.sessions and p["index"] > 0}
        return any(re.fullmatch(r"(?:UniVPN|UVP\d{3})CS", str(peer.get("process", "")))
                   and peer.get("process") not in owned and self._remote_peer(peer)
                   for peer in self.inventory.get("peers", []))

    def _slot_busy(self, index):
        if any(operation["index"] == index for operation in self._disconnecting.values()):
            return True
        if any(p["index"] == index and p["id"] in self.sessions for p in self.profiles):
            return True
        backend = "UniVPNCS" if index == 1 else f"UVP{index:03d}CS"
        if any(peer.get("process") == backend and self._remote_peer(peer) for peer in self.inventory.get("peers", [])):
            return True
        records = self.inventory.get("records", [])
        if index == 1:
            managed = {str(r.get("tapGuid", "")).upper() for r in records}
            adapters = [a for a in self.inventory.get("adapters", []) if str(a.get("guid", "")).upper() not in managed]
        else:
            record = next((r for r in records if r.get("index") == index), {})
            adapters = [a for a in self.inventory.get("adapters", [])
                        if str(a.get("guid", "")).upper() == str(record.get("tapGuid", "")).upper()]
        return any(a.get("up") and a.get("addresses") for a in adapters)

    @staticmethod
    def _remote_peer(peer):
        host = str(peer.get("gateway", ""))
        try:
            return not ipaddress.ip_address(host).is_loopback
        except ValueError:
            return host.casefold() != "localhost"

    def _choose_index(self, profile, *, legacy, allow_create):
        if self.inventory_error or not self._inventory_known():
            raise AppError("无法确认原生连接状态，请先检查连接状态", 409)
        available = self._available_indexes()
        if profile["index"] in available and not self._slot_busy(profile["index"]):
            return profile["index"]
        if profile["index"] > 0 and self._slot_busy(profile["index"]):
            raise AppError("此 VPN 的连接资源仍在使用，请先检查连接状态", 409)
        reserved = {p["index"] for p in self.profiles if p["id"] != profile["id"] and p["index"] > 0}
        choices = sorted(index for index in available - reserved if not self._slot_busy(index))
        if choices:
            source = self.source_links.get(profile["id"])
            if legacy and source and source["sourceIndex"] in choices:
                return source["sourceIndex"]
            return choices[0]
        if not allow_create:
            raise AppError("请先手动连接一次，系统会自动创建所需连接环境", 409)
        if self.sessions or self._disconnecting or self.inventory.get("processes") or any(self._slot_busy(index) for index in available) or any(
                self._remote_peer(peer) for peer in self.inventory.get("peers", [])) or any(
                a.get("up") and a.get("addresses") for a in self.inventory.get("adapters", [])):
            raise AppError("新增并发连接需要暂时断开当前连接，创建后恢复；动态口令需你填写", 409,
                           code="expansion_required", details={"profileIds": list(self.sessions)})
        # The caller resumes through the same operation lease used by explicit
        # expansion. A privileged creator must never run under Manager.lock.
        raise AppError("需要新增连接资源", 409, code="creation_required")

    def _assign_index(self, profile_id, index):
        for other in self.profiles:
            if other["id"] != profile_id and other["index"] == index:
                raise AppError("此连接环境已分配给其他配置", 409)
        self._profile(profile_id)["index"] = index

    def edit(self, profile_id: str, values: dict) -> dict:
        with self.lock:
            self._check_expansion()
            profile = self._profile(profile_id)
            if profile_id in self._disconnecting:
                raise AppError("正在断开此 VPN，请稍后操作", 409)
            network = validate_network({**profile, **{k: values[k] for k in ("name", "gateway", "port") if k in values}})
            network_changed = any(network[k] != profile[k] for k in ("gateway", "port"))
            if network_changed and (self._connected(profile) or profile_id in self.sessions):
                raise AppError("请先断开此 VPN", 409)
            automatic = values.get("autoConnect", profile.get("autoConnect", False))
            if type(automatic) is not bool:
                raise AppError("自动连接选项无效")
            if network_changed:
                if self.credentials:
                    try:
                        self.credentials.delete(profile_id)
                    except Exception:
                        raise AppError("无法清除旧网关凭据，连接信息已保留", 409) from None
                automatic = False
                if self.source_links.pop(profile_id, None) is not None:
                    self._save_sources()
                profile["useLegacyCredential"] = False
            profile.update(network)
            profile["autoConnect"] = automatic
            self._save()
            return {"ok": True}

    def remove(self, profile_id: str) -> dict:
        with self.lock:
            self._check_expansion()
            profile = self._profile(profile_id)
            if profile_id in self._disconnecting:
                raise AppError("正在断开此 VPN，请稍后操作", 409)
            if self._connected(profile) or profile_id in self.sessions:
                raise AppError("请先断开此 VPN", 409)
            if self.credentials:
                try:
                    self.credentials.delete(profile_id)
                except Exception:
                    raise AppError("无法清除此连接保存的密码", 409) from None
            self.profiles.remove(profile)
            self.events.pop(profile_id, None)
            self._pending_credentials.pop(profile_id, None)
            self._challenge_ids.pop(profile_id, None)
            link = self.source_links.pop(profile_id, None)
            if link:
                self.deleted_sources.add(link["sourceId"])
                self._save_sources()
            self._save()
            # Reusable native files/TAPs remain; removing a list entry must not
            # silently uninstall the shared vendor driver.
            return {"ok": True}

    def _event(self, profile_id: str, event: dict, *, attempt=None):
        allowed = {k: event[k] for k in ("status", "error", "challenge") if k in event}
        if allowed.get("status") not in {None, "starting", "authenticating", "otp", "authenticated", "connected", "disconnected", "disconnecting", "error"}:
            return
        with self.lock:
            if attempt is not None and (self._attempts.get(profile_id) is not attempt or self._stop.is_set()):
                return
            if allowed.get("status") == "otp":
                self._challenge_ids[profile_id] = self._challenge_ids.get(profile_id, 0) + 1
            if allowed.get("status") == "authenticated":
                pending = self._pending_credentials.pop(profile_id, None)
                if pending and self.credentials:
                    try:
                        self.credentials.save(profile_id, pending[0], pending[1])
                    except Exception:
                        self._warnings[profile_id] = "已认证，但密码未能保存"
                    else:
                        self._warnings.pop(profile_id, None)
                    finally:
                        del pending
            if allowed.get("status") in {"error", "disconnected"}:
                self._pending_credentials.pop(profile_id, None)
            self.events[profile_id] = allowed

    def connect(self, profile_id: str, values: dict, *, allow_create=True, _expansion_token=None) -> dict:
        with self.lock:
            self._check_expansion(_expansion_token)
            values = self._bind_network(self._profile(profile_id), values)
        try:
            return self._connect(profile_id, values, allow_create=allow_create, _expansion_token=_expansion_token)
        except AppError as exc:
            if exc.code != "creation_required" or not allow_create or _expansion_token is not None:
                raise
        # A plain click may provision only while still idle. If another session
        # won this race, its tunnel needs a fresh explicit expansion consent.
        return self.expand_connect(profile_id, values, _idle_only=True)

    def _connect(self, profile_id: str, values: dict, *, allow_create=True, _expansion_token=None) -> dict:
        if not self.bridge or not getattr(self.bridge, "available", False):
            raise AppError("原生认证接口尚在验证", 409)
        username, password = values.get("username"), values.get("password")
        using_saved = username is None and password is None
        remember = values.get("remember", False)
        automatic = values.get("autoConnect", None)
        if type(remember) is not bool or (automatic is not None and type(automatic) is not bool):
            raise AppError("登录选项无效")
        legacy = None
        attempt = object()
        with self.lock:
            self._check_expansion(_expansion_token)
            if self._stop.is_set():
                raise AppError("后台已停止", 409)
            if self._inspect and os.name == "nt":
                self.refresh_inventory()
                if self.inventory_error:
                    raise AppError("无法确认原生连接状态，请先检查连接状态", 409)
            profile = dict(self._profile(profile_id))
            self._bind_network(profile, values)
            if profile_id in self._disconnecting:
                raise AppError("正在断开此 VPN，请稍后操作", 409)
            if self._handoff_required():
                raise AppError("请先在原客户端断开 VPN 并退出，再由网页连接", 409)
            if self._connected(profile):
                raise AppError("此 VPN 已连接", 409)
            if profile_id in self.sessions:
                raise AppError("请先断开此 VPN，再重新登录", 409)
            # Resolve credentials while the endpoint assignment is locked, so
            # a simultaneous gateway edit cannot redirect saved credentials.
            if using_saved:
                try:
                    saved = self.credentials.read(profile_id) if self.credentials else None
                    if saved is not None:
                        username, password = saved.username, saved.password
                        del saved
                except Exception:
                    raise AppError("无法读取保存的登录信息，请重新登录", 409) from None
            if automatic:
                remember = not using_saved
            if not using_saved or username is not None:
                if remember and not self.credentials:
                    raise AppError("当前无法安全保存密码", 409)
                if not isinstance(username, str) or not isinstance(password, str) or not username or not password:
                    raise AppError("请输入账号和密码")
                if "\x00" in username + password or len(username) > 256 or len(password) > 1024:
                    raise AppError("账号或密码格式无效")
            index = self._choose_index(profile, legacy=using_saved and username is None, allow_create=allow_create)
            profile["index"] = index
            self._assign_index(profile_id, index)
            self._save()
            if using_saved and username is None:
                try:
                    legacy = self._legacy_reference(profile)
                except Exception:
                    raise AppError("无法读取保存的登录信息，请重新登录", 409) from None
                if legacy is None:
                    self.events.pop(profile_id, None)
                    self._warnings.pop(profile_id, None)
                    raise AppError("请输入账号和密码连接此 VPN", 409, code="credentials_required")
            session = self.bridge.session(profile, lambda event: self._event(profile_id, event, attempt=attempt))
            if legacy is not None and not callable(getattr(session, "start_saved", None)):
                raise AppError("旧登录信息尚不能复用，请重新登录", 409)
            self.sessions[profile_id] = session
            self._attempts[profile_id] = attempt
            self.events[profile_id] = {"status": "authenticating"}
            if remember and legacy is None:
                self._pending_credentials[profile_id] = (username, password)
            self._warnings.pop(profile_id, None)
            if automatic is not None:
                self._profile(profile_id)["autoConnect"] = automatic
            self._save()
        try:
            with self.lock:
                if self._attempts.get(profile_id) is not attempt or self.sessions.get(profile_id) is not session or self._stop.is_set():
                    raise AppError("本次连接已取消", 409)
            if legacy is not None:
                # The vendor decrypts its own stored password internally. It
                # never enters Python, HTTP state, logs or the manager vault.
                session.start_saved(legacy.username, legacy.profile_name)
                del legacy
            else:
                session.start(username, password)
            with self.lock:
                if self._attempts.get(profile_id) is not attempt or self.sessions.get(profile_id) is not session:
                    raise AppError("本次连接已取消", 409)
        except Exception:
            with self.lock:
                current = self._attempts.get(profile_id) is attempt and self.sessions.get(profile_id) is session
                if current:
                    self._pending_credentials.pop(profile_id, None)
                    self._attempts.pop(profile_id, None)
                    self.sessions.pop(profile_id, None)
                    self.events[profile_id] = {"status": "error", "error": "原生连接未能开始"}
            raise AppError("原生连接未能开始，请检查连接设置" if current else "本次连接已取消", 409) from None
        return {"ok": True}

    def _check_expansion(self, token=None):
        if self._expansion is not None and self._expansion["token"] is not token:
            raise AppError("正在新增并发连接，请稍后操作", 409, code="expansion_in_progress")

    def _observe_expansion(self):
        # Observe outside Manager.lock. Native inspection and UAC may be slow;
        # read-only HTTP state and the dynamic-token form must keep working.
        observer = getattr(self.bridge, "_inventory", None)
        if callable(observer):
            try:
                inventory = observer()
            except Exception:
                raise AppError("无法确认连接状态，已停止新增连接", 409) from None
            with self.lock:
                previous = self.inventory
                self.inventory = inventory
                if not self._inventory_known() or not all(key in inventory for key in ("records", "adapters", "peers", "processes")):
                    self.inventory = previous
                    raise AppError("无法确认连接状态，已停止新增连接", 409)
                self.inventory_error = ""
        elif self._inspect and os.name == "nt":
            self.refresh_inventory()
        with self.lock:
            if self.inventory_error or not self._inventory_known() or ((self._inspect or callable(observer)) and not all(key in self.inventory for key in ("records", "adapters", "peers", "processes"))):
                raise AppError("无法确认连接状态，已停止新增连接", 409)

    def _expansion_idle(self, *, processes=True):
        return (not self.sessions and not self._disconnecting and (not processes or not self.inventory.get("processes"))
                and not any(self._remote_peer(p) for p in self.inventory.get("peers", []))
                and not any(a.get("up") and a.get("addresses") for a in self.inventory.get("adapters", [])))

    def _wait_expansion_idle(self, operation, *, processes=True):
        deadline = time.monotonic() + 20
        while True:
            self._observe_expansion()
            with self.lock:
                if self._expansion is not operation or self._stop.is_set():
                    raise AppError("新增连接已取消", 409)
                if self._expansion_idle(processes=processes):
                    return
            if time.monotonic() >= deadline:
                raise AppError("连接尚未全部断开，已停止新增连接", 409)
            if self._stop.wait(0.2):
                raise AppError("新增连接已取消", 409)

    def expand_connect(self, profile_id: str, values: dict, *, _idle_only=False, _provision_only=False) -> dict:
        """Explicitly confirmed, single-pass expansion. Never retries auth/UAC."""
        if not self.bridge or not getattr(self.bridge, "available", False):
            raise AppError("原生认证接口尚在验证", 409)
        with self.lock:
            self._check_expansion()
            values = self._bind_network(self._profile(profile_id), values)
        # Reject malformed credentials before interrupting any owned tunnel.
        username, password = values.get("username"), values.get("password")
        if username is not None or password is not None:
            if (not isinstance(username, str) or not isinstance(password, str) or not username or not password
                    or len(username) > 256 or len(password) > 1024 or "\x00" in username + password):
                raise AppError("请输入有效的账号和密码")
        if type(values.get("remember", False)) is not bool or (values.get("autoConnect") is not None and type(values["autoConnect"]) is not bool):
            raise AppError("登录选项无效")
        if (values.get("remember") or values.get("autoConnect")) and username is not None and self.credentials is None:
            raise AppError("当前无法安全保存密码", 409)
        self._observe_expansion()
        operation = {"token": object(), "profileId": profile_id}
        token = operation["token"]
        with self.lock:
            self._check_expansion()
            if self._stop.is_set():
                raise AppError("后台已停止", 409)
            target = dict(self._profile(profile_id))
            self._bind_network(target, values)
            if profile_id in self.sessions or profile_id in self._disconnecting or self._connected(target):
                raise AppError("请先断开此 VPN，再重新登录", 409)
            if self._handoff_required() or self._disconnecting:
                raise AppError("请先在原客户端断开 VPN 并退出，再新增连接", 409)
            owned_backends = {"UniVPNCS" if p["index"] == 1 else f"UVP{p['index']:03d}CS"
                              for p in self.profiles if p["id"] in self.sessions}
            anchor_check = getattr(self.bridge, "is_owned_anchor", None)
            process_rows = []
            for row in self.inventory.get("processes", []):
                try:
                    if callable(anchor_check) and anchor_check(row) is True:
                        continue
                except Exception:
                    pass
                process_rows.append(row)
            if any(p.get("name") not in owned_backends for p in process_rows):
                raise AppError("检测到其他客户端，请先退出后再新增连接", 409)
            if any(self._remote_peer(p) and p.get("process") not in owned_backends for p in self.inventory.get("peers", [])):
                raise AppError("检测到其他连接，请先断开并退出原客户端", 409)
            for index in self._available_indexes():
                if self._slot_busy(index) and not any(p["index"] == index and p["id"] in self.sessions for p in self.profiles):
                    raise AppError("检测到其他连接，请先断开并退出原客户端", 409)
            # If capacity appeared since the first click, use it directly. This
            # confirmed request still never stops another session unnecessarily.
            try:
                self._choose_index(target, legacy=False, allow_create=False)
                needs_creation = False
            except AppError:
                needs_creation = True
            restore = []
            if needs_creation:
                if _idle_only and self.sessions:
                    raise AppError("新增并发连接需要暂时断开当前连接，创建后恢复；动态口令需你填写", 409,
                                   code="expansion_required", details={"profileIds": list(self.sessions)})
                for key in self.sessions:
                    profile = self._profile(key)
                    if self._public_status(profile)[0] != "connected":
                        raise AppError("请先完成当前连接的验证，再新增并发连接", 409)
                    backend = "UniVPNCS" if profile["index"] == 1 else f"UVP{profile['index']:03d}CS"
                    rows = [p for p in process_rows if p.get("name") == backend]
                    owns_backend = getattr(self.bridge, "owns_backend", None)
                    try:
                        verified = len(rows) == 1 and (not callable(owns_backend) or owns_backend(profile, rows[0]) is True)
                    except Exception:
                        verified = False
                    try:
                        gateway = str(ipaddress.IPv4Address(profile["gateway"]))
                        addresses = {gateway}
                    except ipaddress.AddressValueError:
                        try:
                            addresses = {row[4][0] for row in socket.getaddrinfo(profile["gateway"], profile["port"], socket.AF_INET, socket.SOCK_STREAM)}
                        except (OSError, ValueError):
                            addresses = set()
                    peers = [p for p in self.inventory.get("peers", []) if p.get("process") == backend and self._remote_peer(p)]
                    if not verified or not peers or any(p.get("gateway") not in addresses or p.get("port") != profile["port"] for p in peers):
                        raise AppError("连接归属无法确认，已停止新增连接；请检查当前状态", 409)
                    if not self._has_credential(key):
                        raise AppError("当前连接未保存密码，请先保存登录信息后再新增并发连接", 409)
                    restore.append(dict(profile))
            self._expansion = operation
        stopped, failed = [], []
        operation_failed = False
        try:
            if needs_creation:
                try:
                    for profile in restore:
                        self.disconnect(profile["id"], _expansion_token=token)
                        stopped.append(profile)
                    self._wait_expansion_idle(operation, processes=False)
                    # The original multi creator requires even idle CS workers
                    # to exit. Only the bridge may release its verified owned
                    # backend, and only after a normal tunnel disconnect.
                    quiesce = getattr(self.bridge, "quiesce_owned", None)
                    for profile in stopped:
                        if callable(quiesce):
                            quiesce(profile)
                    self._wait_expansion_idle(operation)
                    with self.lock:
                        before = self._available_indexes()
                        reserved = {p["index"] for p in self.profiles if p["index"] > 0}
                    creator = getattr(self.bridge, "create_instance", None)
                    if not callable(creator):
                        raise AppError("新增连接暂不可用", 409)
                    index = creator()  # UAC and original multi work outside lock.
                    with self.lock:
                        if self._expansion is not operation or self._stop.is_set():
                            raise AppError("新增连接已取消", 409)
                        if type(index) is not int or not 1 <= index <= 999 or index in before or index in reserved:
                            raise AppError("新增连接结果无法确认", 409)
                        self._assign_index(profile_id, index)
                        self._save()
                    self._observe_expansion()
                except Exception:
                    operation_failed = True
                # A failure never spins a restoration loop. Only successfully
                # disconnected owned profiles get one saved-login attempt.
                for profile in stopped:
                    try:
                        self.connect(profile["id"], {}, allow_create=False, _expansion_token=token)
                    except Exception:
                        failed.append(profile["id"])
                if operation_failed:
                    raise AppError("新增连接未完成，已尝试恢复先前连接；请检查当前状态", 409,
                                   details={"failedProfileIds": failed})
            if _provision_only:
                with self.lock:
                    profile = self._profile(profile_id)
                    index = self._choose_index(profile, legacy=False, allow_create=False)
                    self._assign_index(profile_id, index)
                    self._save()
                return {"ok": True}
            try:
                result = self.connect(profile_id, values, allow_create=False, _expansion_token=token)
            except AppError as exc:
                if exc.code == "credentials_required":
                    raise AppError(str(exc), exc.status, code=exc.code, details={"failedProfileIds": failed}) from None
                raise
            return {**result, **({"failedProfileIds": failed} if failed else {})}
        finally:
            with self.lock:
                if self._expansion is operation:
                    self._expansion = None

    def otp(self, profile_id: str, values: dict) -> dict:
        code = values.get("code")
        if not isinstance(code, str) or not 1 <= len(code) <= 128 or "\x00" in code:
            raise AppError("请输入动态口令")
        with self.lock:
            self._profile(profile_id)
            session = self.sessions.get(profile_id)
            if not session or self.events.get(profile_id, {}).get("status") != "otp":
                raise AppError("当前没有待完成的动态校验", 409)
        try:
            session.submit_otp(code)
        except Exception:
            raise AppError("动态校验未完成，请检查当前连接", 409) from None
        return {"ok": True}

    def disconnect(self, profile_id: str, *, _expansion_token=None) -> dict:
        if not self.bridge or not getattr(self.bridge, "available", False):
            raise AppError("原生控制接口尚在验证", 409)
        with self.lock:
            self._check_expansion(_expansion_token)
            profile = dict(self._profile(profile_id))
            session = self.sessions.get(profile_id)
            if profile_id in self._disconnecting:
                raise AppError("正在断开此 VPN，请稍后操作", 409)
            if session is None and self._handoff_required():
                raise AppError("请先在原客户端断开 VPN 并退出，再由网页连接", 409)
            if not session and profile["index"] == 0:
                raise AppError("此 VPN 尚未连接", 409)
            operation = {"token": object(), "index": profile["index"], "session": session}
            self._disconnecting[profile_id] = operation
            self._attempts.pop(profile_id, None)
            self._pending_credentials.pop(profile_id, None)
            self.events[profile_id] = {"status": "disconnecting"}
        try:
            if session:
                session.disconnect()
            else:
                self.bridge.disconnect_external(profile)
        except Exception:
            with self.lock:
                if self._disconnecting.get(profile_id) is operation:
                    if self.sessions.get(profile_id) is session:
                        self.events[profile_id] = {"status": "error", "error": "断开尚未确认，请检查当前连接"}
                    self._disconnecting.pop(profile_id, None)
            raise AppError("断开尚未确认，请检查当前连接", 409) from None
        with self.lock:
            if self._disconnecting.get(profile_id) is not operation:
                raise AppError("断开结果已过期，请检查当前连接", 409)
            self._disconnecting.pop(profile_id, None)
            if self.sessions.get(profile_id) is not session or self._profile(profile_id)["index"] != operation["index"]:
                raise AppError("断开结果已过期，请检查当前连接", 409)
            if session is not None:
                self.sessions.pop(profile_id, None)
            self.events[profile_id] = {"status": "disconnected"}
        return {"ok": True}

    def forget_credential(self, profile_id):
        with self.lock:
            self._check_expansion()
            profile = self._profile(profile_id)
            self._pending_credentials.pop(profile_id, None)
            if self.credentials:
                try:
                    self.credentials.delete(profile_id)
                except Exception:
                    raise AppError("无法清除保存的密码", 409) from None
            profile["autoConnect"] = False
            # Forget only the manager's permission to reuse the old native
            # credential. The original vendor profile and key stay untouched.
            profile["useLegacyCredential"] = False
            self._save()
        return {"ok": True}

    def set_automatic(self, values):
        enabled = values.get("enabled")
        if type(enabled) is not bool:
            raise AppError("自动连接选项无效")
        with self.lock:
            self._check_expansion()
            for profile in self.profiles:
                profile["autoConnect"] = enabled
            self._save()
        return {"ok": True}

    def settings(self, values):
        with self.lock:
            self._check_expansion()
        enabled = values.get("startup")
        if type(enabled) is not bool or self.startup is None:
            raise AppError("登录启动选项不可用", 409)
        try:
            self.startup.set_enabled(enabled)
        except Exception:
            raise AppError("无法保存登录启动设置，请将程序放在固定目录", 409) from None
        return {"ok": True}

    def can_shutdown(self):
        # An external native GUI owns its own channels. Stopping this HTTP
        # process cannot disconnect those external sessions. Owned channels,
        # however, remain live until explicitly disconnected by the user.
        with self.lock:
            if self._disconnecting or self._expansion:
                return False
            for profile_id in self.sessions:
                profile = self._profile(profile_id)
                if self.events.get(profile_id, {}).get("status") != "disconnected" or self._connected(profile):
                    return False
        return True

    def close(self):
        self._stop.set()
        with self.lock:
            self._pending_credentials.clear()
            self._attempts.clear()
        # Exiting the management window is not a request to disconnect a VPN.

