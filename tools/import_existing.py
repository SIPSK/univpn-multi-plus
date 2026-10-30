"""Remember only network endpoints of already-running native instances."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from core import Manager, hidden_kwargs, powershell_path
from server import protect_runtime


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--runtime-dir", type=Path, default=Path(os.environ["LOCALAPPDATA"]) / "UniVPNManager")
    args = parser.parse_args()
    runtime = args.runtime_dir.resolve()
    protect_runtime(runtime)
    result = subprocess.run([powershell_path(), "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(ROOT / "tools/inspect.ps1")], capture_output=True, timeout=20, **hidden_kwargs())
    if result.returncode:
        raise SystemExit("无法读取原生连接元数据；没有修改配置。")
    inventory = json.loads(result.stdout.decode("utf-8-sig"))
    manager = Manager(runtime, inspect=False)
    indexes = [1] if inventory.get("installed") else []
    indexes += [r["index"] for r in inventory.get("records", []) if r.get("status") == "Ready"]
    imported = []
    for index in sorted(set(indexes)):
        backend = "UniVPNCS" if index == 1 else f"UVP{index:03d}CS"
        peers = {(p["gateway"], int(p["port"])) for p in inventory.get("peers", []) if p.get("process") == backend}
        if len(peers) != 1:
            continue
        gateway, port = next(iter(peers))
        existing = next((p for p in manager.profiles if p["index"] == index), None)
        if existing:
            existing.update(gateway=gateway, port=port)
        else:
            manager.profiles.append({"id": f"vpn-{index}", "name": "", "gateway": gateway, "port": port, "index": index})
        imported.append(f"{gateway}:{port}")
    if not imported:
        raise SystemExit("未找到唯一可识别的已连接网关；没有修改配置。")
    manager._save()
    print(json.dumps({"path": str(manager.path), "gateways": imported}, ensure_ascii=False))


if __name__ == "__main__":
    main()
