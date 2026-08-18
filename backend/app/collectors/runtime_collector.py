"""Host health + live Docker runtime probe."""

from __future__ import annotations

import json
import platform
import shutil
import subprocess
from typing import Any


def _run(cmd: list[str], timeout: int = 12) -> tuple[int, str, str]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
        return p.returncode, p.stdout, p.stderr
    except (subprocess.TimeoutExpired, OSError) as exc:
        return 1, "", str(exc)


def collect_host_health() -> dict[str, Any]:
    info: dict[str, Any] = {
        "platform": platform.platform(),
        "python": platform.python_version(),
        "processor": platform.processor(),
    }
    # Prefer portable commands
    code, out, _ = _run(["uptime"])
    if code == 0:
        info["uptime"] = out.strip()
    code, out, _ = _run(["df", "-h"])
    if code == 0:
        info["disk"] = out.strip().splitlines()[:12]
    code, out, _ = _run(["vm_stat"])  # macOS
    if code == 0:
        info["memory_vm_stat"] = out.strip().splitlines()[:20]
    else:
        code, out, _ = _run(["free", "-m"])
        if code == 0:
            info["memory_free"] = out.strip().splitlines()[:8]
    code, out, _ = _run(["ps", "aux"])
    if code == 0:
        lines = out.splitlines()
        info["top_processes"] = lines[:1] + lines[1:16]
    return info


def collect_docker_runtime(*, live: bool = False) -> dict[str, Any]:
    result: dict[str, Any] = {"available": bool(shutil.which("docker")), "live": live}
    if not live or not result["available"]:
        return result

    issues: list[dict[str, Any]] = []
    code, out, err = _run(["docker", "ps", "-a", "--format", "{{json .}}"])
    containers = []
    if code == 0:
        for line in out.splitlines():
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            containers.append(row)
            status = str(row.get("Status") or "")
            if "Restarting" in status or "Exited" in status:
                issues.append(
                    {
                        "type": "container_unhealthy",
                        "severity": "high",
                        "detail": f"{row.get('Names')}: {status}",
                        "path": row.get("ID"),
                    }
                )
    else:
        result["error"] = err[:400]

    code, out, _ = _run(["docker", "stats", "--no-stream", "--format", "{{json .}}"])
    stats = []
    if code == 0:
        for line in out.splitlines():
            try:
                stats.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    # Sample logs from unhealthy / recent containers
    log_samples = []
    for c in containers[:8]:
        name = c.get("Names") or c.get("ID")
        if not name:
            continue
        code, out, _ = _run(["docker", "logs", "--tail", "40", str(name)], timeout=8)
        if code == 0 and out.strip():
            log_samples.append({"container": name, "tail": out[-3000:]})

    result.update(
        {
            "containers": containers[:40],
            "stats": stats[:40],
            "log_samples": log_samples,
            "issues": issues[:40],
        }
    )
    return result


def collect_runtime(*, live: bool = False) -> dict[str, Any]:
    return {
        "host": collect_host_health() if live else {"enabled": False},
        "docker_runtime": collect_docker_runtime(live=live),
        "live_probe": live,
    }
