"""Extract IPs, hosts, ports, and network-related configuration."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from app.config import Settings

IPV4 = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)
PORT_BIND = re.compile(r"(?i)\b(?:port|listen|bind|host)\s*[:=]\s*['\"]?([^\s'\"]+)")
URL_HOST = re.compile(r"https?://([a-zA-Z0-9.-]+)(?::(\d+))?")
DOCKER_PORT = re.compile(r"['\"]?(\d{2,5}):(\d{2,5})['\"]?")

SKIP_DIRS = {".git", "node_modules", "vendor", "dist", "build", ".venv", "__pycache__"}
PRIVATE_PREFIXES = ("10.", "192.168.", "127.", "0.0.0.0", "172.16.", "172.17.", "172.18.", "172.19.", "172.2", "172.30.", "172.31.")


def _classify_ip(ip: str) -> str:
    if ip.startswith(PRIVATE_PREFIXES) or ip == "localhost":
        return "private_or_local"
    if ip.startswith("169.254."):
        return "link_local"
    return "public_or_external"


def collect_network(
    repo_path: Path,
    settings: Settings,
    user_ip_info: dict[str, Any] | None = None,
) -> dict[str, Any]:
    ips: dict[str, set[str]] = {}
    hosts: set[str] = set()
    ports: set[str] = set()
    bindings: list[dict[str, str]] = []
    scanned = 0

    for path in repo_path.rglob("*"):
        if scanned >= settings.max_files_scanned:
            break
        if not path.is_file():
            continue
        if any(p in SKIP_DIRS for p in path.parts):
            continue
        if path.suffix.lower() in {".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".pdf", ".zip", ".gz", ".woff", ".woff2"}:
            continue
        scanned += 1
        if path.stat().st_size > settings.max_file_bytes:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        rel = str(path.relative_to(repo_path))
        for ip in IPV4.findall(text):
            # skip version-like false positives somewhat
            if ip.startswith("0.") and ip.count(".") == 3:
                parts = ip.split(".")
                if all(p.isdigit() and int(p) < 100 for p in parts):
                    # still keep 0.0.0.0
                    if ip != "0.0.0.0":
                        continue
            kind = _classify_ip(ip)
            ips.setdefault(kind, set()).add(ip)
            if len(bindings) < 80:
                bindings.append({"file": rel, "ip": ip, "kind": kind})

        for m in URL_HOST.finditer(text):
            hosts.add(m.group(1).lower())
            if m.group(2):
                ports.add(m.group(2))

        for m in DOCKER_PORT.finditer(text):
            ports.add(m.group(1))
            ports.add(m.group(2))

        for m in PORT_BIND.finditer(text):
            val = m.group(1)
            if val.isdigit() and 1 <= int(val) <= 65535:
                ports.add(val)

    return {
        "ips": {k: sorted(v)[:50] for k, v in ips.items()},
        "hosts": sorted(hosts)[:100],
        "ports": sorted(ports, key=lambda x: int(x) if x.isdigit() else 0)[:80],
        "sample_bindings": bindings[:60],
        "user_provided": user_ip_info or {},
        "files_scanned": scanned,
    }
