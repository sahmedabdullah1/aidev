"""Heuristic security scans: secrets, risky configs, insecure defaults."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from app.config import Settings

SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("AWS Access Key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("Generic API Key", re.compile(r"(?i)(api[_-]?key|apikey|secret[_-]?key)\s*[:=]\s*['\"][^'\"]{8,}['\"]")),
    ("Private Key Block", re.compile(r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("GitHub Token", re.compile(r"gh[pousr]_[A-Za-z0-9_]{20,}")),
    ("GitLab Token", re.compile(r"glpat-[A-Za-z0-9\-_]{20,}")),
    ("Slack Token", re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}")),
    ("JWT-like", re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")),
    ("Password assignment", re.compile(r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"][^'\"]{4,}['\"]")),
]

RISKY_FILES = {
    ".env",
    ".env.local",
    ".env.production",
    "credentials.json",
    "service-account.json",
    "id_rsa",
    "id_ed25519",
}

SKIP_DIRS = {".git", "node_modules", "vendor", "dist", "build", ".venv", "__pycache__", ".next"}


def collect_security(repo_path: Path, settings: Settings) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    risky_paths: list[str] = []
    scanned = 0

    for path in repo_path.rglob("*"):
        if scanned >= settings.max_files_scanned:
            break
        if not path.is_file():
            continue
        if any(p in SKIP_DIRS for p in path.parts):
            continue
        scanned += 1
        rel = str(path.relative_to(repo_path))

        if path.name in RISKY_FILES or path.name.endswith(".pem") or path.name.endswith(".key"):
            risky_paths.append(rel)
            findings.append(
                {
                    "type": "risky_file",
                    "severity": "high",
                    "path": rel,
                    "detail": f"Potentially sensitive file present: {path.name}",
                }
            )

        if path.stat().st_size > settings.max_file_bytes:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        for label, pattern in SECRET_PATTERNS:
            if pattern.search(text):
                findings.append(
                    {
                        "type": "possible_secret",
                        "severity": "critical",
                        "path": rel,
                        "detail": f"Possible {label} detected (heuristic — verify manually)",
                    }
                )
                break  # one hit per file is enough for the digest

        lower = text.lower()
        if "insecure_skip_verify" in lower or "verify=false" in lower or "ssl_verify: false" in lower:
            findings.append(
                {
                    "type": "tls_disabled",
                    "severity": "high",
                    "path": rel,
                    "detail": "TLS verification appears disabled",
                }
            )

    # Dependency risk signals (not a CVE DB — flags missing lockfiles etc.)
    lock_hints = []
    if (repo_path / "package.json").exists() and not any(
        (repo_path / n).exists() for n in ("package-lock.json", "yarn.lock", "pnpm-lock.yaml")
    ):
        lock_hints.append("Node package.json without lockfile — non-reproducible builds / supply-chain drift")
    if (repo_path / "requirements.txt").exists() and not (repo_path / "poetry.lock").exists():
        # requirements alone is ok, but note missing pins
        req = (repo_path / "requirements.txt").read_text(encoding="utf-8", errors="replace")
        if any(line.strip() and not re.search(r"[=<>~]", line) and not line.startswith("#") for line in req.splitlines()):
            lock_hints.append("Some Python requirements appear unpinned")

    return {
        "findings": findings[:100],
        "risky_files": risky_paths[:50],
        "dependency_hygiene": lock_hints,
        "files_scanned": scanned,
        "secret_hit_count": sum(1 for f in findings if f["type"] == "possible_secret"),
    }
