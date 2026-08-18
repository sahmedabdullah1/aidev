"""Log ingestion from uploads or paths inside the cloned workspace."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from app.config import Settings

ERROR_LINE = re.compile(
    r"(?i)\b(error|exception|fatal|panic|traceback|failed|critical|oom|segfault|timeout|denied|unauthorized)\b"
)
WARN_LINE = re.compile(r"(?i)\b(warn(ing)?|deprecated)\b")


def _summarize_log_text(text: str, source: str) -> dict[str, Any]:
    lines = text.splitlines()
    errors: list[str] = []
    warnings: list[str] = []
    for line in lines:
        s = line.strip()
        if not s:
            continue
        if ERROR_LINE.search(s) and len(errors) < 40:
            errors.append(s[:400])
        elif WARN_LINE.search(s) and len(warnings) < 20:
            warnings.append(s[:300])

    tail = "\n".join(lines[-80:])[:8000]
    return {
        "source": source,
        "line_count": len(lines),
        "byte_count": len(text.encode("utf-8", errors="replace")),
        "error_lines": errors,
        "warning_lines": warnings,
        "tail": tail,
    }


def collect_logs(
    *,
    settings: Settings,
    repo_path: Path | None = None,
    log_paths: list[str] | None = None,
    uploaded_files: list[Path] | None = None,
) -> dict[str, Any]:
    digests: list[dict[str, Any]] = []

    candidates: list[Path] = []
    if uploaded_files:
        candidates.extend(uploaded_files)
    if repo_path and log_paths:
        for lp in log_paths:
            p = Path(lp)
            if not p.is_absolute():
                p = repo_path / lp
            if p.is_file():
                candidates.append(p)
    if repo_path:
        for pattern in ("**/*.log", "**/logs/**/*.txt", "**/log/**/*.txt"):
            for p in list(repo_path.glob(pattern))[:15]:
                if ".git" in p.parts or "node_modules" in p.parts:
                    continue
                candidates.append(p)

    seen: set[str] = set()
    for path in candidates:
        key = str(path.resolve()) if path.exists() else str(path)
        if key in seen:
            continue
        seen.add(key)
        if not path.is_file():
            continue
        try:
            raw = path.read_bytes()[: settings.max_log_bytes]
            text = raw.decode("utf-8", errors="replace")
        except OSError:
            continue
        source = str(path)
        if repo_path and str(path).startswith(str(repo_path)):
            source = str(path.relative_to(repo_path))
        digests.append(_summarize_log_text(text, source))

    return {
        "log_files": digests,
        "total_error_signals": sum(len(d["error_lines"]) for d in digests),
        "total_warning_signals": sum(len(d["warning_lines"]) for d in digests),
    }
