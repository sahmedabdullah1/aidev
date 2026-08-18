"""Collect software stack, dependency manifests, and language signals."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from app.config import Settings

MANIFEST_NAMES = {
    "package.json",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "requirements.txt",
    "Pipfile",
    "pyproject.toml",
    "poetry.lock",
    "go.mod",
    "go.sum",
    "Cargo.toml",
    "Cargo.lock",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "composer.json",
    "Gemfile",
    "Gemfile.lock",
    "mix.exs",
    "Package.swift",
    ".nvmrc",
    ".python-version",
    ".tool-versions",
    "runtime.txt",
}

LANG_EXT = {
    ".py": "Python",
    ".js": "JavaScript",
    ".ts": "TypeScript",
    ".tsx": "TypeScript",
    ".jsx": "JavaScript",
    ".go": "Go",
    ".rs": "Rust",
    ".java": "Java",
    ".kt": "Kotlin",
    ".rb": "Ruby",
    ".php": "PHP",
    ".cs": "C#",
    ".swift": "Swift",
    ".scala": "Scala",
    ".tf": "Terraform",
    ".yml": "YAML",
    ".yaml": "YAML",
}


def _read_limited(path: Path, max_bytes: int) -> str:
    data = path.read_bytes()[:max_bytes]
    return data.decode("utf-8", errors="replace")


def _parse_package_json(text: str) -> dict[str, Any]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return {"raw_preview": text[:2000]}
    return {
        "name": data.get("name"),
        "version": data.get("version"),
        "engines": data.get("engines"),
        "scripts": list((data.get("scripts") or {}).keys()),
        "dependencies": list((data.get("dependencies") or {}).keys())[:80],
        "devDependencies": list((data.get("devDependencies") or {}).keys())[:80],
    }


def _parse_requirements(text: str) -> list[str]:
    pkgs = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        pkgs.append(line.split(";")[0].strip()[:120])
        if len(pkgs) >= 120:
            break
    return pkgs


def collect_software(repo_path: Path, settings: Settings, extra: dict[str, Any] | None = None) -> dict[str, Any]:
    manifests: list[dict[str, Any]] = []
    languages: dict[str, int] = {}
    files_seen = 0

    for path in repo_path.rglob("*"):
        if files_seen >= settings.max_files_scanned:
            break
        if not path.is_file():
            continue
        if any(p in {".git", "node_modules", "vendor", "dist", "build", ".venv", "__pycache__"} for p in path.parts):
            continue
        files_seen += 1
        ext = path.suffix.lower()
        if ext in LANG_EXT:
            languages[LANG_EXT[ext]] = languages.get(LANG_EXT[ext], 0) + 1

        if path.name in MANIFEST_NAMES or path.name.endswith(".csproj"):
            try:
                text = _read_limited(path, settings.max_file_bytes)
            except OSError:
                continue
            entry: dict[str, Any] = {
                "path": str(path.relative_to(repo_path)),
                "name": path.name,
            }
            if path.name == "package.json":
                entry["parsed"] = _parse_package_json(text)
            elif path.name == "requirements.txt":
                entry["packages"] = _parse_requirements(text)
            elif path.name in {"pyproject.toml", "go.mod", "Cargo.toml", "composer.json", "Gemfile"}:
                entry["preview"] = text[:3000]
            else:
                entry["preview"] = text[:1500]
            manifests.append(entry)

    sorted_langs = sorted(languages.items(), key=lambda x: x[1], reverse=True)
    result = {
        "languages": [{"name": n, "files": c} for n, c in sorted_langs],
        "primary_language": sorted_langs[0][0] if sorted_langs else None,
        "manifests": manifests[:60],
        "file_count_sampled": files_seen,
        "user_provided": extra or {},
    }
    return result
