"""Docker / container / compose discovery."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from app.config import Settings

DOCKER_FILES = {
    "Dockerfile",
    "dockerfile",
    "Containerfile",
    "docker-compose.yml",
    "docker-compose.yaml",
    "compose.yml",
    "compose.yaml",
}


def collect_docker(repo_path: Path, settings: Settings) -> dict[str, Any]:
    files: list[dict[str, Any]] = []
    services: list[str] = []
    images: list[str] = []
    ports: list[str] = []

    for path in repo_path.rglob("*"):
        if not path.is_file():
            continue
        if any(p in {".git", "node_modules", "vendor"} for p in path.parts):
            continue
        name = path.name
        if name not in DOCKER_FILES and not name.startswith("Dockerfile"):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")[: settings.max_file_bytes]
        except OSError:
            continue
        rel = str(path.relative_to(repo_path))
        entry: dict[str, Any] = {"path": rel, "name": name, "preview": text[:4000]}

        if "compose" in name.lower() or name in {"compose.yml", "compose.yaml"}:
            try:
                data = yaml.safe_load(text) or {}
                svc = (data.get("services") or {}) if isinstance(data, dict) else {}
                for svc_name, cfg in svc.items():
                    services.append(svc_name)
                    if isinstance(cfg, dict):
                        if img := cfg.get("image"):
                            images.append(str(img))
                        for p in cfg.get("ports") or []:
                            ports.append(str(p))
            except yaml.YAMLError:
                pass
        else:
            for line in text.splitlines():
                if line.strip().upper().startswith("FROM "):
                    images.append(line.strip()[5:].strip())
                if line.strip().upper().startswith("EXPOSE "):
                    ports.append(line.strip()[7:].strip())

        files.append(entry)

    return {
        "dockerfiles": files,
        "compose_services": sorted(set(services)),
        "images": sorted(set(images)),
        "exposed_ports": sorted(set(ports)),
        "has_containers": bool(files),
    }
