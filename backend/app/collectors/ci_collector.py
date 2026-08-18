"""CI/CD pipeline and infrastructure-as-code discovery."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from app.config import Settings

CI_GLOBS = [
    ".gitlab-ci.yml",
    ".github/workflows",
    ".circleci",
    "Jenkinsfile",
    "azure-pipelines.yml",
    "bitbucket-pipelines.yml",
    ".travis.yml",
    "buildkite.yml",
    "cloudbuild.yaml",
    "tekton",
    ".drone.yml",
]


def collect_ci(repo_path: Path, settings: Settings) -> dict[str, Any]:
    pipelines: list[dict[str, Any]] = []
    platforms: set[str] = set()

    gitlab_ci = repo_path / ".gitlab-ci.yml"
    if gitlab_ci.is_file():
        platforms.add("GitLab CI")
        text = gitlab_ci.read_text(encoding="utf-8", errors="replace")[: settings.max_file_bytes]
        jobs: list[str] = []
        stages: list[str] = []
        try:
            data = yaml.safe_load(text) or {}
            if isinstance(data, dict):
                stages = list(data.get("stages") or [])
                for key, val in data.items():
                    if key.startswith(".") or key in {"stages", "variables", "include", "workflow", "default", "image"}:
                        continue
                    if isinstance(val, dict) and ("script" in val or "extends" in val or "stage" in val):
                        jobs.append(key)
        except yaml.YAMLError:
            pass
        pipelines.append(
            {
                "platform": "GitLab CI",
                "path": ".gitlab-ci.yml",
                "stages": stages,
                "jobs": jobs[:80],
                "preview": text[:3500],
            }
        )

    gh = repo_path / ".github" / "workflows"
    if gh.is_dir():
        platforms.add("GitHub Actions")
        for wf in sorted(gh.glob("*.y*ml"))[:30]:
            text = wf.read_text(encoding="utf-8", errors="replace")[: settings.max_file_bytes]
            pipelines.append(
                {
                    "platform": "GitHub Actions",
                    "path": str(wf.relative_to(repo_path)),
                    "preview": text[:3000],
                }
            )

    for name in ("Jenkinsfile", "azure-pipelines.yml", "bitbucket-pipelines.yml", ".travis.yml", ".drone.yml"):
        p = repo_path / name
        if p.is_file():
            platforms.add(name)
            pipelines.append(
                {
                    "platform": name,
                    "path": name,
                    "preview": p.read_text(encoding="utf-8", errors="replace")[:3000],
                }
            )

    # Terraform / K8s hints
    iac: list[str] = []
    for pattern in ("**/*.tf", "**/Chart.yaml", "**/kustomization.yaml", "**/helmfile.yaml"):
        for path in list(repo_path.glob(pattern))[:40]:
            if ".git" in path.parts:
                continue
            iac.append(str(path.relative_to(repo_path)))

    return {
        "platforms": sorted(platforms),
        "pipelines": pipelines,
        "iac_files": iac[:80],
        "has_ci": bool(pipelines),
    }
