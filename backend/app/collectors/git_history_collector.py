"""Recent git history and risky change signals."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from git import Repo
from git.exc import InvalidGitRepositoryError


RISKY_PATH_HINTS = (
    "Dockerfile",
    "docker-compose",
    ".gitlab-ci",
    ".github/workflows",
    "k8s/",
    "kubernetes/",
    "helm/",
    "terraform",
    ".tf",
    "Chart.yaml",
    ".env",
    "secret",
    "iam",
    "firewall",
    "nginx",
    "migration",
)


def collect_git_history(repo_path: Path, limit: int = 25) -> dict[str, Any]:
    try:
        repo = Repo(repo_path)
    except InvalidGitRepositoryError:
        return {"commits": [], "risky_commits": [], "error": "not a git repo"}

    commits = []
    risky = []
    for c in list(repo.iter_commits(max_count=limit)):
        files = []
        try:
            files = list(c.stats.files.keys())[:40]
        except Exception:  # noqa: BLE001
            files = []
        entry = {
            "sha": c.hexsha[:8],
            "author": str(c.author),
            "message": (c.message or "").strip().splitlines()[0][:200],
            "date": c.committed_datetime.isoformat(),
            "files": files,
        }
        commits.append(entry)
        risky_files = [f for f in files if any(h.lower() in f.lower() for h in RISKY_PATH_HINTS)]
        msg = (c.message or "").lower()
        if risky_files or any(w in msg for w in ("hotfix", "rollback", "outage", "incident", "revert", "password", "secret")):
            risky.append({**entry, "risky_files": risky_files})

    return {
        "commits": commits,
        "risky_commits": risky[:15],
        "active_branch": repo.active_branch.name if not repo.head.is_detached else None,
    }
