"""Git repository acquisition and metadata."""

from __future__ import annotations

import re
import shutil
from pathlib import Path
from typing import Any
from urllib.parse import urlparse, urlunparse

from git import Repo
from git.exc import GitCommandError

from app.config import Settings


SECRET_IN_URL = re.compile(r"(://)([^:@/]+):([^@/]+)@")


def sanitize_repo_url(url: str) -> str:
    """Strip credentials from a git URL for safe display/storage."""
    return SECRET_IN_URL.sub(r"\1***:***@", url.strip())


def inject_token(url: str, token: str | None) -> str:
    if not token:
        return url.strip()
    parsed = urlparse(url.strip())
    if parsed.scheme not in ("http", "https"):
        return url.strip()
    # oauth2:token@host for GitLab private repos
    netloc = f"oauth2:{token}@{parsed.hostname}"
    if parsed.port:
        netloc += f":{parsed.port}"
    return urlunparse(parsed._replace(netloc=netloc))


def clone_repository(
    repo_url: str,
    dest: Path,
    *,
    branch: str | None,
    settings: Settings,
    token: str | None = None,
) -> dict[str, Any]:
    if dest.exists():
        shutil.rmtree(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)

    auth_url = inject_token(repo_url, token or settings.gitlab_token or None)
    kwargs: dict[str, Any] = {
        "url": auth_url,
        "to_path": str(dest),
        "depth": settings.max_clone_depth,
        "single_branch": True,
    }
    if branch:
        kwargs["branch"] = branch

    try:
        repo = Repo.clone_from(**kwargs)
    except GitCommandError as exc:
        # Retry without depth for repos that reject shallow clones
        kwargs.pop("depth", None)
        try:
            repo = Repo.clone_from(**kwargs)
        except GitCommandError:
            raise RuntimeError(f"Failed to clone repository: {exc}") from exc

    head = repo.head.commit
    remotes = [r.url for r in repo.remotes]
    return {
        "path": str(dest),
        "branch": branch or (repo.active_branch.name if not repo.head.is_detached else None),
        "commit": head.hexsha,
        "commit_short": head.hexsha[:8],
        "author": str(head.author),
        "message": (head.message or "").strip()[:500],
        "committed_date": head.committed_datetime.isoformat(),
        "remotes": [sanitize_repo_url(u) for u in remotes],
        "is_dirty": repo.is_dirty(),
    }
