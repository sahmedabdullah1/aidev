"""GitLab webhook handler — push / merge request → investigation job."""

from __future__ import annotations

from typing import Any

from fastapi import Header, HTTPException, Request

from app.config import get_settings
from app.models.schemas import WebhookAck
from app.services.investigation import investigation_service


def _project_http_url(payload: dict[str, Any]) -> str | None:
    project = payload.get("project") or {}
    return (
        project.get("git_http_url")
        or project.get("http_url")
        or project.get("web_url")
        or (payload.get("repository") or {}).get("git_http_url")
        or (payload.get("repository") or {}).get("url")
    )


def _branch_from_ref(ref: str | None) -> str | None:
    if not ref:
        return None
    for prefix in ("refs/heads/", "refs/tags/"):
        if ref.startswith(prefix):
            return ref[len(prefix) :]
    return ref


async def handle_gitlab_webhook(
    payload: dict[str, Any],
    token: str | None = None,
    header_token: str | None = None,
) -> WebhookAck:
    settings = get_settings()
    provided = header_token or token
    if settings.gitlab_webhook_secret:
        if not provided or provided != settings.gitlab_webhook_secret:
            raise HTTPException(401, "Invalid GitLab webhook token")

    event = payload.get("object_kind") or payload.get("event_name") or "unknown"
    repo_url = _project_http_url(payload)
    if not repo_url:
        return WebhookAck(accepted=False, job_id=None, message="No repository URL in payload")

    branch = None
    notes_parts = [f"GitLab event: {event}"]

    if event in {"push", "tag_push"}:
        branch = _branch_from_ref(payload.get("ref"))
        commits = payload.get("commits") or []
        notes_parts.append(f"Push to {branch or payload.get('ref')} with {len(commits)} commit(s)")
        if commits:
            last = commits[-1]
            notes_parts.append(f"Latest: {last.get('id', '')[:8]} — {last.get('message', '')[:200]}")
        trigger = "gitlab_push"
    elif event in {"merge_request", "merge_request_event"}:
        attrs = payload.get("object_attributes") or {}
        branch = attrs.get("source_branch")
        notes_parts.append(
            f"MR !{attrs.get('iid')} {attrs.get('title')} "
            f"({attrs.get('source_branch')} → {attrs.get('target_branch')}) action={attrs.get('action')}"
        )
        trigger = "gitlab_mr"
        # Prefer MR source project URL if present
        source = (payload.get("object_attributes") or {}).get("source") or {}
        repo_url = source.get("git_http_url") or source.get("http_url") or repo_url
    else:
        notes_parts.append("Unhandled event kind — still investigating default branch HEAD")
        trigger = f"gitlab_{event}"

    user = payload.get("user_name") or payload.get("user_username") or (payload.get("user") or {}).get("name")
    if user:
        notes_parts.append(f"Triggered by {user}")

    job_id = await investigation_service.enqueue(
        repo_url=repo_url,
        branch=branch,
        notes="\n".join(notes_parts),
        trigger=trigger,
    )
    return WebhookAck(
        accepted=True,
        job_id=job_id,
        message=f"Investigation queued for {repo_url} ({event})",
    )


async def gitlab_webhook_endpoint(
    request: Request,
    x_gitlab_token: str | None = Header(default=None, alias="X-Gitlab-Token"),
) -> WebhookAck:
    payload = await request.json()
    return await handle_gitlab_webhook(payload, header_token=x_gitlab_token)
