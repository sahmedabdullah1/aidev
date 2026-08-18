"""Orchestrate all collectors into one SRE evidence pack."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from app.collectors.ci_collector import collect_ci
from app.collectors.docker_collector import collect_docker
from app.collectors.git_collector import clone_repository, sanitize_repo_url
from app.collectors.git_history_collector import collect_git_history
from app.collectors.k8s_collector import collect_kubernetes
from app.collectors.logs_collector import collect_logs
from app.collectors.network_collector import collect_network
from app.collectors.runtime_collector import collect_runtime
from app.collectors.security_collector import collect_security
from app.collectors.software_collector import collect_software
from app.collectors.sre_domains import (
    collect_app_log_patterns,
    collect_cloud_iac,
    collect_database_signals,
    collect_monitoring_configs,
    collect_quality,
    collect_webserver,
)
from app.config import Settings


def _coverage(evidence: dict[str, Any]) -> list[dict[str, str]]:
    mapping = [
        ("application_logs", "logs", "app_log_patterns"),
        ("infrastructure", "runtime"),
        ("kubernetes", "kubernetes"),
        ("docker", "docker"),
        ("cicd", "ci"),
        ("git", "git_history"),
        ("server_health", "runtime"),
        ("web_server", "webserver"),
        ("database", "database"),
        ("api", "app_log_patterns"),
        ("security", "security"),
        ("performance", "runtime"),
        ("monitoring", "monitoring"),
        ("alerts", "user_metrics"),
        ("source_code", "software"),
        ("build_quality", "quality"),
        ("cloud", "cloud_iac"),
        ("business", "business_metrics"),
    ]
    rows = []
    for domain, *keys in mapping:
        present = any(evidence.get(k) for k in keys)
        status = "collected" if present else "missing"
        if domain in {"infrastructure", "server_health", "kubernetes", "docker"} and (evidence.get("runtime") or {}).get("live_probe"):
            status = "live" if present else "partial"
        rows.append({"domain": domain, "status": status, "notes": None})
    return rows


def gather_evidence(
    *,
    settings: Settings,
    repo_url: str,
    work_dir: Path,
    branch: str | None = None,
    notes: str | None = None,
    software_info: dict[str, Any] | None = None,
    ip_info: dict[str, Any] | None = None,
    metrics: dict[str, Any] | None = None,
    business_metrics: dict[str, Any] | None = None,
    monitoring_snapshot: dict[str, Any] | None = None,
    log_paths: list[str] | None = None,
    uploaded_logs: list[Path] | None = None,
    live_probe: bool = False,
    progress_cb=None,
) -> dict[str, Any]:
    def progress(msg: str) -> None:
        if progress_cb:
            progress_cb(msg)

    progress("Cloning repository")
    git_meta = clone_repository(repo_url, work_dir, branch=branch, settings=settings)
    repo_path = Path(git_meta["path"])

    progress("Collecting software & source inventory")
    software = collect_software(repo_path, settings, extra=software_info)

    progress("Scanning Docker definitions")
    docker = collect_docker(repo_path, settings)

    progress("Inspecting CI/CD pipelines")
    ci = collect_ci(repo_path, settings)

    progress("Scanning Kubernetes / Helm manifests")
    kubernetes = collect_kubernetes(repo_path, settings, live=live_probe)

    progress("Scanning cloud / Terraform IaC")
    cloud_iac = collect_cloud_iac(repo_path, settings)

    progress("Database & data-store signals")
    database = collect_database_signals(repo_path, settings)

    progress("Web server configs")
    webserver = collect_webserver(repo_path, settings)

    progress("Build quality / tests / lint")
    quality = collect_quality(repo_path, settings)

    progress("Monitoring & observability configs")
    monitoring = collect_monitoring_configs(repo_path, settings)
    if monitoring_snapshot:
        monitoring = {**monitoring, "user_snapshot": monitoring_snapshot}

    progress("Security heuristics")
    security = collect_security(repo_path, settings)

    progress("Network / IP / ports")
    network = collect_network(repo_path, settings, user_ip_info=ip_info)

    progress("Git history & risky changes")
    git_history = collect_git_history(repo_path)

    progress("Summarizing application logs")
    logs = collect_logs(
        settings=settings,
        repo_path=repo_path,
        log_paths=log_paths,
        uploaded_files=uploaded_logs,
    )
    app_log_patterns = collect_app_log_patterns(repo_path, settings, uploaded_summaries=logs.get("log_files"))

    progress("Runtime / host / live Docker probe" if live_probe else "Skipping live runtime probe")
    runtime = collect_runtime(live=live_probe)

    readme = None
    for name in ("README.md", "README.rst", "README.txt", "README"):
        p = repo_path / name
        if p.is_file():
            readme = p.read_text(encoding="utf-8", errors="replace")[:5000]
            break

    top_level = sorted(
        [p.name + ("/" if p.is_dir() else "") for p in repo_path.iterdir() if p.name != ".git"]
    )[:80]

    evidence = {
        "repo_url": sanitize_repo_url(repo_url),
        "notes": notes,
        "investigation_mode": "full_sre_rca",
        "domains_in_scope": [
            "application_logs",
            "infrastructure",
            "kubernetes",
            "docker",
            "cicd",
            "git",
            "server_health",
            "web_server",
            "database",
            "api",
            "security",
            "performance",
            "monitoring",
            "alerts",
            "source_code",
            "build_quality",
            "cloud",
            "business",
        ],
        "git": {**git_meta, "path": str(repo_path)},
        "git_history": git_history,
        "structure": {"top_level": top_level, "readme_excerpt": readme},
        "software": software,
        "docker": docker,
        "kubernetes": kubernetes,
        "ci": ci,
        "cloud_iac": cloud_iac,
        "database": database,
        "webserver": webserver,
        "quality": quality,
        "monitoring": monitoring,
        "security": security,
        "network": network,
        "logs": logs,
        "app_log_patterns": app_log_patterns,
        "runtime": runtime,
        "user_metrics": metrics or {},
        "business_metrics": business_metrics or {},
    }
    evidence["domain_coverage"] = _coverage(evidence)
    return evidence
