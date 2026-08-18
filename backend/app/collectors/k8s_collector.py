"""Kubernetes manifest scan + optional live kubectl probe."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

import yaml

from app.config import Settings

K8S_KINDS = {
    "Deployment",
    "StatefulSet",
    "DaemonSet",
    "Job",
    "CronJob",
    "Service",
    "Ingress",
    "ConfigMap",
    "Secret",
    "HorizontalPodAutoscaler",
    "PodDisruptionBudget",
    "NetworkPolicy",
    "PersistentVolumeClaim",
    "ServiceAccount",
    "Role",
    "RoleBinding",
    "ClusterRole",
    "ClusterRoleBinding",
}

PROBLEM_RE = re.compile(
    r"(CrashLoopBackOff|ImagePullBackOff|ErrImagePull|OOMKilled|CreateContainerConfigError|"
    r"FailedScheduling|Liveness|Readiness|Back-off|Evicted|NodeNotReady)",
    re.I,
)


def _load_docs(text: str) -> list[dict[str, Any]]:
    docs: list[dict[str, Any]] = []
    try:
        for doc in yaml.safe_load_all(text):
            if isinstance(doc, dict):
                docs.append(doc)
    except yaml.YAMLError:
        pass
    return docs


def collect_kubernetes(repo_path: Path, settings: Settings, *, live: bool = False) -> dict[str, Any]:
    manifests: list[dict[str, Any]] = []
    issues: list[dict[str, Any]] = []
    kinds: dict[str, int] = {}

    patterns = [
        "**/*.yaml",
        "**/*.yml",
        "**/k8s/**/*",
        "**/kubernetes/**/*",
        "**/deploy/**/*",
        "**/manifests/**/*",
        "**/charts/**/*.yaml",
    ]
    seen: set[str] = set()
    for pattern in patterns:
        for path in repo_path.glob(pattern):
            if not path.is_file() or ".git" in path.parts or "node_modules" in path.parts:
                continue
            rel = str(path.relative_to(repo_path))
            if rel in seen:
                continue
            seen.add(rel)
            if path.stat().st_size > settings.max_file_bytes:
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            docs = _load_docs(text)
            k8s_docs = [d for d in docs if str(d.get("kind") or "") in K8S_KINDS or "apiVersion" in d]
            if not k8s_docs and "kind:" not in text:
                continue
            for doc in k8s_docs or [{"raw": True}]:
                kind = str(doc.get("kind") or "Unknown")
                kinds[kind] = kinds.get(kind, 0) + 1
                name = ((doc.get("metadata") or {}) if isinstance(doc, dict) else {}).get("name")
                entry = {"path": rel, "kind": kind, "name": name}
                # Probe probes / resources
                if kind in {"Deployment", "StatefulSet", "DaemonSet"}:
                    spec = ((doc.get("spec") or {}).get("template") or {}).get("spec") or {}
                    containers = spec.get("containers") or []
                    for c in containers:
                        if not isinstance(c, dict):
                            continue
                        if not c.get("livenessProbe") and not c.get("readinessProbe"):
                            issues.append(
                                {
                                    "type": "missing_probes",
                                    "severity": "medium",
                                    "path": rel,
                                    "detail": f"Container {c.get('name')} missing liveness/readiness probes",
                                }
                            )
                        resources = c.get("resources") or {}
                        if not resources.get("limits") or not resources.get("requests"):
                            issues.append(
                                {
                                    "type": "missing_resources",
                                    "severity": "medium",
                                    "path": rel,
                                    "detail": f"Container {c.get('name')} missing CPU/memory requests/limits",
                                }
                            )
                        image = str(c.get("image") or "")
                        if image.endswith(":latest") or (":" not in image and image):
                            issues.append(
                                {
                                    "type": "latest_tag",
                                    "severity": "high",
                                    "path": rel,
                                    "detail": f"Image uses mutable/latest tag: {image}",
                                }
                            )
                if kind == "Secret":
                    issues.append(
                        {
                            "type": "secret_manifest",
                            "severity": "high",
                            "path": rel,
                            "detail": "Kubernetes Secret manifest present — verify not storing plaintext in git",
                        }
                    )
                manifests.append({**entry, "preview": text[:2000]})
                if len(manifests) >= 40:
                    break
            if len(manifests) >= 40:
                break

    live_data: dict[str, Any] = {"enabled": live, "available": False}
    if live and shutil.which("kubectl"):
        live_data["available"] = True
        for cmd, key in [
            (["kubectl", "get", "pods", "-A", "-o", "json"], "pods"),
            (["kubectl", "get", "events", "-A", "--sort-by=.lastTimestamp"], "events"),
            (["kubectl", "get", "deployments", "-A", "-o", "json"], "deployments"),
        ]:
            try:
                out = subprocess.run(cmd, capture_output=True, text=True, timeout=15, check=False)
                if out.returncode != 0:
                    live_data[key] = {"error": out.stderr[:500]}
                    continue
                if key == "events":
                    lines = out.stdout.splitlines()[-40:]
                    live_data[key] = {"tail": lines}
                    for line in lines:
                        if PROBLEM_RE.search(line):
                            issues.append(
                                {
                                    "type": "live_event",
                                    "severity": "high",
                                    "path": "kubectl events",
                                    "detail": line[:300],
                                }
                            )
                else:
                    data = json.loads(out.stdout)
                    items = data.get("items") or []
                    summary = []
                    for item in items[:60]:
                        meta = item.get("metadata") or {}
                        status = item.get("status") or {}
                        phase = status.get("phase")
                        row = {
                            "namespace": meta.get("namespace"),
                            "name": meta.get("name"),
                            "phase": phase,
                        }
                        if key == "pods":
                            for cs in status.get("containerStatuses") or []:
                                state = cs.get("state") or {}
                                waiting = (state.get("waiting") or {}).get("reason")
                                term = (state.get("terminated") or {}).get("reason")
                                restarts = cs.get("restartCount")
                                if waiting or term in {"OOMKilled", "Error"} or (restarts or 0) > 3:
                                    issues.append(
                                        {
                                            "type": "pod_problem",
                                            "severity": "critical" if waiting in {"CrashLoopBackOff", "ImagePullBackOff"} or term == "OOMKilled" else "high",
                                            "path": f"{meta.get('namespace')}/{meta.get('name')}",
                                            "detail": f"waiting={waiting} terminated={term} restarts={restarts}",
                                        }
                                    )
                                row["restarts"] = restarts
                                row["waiting"] = waiting
                                row["terminated"] = term
                        summary.append(row)
                    live_data[key] = summary
            except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError) as exc:
                live_data[key] = {"error": str(exc)[:300]}

    return {
        "manifest_count": len(manifests),
        "kinds": kinds,
        "manifests": manifests[:40],
        "issues": issues[:80],
        "live": live_data,
        "has_k8s": bool(manifests) or bool(live_data.get("available")),
    }
