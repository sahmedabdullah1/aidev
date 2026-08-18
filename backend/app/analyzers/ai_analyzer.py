"""SRE / DevOps AI analyzer — LLM-only reports (no hardcoded findings)."""

from __future__ import annotations

import json
import re
import uuid
from datetime import datetime, timezone
from typing import Any

from app.analyzers.llm_client import (
    LLMAnalysisError,
    LLMNotConfiguredError,
    chat_json,
    evidence_budget_chars,
    resolve_llm_settings,
)
from app.config import Settings
from app.models.schemas import (
    DevOpsReport,
    DomainCoverage,
    Finding,
    FindingCategory,
    ReportSection,
    Severity,
)

SYSTEM_PROMPT = """You are an expert DevOps/SRE engineer responsible for monitoring, troubleshooting,
and performing root cause analysis across an application's entire infrastructure.

You receive a structured EVIDENCE pack that may include: application logs, infrastructure/host
metrics, Kubernetes manifests + live pod/events, Docker definitions + live containers, CI/CD,
git history, web server configs, database signals, API/error patterns, security findings,
performance signals, monitoring configs, alerts/metrics snapshots, source code/IaC, build quality,
cloud IaC, and business metrics.

MISSION:
- ALL analysis, findings, scores, recommendations, and summaries MUST come from your reasoning
  over the evidence. Do not invent metrics, pods, or logs that are not present.
- Correlate across sources. Do NOT list isolated symptoms when a single root cause explains them.
- Prefer the most likely primary root cause with a confidence score.
- Be specific (paths, services, events, commit SHAs) using only provided evidence.
- If a domain has no data, mark it missing and recommend what to collect — do not fabricate it.
- Flag CrashLoopBackOff, ImagePullBackOff, OOMKilled, secret leaks, open CIDRs, missing probes,
  payment/auth failures, DB deadlocks, 5xx spikes, SSL issues, pipeline failures when evidenced.

Return ONLY valid JSON:
{
  "executive_summary": "3-8 sentences covering overall health + primary RCA",
  "health_score": 0-100,
  "risk_level": "critical|high|medium|low|info",
  "primary_root_cause": "one sentence",
  "correlated_timeline": ["ordered event bullets correlating deploys/logs/metrics"],
  "domain_coverage": [
    {"domain": "application_logs|infrastructure|kubernetes|docker|cicd|git|server_health|web_server|database|api|security|performance|monitoring|alerts|source_code|build_quality|cloud|business",
     "status": "collected|partial|missing|live",
     "notes": "string or null"}
  ],
  "sections": [
    {
      "title": "string",
      "summary": "string",
      "findings": [
        {
          "title": "short issue title",
          "category": "application_logs|infrastructure|kubernetes|docker|cicd|git|server_health|web_server|database|api|security|performance|monitoring|alerts|source_code|build_quality|cloud|business|improvement",
          "severity": "critical|high|medium|low|info",
          "executive_summary": "2-3 sentence exec summary of this issue",
          "affected_services": ["service names"],
          "what_happened": "symptom narrative",
          "root_cause": "most likely root cause after correlation",
          "evidence": "logs/metrics/events/commits cited",
          "impact": "user/business impact",
          "recommendation": "primary fix summary",
          "recommended_fixes": ["actionable fix 1", "fix 2"],
          "preventive_measures": ["prevention 1"],
          "related_components": ["related services/components"],
          "confidence_score": 0-100,
          "file_path": "path or null",
          "effort": "low|medium|high"
        }
      ]
    }
  ],
  "quick_wins": ["string"],
  "roadmap": ["30/60/90 style ordered items"]
}

Required sections (include even if empty findings):
1) Critical Incidents & Outages
2) Application Logs & Errors
3) Kubernetes & Containers
4) CI/CD & Deployments
5) Database & Data Stores
6) Security & Compliance
7) Performance & API Reliability
8) Infrastructure, Cloud & Network
9) Observability, Alerts & Business Impact
10) Source Code, Build Quality & Improvements

Limit to ~20 highest-value findings. Merge duplicates into correlated RCAs.
"""


def _truncate_evidence(evidence: dict[str, Any], max_chars: int) -> str:
    payload = json.dumps(evidence, default=str, indent=2)
    if len(payload) <= max_chars:
        return payload

    slim = json.loads(payload)
    for key in ("docker", "ci", "software", "structure", "kubernetes", "monitoring", "webserver", "cloud_iac"):
        node = slim.get(key)
        if not isinstance(node, dict):
            continue
        for list_key in ("dockerfiles", "pipelines", "manifests", "configs", "iac_files"):
            items = node.get(list_key)
            if isinstance(items, list):
                node[list_key] = items[:12]
                for f in node[list_key]:
                    if isinstance(f, dict) and "preview" in f:
                        f["preview"] = str(f["preview"])[:400]
        if "readme_excerpt" in node and node["readme_excerpt"]:
            node["readme_excerpt"] = str(node["readme_excerpt"])[:800]

    if isinstance(slim.get("logs"), dict):
        log_files = slim["logs"].get("log_files") or []
        slim["logs"]["log_files"] = log_files[:6]
        for lf in slim["logs"]["log_files"]:
            if isinstance(lf, dict):
                lf["tail"] = str(lf.get("tail") or "")[:800]
                lf["error_lines"] = (lf.get("error_lines") or [])[:10]

    if isinstance(slim.get("git_history"), dict):
        slim["git_history"]["commits"] = (slim["git_history"].get("commits") or [])[:10]
        slim["git_history"]["risky_commits"] = (slim["git_history"].get("risky_commits") or [])[:6]

    runtime = slim.get("runtime") or {}
    docker_rt = runtime.get("docker_runtime") if isinstance(runtime, dict) else None
    if isinstance(docker_rt, dict):
        docker_rt["containers"] = (docker_rt.get("containers") or [])[:10]
        docker_rt["log_samples"] = (docker_rt.get("log_samples") or [])[:4]
        for ls in docker_rt["log_samples"]:
            if isinstance(ls, dict) and "tail" in ls:
                ls["tail"] = str(ls["tail"])[:600]

    # Drop bulky unused keys last
    for drop in ("structure",):
        if len(json.dumps(slim, default=str)) > max_chars and drop in slim:
            slim.pop(drop, None)

    payload = json.dumps(slim, default=str, indent=2)
    if len(payload) > max_chars:
        payload = payload[:max_chars] + "\n... [truncated for LLM context budget]"
    return payload


def _extract_json(text: str) -> dict[str, Any]:
    text = text.strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text)
        text = re.sub(r"\s*```$", "", text)
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        match = re.search(r"\{[\s\S]*\}", text)
        if not match:
            raise LLMAnalysisError("LLM did not return valid JSON")
        return json.loads(match.group(0))


def _parse_category(raw: str | None) -> FindingCategory:
    try:
        return FindingCategory(raw or "improvement")
    except Exception:  # noqa: BLE001
        return FindingCategory.improvement


def _parse_finding(f: dict[str, Any]) -> Finding | None:
    try:
        what = f.get("what_happened") or f.get("description") or ""
        fixes = list(f.get("recommended_fixes") or [])
        if not fixes and f.get("recommendation"):
            fixes = [f["recommendation"]]
        return Finding(
            id=uuid.uuid4().hex[:10],
            title=f.get("title") or "Finding",
            category=_parse_category(f.get("category")),
            severity=Severity(f.get("severity") or "info"),
            executive_summary=f.get("executive_summary") or what,
            affected_services=list(f.get("affected_services") or []),
            what_happened=what,
            root_cause=f.get("root_cause") or "",
            evidence=f.get("evidence"),
            impact=f.get("impact") or "",
            recommendation=f.get("recommendation") or (fixes[0] if fixes else ""),
            recommended_fixes=fixes,
            preventive_measures=list(f.get("preventive_measures") or []),
            related_components=list(f.get("related_components") or []),
            confidence_score=max(0, min(100, int(f.get("confidence_score") or 70))),
            file_path=f.get("file_path"),
            description=what,
            effort=f.get("effort"),
        )
    except Exception:  # noqa: BLE001
        return None


def _validate_ai_payload(data: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(data, dict):
        raise LLMAnalysisError("LLM JSON root must be an object")
    if not data.get("executive_summary"):
        raise LLMAnalysisError("LLM response missing executive_summary")
    if not isinstance(data.get("sections"), list) or not data["sections"]:
        raise LLMAnalysisError("LLM response missing sections[]")
    # Reject obvious leftover fallback markers
    notes = str(data.get("raw_ai_notes") or "")
    if notes.startswith("fallback:"):
        raise LLMAnalysisError("Refusing hardcoded fallback payload")
    return data


async def analyze_with_ai(evidence: dict[str, Any], settings: Settings) -> dict[str, Any]:
    """Always call the configured LLM. Never return hardcoded findings."""
    s = resolve_llm_settings(settings)
    if not s.llm_api_key:
        raise LLMNotConfiguredError(
            "LLM_API_KEY / GROQ_API_KEY is required. "
            "Create a free key at https://console.groq.com/keys and add it to .env"
        )

    budget = evidence_budget_chars(s)
    user_content = (
        "Perform a full SRE root-cause investigation. Correlate across all domains in the evidence. "
        "Produce the JSON report schema exactly. Every finding must be derived from the evidence.\n\n"
        f"EVIDENCE:\n{_truncate_evidence(evidence, budget)}"
    )

    try:
        content = await chat_json(settings=s, system=SYSTEM_PROMPT, user=user_content)
        data = _validate_ai_payload(_extract_json(content))
        data["raw_ai_notes"] = f"llm:ok provider={s.llm_base_url} model={s.llm_model}"
        return data
    except (LLMNotConfiguredError, LLMAnalysisError):
        raise
    except Exception as exc:  # noqa: BLE001
        raise LLMAnalysisError(f"LLM analysis failed: {exc}") from exc


def build_report_model(
    *,
    job_id: str,
    evidence: dict[str, Any],
    ai_payload: dict[str, Any],
) -> DevOpsReport:
    report_id = uuid.uuid4().hex[:12]
    sections: list[ReportSection] = []
    for sec in ai_payload.get("sections") or []:
        findings = [f for f in (_parse_finding(x) for x in (sec.get("findings") or [])) if f]
        sections.append(
            ReportSection(
                title=sec.get("title") or "Section",
                summary=sec.get("summary") or "",
                findings=findings,
            )
        )

    try:
        risk = Severity(ai_payload.get("risk_level") or "medium")
    except Exception:  # noqa: BLE001
        risk = Severity.medium

    coverage_raw = ai_payload.get("domain_coverage") or evidence.get("domain_coverage") or []
    coverage: list[DomainCoverage] = []
    for row in coverage_raw:
        try:
            coverage.append(
                DomainCoverage(
                    domain=str(row.get("domain")),
                    status=str(row.get("status") or "missing"),
                    notes=row.get("notes"),
                )
            )
        except Exception:  # noqa: BLE001
            continue

    facts = {
        "llm": {
            "source": "live_llm_only",
            "notes": ai_payload.get("raw_ai_notes"),
        },
        "git": {
            k: evidence.get("git", {}).get(k)
            for k in ("branch", "commit_short", "author", "message", "committed_date")
        },
        "git_history": {
            "risky_commits": ((evidence.get("git_history") or {}).get("risky_commits") or [])[:8],
        },
        "languages": (evidence.get("software") or {}).get("languages"),
        "docker": {
            "has_containers": (evidence.get("docker") or {}).get("has_containers"),
            "services": (evidence.get("docker") or {}).get("compose_services"),
            "images": (evidence.get("docker") or {}).get("images"),
            "ports": (evidence.get("docker") or {}).get("exposed_ports"),
        },
        "kubernetes": {
            "has_k8s": (evidence.get("kubernetes") or {}).get("has_k8s"),
            "kinds": (evidence.get("kubernetes") or {}).get("kinds"),
            "issue_count": len((evidence.get("kubernetes") or {}).get("issues") or []),
        },
        "ci_platforms": (evidence.get("ci") or {}).get("platforms"),
        "database_engines": (evidence.get("database") or {}).get("engines"),
        "monitoring_platforms": (evidence.get("monitoring") or {}).get("platforms"),
        "quality": {
            "test_file_count": (evidence.get("quality") or {}).get("test_file_count"),
            "quality_configs": (evidence.get("quality") or {}).get("quality_configs"),
        },
        "security": {
            "secret_hit_count": (evidence.get("security") or {}).get("secret_hit_count"),
            "risky_files": (evidence.get("security") or {}).get("risky_files"),
        },
        "network": {
            "ips": (evidence.get("network") or {}).get("ips"),
            "hosts": ((evidence.get("network") or {}).get("hosts") or [])[:30],
            "ports": (evidence.get("network") or {}).get("ports"),
        },
        "app_log_patterns": (evidence.get("app_log_patterns") or {}).get("counts"),
        "runtime_live": (evidence.get("runtime") or {}).get("live_probe"),
        "user_metrics": evidence.get("user_metrics") or {},
        "business_metrics": evidence.get("business_metrics") or {},
        "structure": (evidence.get("structure") or {}).get("top_level"),
    }

    return DevOpsReport(
        id=report_id,
        job_id=job_id,
        repo_url=evidence.get("repo_url") or "",
        branch=(evidence.get("git") or {}).get("branch"),
        created_at=datetime.now(timezone.utc),
        executive_summary=ai_payload.get("executive_summary") or "",
        health_score=max(0, min(100, int(ai_payload.get("health_score") or 50))),
        risk_level=risk,
        primary_root_cause=ai_payload.get("primary_root_cause"),
        correlated_timeline=list(ai_payload.get("correlated_timeline") or []),
        sections=sections,
        domain_coverage=coverage,
        quick_wins=list(ai_payload.get("quick_wins") or []),
        roadmap=list(ai_payload.get("roadmap") or []),
        collected_facts=facts,
        raw_ai_notes=ai_payload.get("raw_ai_notes"),
    )
