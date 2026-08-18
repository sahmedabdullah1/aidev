"""WSO2 APIM deep log analysis — LLM-only, correlated with VA report."""

from __future__ import annotations

import json
import re
import uuid
from datetime import datetime, timezone
from typing import Any

from app.analyzers.llm_client import LLMAnalysisError, chat_json, evidence_budget_chars, resolve_llm_settings
from app.analyzers.wso2_impact import enrich_wso2_errors
from app.collectors.wso2_file_stats import build_file_stats
from app.config import Settings
from app.models.schemas import Severity
from app.models.wso2_schemas import (
    Wso2Context,
    Wso2ErrorItem,
    Wso2LogType,
    Wso2Report,
    Wso2VaMapping,
)

WSO2_DOC = (
    "https://apim.docs.wso2.com/en/4.6.0/administer/logging-and-monitoring/logging/configuring-logging/"
)

SYSTEM_PROMPT = f"""WSO2 APIM/EI/MI SRE. Use logger+exception (no error catalog).
WARN auth + INFO business failures (4xx/5xx, Request failed) ARE issues.
If failures[] non-empty you MUST fill errors[] — never claim healthy/no errors.
Use EASY human titles (not raw exception class names). Example: "API login rejected — wrong credentials" not "UserStoreException".
Include plain_meaning, call_flow (short steps), config_checks (file + what to set), impacted_customers when visible in URIs/appName.
Docs:{WSO2_DOC}
JSON only:
{{"executive_summary":"","health_score":0,"risk_level":"high","primary_root_cause":"",
"correlated_timeline":["2026-08-06 12:55 — JWT rejected"],"errors":[{{"log_type":"wso2carbon","severity":"high",
"error":"easy title","technical_name":"ExceptionOrHandler",
"plain_meaning":"Client tried to call APIM with wrong creds",
"call_flow":["Client","APIM Gateway","Reject"],
"config_checks":["deployment.toml: set X","DevPortal: fix subscription"],
"impacted_customers":["Jazz eCare"],
"description":"","possible_occurrence":"","remedial_actions":["fix1"],
"wso2_doc_refs":["{WSO2_DOC}"],"evidence":"","source_file":"","affected_components":[],
"logger":"","subsystem":"","functional_error":"","exception_type":"",
"error_source":"wso2_component_message","va_correlation":"","confidence_score":80}}],
"va_correlations":[],"quick_wins":[],"roadmap":[],"doc_references":["{WSO2_DOC}"]}}
"""


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
            raise LLMAnalysisError("LLM did not return valid JSON for WSO2 analysis")
        return json.loads(match.group(0))


def _pack_evidence(
    *,
    context: Wso2Context,
    log_evidence: dict[str, Any],
    va_report_text: str | None,
    max_chars: int,
) -> str:
    def slim_finding(f: dict[str, Any]) -> dict[str, Any]:
        return {
            "ts": f.get("timestamp"),
            "level": f.get("original_level") or f.get("severity"),
            "logger": f.get("logger"),
            "subsystem": f.get("subsystem"),
            "product": f.get("product"),
            "file": f.get("source_file"),
            "msg": (f.get("functional_error") or "")[:180],
            "exception": f.get("exception_type"),
            "count": f.get("occurrence_count") or 1,
            "source": f.get("error_source"),
        }

    findings = [slim_finding(f) for f in (log_evidence.get("priority_failure_findings") or [])[:20]]
    ctx = context.model_dump(exclude_none=True)
    # Keep only short operational inputs — drop large free-text fields
    slim_inputs = {
        k: (str(v)[:120] if not isinstance(v, (int, float, bool, list, dict)) else v)
        for k, v in ctx.items()
        if k in {
            "os",
            "apim_version",
            "ei_version",
            "ip_addresses",
            "db_version",
            "compute_allocation",
            "infra_compute_consumption",
            "environment",
        }
        and v is not None
    }
    scan = []
    for row in log_evidence.get("scan_summaries") or []:
        scan.append(
            {
                "file": row.get("display_name") or row.get("file"),
                "product": row.get("product"),
                "unique": row.get("failure_count_unique"),
                "signals": row.get("signals"),
                "full": row.get("scanned_fully"),
                "bytes": row.get("size_bytes"),
                "tx": row.get("total_transactions"),
                "errors": row.get("total_errors"),
                "error_pct": row.get("error_pct"),
            }
        )
    compact = {
        "doc": WSO2_DOC,
        "inputs": slim_inputs,
        "scan": scan,
        "failures": findings,
        "missing_logs": (log_evidence.get("missing_log_types") or [])[:8],
        "va": ((va_report_text or "")[:2000] or None),
    }
    raw = json.dumps(compact, default=str, separators=(",", ":"))
    if len(raw) <= max_chars:
        return raw
    compact["failures"] = findings[:12]
    compact["va"] = ((va_report_text or "")[:800] or None)
    raw = json.dumps(compact, default=str, separators=(",", ":"))
    if len(raw) <= max_chars:
        return raw
    compact["failures"] = findings[:8]
    compact.pop("va", None)
    compact.pop("missing_logs", None)
    raw = json.dumps(compact, default=str, separators=(",", ":"))
    return raw[:max_chars]


def _sev(raw: str | None) -> Severity:
    try:
        return Severity(raw or "medium")
    except Exception:  # noqa: BLE001
        return Severity.medium


def _log_type(raw: str | None) -> Wso2LogType:
    try:
        return Wso2LogType(raw or "unknown")
    except Exception:  # noqa: BLE001
        return Wso2LogType.unknown


def _as_text(val: Any) -> str:
    if val is None:
        return ""
    if isinstance(val, str):
        return val.strip()
    if isinstance(val, dict):
        ts = val.get("ts") or val.get("timestamp") or val.get("time")
        event = (
            val.get("event")
            or val.get("message")
            or val.get("text")
            or val.get("summary")
            or val.get("step")
            or val.get("action")
        )
        if ts and event:
            return f"{ts} — {event}"
        if event:
            return str(event)
        return " — ".join(str(v) for v in val.values() if v)[:400]
    return str(val).strip()


def _as_str_list(val: Any) -> list[str]:
    if not val:
        return []
    if isinstance(val, str):
        return [val] if val.strip() else []
    if isinstance(val, dict):
        text = _as_text(val)
        return [text] if text else []
    out: list[str] = []
    for item in val:
        text = _as_text(item)
        if text:
            out.append(text)
    return out


def _as_int(val: Any, default: int) -> int:
    try:
        return int(float(str(val).strip().split()[0]))
    except Exception:  # noqa: BLE001
        return default


async def analyze_wso2(
    *,
    settings: Settings,
    context: Wso2Context,
    log_evidence: dict[str, Any],
    va_report_text: str | None,
    job_id: str,
) -> Wso2Report:
    s = resolve_llm_settings(settings)
    if not s.llm_api_key:
        raise LLMAnalysisError(
            "LLM_API_KEY required for WSO2 analysis. Configure Groq key in .env"
        )

    budget = evidence_budget_chars(s)
    last_err: Exception | None = None
    data: dict[str, Any] | None = None
    for attempt, factor in enumerate((1.0, 0.7, 0.45), start=1):
        user = (
            "Deep WSO2 APIM/EI/MI investigation. NO centralized error catalog — use logger+exception. "
            "WARN auth failures and INFO business failures ARE issues. "
            "Return Error/Description/Possible occurrence/Remedial actions/VA correlation for each. "
            "Never say no errors if failures[] is non-empty.\n\n"
            f"EVIDENCE:\n{_pack_evidence(context=context, log_evidence=log_evidence, va_report_text=va_report_text, max_chars=int(budget * factor))}"
        )
        try:
            content = await chat_json(settings=s, system=SYSTEM_PROMPT, user=user)
            data = _extract_json(content)
            break
        except LLMAnalysisError as exc:
            last_err = exc
            msg = str(exc).lower()
            if "413" in msg or "request too large" in msg or "tpm" in msg:
                continue
            raise
    if data is None:
        raise LLMAnalysisError(f"WSO2 LLM analysis failed: {last_err}")

    if not isinstance(data.get("errors"), list):
        data["errors"] = []

    # If scanner found failures but model returned empty, force a second tighter ask
    scanned_n = len(log_evidence.get("priority_failure_findings") or [])
    if scanned_n > 0 and len(data.get("errors") or []) == 0:
        retry_user = (
            f"Scanner found {scanned_n} failure signatures. You returned zero errors — that is wrong. "
            "Produce errors[] from failures[] now. Also include executive_summary, health_score, risk_level, primary_root_cause.\n\n"
            f"EVIDENCE:\n{_pack_evidence(context=context, log_evidence=log_evidence, va_report_text=None, max_chars=int(budget * 0.5))}"
        )
        content = await chat_json(settings=s, system=SYSTEM_PROMPT, user=retry_user)
        data = _extract_json(content)
        if not isinstance(data.get("errors"), list):
            data["errors"] = []

    errors: list[Wso2ErrorItem] = []
    for item in data.get("errors") or []:
        if not isinstance(item, dict):
            continue
        try:
            errors.append(
                Wso2ErrorItem(
                    id=uuid.uuid4().hex[:10],
                    log_type=_log_type(item.get("log_type")),
                    severity=_sev(item.get("severity")),
                    error=_as_text(item.get("error")) or "Error",
                    description=_as_text(item.get("description")),
                    possible_occurrence=_as_text(item.get("possible_occurrence")),
                    remedial_actions=_as_str_list(item.get("remedial_actions")),
                    wso2_doc_refs=_as_str_list(item.get("wso2_doc_refs") or [WSO2_DOC]),
                    evidence=_as_text(item.get("evidence")) or None,
                    source_file=_as_text(item.get("source_file")) or None,
                    affected_components=_as_str_list(item.get("affected_components")),
                    logger=_as_text(item.get("logger")) or None,
                    subsystem=_as_text(item.get("subsystem")) or None,
                    functional_error=_as_text(item.get("functional_error")) or None,
                    exception_type=_as_text(item.get("exception_type")) or None,
                    error_source=_as_text(item.get("error_source")) or None,
                    va_correlation=_as_text(item.get("va_correlation")) or None,
                    confidence_score=max(0, min(100, _as_int(item.get("confidence_score"), 70))),
                    technical_name=_as_text(item.get("technical_name")) or None,
                    plain_meaning=_as_text(item.get("plain_meaning")) or None,
                    call_flow=_as_str_list(item.get("call_flow")),
                    config_checks=_as_str_list(item.get("config_checks")),
                    impacted_customers=_as_str_list(item.get("impacted_customers")),
                    failure_count=item.get("failure_count"),
                    failure_total=item.get("failure_total"),
                    impact_pct=item.get("impact_pct"),
                    impact_summary=item.get("impact_summary"),
                )
            )
        except Exception:  # noqa: BLE001
            continue

    # Fallback: model often returns only errors[] under token pressure — synthesize the rest
    if scanned_n > 0 and not errors:
        for f in (log_evidence.get("priority_failure_findings") or [])[:12]:
            errors.append(
                Wso2ErrorItem(
                    id=uuid.uuid4().hex[:10],
                    log_type=Wso2LogType.wso2carbon,
                    severity=_sev(f.get("severity") or "high"),
                    error=(f.get("functional_error") or "WSO2 failure")[:180],
                    description=f"Detected via full-file scan ({f.get('original_level') or f.get('severity')} / {f.get('logger')})",
                    possible_occurrence="Repeated in carbon log during the scanned window",
                    remedial_actions=[
                        "Inspect logger + exception in carbon log around this timestamp",
                        "Validate API credentials / backend request contract for the failing URI",
                        f"See WSO2 logging docs: {WSO2_DOC}",
                    ],
                    wso2_doc_refs=[WSO2_DOC],
                    evidence=(f.get("evidence") or "")[:400],
                    source_file=None,
                    affected_components=[f.get("component")] if f.get("component") else [],
                    logger=f.get("logger"),
                    subsystem=f.get("subsystem"),
                    functional_error=f.get("functional_error"),
                    exception_type=f.get("exception_type"),
                    error_source=f.get("error_source"),
                    confidence_score=75,
                )
            )

    if not data.get("executive_summary"):
        if errors:
            top = "; ".join(e.error[:80] for e in errors[:3])
            data["executive_summary"] = (
                f"WSO2 carbon analysis found {len(errors)} issue group(s) from {scanned_n} "
                f"scanned failure signature(s). Top findings: {top}."
            )
        else:
            data["executive_summary"] = (
                "No ERROR/WARN/FATAL or business-failure patterns were found in the uploaded carbon logs."
            )
    if not data.get("primary_root_cause") and errors:
        data["primary_root_cause"] = errors[0].error
    if data.get("health_score") is None:
        data["health_score"] = 35 if errors else 85
    if not data.get("risk_level"):
        data["risk_level"] = "high" if any(e.severity.value in {"critical", "high"} for e in errors) else ("medium" if errors else "low")
    if scanned_n > 0 and not errors:
        raise LLMAnalysisError("Scanner found failures but analysis produced zero errors")

    # Enrich LLM items with concrete scanner counts / hot URIs when present
    signals = {}
    for row in log_evidence.get("scan_summaries") or []:
        for k, v in (row.get("signals") or {}).items():
            signals[k] = signals.get(k, 0) + int(v or 0)
    hot: list[str] = []
    for f in (log_evidence.get("priority_failure_findings") or [])[:8]:
        msg = f.get("functional_error") or ""
        m = re.search(r"requestURI=([^\s]+)", msg)
        if m:
            hot.append(f"{m.group(1)} (x{f.get('occurrence_count') or 1})")
    if errors and signals:
        auth_n = signals.get("auth_failures") or 0
        h4 = signals.get("http_4xx") or 0
        h5 = signals.get("http_5xx") or 0
        extra = f" Scanner totals: auth_failures={auth_n}, http_4xx={h4}, http_5xx={h5}."
        if hot:
            extra += " Hot URIs: " + "; ".join(hot[:5]) + "."
        if extra not in (data.get("executive_summary") or ""):
            data["executive_summary"] = (data.get("executive_summary") or "") + extra
        for e in errors:
            if "Invalid Credentials" in e.error or "authentication" in e.error.lower():
                if auth_n and not e.evidence:
                    e.evidence = f"{auth_n} auth failure WARN lines across uploaded carbon logs"
                if hot and "requestURI" not in (e.description or ""):
                    e.description = (e.description or "") + " Top failing URIs: " + "; ".join(hot[:4])
                if not e.remedial_actions or len(e.remedial_actions) < 3:
                    e.remedial_actions = list(dict.fromkeys((e.remedial_actions or []) + [
                        "Confirm Application Access Token / API Key for the calling app (Developer Portal)",
                        "Check Subscription is ACTIVE for the API+app and token scopes match required scopes",
                        "Compare request Authorization header vs valid JWT/OAuth token from token endpoint",
                        "Review gateway APIAuthenticationHandler WARN lines for appName + requestURI pairs",
                    ]))
            if "400" in e.error or "Request failed" in e.error:
                e.remedial_actions = list(dict.fromkeys((e.remedial_actions or []) + [
                    "Capture the backend response body for the 400 (enable wire logs temporarily if needed)",
                    "Validate outbound payload/headers from the ZARR_WHATSAPP / Infobip mediation sequence",
                    "Confirm backend AI/Infobip endpoint URL, auth, and request schema have not changed",
                ]))
            if re.search(r"(?i)SQL|registry transaction|Could not create connection|constraint violation", e.error + " " + (e.description or "")):
                e.remedial_actions = list(dict.fromkeys((e.remedial_actions or []) + [
                    "Check MySQL 8.4.3 reachability from APIM/MI nodes 10.50.13.126-128 (port, firewall, max_connections)",
                    "Verify master-datasources.xml / deployment.toml DB URL, user, password, and SSL settings",
                    "Inspect MySQL error log for aborted connections / too many connections / auth plugin issues",
                    "Confirm shared registry DB is healthy before restarting APIM/MI nodes",
                ]))
            if re.search(r"(?i)Json Payload is empty", e.error + " " + (e.description or "")):
                e.remedial_actions = list(dict.fromkeys((e.remedial_actions or []) + [
                    "Validate inbound JSON body / Content-Type on the failing MI API or proxy",
                    "Check client or previous mediator is not dropping the payload",
                ]))

    if not data.get("quick_wins"):
        wins = []
        if signals.get("auth_failures"):
            wins.append("Rotate/re-issue tokens for apps hitting Invalid Credentials; verify subscriptions on hot URIs")
        if signals.get("http_4xx") or any("400" in e.error for e in errors):
            wins.append("Trace ZARR_WHATSAPP Infobip TEXT path — AI backend returning HTTP 400")
        wins.append("Upload audit.log + http_access.log next for caller IP / app correlation")
        data["quick_wins"] = wins
    if not data.get("roadmap"):
        data["roadmap"] = [
            "Enable WARN retention and alert on APIAuthenticationHandler spikes",
            "Add synthetic probes for top APIs (checkeligibility, subscription/gmlc)",
            "Collect full 8-log set (wire, GC, catalina) for next deep dive",
        ]

    # Plain-language titles, impact counts, call flow, configs, customers
    errors = enrich_wso2_errors(errors, log_evidence)
    if errors and data.get("primary_root_cause"):
        # Prefer easy title for root cause display when it was still technical
        if re.search(r"Exception|Handler\b", str(data.get("primary_root_cause") or "")):
            data["primary_root_cause"] = errors[0].error

    customer_summary = log_evidence.get("impacted_customers_summary") or {}
    file_stats = build_file_stats(
        log_evidence.get("scan_summaries") or [],
        context.ip_addresses,
    )
    log_evidence["file_stats"] = file_stats
    if file_stats and data.get("executive_summary"):
        worst = max(file_stats, key=lambda r: float(r.get("error_pct") or 0))
        if "error rate" not in (data.get("executive_summary") or "").lower():
            bits = [
                f"{r.get('display_name') or r.get('file')} @ {r.get('ip') or 'IP n/a'}: "
                f"{int(r.get('total_errors') or 0)}/{int(r.get('total_transactions') or 0)} "
                f"({r.get('error_pct')}%)"
                for r in sorted(file_stats, key=lambda x: -float(x.get("error_pct") or 0))[:4]
            ]
            data["executive_summary"] = (
                f"{data['executive_summary'].rstrip()} "
                f"Per-node error rates: {'; '.join(bits)}. Highest: "
                f"{worst.get('display_name')} {worst.get('error_pct')}%."
            )

    if customer_summary.get("headline") and data.get("executive_summary"):
        # Append a clear who-is-hit line when missing
        if "Impacted customers" not in (data.get("executive_summary") or ""):
            data["executive_summary"] = (
                f"{data['executive_summary'].rstrip()} "
                f"Impacted customers/partners: {customer_summary['headline']}."
            )

    va_maps: list[Wso2VaMapping] = []
    for row in data.get("va_correlations") or []:
        if not isinstance(row, dict):
            continue
        try:
            va_maps.append(
                Wso2VaMapping(
                    va_finding=_as_text(row.get("va_finding")),
                    related_log_errors=_as_str_list(row.get("related_log_errors")),
                    correlation_notes=_as_text(row.get("correlation_notes")),
                    risk=_sev(_as_text(row.get("risk")) or None),
                    recommended_actions=_as_str_list(row.get("recommended_actions")),
                )
            )
        except Exception:  # noqa: BLE001
            continue

    docs = _as_str_list(data.get("doc_references") or [WSO2_DOC])
    if WSO2_DOC not in docs:
        docs.insert(0, WSO2_DOC)

    return Wso2Report(
        id=uuid.uuid4().hex[:12],
        job_id=job_id,
        created_at=datetime.now(timezone.utc),
        executive_summary=_as_text(data.get("executive_summary")),
        health_score=max(0, min(100, _as_int(data.get("health_score"), 50))),
        risk_level=_sev(_as_text(data.get("risk_level")) or None),
        primary_root_cause=_as_text(data.get("primary_root_cause")) or None,
        context=context,
        log_coverage={
            "coverage": log_evidence.get("coverage"),
            "missing_log_types": log_evidence.get("missing_log_types"),
            "files_processed": log_evidence.get("files_processed"),
            "scan_summaries": log_evidence.get("scan_summaries"),
            "priority_failure_findings": (log_evidence.get("priority_failure_findings") or [])[:80],
            "impacted_customers_summary": log_evidence.get("impacted_customers_summary"),
            "file_stats": log_evidence.get("file_stats") or [],
            "analysis_hint": log_evidence.get("analysis_hint"),
        },
        errors=errors,
        va_correlations=va_maps,
        correlated_timeline=_as_str_list(data.get("correlated_timeline")),
        quick_wins=_as_str_list(data.get("quick_wins")),
        roadmap=_as_str_list(data.get("roadmap")),
        doc_references=docs,
        raw_ai_notes=f"llm:ok wso2 model={s.llm_model}",
    )
