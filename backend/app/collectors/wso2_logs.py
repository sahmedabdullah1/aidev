"""Parsers for WSO2 APIM standard log files under <APIM_HOME>/repository/logs/."""

from __future__ import annotations

import re
from collections import Counter
from pathlib import Path
from typing import Any

from app.config import Settings
from app.collectors.wso2_ei_mi import parse_carbon_entries
from app.collectors.wso2_log_scan import scan_carbon_file, scan_http_access_file
from app.collectors.wso2_file_stats import display_name, traffic_tuple
from app.models.wso2_schemas import Wso2LogType

LOG_TYPE_PATTERNS: list[tuple[Wso2LogType, re.Pattern[str]]] = [
    (Wso2LogType.wso2carbon, re.compile(r"wso2carbon", re.I)),
    (Wso2LogType.audit, re.compile(r"audit\.log|audit-", re.I)),
    (Wso2LogType.http_access, re.compile(r"http[_-]?access", re.I)),
    (Wso2LogType.wire_tls, re.compile(r"wire[_-]?tls|ssl.?debug|javax\.net\.ssl", re.I)),
    (Wso2LogType.wire, re.compile(r"(?<![_\w])wire(?![_\w])|synapse-wire|transport\.http\.wire", re.I)),
    (Wso2LogType.gc, re.compile(r"(^|[_\-/])gc([_\-.]|$)|garbage.?collect", re.I)),
    (Wso2LogType.heapdump, re.compile(r"heapdump|\.hprof$", re.I)),
    (Wso2LogType.catalina, re.compile(r"catalina\.out|catalina\.", re.I)),
]

ERROR_RE = re.compile(
    r"(?i)\b(ERROR|FATAL|SEVERE|Exception|OutOfMemory|OOM|WARN|failed|denied|"
    r"unauthorized|SSLHandshake|Certificate|timeout|refused|deadlock|"
    r"Connection reset|Too many open files|Address already in use)\b"
)
CARBON_LINE = re.compile(
    r"^\[?(?P<ts>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}[,\.]?\d*)\]?\s+"
    r"(?P<level>ERROR|WARN|FATAL|INFO|DEBUG|TRACE)\b",
    re.I,
)
AUDIT_HINT = re.compile(r"(?i)(login|logout|Role|User|Permission|authenticated|failed)")
HTTP_ACCESS = re.compile(
    r'(?P<ip>\d+\.\d+\.\d+\.\d+).*?"(?P<method>[A-Z]+)\s+(?P<uri>\S+)\s+[^"]*"\s+(?P<status>\d{3})'
)
WIRE_DIR = re.compile(r"(?P<dir>>>|<<)")
GC_PAUSE = re.compile(r"(?i)(Full GC|Pause Young|OutOfMemory|Allocation Failure|Humongous)")
TLS_HINT = re.compile(r"(?i)(handshake|certificate|TLS|SSL|protocol_version|bad_certificate|unknown_ca)")

WSO2_DOC_BASE = (
    "https://apim.docs.wso2.com/en/4.6.0/administer/logging-and-monitoring/logging/configuring-logging/"
)

LOG_META = {
    Wso2LogType.wso2carbon: {
        "purpose": "Main server log (APIM / EI / MI)",
        "usage": "Startup/shutdown, errors, deployments, auth, mediation, API activity",
        "default_path": "<APIM_HOME|EI_HOME|MI_HOME>/repository/logs/wso2carbon.log",
        "format": "Timestamp | Log Level | Logger (Java Class) | Message | Exception",
    },
    Wso2LogType.audit: {
        "purpose": "Administrative audit events",
        "usage": "Login/logout, user/role changes",
        "default_path": "<APIM_HOME>/repository/logs/audit.log",
    },
    Wso2LogType.http_access: {
        "purpose": "HTTP access log",
        "usage": "Client IP, URI, status codes, latency",
        "default_path": "<APIM_HOME>/repository/logs/http_access*.log",
    },
    Wso2LogType.wire: {
        "purpose": "Raw HTTP request/response (Gateway / PassThrough wire)",
        "usage": "Deep integration debugging (>> in, << out)",
        "default_path": "wire / synapse-wire (often in wso2carbon.log when enabled)",
    },
    Wso2LogType.wire_tls: {
        "purpose": "SSL/TLS traffic",
        "usage": "TLS handshake troubleshooting",
        "default_path": "wire_tls / javax.net.debug / carbon TLS logs",
    },
    Wso2LogType.gc: {
        "purpose": "JVM Garbage Collection",
        "usage": "Memory / pause analysis",
        "default_path": "gc.log (JVM -Xlog:gc)",
    },
    Wso2LogType.heapdump: {
        "purpose": "Java heap dump",
        "usage": "OutOfMemory investigation",
        "default_path": "heapdump.hprof",
    },
    Wso2LogType.catalina: {
        "purpose": "Tomcat/JVM console output",
        "usage": "Startup failures",
        "default_path": "catalina.out",
    },
}


def detect_log_type(filename: str, sample: str = "") -> Wso2LogType:
    name = Path(filename).name
    for log_type, pattern in LOG_TYPE_PATTERNS:
        if pattern.search(name):
            return log_type
    # content hints
    if "synapse.transport.http.wire" in sample or " DEBUG - wire " in sample:
        return Wso2LogType.wire
    if TLS_HINT.search(sample[:2000]) and "handshake" in sample.lower():
        return Wso2LogType.wire_tls
    if GC_PAUSE.search(sample[:2000]) and "gc" in sample.lower()[:500]:
        return Wso2LogType.gc
    if CARBON_LINE.search(sample):
        return Wso2LogType.wso2carbon
    return Wso2LogType.unknown


def _read_text(path: Path, max_bytes: int) -> str:
    return path.read_bytes()[:max_bytes].decode("utf-8", errors="replace")


def _sample_matching(text: str, pattern: re.Pattern[str], limit: int = 40) -> list[str]:
    out: list[str] = []
    for line in text.splitlines():
        if pattern.search(line):
            out.append(line.strip()[:400])
            if len(out) >= limit:
                break
    return out


def parse_wso2carbon(text: str) -> dict[str, Any]:
    """Parse APIM/EI/MI carbon logs with EI/MI methodology (logger + exception)."""
    structured = parse_carbon_entries(text)
    # Keep legacy keys for compatibility
    errors = [
        f"[{e.get('timestamp')}] {e.get('severity')} {{{e.get('logger')}}} {e.get('functional_error')}"
        + (f" :: {e.get('exception_type')}" if e.get("exception_type") else "")
        for e in structured.get("structured_events") or []
        if e.get("severity") in {"ERROR", "FATAL"}
    ][:40]
    warns = [
        f"[{e.get('timestamp')}] WARN {{{e.get('logger')}}} {e.get('functional_error')}"
        for e in structured.get("structured_events") or []
        if e.get("severity") == "WARN"
    ][:20]
    return {
        **structured,
        "level_counts": structured.get("level_counts") or {},
        "error_lines": errors,
        "warn_lines": warns,
        "exception_lines": [
            f"{e.get('exception_type')}: {e.get('exception_message') or e.get('functional_error')}"
            for e in structured.get("structured_events") or []
            if e.get("exception_type")
        ][:30],
        "oom_signals": [
            e
            for e in structured.get("structured_events") or []
            if e.get("exception_type") and "OutOfMemory" in str(e.get("exception_type"))
        ][:10],
        "auth_signals": [
            e
            for e in structured.get("structured_events") or []
            if re.search(r"(?i)(Authentication|Unauthorized|JWT|API_AUTH|login failed)", e.get("functional_error") or "")
        ][:15],
        "deployment_signals": [
            e
            for e in structured.get("structured_events") or []
            if re.search(r"(?i)(Deployed|Undeploy|Failed to deploy)", e.get("functional_error") or "")
        ][:15],
        "db_signals": [
            e
            for e in structured.get("structured_events") or []
            if e.get("subsystem") in {"db_pool", "database_connector"}
            or (e.get("exception_type") and "SQL" in str(e.get("exception_type")))
        ][:15],
    }


def parse_audit(text: str) -> dict[str, Any]:
    lines = _sample_matching(text, AUDIT_HINT, limit=50)
    fails = _sample_matching(text, re.compile(r"(?i)(failed|denied|unauthorized|invalid)"), limit=30)
    return {"audit_events": lines, "failure_events": fails, "event_count": len(text.splitlines())}


def parse_http_access(text: str) -> dict[str, Any]:
    statuses: Counter[str] = Counter()
    methods: Counter[str] = Counter()
    top_uris: Counter[str] = Counter()
    clients: Counter[str] = Counter()
    samples_5xx: list[str] = []
    samples_4xx: list[str] = []
    for line in text.splitlines():
        m = HTTP_ACCESS.search(line)
        if not m:
            # fallback status sniff
            sm = re.search(r"\s(\d{3})\s", line)
            if sm:
                statuses[sm.group(1)] += 1
                if sm.group(1).startswith("5") and len(samples_5xx) < 25:
                    samples_5xx.append(line.strip()[:300])
                if sm.group(1).startswith("4") and len(samples_4xx) < 25:
                    samples_4xx.append(line.strip()[:300])
            continue
        statuses[m.group("status")] += 1
        methods[m.group("method")] += 1
        top_uris[m.group("uri")[:120]] += 1
        clients[m.group("ip")] += 1
        if m.group("status").startswith("5") and len(samples_5xx) < 25:
            samples_5xx.append(line.strip()[:300])
        if m.group("status").startswith("4") and len(samples_4xx) < 25:
            samples_4xx.append(line.strip()[:300])
    return {
        "status_counts": dict(statuses.most_common(20)),
        "method_counts": dict(methods.most_common(10)),
        "top_uris": dict(top_uris.most_common(20)),
        "top_clients": dict(clients.most_common(15)),
        "samples_5xx": samples_5xx,
        "samples_4xx": samples_4xx,
    }


def parse_wire(text: str) -> dict[str, Any]:
    inbound = len(re.findall(r">>", text))
    outbound = len(re.findall(r"<<", text))
    return {
        "inbound_markers": inbound,
        "outbound_markers": outbound,
        "errorish": _sample_matching(text, ERROR_RE, limit=30),
        "auth_headers_seen": bool(re.search(r"(?i)Authorization:\s*Bearer", text)),
        "sample_flow": _sample_matching(text, WIRE_DIR, limit=40),
    }


def parse_wire_tls(text: str) -> dict[str, Any]:
    return {
        "tls_events": _sample_matching(text, TLS_HINT, limit=40),
        "handshake_failures": _sample_matching(
            text, re.compile(r"(?i)(handshake_failure|bad_certificate|certificate_unknown|protocol_version)"), limit=30
        ),
    }


def parse_gc(text: str) -> dict[str, Any]:
    return {
        "gc_events": _sample_matching(text, GC_PAUSE, limit=40),
        "full_gc_count": len(re.findall(r"(?i)Full GC", text)),
        "oom_related": _sample_matching(text, re.compile(r"(?i)(OutOfMemory|Allocation Failure)"), limit=20),
        "tail": "\n".join(text.splitlines()[-40:])[:3000],
    }


def parse_heapdump(path: Path) -> dict[str, Any]:
    size = path.stat().st_size if path.exists() else 0
    return {
        "file": path.name,
        "size_bytes": size,
        "size_mb": round(size / (1024 * 1024), 2),
        "note": "Binary HPROF — correlate with OOM in wso2carbon/gc; analyze offline with Eclipse MAT / VisualVM",
        "is_binary": True,
    }


def parse_catalina(text: str) -> dict[str, Any]:
    return {
        "startup_errors": _sample_matching(text, re.compile(r"(?i)(SEVERE|ERROR|Exception|Failed to start|Address already in use)"), limit=40),
        "tail": "\n".join(text.splitlines()[-50:])[:3500],
    }


PARSERS = {
    Wso2LogType.wso2carbon: parse_wso2carbon,
    Wso2LogType.audit: parse_audit,
    Wso2LogType.http_access: parse_http_access,
    Wso2LogType.wire: parse_wire,
    Wso2LogType.wire_tls: parse_wire_tls,
    Wso2LogType.gc: parse_gc,
    Wso2LogType.catalina: parse_catalina,
}


def collect_wso2_logs(files: list[Path], settings: Settings) -> dict[str, Any]:
    by_type: dict[str, list[dict[str, Any]]] = {t.value: [] for t in Wso2LogType}
    coverage = {t.value: {"present": False, **LOG_META.get(t, {})} for t in Wso2LogType if t != Wso2LogType.unknown}
    # Allow large production carbon logs (default was too small and missed WARN/ERROR later in file)
    max_bytes = max(int(getattr(settings, "wso2_max_log_bytes", 0) or 0), int(settings.max_log_bytes), 25_000_000)

    all_failure_findings: list[dict[str, Any]] = []
    scan_summaries: list[dict[str, Any]] = []

    for path in files:
        if not path.is_file():
            continue
        name = path.name
        if path.suffix.lower() == ".hprof" or "heapdump" in name.lower():
            log_type = Wso2LogType.heapdump
            parsed = parse_heapdump(path)
            sample = ""
        else:
            # Peek head for type detection only
            sample = _read_text(path, min(8000, max_bytes))
            log_type = detect_log_type(name, sample)
            # Carbon / unknown text logs: full-file error-first scan (critical fix)
            if log_type in {Wso2LogType.wso2carbon, Wso2LogType.unknown} or "wso2carbon" in name.lower():
                log_type = Wso2LogType.wso2carbon
                scanned = scan_carbon_file(path, max_read_bytes=max_bytes)
                # Also keep classic parse on an error-focused subset for LLM
                focus_blob = "\n".join(
                    f"[{f.get('timestamp')}] {f.get('original_level') or f.get('severity')} "
                    f"{{{f.get('logger')}}} {f.get('functional_error')}"
                    for f in (scanned.get("failure_findings") or [])[:80]
                )
                classic = parse_wso2carbon(focus_blob) if focus_blob.strip() else parse_wso2carbon(sample)
                parsed = {
                    **classic,
                    "full_file_scan": {
                        "size_bytes": scanned.get("size_bytes"),
                        "bytes_scanned": scanned.get("bytes_scanned"),
                        "lines_scanned": scanned.get("lines_scanned"),
                        "scanned_fully": scanned.get("scanned_fully"),
                        "level_counts": scanned.get("level_counts"),
                        "failure_count_raw": scanned.get("failure_count_raw"),
                        "failure_count_unique": scanned.get("failure_count_unique"),
                        "signals": scanned.get("signals"),
                        "top_loggers": scanned.get("top_loggers"),
                        "top_exceptions": scanned.get("top_exceptions"),
                        "note": scanned.get("note"),
                    },
                    "failure_findings": scanned.get("failure_findings") or [],
                    "structured_events": scanned.get("failure_findings") or classic.get("structured_events") or [],
                }
                all_failure_findings.extend(scanned.get("failure_findings") or [])
                scan_summaries.append(
                    {
                        "file": name,
                        "display_name": display_name(name),
                        "log_type": log_type.value,
                        "product": scanned.get("product"),
                        "failure_count_unique": scanned.get("failure_count_unique"),
                        "failure_count_raw": scanned.get("failure_count_raw"),
                        "signals": scanned.get("signals"),
                        "identity": scanned.get("identity"),
                        "ip_mentions": scanned.get("ip_mentions"),
                        "scanned_fully": scanned.get("scanned_fully"),
                        "size_bytes": scanned.get("size_bytes"),
                        "level_counts": scanned.get("level_counts"),
                        "total_transactions": scanned.get("total_transactions"),
                        "total_success": scanned.get("total_success"),
                        "total_errors": scanned.get("total_errors"),
                        "error_pct": scanned.get("error_pct"),
                        "traffic": scanned.get("traffic"),
                    }
                )
            else:
                if log_type == Wso2LogType.http_access:
                    scanned = scan_http_access_file(path, max_read_bytes=max_bytes)
                    parsed = {**parse_http_access(_read_text(path, min(max_bytes, 2_000_000))), **{
                        "traffic": scanned.get("traffic"),
                        "total_transactions": scanned.get("total_transactions"),
                        "total_success": scanned.get("total_success"),
                        "total_errors": scanned.get("total_errors"),
                        "error_pct": scanned.get("error_pct"),
                    }}
                    scan_summaries.append(
                        {
                            "file": name,
                            "display_name": display_name(name),
                            "log_type": log_type.value,
                            "product": scanned.get("product") or "APIM",
                            "failure_count_raw": scanned.get("failure_count_raw"),
                            "failure_count_unique": scanned.get("failure_count_unique"),
                            "signals": scanned.get("signals"),
                            "ip_mentions": scanned.get("ip_mentions"),
                            "scanned_fully": scanned.get("scanned_fully"),
                            "size_bytes": scanned.get("size_bytes"),
                            "total_transactions": scanned.get("total_transactions"),
                            "total_success": scanned.get("total_success"),
                            "total_errors": scanned.get("total_errors"),
                            "error_pct": scanned.get("error_pct"),
                            "traffic": scanned.get("traffic"),
                        }
                    )
                else:
                    text = _read_text(path, max_bytes)
                    parser = PARSERS.get(log_type)
                    parsed = parser(text) if parser else {"error_lines": _sample_matching(text, ERROR_RE, 40), "tail": text[-2000:]}
                    lines_n = text.count("\n") + (1 if text else 0)
                    fail_n = 0
                    if log_type == Wso2LogType.audit:
                        fail_n = len(parsed.get("failure_events") or [])
                        lines_n = int(parsed.get("event_count") or lines_n)
                    elif isinstance(parsed.get("errorish"), list):
                        fail_n = len(parsed["errorish"])
                    elif isinstance(parsed.get("startup_errors"), list):
                        fail_n = len(parsed["startup_errors"])
                    traffic = traffic_tuple(lines_n, fail_n)
                    scan_summaries.append(
                        {
                            "file": name,
                            "display_name": display_name(name),
                            "log_type": log_type.value,
                            "product": "APIM/MI",
                            "failure_count_raw": fail_n,
                            "size_bytes": path.stat().st_size,
                            "total_transactions": traffic["total_transactions"],
                            "total_success": traffic["total_success"],
                            "total_errors": traffic["total_errors"],
                            "error_pct": traffic["error_pct"],
                            "traffic": traffic,
                        }
                    )

        entry = {
            "filename": name,
            "path": str(path),
            "log_type": log_type.value,
            "bytes": path.stat().st_size,
            "meta": LOG_META.get(log_type, {}),
            "parsed": parsed,
            "sample_head": sample[:800] if sample else None,
        }
        by_type.setdefault(log_type.value, []).append(entry)
        if log_type.value in coverage:
            coverage[log_type.value]["present"] = True
            coverage[log_type.value]["files"] = coverage[log_type.value].get("files", []) + [name]

    missing = [k for k, v in coverage.items() if not v.get("present")]
    return {
        "default_location": "<APIM_HOME|EI_HOME|MI_HOME>/repository/logs/",
        "doc_url": WSO2_DOC_BASE,
        "files_processed": sum(len(v) for v in by_type.values()),
        "by_type": {k: v for k, v in by_type.items() if v},
        "coverage": coverage,
        "missing_log_types": missing,
        "priority_failure_findings": all_failure_findings[:100],
        "scan_summaries": scan_summaries,
        "analysis_hint": (
            "Use priority_failure_findings first. WARN auth failures and INFO business "
            "failures (HTTP 4xx/5xx, STATUS=null, Request failed) ARE real issues even without ERROR level."
            if all_failure_findings
            else "Scanner found no failure signatures — say so explicitly and recommend enabling WARN/ERROR logging."
        ),
    }
