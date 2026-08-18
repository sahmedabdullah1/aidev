"""Full-file WSO2 carbon scanner — error-first, not head-truncate.

Real production logs are often mostly INFO. Failures appear as:
- WARN/ERROR/FATAL levels
- INFO LogMediator business failures (HTTP 4xx/5xx, STATUS=null, auth failures)
"""

from __future__ import annotations

import re
from collections import Counter
from pathlib import Path
from typing import Any, Iterable

from app.collectors.wso2_ei_mi import (
    APIM_ENTRY,
    CARBON_ENTRY,
    classify_error_source,
    classify_logger,
)

LEVEL_LINE = re.compile(
    r"(?:TID:\s*\[[^\]]*\]\s*(?:\[[^\]]*\]\s*)?)?"
    r"\[(?P<ts>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}[,\.]\d+)\]\s+"
    r"(?P<level>ERROR|WARN|FATAL|INFO|DEBUG|TRACE)\s+"
    r"(?:\{(?P<logger>[^}]+)\}\s*)?(?:-\s*)?(?P<message>.*)$",
    re.I,
)

BUSINESS_FAIL = re.compile(
    r"(?i)("
    r"Error:\s*Request failed|"
    r"status code\s*[45]\d\d|"
    r"HTTP\s*[45]\d\d|"
    r"STATUS\s*=\s*(null|ERROR|FAILED|KO)\b|"
    r"API authentication failure|"
    r"Invalid Credentials|"
    r"API_AUTH_FAILURE|"
    r"Key validation failed|"
    r"JWT validation failed|"
    r"Couldn't send message|"
    r"Connection reset|"
    r"Connection refused|"
    r"Could not create connection|"
    r"Failed to start new registry transaction|"
    r"constraint violation|"
    r"Json Payload is empty|"
    r"timed?\s*out\b(?!\s+handler)|SocketTimeout|"
    r"\bSQL(?:NonTransient)?(?:Connection)?Exception\b|"
    r"\bNullPointerException\b|"
    r"\bOutOfMemory(?:Error)?\b|"
    r"Failed to (send|validate|deploy|connect)|"
    r"exception occurred|"
    r"Unexpected error"
    r")"
)

STACK_FRAME = re.compile(r"(?i)^\s*at\s+[\w.$]+\(|^\s*\.\.\.\s*\d+\s+more\b|^\s*Caused by:")

PRODUCT_HINTS = [
    (re.compile(r"(?i)carbon\.apimgt|API Manager|APIAuthenticationHandler|apimgt\.gateway"), "APIM"),
    (re.compile(r"(?i)Micro Integrator|micro\.integrator|wso2mi|EI Message Processor"), "MI"),
    (re.compile(r"(?i)synapse\.mediators|LogMediator|InboundEndpoint"), "MI"),
]

APP_NAME_RE = re.compile(r"(?i)appName=([^\s,&]+)")
REQUEST_URI_RE = re.compile(r"(?i)requestURI=([^\s,&]+)")
API_NAME_RE = re.compile(r"(?i)\bapi(?:Name)?[=:][\s]*([A-Za-z0-9_./-]+)")
TX_ID_RE = re.compile(r"(?i)(?:TransactionID|txnId|txn_id|correlation)=([^\s,&]+)")
PMD_RE = re.compile(r"\bPMD-[A-Za-z0-9_-]+")


def _extract_identity(message: str) -> dict[str, list[str]]:
    blob = message or ""
    apps = APP_NAME_RE.findall(blob)
    uris = REQUEST_URI_RE.findall(blob)
    apis = API_NAME_RE.findall(blob)
    txs = TX_ID_RE.findall(blob) + PMD_RE.findall(blob)
    return {
        "app_names": list(dict.fromkeys(apps))[:8],
        "request_uris": list(dict.fromkeys(uris))[:8],
        "api_names": list(dict.fromkeys(apis))[:8],
        "transaction_ids": list(dict.fromkeys(txs))[:8],
    }


def infer_product(filename: str, sample: str = "") -> str:
    name = filename.lower()
    if "apim" in name or "api-manager" in name:
        return "APIM"
    if re.search(r"(^|[_\-/])mi([_\-./]|$)|micro.?integrator|wso2mi", name):
        return "MI"
    blob = f"{filename}\n{sample[:6000]}"
    for pat, label in PRODUCT_HINTS:
        if pat.search(blob):
            return label
    return "APIM/MI"

FALSE_POSITIVE_INFO = re.compile(
    r"(?i)("
    r"PENDING_ENROUTE|"
    r"message sent to next instance|"
    r"STATUS\s*=\s*OK\b|"
    r"Successfully recovered .+ constraint violation|"
    r"Retry attempt to recover .+ constraint violation"
    r")"
)


def _parse_line(line: str) -> dict[str, Any] | None:
    m = LEVEL_LINE.match(line.strip()) or CARBON_ENTRY.match(line.strip()) or APIM_ENTRY.match(line.strip())
    if not m:
        return None
    gd = m.groupdict()
    logger = (gd.get("logger") or "").strip()
    message = (gd.get("message") or "").strip()
    if not logger and message.startswith("{"):
        lm = re.match(r"^\{([^}]+)\}\s*(?:-\s*)?(.*)$", message)
        if lm:
            logger = lm.group(1).strip()
            message = lm.group(2).strip()
    level = (gd.get("level") or "INFO").upper()
    return {
        "timestamp": gd.get("ts"),
        "severity": level,
        "logger": logger or None,
        "message": message[:500],
        "raw": line.strip()[:500],
    }


def _is_business_failure(level: str, message: str) -> bool:
    if FALSE_POSITIVE_INFO.search(message):
        return False
    if level in {"ERROR", "FATAL", "WARN"}:
        return True
    if level != "INFO":
        return False
    return bool(BUSINESS_FAIL.search(message))


def scan_carbon_file(
    path: Path,
    *,
    max_findings: int = 200,
    max_read_bytes: int | None = None,
) -> dict[str, Any]:
    """Stream-scan an entire carbon log and extract failure signals."""
    level_counts: Counter[str] = Counter()
    logger_counts: Counter[str] = Counter()
    # Dedup while scanning so repeated WARNs don't crowd out later ERRORs
    findings: dict[str, dict[str, Any]] = {}
    warn_auth = 0
    http_4xx = 0
    http_5xx = 0
    exceptions = Counter()
    app_counts: Counter[str] = Counter()
    uri_counts: Counter[str] = Counter()
    api_counts: Counter[str] = Counter()
    tx_counts: Counter[str] = Counter()
    bytes_read = 0
    lines_seen = 0
    failure_count_raw = 0

    def _remember(entry: dict[str, Any]) -> None:
        nonlocal failure_count_raw
        failure_count_raw += 1
        ident = _extract_identity(
            f"{entry.get('functional_error') or ''} {entry.get('evidence') or ''}"
        )
        for app in ident["app_names"]:
            app_counts[app] += 1
        for uri in ident["request_uris"]:
            uri_counts[uri] += 1
        for api in ident["api_names"]:
            api_counts[api] += 1
        for tx in ident["transaction_ids"]:
            tx_counts[tx] += 1
        entry.update({k: v for k, v in ident.items() if v})
        key = f"{entry.get('logger')}|{(entry.get('functional_error') or '')[:120]}"
        if key in findings:
            findings[key]["occurrence_count"] = int(findings[key].get("occurrence_count") or 1) + 1
            # merge identity into existing finding
            for field in ("app_names", "request_uris", "api_names", "transaction_ids"):
                existing = list(findings[key].get(field) or [])
                for val in entry.get(field) or []:
                    if val not in existing:
                        existing.append(val)
                if existing:
                    findings[key][field] = existing[:8]
            return
        if len(findings) >= max_findings:
            # Prefer keeping ERROR/FATAL over WARN/INFO when full
            sev = entry.get("severity") or ""
            if sev not in {"ERROR", "FATAL"}:
                return
            victim = next(
                (
                    k
                    for k, v in findings.items()
                    if (v.get("severity") or "") not in {"ERROR", "FATAL"}
                ),
                None,
            )
            if not victim:
                return
            findings.pop(victim, None)
        findings[key] = {**entry, "occurrence_count": 1}

    size = path.stat().st_size if path.exists() else 0
    hit_byte_limit = False
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            lines_seen += 1
            # Prefer file position so scanned_fully matches on-disk size
            try:
                bytes_read = fh.tell()
            except OSError:
                bytes_read += len(line.encode("utf-8", errors="replace"))
            if max_read_bytes and bytes_read > max_read_bytes:
                hit_byte_limit = True
                break

            parsed = _parse_line(line)
            if not parsed:
                # continuation / stack / orphan business-failure fragments
                if STACK_FRAME.search(line):
                    if findings and (line.startswith("\t") or line.strip().startswith("at ") or "Exception" in line):
                        last = next(reversed(findings.values()))
                        if "stack_sample" not in last:
                            last["stack_sample"] = []
                        if len(last["stack_sample"]) < 6:
                            last["stack_sample"].append(line.strip()[:250])
                        ex = re.search(
                            r"\b((?:[a-zA-Z_][\w]*\.)*[A-Za-z][\w]*(?:Exception|Error))\b",
                            line,
                        )
                        if ex and not last.get("exception_type"):
                            last["exception_type"] = ex.group(1)
                            exceptions[ex.group(1)] += 1
                    continue
                if BUSINESS_FAIL.search(line) and not FALSE_POSITIVE_INFO.search(line):
                    ex = re.search(
                        r"\b((?:[a-zA-Z_][\w]*\.)*[A-Za-z][\w]*(?:Exception|Error))\b",
                        line,
                    )
                    msg = line.strip()[:400]
                    _remember(
                        {
                            "timestamp": None,
                            "severity": "ERROR",
                            "original_level": "INFO_CONTINUATION",
                            "logger": (next(reversed(findings.values())).get("logger") if findings else None),
                            "subsystem": "synapse_mediation",
                            "component": "LogMediator / integration payload",
                            "functional_error": msg,
                            "exception_type": ex.group(1) if ex else None,
                            "error_source": "wso2_component_message",
                            "evidence": line.strip()[:500],
                            "line_hint": lines_seen,
                        }
                    )
                    if re.search(r"(?i)status code\s*4\d\d", line):
                        http_4xx += 1
                    if re.search(r"(?i)status code\s*5\d\d", line):
                        http_5xx += 1
                continue

            level_counts[parsed["severity"]] += 1
            if not _is_business_failure(parsed["severity"], parsed["message"]):
                continue

            cls = classify_logger(parsed.get("logger"))
            ex_m = re.search(
                r"\b((?:[a-zA-Z_][\w]*\.)*[A-Za-z][\w]*(?:Exception|Error))\b",
                parsed["message"],
            )
            ex_type = ex_m.group(1) if ex_m else None
            source = classify_error_source(parsed.get("logger") or "", parsed["message"], ex_type)
            if parsed.get("logger"):
                logger_counts[parsed["logger"]] += 1
            if ex_type:
                exceptions[ex_type] += 1
            if re.search(r"(?i)authentication failure|Invalid Credentials|API_AUTH", parsed["message"]):
                warn_auth += 1
            if re.search(r"(?i)status code\s*4\d\d|HTTP\s*4\d\d", parsed["message"]):
                http_4xx += 1
            if re.search(r"(?i)status code\s*5\d\d|HTTP\s*5\d\d", parsed["message"]):
                http_5xx += 1

            _remember(
                {
                    "timestamp": parsed["timestamp"],
                    "severity": "ERROR"
                    if parsed["severity"] == "INFO"
                    else parsed["severity"],
                    "original_level": parsed["severity"],
                    "logger": parsed.get("logger"),
                    "subsystem": cls["subsystem"],
                    "component": cls["component"],
                    "functional_error": parsed["message"][:400],
                    "exception_type": ex_type,
                    "error_source": source,
                    "evidence": parsed["raw"],
                    "line_hint": lines_seen,
                }
            )

    unique = sorted(
        findings.values(),
        key=lambda x: (
            {"FATAL": 0, "ERROR": 1, "WARN": 2}.get(x.get("severity") or "", 3),
            -x.get("occurrence_count", 1),
        ),
    )

    # Sample head for product inference without re-reading whole file
    head = ""
    try:
        with path.open("r", encoding="utf-8", errors="replace") as fh:
            head = fh.read(6000)
    except OSError:
        head = ""
    product = infer_product(path.name, head)

    return {
        "file": path.name,
        "path": str(path),
        "product": product,
        "size_bytes": size,
        "bytes_scanned": bytes_read,
        "lines_scanned": lines_seen,
        "scanned_fully": (not hit_byte_limit) and (size == 0 or bytes_read > 0 or lines_seen > 0),
        "level_counts": dict(level_counts),
        "failure_findings": [
            {**f, "product": product, "source_file": path.name} for f in unique[:80]
        ],
        "failure_count_raw": failure_count_raw,
        "failure_count_unique": len(unique),
        "top_loggers": dict(logger_counts.most_common(20)),
        "top_exceptions": dict(exceptions.most_common(20)),
        "signals": {
            "auth_failures": warn_auth,
            "http_4xx": http_4xx,
            "http_5xx": http_5xx,
            "error_lines": int(level_counts.get("ERROR", 0)),
            "warn_lines": int(level_counts.get("WARN", 0)),
        },
        "identity": {
            "app_names": dict(app_counts.most_common(25)),
            "request_uris": dict(uri_counts.most_common(25)),
            "api_names": dict(api_counts.most_common(25)),
            "transaction_ids": dict(tx_counts.most_common(25)),
        },
        "note": (
            "Full-file error-first scan for APIM/MI carbon logs. INFO business failures "
            "(4xx/5xx, auth, timeouts, DB connect) are treated as findings."
            if unique
            else "No ERROR/WARN/FATAL or business-failure patterns found in scanned content."
        ),
    }


def scan_many(paths: Iterable[Path], max_read_bytes: int | None = None) -> dict[str, Any]:
    files = []
    total_unique = 0
    merged_signals = Counter()
    for path in paths:
        if not path.is_file():
            continue
        result = scan_carbon_file(path, max_read_bytes=max_read_bytes)
        files.append(result)
        total_unique += int(result.get("failure_count_unique") or 0)
        for k, v in (result.get("signals") or {}).items():
            merged_signals[k] += int(v or 0)
    return {
        "files": files,
        "total_failure_signatures": total_unique,
        "merged_signals": dict(merged_signals),
    }
