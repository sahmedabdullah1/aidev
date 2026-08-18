"""WSO2 EI / MI carbon log interpretation — no centralized error catalog.

Methodology (WSO2 support style):
1. Identify logger (Java class / %c)
2. Read functional message
3. Use exception type as root-cause signal
4. Map logger namespace → subsystem
5. Point remediation at that subsystem (Synapse, Axis2, transport, connector, DB, …)
"""

from __future__ import annotations

import re
from collections import Counter
from typing import Any

# [2026-07-31 14:32:15,123] ERROR {org.apache.synapse.mediators.base.SequenceMediator} Unexpected error...
CARBON_ENTRY = re.compile(
    r"^\[(?P<ts>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}[,\.]\d+)\]\s+"
    r"(?P<level>ERROR|WARN|FATAL|INFO|DEBUG|TRACE)\s+"
    r"(?:\{(?P<logger>[^}]+)\}\s*)?"
    r"(?P<message>.*)$",
    re.I,
)

# Also support: TID: [...] [app] [ts] LEVEL {c} - msg  (APIM-style)
APIM_ENTRY = re.compile(
    r"^(?:TID:\s*\[[^\]]*\]\s*(?:\[[^\]]*\]\s*)?)?\[?(?P<ts>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}[,\.]?\d*)\]?\s+"
    r"(?P<level>ERROR|WARN|FATAL|INFO|DEBUG|TRACE)\s+"
    r"(?:\{(?P<logger>[^}]+)\}\s*)?"
    r"(?:-\s*)?(?P<message>.*)$",
    re.I,
)

EXCEPTION_LINE = re.compile(
    r"^(?P<ex>(?:[a-zA-Z_][\w\.]*\.)*[A-Za-z][\w]*(?:Exception|Error|Throwable|Failure))"
    r"(?::\s*(?P<ex_msg>.*))?$"
)
CAUSED_BY = re.compile(
    r"^Caused by:\s*(?P<ex>(?:[a-zA-Z_][\w\.]*\.)*[A-Za-z][\w]*(?:Exception|Error|Throwable))"
    r"(?::\s*(?P<ex_msg>.*))?$"
)

# Primary logger namespaces for AI-driven EI/MI analysis
LOGGER_SUBSYSTEMS: list[tuple[str, str, str]] = [
    ("org.apache.synapse.endpoints", "synapse_endpoints", "Endpoint routing / backend send"),
    ("org.apache.synapse.transport", "synapse_transport", "HTTP/HTTPS PassThrough transport"),
    ("org.apache.synapse", "synapse_mediation", "Synapse mediation engine"),
    ("org.apache.axis2", "axis2", "SOAP / Axis2 runtime"),
    ("org.wso2.micro.integrator", "micro_integrator", "Micro Integrator runtime"),
    ("org.wso2.carbon", "carbon", "Carbon platform services"),
    ("org.apache.http", "http_client", "HTTP client communications"),
    ("org.apache.commons.dbcp", "db_pool", "Database connection pools"),
    ("org.quartz", "scheduled_tasks", "Scheduled tasks"),
    ("org.apache.tomcat", "tomcat", "Tomcat servlet container"),
    ("com.hazelcast", "hazelcast", "Hazelcast clustering"),
    ("org.wso2.carbon.apimgt", "apim", "API Manager component"),
]

CONNECTOR_HINTS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"(?i)kafka"), "kafka_connector"),
    (re.compile(r"(?i)\bjms\b|activemq|artemis"), "jms_transport"),
    (re.compile(r"(?i)rabbitmq|amqp"), "rabbitmq_connector"),
    (re.compile(r"(?i)smtp|mail\.|javamail"), "smtp_connector"),
    (re.compile(r"(?i)ftp|sftp|vfs|file.?connector"), "file_connector"),
    (re.compile(r"(?i)jdbc|datasource|sql|dbcp|database"), "database_connector"),
    (re.compile(r"(?i)data.?service|dss"), "data_services"),
    (re.compile(r"(?i)class.?mediator"), "class_mediator"),
    (re.compile(r"(?i)passthrough|PassThrough"), "passthrough_transport"),
]

ERROR_SOURCE_HINTS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"(?i)NullPointerException|SQLException|ConnectException|SocketTimeoutException|OutOfMemory"), "java_exception"),
    (re.compile(r"(?i)API_AUTH_FAILURE|Key validation failed|JWT validation failed"), "wso2_component_message"),
    (re.compile(r"(?i)synapse"), "synapse_error"),
    (re.compile(r"(?i)axis2"), "axis2_error"),
    (re.compile(r"(?i)hazelcast"), "hazelcast_error"),
    (re.compile(r"(?i)tomcat|coyote|catalina"), "tomcat_error"),
    (re.compile(r"(?i)jdbc|SQLException|datasource"), "jdbc_driver_error"),
]


def classify_logger(logger: str | None) -> dict[str, str]:
    if not logger:
        return {"subsystem": "unknown", "component": "unknown", "logger": ""}
    low = logger.strip()
    for prefix, subsystem, component in LOGGER_SUBSYSTEMS:
        if low.startswith(prefix) or prefix in low:
            return {"subsystem": subsystem, "component": component, "logger": low}
    for pattern, name in CONNECTOR_HINTS:
        if pattern.search(low):
            return {"subsystem": name, "component": name.replace("_", " "), "logger": low}
    return {"subsystem": "other", "component": low.rsplit(".", 1)[-1], "logger": low}


def classify_error_source(logger: str, message: str, exception: str | None) -> str:
    blob = f"{logger}\n{message}\n{exception or ''}"
    for pattern, name in ERROR_SOURCE_HINTS:
        if pattern.search(blob):
            return name
    if exception:
        return "java_exception"
    if logger.startswith("org.apache.synapse"):
        return "synapse_error"
    if logger.startswith("org.apache.axis2"):
        return "axis2_error"
    if logger.startswith("org.wso2"):
        return "wso2_component_message"
    return "subsystem_message"


def _parse_exception_block(lines: list[str], start: int) -> tuple[str | None, str | None, list[str], int]:
    """Return (exception_type, exception_message, stack_sample, next_index)."""
    ex_type = None
    ex_msg = None
    stack: list[str] = []
    i = start
    while i < len(lines):
        line = lines[i].rstrip()
        if not line.strip():
            i += 1
            if ex_type:
                break
            continue
        # New carbon entry starts
        if CARBON_ENTRY.match(line) or (line.startswith("[") and re.match(r"^\[\d{4}-\d{2}-\d{2}", line)):
            break
        m = CAUSED_BY.match(line.strip()) or EXCEPTION_LINE.match(line.strip())
        if m and ("Exception" in m.group("ex") or "Error" in m.group("ex")):
            # Prefer deepest Caused by as root
            ex_type = m.group("ex")
            ex_msg = (m.group("ex_msg") or "").strip() or None
            stack.append(line.strip()[:300])
            i += 1
            continue
        if line.strip().startswith("at ") or line.strip().startswith("..."):
            if len(stack) < 12:
                stack.append(line.strip()[:300])
            i += 1
            continue
        if ex_type:
            break
        i += 1
        break
    return ex_type, ex_msg, stack, i


def parse_carbon_entries(text: str, *, max_events: int = 80) -> dict[str, Any]:
    """Parse EI/MI / APIM carbon logs into structured events."""
    lines = text.splitlines()
    events: list[dict[str, Any]] = []
    level_counts: Counter[str] = Counter()
    logger_counts: Counter[str] = Counter()
    exception_counts: Counter[str] = Counter()
    subsystem_counts: Counter[str] = Counter()
    i = 0
    while i < len(lines) and len(events) < max_events:
        line = lines[i]
        m = CARBON_ENTRY.match(line) or APIM_ENTRY.match(line)
        if not m:
            i += 1
            continue
        level = m.group("level").upper()
        level_counts[level] += 1
        logger = (m.groupdict().get("logger") or "").strip()
        message = (m.group("message") or "").strip()
        # If logger missing, message may start with {logger}
        if not logger and message.startswith("{"):
            lm = re.match(r"^\{([^}]+)\}\s*(.*)$", message)
            if lm:
                logger = lm.group(1).strip()
                message = lm.group(2).strip()

        ex_type, ex_msg, stack, next_i = _parse_exception_block(lines, i + 1)
        # Also detect exception named in the same line
        if not ex_type:
            inline = re.search(
                r"\b((?:[a-zA-Z_][\w]*\.)*[A-Za-z][\w]*(?:Exception|Error))\b",
                message,
            )
            if inline:
                ex_type = inline.group(1)

        cls = classify_logger(logger)
        source = classify_error_source(logger, message, ex_type)
        if logger:
            logger_counts[logger] += 1
        if ex_type:
            exception_counts[ex_type] += 1
        subsystem_counts[cls["subsystem"]] += 1

        if level in {"ERROR", "FATAL", "WARN"} or ex_type:
            events.append(
                {
                    "timestamp": m.group("ts"),
                    "severity": level,
                    "logger": logger or None,
                    "subsystem": cls["subsystem"],
                    "component": cls["component"],
                    "functional_error": message[:400],
                    "exception_type": ex_type,
                    "exception_message": (ex_msg or "")[:300] or None,
                    "error_source": source,
                    "stack_sample": stack[:8],
                    "interpretation_hint": _hint(cls["subsystem"], message, ex_type),
                }
            )
        i = max(next_i, i + 1)

    # Aggregate high-value ERROR/FATAL only for summary
    error_events = [e for e in events if e["severity"] in {"ERROR", "FATAL"}]
    return {
        "methodology": {
            "note": "EI/MI have no centralized error code catalog",
            "primary_indicators": ["logger (%c)", "exception type", "functional message"],
            "error_sources": [
                "Java Exception",
                "WSO2 component message",
                "Synapse error",
                "Axis2 error",
                "Hazelcast error",
                "Tomcat error",
                "JDBC driver error",
            ],
            "important_loggers": [x[0] for x in LOGGER_SUBSYSTEMS],
            "default_paths": {
                "EI": "<EI_HOME>/repository/logs/wso2carbon.log",
                "MI": "<MI_HOME>/repository/logs/wso2carbon.log",
                "APIM": "<APIM_HOME>/repository/logs/wso2carbon.log",
            },
            "log_format": "Timestamp | Log Level | Logger (Java Class) | Message | Exception",
            "example": (
                "ERROR {org.apache.synapse.endpoints.AddressEndpoint} "
                "Couldn't send message to endpoint. java.net.SocketTimeoutException "
                "→ reached backend, network OK, backend/timeout config issue"
            ),
        },
        "level_counts": dict(level_counts),
        "top_loggers": dict(logger_counts.most_common(25)),
        "top_exceptions": dict(exception_counts.most_common(25)),
        "subsystem_counts": dict(subsystem_counts),
        "structured_events": error_events[:60] or events[:40],
        "event_count_parsed": len(events),
        "error_event_count": len(error_events),
    }


def _hint(subsystem: str, message: str, ex_type: str | None) -> str:
    if ex_type and "SocketTimeoutException" in ex_type:
        return (
            "Integration reached the backend; network path exists; backend did not respond "
            "within configured timeout — check backend health and endpoint timeout settings."
        )
    if ex_type and "ConnectException" in ex_type:
        return "Could not establish TCP connection to backend — check host/port, firewall, DNS, service up."
    if ex_type and "SQLException" in (ex_type or ""):
        return "Database/JDBC failure — check DB availability, credentials, pool, and SQL."
    if subsystem == "synapse_endpoints":
        return "Endpoint routing/send failure — inspect endpoint URL, timeout, and backend."
    if subsystem == "synapse_mediation":
        return "Mediation sequence failure — inspect proxy/API sequence, mediators, and payload."
    if subsystem == "db_pool" or subsystem == "database_connector":
        return "DB pool/connector issue — check maxActive, validation query, DB load."
    if "auth" in message.lower() or "JWT" in message or "API_AUTH" in message:
        return "Auth/token validation failure — check keys, token expiry, and security policies."
    return "Use logger + exception as primary indicators; search WSO2 GitHub/docs for the logger class."
