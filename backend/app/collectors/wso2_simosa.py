"""Scanner for SIMOSA / JAZZADVANCE transaction logs.

Log format (grep extract or native wso2carbon lines):
  <filename>:[<timestamp>] ... LOG_TYPE_JAZZADVANCE = LOG_REQUEST_SEQUENCE|LOG_RESPONSE_SEQUENCE,
  ID = <tx_id>, API_NAME = <api>, INTERFACE_NAME = REQUEST|RESPONSE, STATUS = OK|KO,
  APP_NAME = SIMOSA, MSISDN = <msisdn>, status_code = <code>, message = <msg>
"""
from __future__ import annotations

import re
from collections import Counter
from pathlib import Path
from typing import Any

# Regexes
_ID = re.compile(r"\bID\s*=\s*(\d+)")
_API = re.compile(r"\bAPI_NAME\s*=\s*(\w+)")
_IFACE = re.compile(r"\bINTERFACE_NAME\s*=\s*(REQUEST|RESPONSE)", re.I)
_STATUS = re.compile(r"\bSTATUS\s*=\s*(OK|KO)\b", re.I)
_APP = re.compile(r"\bAPP_NAME\s*=\s*(\w+)")
_CODE = re.compile(r'"status_code"\s*:\s*"(\d+)"')
_MSG = re.compile(r'"message"\s*:\s*"([^"]{3,120})"')
_MSISDN = re.compile(r"\bMSISDN\s*=\s*(9\d{10,11})")
_TS = re.compile(r"\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})")
_RESP_TIME = re.compile(r"\bRESPONSE_TIME\s*=\s*([\d\-: .]+)")
_REQ_TIME = re.compile(r"\bREQUEST_TIME\s*=\s*([\d\-: .]+)")

SIMOSA_HINT = re.compile(
    r"(?i)(LOG_TYPE_JAZZADVANCE|APP_NAME\s*=\s*SIMOSA|CHANNEL:SIMOSA|JAZZADVANCE_ELIGIBLITY|JAZZADVANCE_PROVISIONING)",
)


def is_simosa_log(path: Path, sample: str = "") -> bool:
    if not sample:
        try:
            sample = path.read_bytes()[:4096].decode("utf-8", errors="replace")
        except Exception:  # noqa: BLE001
            return False
    return bool(SIMOSA_HINT.search(sample))


def scan_simosa_file(path: Path, max_read_bytes: int = 40_000_000) -> dict[str, Any]:
    """Scan a SIMOSA transaction log. Returns traffic stats + error breakdown."""
    requests: dict[str, dict[str, Any]] = {}  # tx_id -> request row
    responses: dict[str, dict[str, Any]] = {}  # tx_id -> response row
    api_counts: Counter[str] = Counter()
    status_codes: Counter[str] = Counter()
    failure_msgs: Counter[str] = Counter()
    timestamps: list[str] = []
    bytes_read = 0

    try:
        with path.open("r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                bytes_read += len(line.encode("utf-8", errors="replace"))
                if max_read_bytes and bytes_read > max_read_bytes:
                    break
                if not SIMOSA_HINT.search(line):
                    continue

                id_m = _ID.search(line)
                if not id_m:
                    continue
                tx_id = id_m.group(1)

                iface_m = _IFACE.search(line)
                if not iface_m:
                    continue
                iface = iface_m.group(1).upper()

                api_m = _API.search(line)
                api = api_m.group(1) if api_m else "UNKNOWN"
                api_counts[api] += 1

                ts_m = _TS.search(line)
                if ts_m:
                    timestamps.append(ts_m.group(1))

                if iface == "REQUEST":
                    ms_m = _MSISDN.search(line)
                    req_t = _REQ_TIME.search(line)
                    requests[tx_id] = {
                        "api": api,
                        "msisdn": ms_m.group(1) if ms_m else None,
                        "request_time": req_t.group(1).strip() if req_t else None,
                    }
                elif iface == "RESPONSE":
                    status_m = _STATUS.search(line)
                    status = status_m.group(1).upper() if status_m else "UNKNOWN"
                    code_m = _CODE.search(line)
                    msg_m = _MSG.search(line)
                    resp_t = _RESP_TIME.search(line)
                    responses[tx_id] = {
                        "api": api,
                        "status": status,
                        "code": code_m.group(1) if code_m else None,
                        "message": msg_m.group(1) if msg_m else None,
                        "response_time": resp_t.group(1).strip() if resp_t else None,
                    }
                    if code_m:
                        status_codes[code_m.group(1)] += 1
                    if status == "KO" and msg_m:
                        failure_msgs[msg_m.group(1)] += 1
    except Exception:  # noqa: BLE001
        pass

    # Build paired stats
    paired = set(requests) & set(responses)
    total = len(paired) or max(len(requests), len(responses))
    ok = sum(1 for tx in paired if responses[tx]["status"] == "OK")
    ko = sum(1 for tx in paired if responses[tx]["status"] == "KO")
    errors = ko
    success = ok
    pct = round(100.0 * errors / total, 2) if total else 0.0

    # Sample failure findings
    failure_findings: list[dict[str, Any]] = []
    for tx in list(paired):
        resp = responses[tx]
        if resp["status"] == "KO":
            req = requests.get(tx, {})
            failure_findings.append({
                "timestamp": (timestamps[0] if timestamps else None),
                "severity": "WARN",
                "original_level": "INFO",
                "logger": "org.apache.synapse.mediators.builtin.LogMediator",
                "subsystem": "synapse_mediation",
                "component": "SIMOSA JAZZADVANCE",
                "functional_error": (
                    f"JAZZADVANCE {resp.get('api','?')} KO — "
                    f"status_code={resp.get('code','?')}: {resp.get('message','?')} "
                    f"(MSISDN={req.get('msisdn','?')})"
                )[:400],
                "exception_type": None,
                "error_source": "wso2_component_message",
                "evidence": f"TX_ID={tx} STATUS=KO code={resp.get('code')} msg={resp.get('message')}",
                "occurrence_count": 1,
            })
        if len(failure_findings) >= 60:
            break

    top_codes = [{"code": c, "count": n} for c, n in status_codes.most_common(10)]
    top_msgs = [{"message": m, "count": n} for m, n in failure_msgs.most_common(5)]
    top_apis = [{"api": a, "count": n} for a, n in api_counts.most_common(10)]

    size = path.stat().st_size if path.exists() else 0
    return {
        "log_type": "wso2carbon",
        "product": "MI",
        "is_simosa": True,
        "app": "SIMOSA",
        "size_bytes": size,
        "bytes_scanned": bytes_read,
        "scanned_fully": bytes_read < max_read_bytes,
        "total_transactions": total,
        "total_success": success,
        "total_errors": errors,
        "error_pct": pct,
        "traffic": {
            "total_transactions": total,
            "total_success": success,
            "total_errors": errors,
            "error_pct": pct,
        },
        "top_status_codes": top_codes,
        "top_failure_messages": top_msgs,
        "top_apis": top_apis,
        "failure_findings": failure_findings[:60],
        "failure_count_raw": errors,
        "failure_count_unique": len({f["functional_error"] for f in failure_findings}),
        "time_range": (
            f"{min(timestamps)} → {max(timestamps)}" if timestamps else None
        ),
        "signals": {
            "simosa_ok": ok,
            "simosa_ko": ko,
            "simosa_error_pct": pct,
        },
        "ip_mentions": {},
    }
