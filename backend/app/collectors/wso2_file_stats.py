"""Per-log-file traffic: IP, total transactions, success, errors, error %."""

from __future__ import annotations

import re
from collections import Counter
from typing import Any

IPV4 = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b")
UUID_PREFIX = re.compile(r"^[0-9a-f]{8}_", re.I)
TX_HINT = re.compile(
    r"(?i)(\{api:|requestURI=|TRANSACTION_ID\s*=|APIAuthenticationHandler|"
    r"API_FULL_REQUEST|INTERFACE_NAME\s*=)"
)


def display_name(filename: str) -> str:
    return UUID_PREFIX.sub("", filename or "") or (filename or "log")


def flatten_node_ips(ip_addresses: Any) -> list[tuple[str, str]]:
    """Return [(ip, role)] from form context: dict {apim:[], mi:[]}, list, or string."""
    out: list[tuple[str, str]] = []
    seen: set[str] = set()

    def _add(ip: str, role: str) -> None:
        ip = (ip or "").strip()
        if not ip or not IPV4.fullmatch(ip) or ip in seen:
            return
        seen.add(ip)
        out.append((ip, role))

    if isinstance(ip_addresses, dict):
        for key, val in ip_addresses.items():
            role = str(key).upper()
            if role in {"APIM", "API-MANAGER", "API_MANAGER"}:
                role = "APIM"
            elif role in {"MI", "EI", "MICRO-INTEGRATOR", "MICRO_INTEGRATOR"}:
                role = "MI"
            if isinstance(val, list):
                for item in val:
                    _add(str(item), role)
            else:
                _add(str(val), role)
    elif isinstance(ip_addresses, list):
        for item in ip_addresses:
            _add(str(item), "NODE")
    elif isinstance(ip_addresses, str):
        for ip in IPV4.findall(ip_addresses):
            _add(ip, "NODE")
    return out


def error_pct(errors: int, total: int) -> float:
    if total <= 0:
        return 0.0
    return round(100.0 * errors / total, 2)


def traffic_tuple(total: int, errors: int) -> dict[str, Any]:
    total = max(0, int(total))
    errors = max(0, min(int(errors), total) if total else int(errors))
    success = max(0, total - errors)
    return {
        "total_transactions": total,
        "total_success": success,
        "total_errors": errors,
        "error_pct": error_pct(errors, total),
    }


def traffic_from_scan_row(row: dict[str, Any]) -> dict[str, Any]:
    if row.get("total_transactions") is not None:
        return traffic_tuple(int(row.get("total_transactions") or 0), int(row.get("total_errors") or 0))
    traffic = row.get("traffic") or {}
    if traffic.get("total_transactions") is not None:
        return traffic_tuple(
            int(traffic.get("total_transactions") or 0),
            int(traffic.get("total_errors") or 0),
        )
    levels = row.get("level_counts") or {}
    parsed = sum(int(v or 0) for v in levels.values())
    errors = int(row.get("failure_count_raw") or 0)
    if errors <= 0:
        errors = int((row.get("signals") or {}).get("error_lines") or 0) + int(
            (row.get("signals") or {}).get("warn_lines") or 0
        )
    return traffic_tuple(parsed, errors)


def _filename_ip(name: str) -> str | None:
    found = IPV4.findall(name or "")
    return found[0] if found else None


def assign_file_ips(
    files: list[dict[str, Any]],
    ip_addresses: Any,
) -> list[dict[str, Any]]:
    """Attach one node IP to each log file (filename → known IPs in content → leftover pool)."""
    pool = flatten_node_ips(ip_addresses)
    used: set[str] = set()
    by_role: dict[str, list[str]] = {}
    for ip, role in pool:
        by_role.setdefault(role, []).append(ip)
    leftover = [ip for ip, _ in pool]

    def _take(preferred: str | None) -> tuple[str | None, str]:
        if preferred and preferred not in used:
            used.add(preferred)
            if preferred in leftover:
                leftover.remove(preferred)
            return preferred, "matched"
        return None, ""

    for row in files:
        product = str(row.get("product") or "").upper()
        name = str(row.get("display_name") or row.get("file") or "")
        mentions = row.get("ip_mentions") or {}
        ip = None
        source = "unassigned"

        fn_ip = _filename_ip(name)
        if fn_ip:
            got, _ = _take(fn_ip)
            if got:
                ip, source = got, "filename"

        if not ip:
            known = {p for p, _ in pool}
            ranked = sorted(
                ((str(k), int(v or 0)) for k, v in mentions.items() if k in known and k not in used),
                key=lambda x: -x[1],
            )
            if ranked:
                got, _ = _take(ranked[0][0])
                if got:
                    ip, source = got, "log_content"

        if not ip:
            role = "APIM" if "APIM" in product and "MI" not in product.replace("APIM", "") else (
                "MI" if "MI" in product or "EI" in product else None
            )
            if role:
                for candidate in by_role.get(role, []):
                    got, _ = _take(candidate)
                    if got:
                        ip, source = got, f"context_{role.lower()}"
                        break

        if not ip and leftover:
            ip, source = leftover.pop(0), "context_pool"
            used.add(ip)

        row["ip"] = ip
        row["ip_source"] = source
        row["ip_role"] = next((r for p, r in pool if p == ip), None)
    return files


def build_file_stats(
    scan_summaries: list[dict[str, Any]],
    ip_addresses: Any = None,
) -> list[dict[str, Any]]:
    stats: list[dict[str, Any]] = []
    for row in scan_summaries or []:
        traffic = traffic_from_scan_row(row)
        name = str(row.get("file") or "")
        item = {
            "file": name,
            "display_name": row.get("display_name") or display_name(name),
            "log_type": row.get("log_type") or "wso2carbon",
            "product": row.get("product") or "APIM/MI",
            "ip_mentions": row.get("ip_mentions") or {},
            **traffic,
        }
        stats.append(item)
    return assign_file_ips(stats, ip_addresses)
