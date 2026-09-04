"""Incremental log + host-metric ingest for the live monitor."""

from __future__ import annotations

import re
from collections import Counter, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from app.collectors.wso2_file_stats import IPV4
from app.collectors.wso2_log_scan import _is_business_failure, _parse_line
from app.collectors.wso2_logs import ERROR_RE, HTTP_ACCESS, detect_log_type
from app.models.wso2_schemas import Wso2LogType

ACCESS_LATENCY = re.compile(
    r'(?P<ip>\d+\.\d+\.\d+\.\d+).*?"(?P<method>[A-Z]+)\s+(?P<uri>\S+)\s+[^"]*"\s+'
    r"(?P<status>\d{3})\s+(?P<size>\d+|-)\s+(?P<latency>[\d.]+)"
)
GC_HINT = re.compile(r"(?i)(Full GC|Pause Young|OutOfMemory|Allocation Failure)")
INTERESTING_NAME = re.compile(
    r"(?i)(wso2carbon|http[_-]?access|audit|wire|catalina|gc|carbon|\.log$|\.out$)"
)
SKIP_NAME = re.compile(r"(?i)(\.hprof$|\.gz$|\.zip$|\.bz2$|\.tmp$|\.\d+$)")
METRICS_KV = re.compile(r"^([A-Z_]+)=(.*)$", re.M)


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def is_active_log_name(name: str) -> bool:
    if not name or name.startswith("."):
        return False
    if SKIP_NAME.search(name):
        return False
    return bool(INTERESTING_NAME.search(name))


def classify_filename(name: str, sample: str = "") -> str:
    return detect_log_type(name, sample).value


def split_complete_lines(leftover: str, chunk: str) -> tuple[list[str], str]:
    data = leftover + chunk
    if not data:
        return [], ""
    lines = data.splitlines()
    if data.endswith("\n") or data.endswith("\r"):
        return lines, ""
    if not lines:
        return [], data
    return lines[:-1], lines[-1]


def _allocated_vcpu(allocation: Any) -> float:
    if isinstance(allocation, dict):
        for key in ("vcpu", "vcpus", "cpu", "cores"):
            val = allocation.get(key)
            if val is None or val == "":
                continue
            try:
                n = float(val)
            except (TypeError, ValueError):
                continue
            if n > 0:
                return n
    return 8.0


@dataclass
class RollingText:
    max_bytes: int = 8_000_000
    _parts: list[str] = field(default_factory=list)
    _size: int = 0

    def append(self, text: str) -> None:
        if not text:
            return
        self._parts.append(text)
        self._size += len(text.encode("utf-8", errors="replace"))
        while self._size > self.max_bytes and self._parts:
            dropped = self._parts.pop(0)
            self._size -= len(dropped.encode("utf-8", errors="replace"))

    def get(self) -> str:
        return "".join(self._parts)

    def __len__(self) -> int:
        return self._size


@dataclass
class LiveAggregator:
    compute_allocation: Any = None
    grid_kg_co2_per_kwh: float = 0.4
    watts_per_vcpu: float = 15.0
    started_at: datetime = field(default_factory=utcnow)

    requests: int = 0
    success: int = 0
    http_errors: int = 0
    carbon_errors: int = 0
    carbon_warns: int = 0
    carbon_lines: int = 0
    gc_pauses: int = 0
    bytes_ingested: int = 0
    latencies: deque[float] = field(default_factory=lambda: deque(maxlen=2000))
    status_counts: Counter[str] = field(default_factory=Counter)
    method_counts: Counter[str] = field(default_factory=Counter)
    top_uris: Counter[str] = field(default_factory=Counter)
    top_clients: Counter[str] = field(default_factory=Counter)
    client_errors: Counter[str] = field(default_factory=Counter)
    error_messages: Counter[str] = field(default_factory=Counter)
    loggers: Counter[str] = field(default_factory=Counter)
    recent_errors: deque[dict[str, Any]] = field(default_factory=lambda: deque(maxlen=40))
    recent_access: deque[dict[str, Any]] = field(default_factory=lambda: deque(maxlen=30))
    series: deque[dict[str, Any]] = field(default_factory=lambda: deque(maxlen=120))
    windows: dict[str, RollingText] = field(default_factory=dict)

    prev_cpu: tuple[float, float] | None = None  # idle, total
    prev_net: tuple[float, float] | None = None  # rx, tx
    prev_poll_at: datetime | None = None
    last_requests: int = 0
    last_http_errors: int = 0
    last_carbon_errors: int = 0
    session_kg_co2: float = 0.0
    last_metrics: dict[str, Any] = field(default_factory=dict)

    def window_for(self, filename: str) -> RollingText:
        buf = self.windows.get(filename)
        if buf is None:
            buf = RollingText()
            self.windows[filename] = buf
        return buf

    def ingest_lines(self, filename: str, lines: list[str], log_type: str | None = None) -> int:
        if not lines:
            return 0
        sample = "\n".join(lines[:8])
        kind = log_type or classify_filename(filename, sample)
        text = "\n".join(lines) + "\n"
        self.window_for(filename).append(text)
        self.bytes_ingested += len(text.encode("utf-8", errors="replace"))
        n = 0
        if kind == Wso2LogType.http_access.value:
            for line in lines:
                n += self._ingest_access(line)
        elif kind in {Wso2LogType.wso2carbon.value, Wso2LogType.unknown.value, Wso2LogType.catalina.value}:
            for line in lines:
                n += self._ingest_carbon(line, filename, kind)
        elif kind == Wso2LogType.gc.value:
            for line in lines:
                if GC_HINT.search(line):
                    self.gc_pauses += 1
                    n += 1
                    self.recent_errors.append(
                        {
                            "file": filename,
                            "level": "WARN",
                            "logger": "gc",
                            "message": line.strip()[:280],
                        }
                    )
        else:
            for line in lines:
                if ERROR_RE.search(line):
                    self.carbon_errors += 1
                    n += 1
                    self.recent_errors.append(
                        {
                            "file": filename,
                            "level": "ERROR",
                            "logger": kind,
                            "message": line.strip()[:280],
                        }
                    )
        return n

    def _ingest_access(self, line: str) -> int:
        m = ACCESS_LATENCY.search(line) or HTTP_ACCESS.search(line)
        if not m:
            return 0
        status = m.group("status")
        ip = m.group("ip")
        method = m.group("method")
        uri = m.group("uri")[:160]
        self.requests += 1
        self.status_counts[status] += 1
        self.method_counts[method] += 1
        self.top_uris[uri] += 1
        self.top_clients[ip] += 1
        is_err = status.startswith("4") or status.startswith("5")
        if is_err:
            self.http_errors += 1
            self.client_errors[ip] += 1
        else:
            self.success += 1
        latency = m.groupdict().get("latency")
        if latency:
            try:
                val = float(latency)
                # WSO2 often logs seconds; values > 20 are more likely milliseconds
                if val > 20:
                    val = val / 1000.0
                self.latencies.append(val)
            except ValueError:
                pass
        self.recent_access.append(
            {"ip": ip, "method": method, "uri": uri, "status": status}
        )
        return 1

    def _ingest_carbon(self, line: str, filename: str, kind: str) -> int:
        self.carbon_lines += 1
        parsed = _parse_line(line)
        if parsed:
            level = str(parsed.get("severity") or "INFO").upper()
            message = str(parsed.get("message") or "")
            logger = str(parsed.get("logger") or "")
            if level == "ERROR" or level == "FATAL":
                self.carbon_errors += 1
            elif level == "WARN":
                self.carbon_warns += 1
            if logger:
                self.loggers[logger.split(".")[-1][:80]] += 1
            if _is_business_failure(level, message):
                key = (message or line.strip())[:160]
                self.error_messages[key] += 1
                self.recent_errors.append(
                    {
                        "file": filename,
                        "level": level,
                        "logger": logger or kind,
                        "message": message[:280] or line.strip()[:280],
                        "ts": parsed.get("timestamp"),
                    }
                )
                for ip in IPV4.findall(message)[:3]:
                    self.client_errors[ip] += 1
                return 1
            return 0
        if ERROR_RE.search(line):
            self.carbon_errors += 1
            self.recent_errors.append(
                {
                    "file": filename,
                    "level": "ERROR",
                    "logger": kind,
                    "message": line.strip()[:280],
                }
            )
            return 1
        return 0

    def apply_metrics(
        self,
        raw: dict[str, Any],
        *,
        interval_seconds: float,
    ) -> dict[str, Any]:
        now = utcnow()
        cpu_pct = None
        idle_total = raw.get("cpu_idle_total")
        if isinstance(idle_total, (list, tuple)) and len(idle_total) == 2:
            idle, total = float(idle_total[0]), float(idle_total[1])
            if self.prev_cpu and total > self.prev_cpu[1]:
                di = idle - self.prev_cpu[0]
                dt = total - self.prev_cpu[1]
                if dt > 0:
                    cpu_pct = round(max(0.0, min(100.0, (1.0 - di / dt) * 100.0)), 1)
            self.prev_cpu = (idle, total)
        if cpu_pct is None and raw.get("cpu_pct") is not None:
            try:
                cpu_pct = round(float(raw["cpu_pct"]), 1)
            except (TypeError, ValueError):
                cpu_pct = None

        mem_pct = raw.get("mem_pct")
        disk_pct = raw.get("disk_pct")
        load = raw.get("load_1")
        net_rx_bps = None
        net_tx_bps = None
        rx_tx = raw.get("net_rx_tx")
        if isinstance(rx_tx, (list, tuple)) and len(rx_tx) == 2 and interval_seconds > 0:
            rx, tx = float(rx_tx[0]), float(rx_tx[1])
            if self.prev_net:
                net_rx_bps = max(0.0, (rx - self.prev_net[0]) / interval_seconds)
                net_tx_bps = max(0.0, (tx - self.prev_net[1]) / interval_seconds)
            self.prev_net = (rx, tx)

        vcpu = _allocated_vcpu(self.compute_allocation)
        load_factor = (cpu_pct or 0.0) / 100.0
        kw = (vcpu * self.watts_per_vcpu / 1000.0) * (0.3 + 0.7 * load_factor)
        kg_per_hour = round(kw * self.grid_kg_co2_per_kwh, 4)
        self.session_kg_co2 += kg_per_hour * (max(interval_seconds, 0.0) / 3600.0)

        req_delta = self.requests - self.last_requests
        err_delta = (self.http_errors + self.carbon_errors) - (
            self.last_http_errors + self.last_carbon_errors
        )
        elapsed = interval_seconds if interval_seconds > 0 else 1.0
        rps = round(req_delta / elapsed, 2)
        error_pct = round(
            (100.0 * (self.http_errors + self.carbon_errors) / self.requests) if self.requests else 0.0,
            2,
        )
        window_error_pct = round((100.0 * err_delta / req_delta) if req_delta else 0.0, 2)
        avg_latency = None
        if self.latencies:
            avg_latency = round(sum(self.latencies) / len(self.latencies), 3)

        self.last_requests = self.requests
        self.last_http_errors = self.http_errors
        self.last_carbon_errors = self.carbon_errors
        self.prev_poll_at = now

        metrics = {
            "cpu_pct": cpu_pct,
            "mem_pct": mem_pct,
            "disk_pct": disk_pct,
            "load_1": load,
            "net_rx_bps": round(net_rx_bps, 0) if net_rx_bps is not None else None,
            "net_tx_bps": round(net_tx_bps, 0) if net_tx_bps is not None else None,
            "hostname": raw.get("hostname"),
            "uname": raw.get("uname"),
            "uptime_seconds": raw.get("uptime_seconds"),
            "ips": raw.get("ips") or [],
            "mem_total_mb": raw.get("mem_total_mb"),
            "mem_used_mb": raw.get("mem_used_mb"),
            "disk_used_pct": disk_pct,
            "note": raw.get("note"),
        }
        emissions = {
            "kg_co2_per_hour": kg_per_hour,
            "session_kg_co2": round(self.session_kg_co2, 5),
            "assumed_vcpu": vcpu,
            "watts_per_vcpu": self.watts_per_vcpu,
            "grid_kg_co2_per_kwh": self.grid_kg_co2_per_kwh,
            "method": "estimated from CPU×vCPU×grid factor (not a measured meter)",
        }
        self.last_metrics = metrics
        self.series.append(
            {
                "t": now.isoformat(),
                "rps": rps,
                "error_pct": window_error_pct,
                "cpu_pct": cpu_pct,
                "mem_pct": mem_pct,
                "kg_co2_per_hour": kg_per_hour,
            }
        )
        return {
            "metrics": metrics,
            "emissions": emissions,
            "rates": {
                "requests_per_sec": rps,
                "window_error_pct": window_error_pct,
                "session_error_pct": error_pct,
                "avg_latency_sec": avg_latency,
                "interval_seconds": round(elapsed, 2),
            },
        }

    def snapshot(self) -> dict[str, Any]:
        suspicious = []
        for ip, hits in self.client_errors.most_common(12):
            total = self.top_clients.get(ip, hits)
            ratio = hits / total if total else 1.0
            if hits >= 3 and ratio >= 0.15:
                suspicious.append(
                    {"ip": ip, "error_hits": hits, "requests": total, "error_share": round(ratio * 100, 1)}
                )
        p95 = None
        if self.latencies:
            ordered = sorted(self.latencies)
            p95 = round(ordered[min(len(ordered) - 1, int(len(ordered) * 0.95))], 3)
        return {
            "started_at": self.started_at.isoformat(),
            "bytes_ingested": self.bytes_ingested,
            "traffic": {
                "total_requests": self.requests,
                "success": self.success,
                "http_errors": self.http_errors,
                "error_pct": round(
                    (100.0 * self.http_errors / self.requests) if self.requests else 0.0, 2
                ),
                "status_counts": dict(self.status_counts.most_common(15)),
                "method_counts": dict(self.method_counts.most_common(10)),
                "top_uris": dict(self.top_uris.most_common(12)),
                "top_clients": dict(self.top_clients.most_common(12)),
                "avg_latency_sec": round(sum(self.latencies) / len(self.latencies), 3)
                if self.latencies
                else None,
                "p95_latency_sec": p95,
            },
            "carbon_log": {
                "lines": self.carbon_lines,
                "errors": self.carbon_errors,
                "warnings": self.carbon_warns,
                "gc_pauses": self.gc_pauses,
                "top_error_messages": dict(self.error_messages.most_common(10)),
                "top_loggers": dict(self.loggers.most_common(10)),
            },
            "suspicious_ips": suspicious,
            "recent_errors": list(self.recent_errors)[-20:],
            "recent_access": list(self.recent_access)[-15:],
            "series": list(self.series),
            "metrics": self.last_metrics,
            "emissions": {
                "kg_co2_per_hour": (self.series[-1]["kg_co2_per_hour"] if self.series else None),
                "session_kg_co2": round(self.session_kg_co2, 5),
                "assumed_vcpu": _allocated_vcpu(self.compute_allocation),
                "method": "estimated from CPU×vCPU×grid factor (not a measured meter)",
            },
        }


def parse_metrics_script_output(text: str) -> dict[str, Any]:
    """Parse KEY=value output from the remote Linux metrics script."""
    raw: dict[str, str] = {}
    for m in METRICS_KV.finditer(text or ""):
        raw[m.group(1)] = m.group(2).strip()
    out: dict[str, Any] = {
        "hostname": raw.get("HOSTNAME") or None,
        "uname": raw.get("UNAME") or None,
        "ips": [ip for ip in (raw.get("IPS") or "").split() if ip],
        "note": None,
    }
    load = (raw.get("LOAD") or "").split()
    if load:
        try:
            out["load_1"] = float(load[0])
        except ValueError:
            pass
    try:
        out["uptime_seconds"] = float(raw.get("UPTIME") or 0) or None
    except ValueError:
        pass
    cpu_parts = (raw.get("CPU") or "").split()
    if len(cpu_parts) >= 5:
        try:
            nums = [float(x) for x in cpu_parts[:8]]
            idle = nums[3] + (nums[4] if len(nums) > 4 else 0)  # idle + iowait
            total = sum(nums)
            out["cpu_idle_total"] = (idle, total)
        except ValueError:
            pass
    try:
        mem_total = float(raw.get("MEM_TOTAL") or 0)  # kB
        mem_avail = float(raw.get("MEM_AVAIL") or 0)
        if mem_total > 0:
            used = mem_total - mem_avail
            out["mem_pct"] = round(100.0 * used / mem_total, 1)
            out["mem_total_mb"] = round(mem_total / 1024.0, 0)
            out["mem_used_mb"] = round(used / 1024.0, 0)
    except ValueError:
        pass
    disk_parts = (raw.get("DISK") or "").split()
    if len(disk_parts) >= 4:
        pct = disk_parts[3].rstrip("%")
        try:
            out["disk_pct"] = float(pct)
        except ValueError:
            pass
    net_parts = (raw.get("NET") or "").split()
    if len(net_parts) >= 2:
        try:
            out["net_rx_tx"] = (float(net_parts[0]), float(net_parts[1]))
        except ValueError:
            pass
    return out


LINUX_METRICS_SCRIPT = r"""
echo HOSTNAME=$(hostname 2>/dev/null)
echo UNAME=$(uname -srm 2>/dev/null)
echo LOAD=$(cat /proc/loadavg 2>/dev/null)
echo UPTIME=$(awk '{print $1}' /proc/uptime 2>/dev/null)
echo CPU=$(awk '/^cpu /{print $2,$3,$4,$5,$6,$7,$8,$9}' /proc/stat 2>/dev/null)
echo MEM_TOTAL=$(awk '/MemTotal/{print $2}' /proc/meminfo 2>/dev/null)
echo MEM_AVAIL=$(awk '/MemAvailable/{print $2}' /proc/meminfo 2>/dev/null)
echo DISK=$(df -P / 2>/dev/null | awk 'NR==2{print $2,$3,$4,$5}')
echo NET=$(awk 'NR>2{rx+=$2; tx+=$10} END{print rx+0, tx+0}' /proc/net/dev 2>/dev/null)
echo IPS=$(hostname -I 2>/dev/null || true)
""".strip()
