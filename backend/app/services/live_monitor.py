"""Live SSH/local log tail + periodic AI reports."""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Protocol

from app.collectors.live_ingest import (
    LINUX_METRICS_SCRIPT,
    LiveAggregator,
    classify_filename,
    is_active_log_name,
    parse_metrics_script_output,
    split_complete_lines,
)
from app.collectors.runtime_collector import collect_host_health
from app.config import Settings, get_settings
from app.db.database import utcnow
from app.models.live_schemas import LiveConnectRequest
from app.models.wso2_schemas import Wso2Context
from app.services.investigation import investigation_service

log = logging.getLogger("aidev.live")

CHUNK_PER_FILE = 2_000_000
MAX_FILES = 40


class LogTransport(Protocol):
    async def list_files(self, directory: str) -> list[tuple[str, int]]:
        """Return [(full_path, size), ...]."""

    async def read_from(self, path: str, offset: int, max_bytes: int) -> tuple[bytes, int]:
        """Read up to max_bytes from offset. Returns (data, current_size)."""

    async def metrics_raw(self) -> str:
        ...

    async def close(self) -> None:
        ...


@dataclass
class FileCursor:
    path: str
    name: str
    log_type: str
    offset: int = 0
    size: int = 0
    leftover: str = ""
    bytes_read: int = 0
    rotated: int = 0


@dataclass
class _Session:
    id: str
    req: LiveConnectRequest
    transport: LogTransport
    dirs: list[str]
    aggregator: LiveAggregator
    files: dict[str, FileCursor] = field(default_factory=dict)
    started_at: datetime = field(default_factory=utcnow)
    last_poll_at: datetime | None = None
    error: str | None = None
    warnings: list[str] = field(default_factory=list)
    last_report_id: str | None = None
    last_job_id: str | None = None
    last_report_at: datetime | None = None
    analyzing: bool = False
    reports_generated: int = 0
    rates: dict[str, Any] = field(default_factory=dict)


class LocalTransport:
    async def list_files(self, directory: str) -> list[tuple[str, int]]:
        root = Path(directory)
        if not root.is_dir():
            raise FileNotFoundError(f"Log directory not found: {directory}")
        out: list[tuple[str, int]] = []
        for path in sorted(root.iterdir()):
            if not path.is_file() or not is_active_log_name(path.name):
                continue
            try:
                out.append((str(path), path.stat().st_size))
            except OSError:
                continue
        return out[:MAX_FILES]

    async def read_from(self, path: str, offset: int, max_bytes: int) -> tuple[bytes, int]:
        p = Path(path)
        size = p.stat().st_size
        if offset > size:
            offset = 0
        if offset >= size:
            return b"", size
        def _read() -> bytes:
            with p.open("rb") as fh:
                fh.seek(offset)
                return fh.read(min(max_bytes, size - offset))
        data = await asyncio.to_thread(_read)
        return data, size

    async def metrics_raw(self) -> str:
        proc = Path("/proc/stat")
        if proc.is_file():
            def _run() -> str:
                import subprocess

                return subprocess.run(
                    ["bash", "-lc", LINUX_METRICS_SCRIPT],
                    capture_output=True,
                    text=True,
                    timeout=8,
                    check=False,
                ).stdout
            return await asyncio.to_thread(_run)
        host = await asyncio.to_thread(collect_host_health)
        return json.dumps({"note": "no /proc — limited host metrics", "host": host})

    async def close(self) -> None:
        return None


class SshTransport:
    def __init__(self, conn: Any, sftp: Any) -> None:
        self._conn = conn
        self._sftp = sftp

    async def list_files(self, directory: str) -> list[tuple[str, int]]:
        try:
            entries = await self._sftp.readdir(directory)
        except Exception as exc:  # noqa: BLE001
            raise FileNotFoundError(f"Cannot list {directory}: {exc}") from exc
        out: list[tuple[str, int]] = []
        for item in entries:
            name = getattr(item, "filename", "") or ""
            if not is_active_log_name(name):
                continue
            attrs = getattr(item, "attrs", None)
            size = int(getattr(attrs, "size", 0) or 0)
            path = directory.rstrip("/") + "/" + name
            out.append((path, size))
        out.sort(key=lambda x: x[0])
        return out[:MAX_FILES]

    async def read_from(self, path: str, offset: int, max_bytes: int) -> tuple[bytes, int]:
        attrs = await self._sftp.stat(path)
        size = int(getattr(attrs, "size", 0) or 0)
        if offset > size:
            offset = 0
        if offset >= size:
            return b"", size
        handle = await self._sftp.open(path, "rb")
        try:
            await handle.seek(offset)
            data = await handle.read(min(max_bytes, size - offset))
        finally:
            await handle.close()
        return data or b"", size

    async def metrics_raw(self) -> str:
        result = await self._conn.run(LINUX_METRICS_SCRIPT, check=False, timeout=12)
        stdout = result.stdout
        if isinstance(stdout, bytes):
            return stdout.decode("utf-8", errors="replace")
        return str(stdout or "")

    async def close(self) -> None:
        try:
            await self._sftp.exit()
        except Exception:  # noqa: BLE001
            pass
        self._conn.close()
        try:
            await self._conn.wait_closed()
        except Exception:  # noqa: BLE001
            pass


def _load_client_key(raw: str, passphrase: str | None) -> Any:
    import asyncssh

    text = raw.strip()
    path = Path(text).expanduser()
    if path.is_file():
        text = path.read_text(encoding="utf-8", errors="replace")
    return asyncssh.import_private_key(text, passphrase=passphrase or None)


async def open_ssh(req: LiveConnectRequest) -> SshTransport:
    import asyncssh

    if not req.host or not req.username:
        raise ValueError("SSH mode requires host and username")
    kwargs: dict[str, Any] = {
        "host": req.host,
        "port": req.port,
        "username": req.username,
        "connect_timeout": 20,
    }
    if not req.strict_host_key:
        kwargs["known_hosts"] = None
    if req.password:
        kwargs["password"] = req.password
    if req.private_key and req.private_key.strip():
        kwargs["client_keys"] = [_load_client_key(req.private_key, req.key_passphrase)]
    conn = await asyncssh.connect(**kwargs)
    sftp = await conn.start_sftp_client()
    return SshTransport(conn, sftp)


def _local_metrics_from_json(text: str) -> dict[str, Any]:
    try:
        blob = json.loads(text)
    except json.JSONDecodeError:
        return parse_metrics_script_output(text)
    if "HOSTNAME=" in text or text.startswith("HOSTNAME"):
        return parse_metrics_script_output(text)
    host = blob.get("host") if isinstance(blob, dict) else {}
    note = blob.get("note") if isinstance(blob, dict) else None
    return {
        "hostname": None,
        "uname": (host or {}).get("platform"),
        "note": note or "limited host metrics",
        "ips": [],
    }


class LiveMonitorService:
    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()
        self._session: _Session | None = None
        self._task: asyncio.Task | None = None
        self._lock = asyncio.Lock()
        self._subs: set[asyncio.Queue] = set()

    def subscribe(self, q: asyncio.Queue) -> None:
        self._subs.add(q)

    def unsubscribe(self, q: asyncio.Queue) -> None:
        self._subs.discard(q)

    def _publish(self) -> None:
        state = self.public_state()
        dead: list[asyncio.Queue] = []
        for q in self._subs:
            try:
                if q.full():
                    try:
                        q.get_nowait()
                    except asyncio.QueueEmpty:
                        pass
                q.put_nowait(state)
            except Exception:  # noqa: BLE001
                dead.append(q)
        for q in dead:
            self._subs.discard(q)

    def public_state(self) -> dict[str, Any]:
        s = self._session
        if not s:
            return {
                "connected": False,
                "mode": None,
                "host": None,
                "username": None,
                "log_dirs": [],
                "started_at": None,
                "last_poll_at": None,
                "error": None,
                "warnings": [],
                "files": [],
                "snapshot": {},
                "last_report_id": None,
                "last_job_id": None,
                "analyzing": False,
                "reports_generated": 0,
            }
        snap = s.aggregator.snapshot()
        snap["rates"] = s.rates
        files = [
            {
                "name": c.name,
                "path": c.path,
                "log_type": c.log_type,
                "size": c.size,
                "bytes_read": c.bytes_read,
                "offset": c.offset,
                "rotated": c.rotated,
            }
            for c in s.files.values()
        ]
        return {
            "connected": True,
            "mode": s.req.mode,
            "host": s.req.host if s.req.mode == "ssh" else "localhost",
            "username": s.req.username,
            "log_dirs": s.dirs,
            "started_at": s.started_at.isoformat(),
            "last_poll_at": s.last_poll_at.isoformat() if s.last_poll_at else None,
            "error": s.error,
            "warnings": s.warnings[-12:],
            "files": files,
            "snapshot": snap,
            "last_report_id": s.last_report_id,
            "last_job_id": s.last_job_id,
            "analyzing": s.analyzing,
            "reports_generated": s.reports_generated,
        }

    async def connect(self, req: LiveConnectRequest) -> dict[str, Any]:
        await self.disconnect()
        dirs = [req.log_dir.strip()]
        dirs.extend(d.strip() for d in req.extra_log_dirs if d and d.strip())
        dirs = list(dict.fromkeys(dirs))
        warnings: list[str] = []
        if req.mode == "local":
            transport: LogTransport = LocalTransport()
            present = [d for d in dirs if Path(d).is_dir()]
            warnings.extend(f"Directory not found: {d}" for d in dirs if d not in present)
            if not present:
                raise FileNotFoundError("Local log directory not found: " + ", ".join(dirs))
            dirs = present
        else:
            transport = await open_ssh(req)

        agg = LiveAggregator(
            compute_allocation=req.compute_allocation,
            grid_kg_co2_per_kwh=req.grid_kg_co2_per_kwh,
            watts_per_vcpu=req.watts_per_vcpu,
        )
        session = _Session(
            id=uuid.uuid4().hex[:12],
            req=req,
            transport=transport,
            dirs=dirs,
            aggregator=agg,
        )
        for directory in dirs:
            try:
                listed = await transport.list_files(directory)
            except Exception as exc:  # noqa: BLE001
                warnings.append(str(exc))
                continue
            for path, size in listed:
                name = path.rstrip("/").rsplit("/", 1)[-1]
                cursor = FileCursor(
                    path=path,
                    name=name,
                    log_type=classify_filename(name),
                    size=size,
                    offset=max(0, size - int(req.seed_bytes)),
                )
                session.files[path] = cursor
        if not session.files:
            await transport.close()
            detail = "; ".join(warnings) or "no matching *.log files"
            raise FileNotFoundError(f"No live log files found in {dirs}: {detail}")
        session.warnings = warnings
        self._session = session
        # Seed + first metrics immediately so the dashboard is not empty
        await self._poll_once()
        self._task = asyncio.create_task(self._loop(), name="live-monitor")
        names = [c.name for c in session.files.values()]
        return {
            "status": "connected",
            "message": f"Tailing {len(names)} log file(s) — live stats every {req.poll_seconds:.0f}s, AI report every {max(req.report_interval_seconds, 0):.0f}s",
            "mode": req.mode,
            "host": req.host if req.mode == "ssh" else "localhost",
            "log_dirs": dirs,
            "files": names,
        }

    async def disconnect(self) -> None:
        task = self._task
        self._task = None
        if task and not task.done():
            task.cancel()
            try:
                await task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass
        session = self._session
        self._session = None
        if session:
            try:
                await session.transport.close()
            except Exception:  # noqa: BLE001
                pass
        self._publish()

    async def analyze_now(self) -> str | None:
        session = self._session
        if not session:
            raise RuntimeError("Not connected")
        return await self._enqueue_report(session, reason="manual")

    async def _loop(self) -> None:
        session = self._session
        if not session:
            return
        interval = max(1.0, float(session.req.poll_seconds))
        try:
            while self._session is session:
                await asyncio.sleep(interval)
                if self._session is not session:
                    break
                try:
                    await self._poll_once()
                except asyncio.CancelledError:
                    raise
                except Exception as exc:  # noqa: BLE001
                    log.warning("live poll failed: %s", exc)
                    session.error = str(exc)[:400]
                    self._publish()
        except asyncio.CancelledError:
            raise

    async def _poll_once(self) -> None:
        session = self._session
        if not session:
            return
        async with self._lock:
            await self._refresh_file_list(session)
            new_bytes = 0
            for cursor in list(session.files.values()):
                try:
                    data, size = await session.transport.read_from(
                        cursor.path, cursor.offset, CHUNK_PER_FILE
                    )
                except Exception as exc:  # noqa: BLE001
                    session.warnings.append(f"{cursor.name}: {exc}")
                    session.warnings = session.warnings[-20:]
                    continue
                if size < cursor.offset:
                    cursor.offset = 0
                    cursor.rotated += 1
                    cursor.leftover = ""
                    try:
                        data, size = await session.transport.read_from(
                            cursor.path, 0, CHUNK_PER_FILE
                        )
                    except Exception:  # noqa: BLE001
                        continue
                cursor.size = size
                if not data:
                    continue
                text = data.decode("utf-8", errors="replace")
                lines, leftover = split_complete_lines(cursor.leftover, text)
                cursor.leftover = leftover
                cursor.offset += len(data)
                cursor.bytes_read += len(data)
                new_bytes += len(data)
                if lines:
                    session.aggregator.ingest_lines(cursor.name, lines, cursor.log_type)
            interval = 0.0
            if session.last_poll_at:
                interval = (utcnow() - session.last_poll_at).total_seconds()
            try:
                raw_text = await session.transport.metrics_raw()
                head = (raw_text or "").lstrip()[:80]
                if head.startswith("HOSTNAME") or "HOSTNAME=" in head:
                    parsed = parse_metrics_script_output(raw_text)
                else:
                    parsed = _local_metrics_from_json(raw_text)
            except Exception as exc:  # noqa: BLE001
                parsed = {"note": f"metrics unavailable: {exc}"}
            rates_pack = session.aggregator.apply_metrics(
                parsed, interval_seconds=interval or float(session.req.poll_seconds)
            )
            session.rates = rates_pack.get("rates") or {}
            session.last_poll_at = utcnow()
            session.error = None
            await self._maybe_report(session, new_bytes=new_bytes)
        self._publish()

    async def _refresh_file_list(self, session: _Session) -> None:
        for directory in session.dirs:
            try:
                listed = await session.transport.list_files(directory)
            except Exception as exc:  # noqa: BLE001
                session.warnings.append(str(exc))
                continue
            for path, size in listed:
                if path in session.files:
                    continue
                name = path.rstrip("/").rsplit("/", 1)[-1]
                session.files[path] = FileCursor(
                    path=path,
                    name=name,
                    log_type=classify_filename(name),
                    size=size,
                    offset=max(0, size - 256_000),
                )

    async def _maybe_report(self, session: _Session, *, new_bytes: int) -> None:
        if session.analyzing:
            if session.last_job_id:
                job = await investigation_service.get_job(session.last_job_id)
                if job and job.status in {"completed", "failed", "cancelled"}:
                    session.analyzing = False
                    if job.status == "completed" and job.report_id:
                        session.last_report_id = job.report_id
                        session.reports_generated += 1
                        session.last_report_at = utcnow()
            return
        interval = session.req.report_interval_seconds
        if interval < 0:
            return
        now = utcnow()
        due = session.last_report_at is None or (
            (now - session.last_report_at).total_seconds() >= interval
        )
        spike = False
        rates = session.rates or {}
        try:
            if float(rates.get("window_error_pct") or 0) >= 15 and int(
                (session.aggregator.snapshot().get("traffic") or {}).get("total_requests") or 0
            ) > 20:
                spike = True
        except (TypeError, ValueError):
            pass
        cpu = (session.aggregator.last_metrics or {}).get("cpu_pct")
        if cpu is not None and float(cpu) >= 92:
            spike = True
        if not due and not spike:
            return
        if spike and session.last_report_at and (now - session.last_report_at).total_seconds() < 60:
            return
        if session.last_report_at is None and new_bytes == 0 and session.aggregator.bytes_ingested == 0:
            return
        reason = "spike" if spike and not due else "interval"
        await self._enqueue_report(session, reason=reason)

    async def _enqueue_report(self, session: _Session, *, reason: str) -> str | None:
        if session.analyzing:
            return session.last_job_id
        files = self._flush_windows(session)
        if not files:
            return None
        req = session.req
        metrics = session.aggregator.last_metrics or {}
        emissions = session.aggregator.snapshot().get("emissions") or {}
        traffic = session.aggregator.snapshot().get("traffic") or {}
        consumption = {
            "cpu_pct": metrics.get("cpu_pct"),
            "ram_pct": metrics.get("mem_pct"),
            "disk_pct": metrics.get("disk_pct"),
            "load_1": metrics.get("load_1"),
            "kg_co2_per_hour": emissions.get("kg_co2_per_hour"),
            "session_kg_co2": emissions.get("session_kg_co2"),
            "requests": traffic.get("total_requests"),
            "http_error_pct": traffic.get("error_pct"),
        }
        live_notes = (
            f"LIVE {reason} window on {req.host or 'localhost'} dirs={session.dirs}. "
            f"CPU={consumption.get('cpu_pct')}% RAM={consumption.get('ram_pct')}% "
            f"disk={consumption.get('disk_pct')}% req={consumption.get('requests')} "
            f"HTTP error {consumption.get('http_error_pct')}% "
            f"est. {consumption.get('kg_co2_per_hour')} kgCO2/h. "
            f"{req.notes or ''}"
        ).strip()
        context = Wso2Context(
            os=req.os_name,
            apim_version=req.apim_version,
            ei_version=req.ei_version,
            ip_addresses=req.ip_addresses or metrics.get("ips"),
            infra_compute_consumption=consumption,
            compute_allocation=req.compute_allocation,
            db_version=req.db_version,
            notes=live_notes,
            environment=req.environment or "live",
        )
        job_id = await investigation_service.enqueue_wso2(
            context=context,
            log_files=files,
            trigger=f"live_{reason}",
        )
        session.analyzing = True
        session.last_job_id = job_id
        session.last_report_at = utcnow()
        return job_id

    def _flush_windows(self, session: _Session) -> list[str]:
        dest = self.settings.uploads_dir / "live" / session.id
        dest.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(timezone.utc).strftime("%H%M%S")
        saved: list[str] = []
        for name, buf in session.aggregator.windows.items():
            text = buf.get()
            if not text.strip():
                continue
            safe = Path(name).name.replace(" ", "_")
            path = dest / f"{stamp}_{safe}"
            path.write_text(text, encoding="utf-8", errors="replace")
            saved.append(str(path))
        return saved


live_monitor = LiveMonitorService()
