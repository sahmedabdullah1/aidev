"""Investigation job orchestration."""

from __future__ import annotations

import asyncio
import shutil
import traceback
import uuid
from pathlib import Path
from typing import Any

from sqlalchemy import select

from app.analyzers.ai_analyzer import analyze_with_ai, build_report_model
from app.analyzers.wso2_analyzer import analyze_wso2
from app.collectors import gather_evidence
from app.collectors.wso2_logs import collect_wso2_logs
from app.config import Settings, get_settings
from app.db.database import JobRow, ReportRow, SessionLocal, dumps, loads, utcnow
from app.models.schemas import JobStatus
from app.models.wso2_schemas import Wso2Context
from app.reports.renderer import write_report_files, write_wso2_report_files


class InvestigationService:
    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()
        self._tasks: set[asyncio.Task] = set()

    async def enqueue(
        self,
        *,
        repo_url: str,
        branch: str | None = None,
        notes: str | None = None,
        software_info: dict[str, Any] | None = None,
        ip_info: dict[str, Any] | None = None,
        metrics: dict[str, Any] | None = None,
        business_metrics: dict[str, Any] | None = None,
        monitoring_snapshot: dict[str, Any] | None = None,
        log_paths: list[str] | None = None,
        uploaded_logs: list[str] | None = None,
        live_probe: bool = False,
        trigger: str = "manual",
    ) -> str:
        job_id = uuid.uuid4().hex[:12]
        request = {
            "repo_url": repo_url.strip(),
            "branch": branch,
            "notes": notes,
            "software_info": software_info,
            "ip_info": ip_info,
            "metrics": metrics,
            "business_metrics": business_metrics,
            "monitoring_snapshot": monitoring_snapshot,
            "log_paths": log_paths,
            "uploaded_logs": uploaded_logs or [],
            "live_probe": live_probe,
        }
        async with SessionLocal() as session:
            row = JobRow(
                id=job_id,
                status=JobStatus.queued.value,
                repo_url=repo_url.strip(),
                branch=branch,
                trigger=trigger,
                progress="Queued",
                request_json=dumps(request),
                created_at=utcnow(),
                updated_at=utcnow(),
            )
            session.add(row)
            await session.commit()

        task = asyncio.create_task(self._run(job_id), name=f"job-{job_id}")
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)
        return job_id

    async def enqueue_wso2(
        self,
        *,
        context: Wso2Context,
        log_files: list[str],
        va_report_path: str | None = None,
        trigger: str = "wso2_manual",
    ) -> str:
        job_id = uuid.uuid4().hex[:12]
        label = f"wso2-apim:{context.apim_version or 'unknown'}"
        request = {
            "mode": "wso2",
            "context": context.model_dump(exclude_none=True),
            "log_files": log_files,
            "va_report_path": va_report_path,
        }
        async with SessionLocal() as session:
            session.add(
                JobRow(
                    id=job_id,
                    status=JobStatus.queued.value,
                    repo_url=label,
                    branch=context.environment,
                    trigger=trigger,
                    progress="Queued WSO2 APIM analysis",
                    request_json=dumps(request),
                    created_at=utcnow(),
                    updated_at=utcnow(),
                )
            )
            await session.commit()

        task = asyncio.create_task(self._run_wso2(job_id), name=f"wso2-{job_id}")
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)
        return job_id

    async def _run_wso2(self, job_id: str) -> None:
        try:
            async with SessionLocal() as session:
                row = await session.get(JobRow, job_id)
                if not row:
                    return
                req = loads(row.request_json)

            await self._update(job_id, status=JobStatus.collecting.value, progress="Parsing WSO2 log set")
            context = Wso2Context.model_validate(req.get("context") or {})
            paths = [Path(p) for p in req.get("log_files") or []]
            log_evidence = await asyncio.to_thread(collect_wso2_logs, paths, self.settings)

            va_text = None
            va_path = req.get("va_report_path")
            if va_path and Path(va_path).is_file():
                va_text = Path(va_path).read_text(encoding="utf-8", errors="replace")[
                    : self.settings.max_log_bytes
                ]

            await self._update(
                job_id,
                status=JobStatus.analyzing.value,
                progress="LLM analyzing WSO2 logs + VA correlation",
            )
            report = await analyze_wso2(
                settings=self.settings,
                context=context,
                log_evidence=log_evidence,
                va_report_text=va_text,
                job_id=job_id,
            )
            paths_out = write_wso2_report_files(report, self.settings.reports_dir)

            async with SessionLocal() as session:
                session.add(
                    ReportRow(
                        id=report.id,
                        job_id=job_id,
                        repo_url=f"wso2-apim:{context.apim_version or 'unknown'}",
                        branch=context.environment,
                        payload_json=report.model_dump_json(),
                        created_at=report.created_at,
                    )
                )
                job = await session.get(JobRow, job_id)
                if job:
                    job.status = JobStatus.completed.value
                    job.progress = f"WSO2 report ready ({paths_out['markdown']})"
                    job.report_id = report.id
                    job.updated_at = utcnow()
                await session.commit()
        except Exception as exc:  # noqa: BLE001
            await self._update(
                job_id,
                status=JobStatus.failed.value,
                progress=str(exc).split("\n", 1)[0][:240] or "Failed",
                error=f"{exc}\n{traceback.format_exc()[-1500:]}",
            )

    async def _update(self, job_id: str, **fields: Any) -> None:
        async with SessionLocal() as session:
            row = await session.get(JobRow, job_id)
            if not row:
                return
            for k, v in fields.items():
                setattr(row, k, v)
            row.updated_at = utcnow()
            await session.commit()

    async def _run(self, job_id: str) -> None:
        work_dir = self.settings.workspace_dir / job_id
        try:
            async with SessionLocal() as session:
                row = await session.get(JobRow, job_id)
                if not row:
                    return
                req = loads(row.request_json)

            await self._update(job_id, status=JobStatus.cloning.value, progress="Cloning repository")

            loop = asyncio.get_running_loop()

            def progress_cb(msg: str) -> None:
                status = (
                    JobStatus.cloning.value
                    if "Clon" in msg
                    else JobStatus.collecting.value
                )
                fut = asyncio.run_coroutine_threadsafe(
                    self._update(job_id, status=status, progress=msg),
                    loop,
                )
                try:
                    fut.result(timeout=5)
                except Exception:  # noqa: BLE001
                    pass

            # gather_evidence is sync/blocking — run in thread
            evidence = await asyncio.to_thread(
                gather_evidence,
                settings=self.settings,
                repo_url=req["repo_url"],
                work_dir=work_dir,
                branch=req.get("branch"),
                notes=req.get("notes"),
                software_info=req.get("software_info"),
                ip_info=req.get("ip_info"),
                metrics=req.get("metrics"),
                business_metrics=req.get("business_metrics"),
                monitoring_snapshot=req.get("monitoring_snapshot"),
                log_paths=req.get("log_paths"),
                uploaded_logs=[Path(p) for p in req.get("uploaded_logs") or []],
                live_probe=bool(req.get("live_probe")),
                progress_cb=progress_cb,
            )

            await self._update(
                job_id,
                status=JobStatus.analyzing.value,
                progress="SRE AI correlating logs, infra, deploys, and code",
            )
            ai_payload = await analyze_with_ai(evidence, self.settings)
            report = build_report_model(job_id=job_id, evidence=evidence, ai_payload=ai_payload)
            paths = write_report_files(report, self.settings.reports_dir)

            async with SessionLocal() as session:
                session.add(
                    ReportRow(
                        id=report.id,
                        job_id=job_id,
                        repo_url=report.repo_url,
                        branch=report.branch,
                        payload_json=report.model_dump_json(),
                        created_at=report.created_at,
                    )
                )
                job = await session.get(JobRow, job_id)
                if job:
                    job.status = JobStatus.completed.value
                    job.progress = f"Report ready ({paths['markdown']})"
                    job.report_id = report.id
                    job.updated_at = utcnow()
                await session.commit()
        except Exception as exc:  # noqa: BLE001
            await self._update(
                job_id,
                status=JobStatus.failed.value,
                progress=str(exc).split("\n", 1)[0][:240] or "Failed",
                error=f"{exc}\n{traceback.format_exc()[-1500:]}",
            )
        finally:
            # keep workspace for debugging in development; prune in production
            if self.settings.app_env == "production" and work_dir.exists():
                shutil.rmtree(work_dir, ignore_errors=True)

    async def get_job(self, job_id: str) -> JobRow | None:
        async with SessionLocal() as session:
            return await session.get(JobRow, job_id)

    async def list_jobs(self, limit: int = 50) -> list[JobRow]:
        async with SessionLocal() as session:
            result = await session.execute(
                select(JobRow).order_by(JobRow.created_at.desc()).limit(limit)
            )
            return list(result.scalars().all())

    async def get_report(self, report_id: str) -> ReportRow | None:
        async with SessionLocal() as session:
            return await session.get(ReportRow, report_id)

    async def list_reports(self, limit: int = 50) -> list[ReportRow]:
        async with SessionLocal() as session:
            result = await session.execute(
                select(ReportRow).order_by(ReportRow.created_at.desc()).limit(limit)
            )
            return list(result.scalars().all())


investigation_service = InvestigationService()
