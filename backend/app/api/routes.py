from __future__ import annotations

from fastapi import APIRouter, File, Form, HTTPException, UploadFile
from fastapi.responses import FileResponse

from app.config import get_settings
from app.analyzers.llm_client import resolve_llm_settings
from app.db.database import loads
from app.models.schemas import (
    DevOpsReport,
    HealthResponse,
    InvestigateRequest,
    JobListResponse,
    JobResponse,
    JobStatus,
    ReportListResponse,
)
from app.models.wso2_schemas import Wso2AnalyzeResponse, Wso2Context, Wso2Report
from app.services.investigation import investigation_service

router = APIRouter()


def _settings():
    return get_settings()


def _job_to_response(row) -> JobResponse:
    try:
        status_enum = JobStatus(row.status)
    except Exception:
        status_enum = JobStatus.cancelled if "cancel" in str(row.status).lower() or "stop" in str(row.status).lower() else JobStatus.failed
    return JobResponse(
        id=row.id,
        status=status_enum,
        repo_url=row.repo_url,
        branch=row.branch,
        created_at=row.created_at,
        updated_at=row.updated_at,
        progress=row.progress,
        error=row.error,
        report_id=row.report_id,
        trigger=row.trigger,
    )


@router.get("/health", response_model=HealthResponse)
async def health() -> HealthResponse:
    settings = resolve_llm_settings(_settings())
    provider = settings.llm_base_url or "unknown"
    if "groq.com" in provider:
        provider_name = "groq"
    elif "11434" in provider or "localhost" in provider:
        provider_name = "ollama"
    elif "openai.com" in provider:
        provider_name = "openai"
    else:
        provider_name = provider
    return HealthResponse(
        status="ok",
        app=settings.app_name,
        llm_configured=bool(settings.llm_api_key),
        llm_provider=provider_name,
        llm_model=settings.llm_model,
        gitlab_configured=bool(settings.gitlab_token or settings.gitlab_webhook_secret),
        analysis_mode="llm_only",
    )


@router.post("/investigate", response_model=JobResponse)
async def investigate(body: InvestigateRequest) -> JobResponse:
    job_id = await investigation_service.enqueue(
        repo_url=body.repo_url,
        branch=body.branch,
        notes=body.notes,
        software_info=body.software_info,
        ip_info=body.ip_info,
        metrics=body.metrics,
        business_metrics=body.business_metrics,
        monitoring_snapshot=body.monitoring_snapshot,
        log_paths=body.log_paths,
        live_probe=body.live_probe,
        trigger="manual",
    )
    row = await investigation_service.get_job(job_id)
    if not row:
        raise HTTPException(500, "Failed to create job")
    return _job_to_response(row)


@router.post("/investigate/with-logs", response_model=JobResponse)
async def investigate_with_logs(
    repo_url: str = Form(...),
    branch: str | None = Form(None),
    notes: str | None = Form(None),
    software_info: str | None = Form(None),
    ip_info: str | None = Form(None),
    metrics: str | None = Form(None),
    business_metrics: str | None = Form(None),
    monitoring_snapshot: str | None = Form(None),
    live_probe: bool = Form(False),
    files: list[UploadFile] = File(default=[]),
) -> JobResponse:
    import json

    settings = _settings()
    saved: list[str] = []
    upload_dir = settings.uploads_dir
    upload_dir.mkdir(parents=True, exist_ok=True)
    for f in files:
        dest = upload_dir / f"{repo_url.split('/')[-1][:40]}_{f.filename}"
        content = await f.read()
        dest.write_bytes(content[: settings.max_log_bytes])
        saved.append(str(dest))

    def parse(raw: str | None):
        return json.loads(raw) if raw else None

    job_id = await investigation_service.enqueue(
        repo_url=repo_url,
        branch=branch,
        notes=notes,
        software_info=parse(software_info),
        ip_info=parse(ip_info),
        metrics=parse(metrics),
        business_metrics=parse(business_metrics),
        monitoring_snapshot=parse(monitoring_snapshot),
        uploaded_logs=saved,
        live_probe=live_probe,
        trigger="manual",
    )
    row = await investigation_service.get_job(job_id)
    if not row:
        raise HTTPException(500, "Failed to create job")
    return _job_to_response(row)


@router.get("/jobs", response_model=JobListResponse)
async def list_jobs() -> JobListResponse:
    rows = await investigation_service.list_jobs()
    return JobListResponse(jobs=[_job_to_response(r) for r in rows])


@router.get("/jobs/{job_id}", response_model=JobResponse)
async def get_job(job_id: str) -> JobResponse:
    row = await investigation_service.get_job(job_id)
    if not row:
        raise HTTPException(404, "Job not found")
    return _job_to_response(row)


@router.post("/jobs/{job_id}/stop", response_model=JobResponse)
@router.post("/jobs/{job_id}/cancel", response_model=JobResponse)
async def stop_job(job_id: str) -> JobResponse:
    row = await investigation_service.cancel_job(job_id)
    if not row:
        raise HTTPException(404, "Job not found")
    return _job_to_response(row)


@router.get("/reports", response_model=ReportListResponse)
async def list_reports() -> ReportListResponse:
    rows = await investigation_service.list_reports()
    reports: list[DevOpsReport] = []
    for r in rows:
        try:
            payload = loads(r.payload_json)
            if payload.get("errors") is not None and payload.get("context") is not None:
                continue  # WSO2 reports listed via /api/wso2/reports
            reports.append(DevOpsReport.model_validate(payload))
        except Exception:  # noqa: BLE001
            continue
    return ReportListResponse(reports=reports)


@router.get("/reports/{report_id}")
async def get_report(report_id: str):
    row = await investigation_service.get_report(report_id)
    if not row:
        raise HTTPException(404, "Report not found")
    payload = loads(row.payload_json)
    if payload.get("errors") is not None and "context" in payload:
        from app.analyzers.wso2_impact import enrich_wso2_errors
        from app.models.wso2_schemas import Wso2Report

        report = Wso2Report.model_validate(payload)
        cov = dict(report.log_coverage or {})
        needs = any(
            not (e.plain_meaning and e.call_flow and e.impact_summary) or not e.impacted_customers
            for e in report.errors
        )
        if (needs or not cov.get("impacted_customers_summary") or not cov.get("file_stats")) and (
            report.errors or cov.get("scan_summaries")
        ):
            evidence = {
                "priority_failure_findings": cov.get("priority_failure_findings") or [],
                "scan_summaries": cov.get("scan_summaries") or [],
            }
            if report.errors:
                report.errors = enrich_wso2_errors(report.errors, evidence)
                if evidence.get("impacted_customers_summary"):
                    cov["impacted_customers_summary"] = evidence["impacted_customers_summary"]
            if not cov.get("file_stats") and cov.get("scan_summaries"):
                from app.collectors.wso2_file_stats import build_file_stats

                cov["file_stats"] = build_file_stats(
                    cov.get("scan_summaries") or [],
                    report.context.ip_addresses,
                )
            report.log_coverage = cov
        return report
    return DevOpsReport.model_validate(payload)


@router.post("/wso2/analyze", response_model=Wso2AnalyzeResponse)
async def wso2_analyze(
    os_name: str | None = Form(None, alias="os"),
    apim_version: str | None = Form(None),
    ei_version: str | None = Form(None),
    ip_addresses: str | None = Form(None),
    infra_compute_consumption: str | None = Form(None),
    compute_allocation: str | None = Form(None),
    db_version: str | None = Form(None),
    notes: str | None = Form(None),
    environment: str | None = Form(None),
    log_files: list[UploadFile] = File(default=[]),
    va_report: UploadFile | None = File(None),
) -> Wso2AnalyzeResponse:
    """Deep WSO2 APIM analysis for the 8 standard log types + VA correlation."""
    import json

    settings = _settings()
    if not log_files:
        raise HTTPException(400, "Upload at least one WSO2 log file (wso2carbon, audit, http_access, ...)")

    upload_dir = settings.uploads_dir / "wso2"
    upload_dir.mkdir(parents=True, exist_ok=True)
    saved: list[str] = []
    log_limit = max(settings.max_log_bytes, getattr(settings, "wso2_max_log_bytes", 40_000_000))

    def _save_bytes(name: str, data: bytes) -> None:
        import zipfile as _zip
        fname = (name or "upload.log").replace(" ", "_")
        is_hprof = fname.lower().endswith(".hprof")
        limit = 50_000_000 if is_hprof else log_limit
        # If it looks like a ZIP, expand it in place
        if fname.lower().endswith(".zip") or data[:2] == b"PK":
            try:
                import io
                with _zip.ZipFile(io.BytesIO(data)) as zf:
                    for member in zf.infolist():
                        if member.is_dir():
                            continue
                        mname = member.filename.split("/")[-1]
                        if not mname or mname.startswith("."):
                            continue
                        mdata = zf.read(member)[:limit]
                        dest = upload_dir / uuid_name(mname)
                        dest.write_bytes(mdata)
                        saved.append(str(dest))
                return
            except Exception:  # noqa: BLE001
                pass  # fall through to save raw
        dest = upload_dir / uuid_name(fname)
        dest.write_bytes(data[:limit])
        saved.append(str(dest))

    for f in log_files:
        content = await f.read()
        _save_bytes(f.filename or "upload.log", content)

    va_path = None
    if va_report and va_report.filename:
        va_dest = upload_dir / f"va_{uuid_name(va_report.filename)}"
        va_dest.write_bytes((await va_report.read())[: settings.max_log_bytes])
        va_path = str(va_dest)

    def maybe_json(raw: str | None):
        if not raw or not raw.strip():
            return None
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return raw.strip()

    context = Wso2Context(
        os=os_name,
        apim_version=apim_version,
        ei_version=ei_version,
        ip_addresses=maybe_json(ip_addresses),
        infra_compute_consumption=maybe_json(infra_compute_consumption),
        compute_allocation=maybe_json(compute_allocation),
        db_version=db_version,
        notes=notes,
        environment=environment,
    )
    job_id = await investigation_service.enqueue_wso2(
        context=context,
        log_files=saved,
        va_report_path=va_path,
    )
    return Wso2AnalyzeResponse(
        job_id=job_id,
        status="queued",
        message="WSO2 APIM analysis queued — poll /api/jobs/{job_id} then /api/reports/{report_id}",
    )


@router.get("/wso2/reports", response_model=list[Wso2Report])
async def list_wso2_reports() -> list[Wso2Report]:
    rows = await investigation_service.list_reports()
    out: list[Wso2Report] = []
    for r in rows:
        try:
            payload = loads(r.payload_json)
            if payload.get("errors") is not None and "context" in payload:
                out.append(Wso2Report.model_validate(payload))
        except Exception:  # noqa: BLE001
            continue
    return out


def uuid_name(name: str | None) -> str:
    import uuid as _uuid
    from pathlib import Path as _P

    safe = _P(name or "upload.log").name.replace(" ", "_")
    return f"{_uuid.uuid4().hex[:8]}_{safe}"


@router.get("/reports/{report_id}/download/{fmt}")
async def download_report(report_id: str, fmt: str) -> FileResponse:
    settings = _settings()
    if fmt not in {"md", "html", "json"}:
        raise HTTPException(400, "fmt must be md|html|json")

    # Always refresh HTML from stored payload so older reports get fonts/charts
    if fmt == "html":
        row = await investigation_service.get_report(report_id)
        if row:
            payload = loads(row.payload_json)
            if payload.get("errors") is not None and "context" in payload:
                from app.analyzers.wso2_impact import enrich_wso2_errors
                from app.models.wso2_schemas import Wso2Report
                from app.reports.renderer import render_wso2_html

                report = Wso2Report.model_validate(payload)
                cov = dict(report.log_coverage or {})
                evidence = {
                    "priority_failure_findings": cov.get("priority_failure_findings") or [],
                    "scan_summaries": cov.get("scan_summaries") or [],
                }
                report.errors = enrich_wso2_errors(report.errors, evidence)
                if evidence.get("impacted_customers_summary"):
                    cov["impacted_customers_summary"] = evidence["impacted_customers_summary"]
                if not cov.get("file_stats") and cov.get("scan_summaries"):
                    from app.collectors.wso2_file_stats import build_file_stats

                    cov["file_stats"] = build_file_stats(
                        cov.get("scan_summaries") or [],
                        report.context.ip_addresses,
                    )
                report.log_coverage = cov
                path = settings.reports_dir / f"{report_id}.html"
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(render_wso2_html(report), encoding="utf-8")
                return FileResponse(path, media_type="text/html", filename=path.name)

    if fmt == "md":
        path = settings.reports_dir / f"{report_id}.md"
    elif fmt == "html":
        path = settings.reports_dir / f"{report_id}.html"
    else:
        path = settings.reports_dir / f"{report_id}.json"
    if not path.exists():
        raise HTTPException(404, "File not found")
    media = {"md": "text/markdown", "html": "text/html", "json": "application/json"}[fmt]
    return FileResponse(path, media_type=media, filename=path.name)

