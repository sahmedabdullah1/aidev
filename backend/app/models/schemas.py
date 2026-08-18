from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class JobStatus(str, Enum):
    queued = "queued"
    cloning = "cloning"
    collecting = "collecting"
    analyzing = "analyzing"
    completed = "completed"
    failed = "failed"


class Severity(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"


class FindingCategory(str, Enum):
    application_logs = "application_logs"
    infrastructure = "infrastructure"
    kubernetes = "kubernetes"
    docker = "docker"
    cicd = "cicd"
    git = "git"
    server_health = "server_health"
    web_server = "web_server"
    database = "database"
    api = "api"
    security = "security"
    performance = "performance"
    monitoring = "monitoring"
    alerts = "alerts"
    source_code = "source_code"
    build_quality = "build_quality"
    cloud = "cloud"
    business = "business"
    # legacy aliases still accepted
    error = "error"
    reliability = "reliability"
    compliance = "compliance"
    devops = "devops"
    improvement = "improvement"
    dependency = "dependency"
    network = "network"
    configuration = "configuration"


class InvestigateRequest(BaseModel):
    repo_url: str = Field(..., description="Git / GitLab repository URL")
    branch: str | None = None
    include_logs: bool = True
    live_probe: bool = Field(
        False,
        description="If true, probe local docker/kubectl/host metrics when available",
    )
    notes: str | None = Field(None, description="Extra context for the AI (infra, IPs, SLAs)")
    software_info: dict[str, Any] | None = None
    ip_info: dict[str, Any] | None = None
    metrics: dict[str, Any] | None = Field(
        None,
        description="Optional metrics snapshot (CPU/mem/latency/error rates/alerts)",
    )
    business_metrics: dict[str, Any] | None = None
    monitoring_snapshot: dict[str, Any] | None = None
    log_paths: list[str] | None = None


class Finding(BaseModel):
    """Full SRE root-cause finding."""

    id: str
    title: str
    category: FindingCategory
    severity: Severity
    executive_summary: str = ""
    affected_services: list[str] = Field(default_factory=list)
    what_happened: str = ""
    root_cause: str = ""
    evidence: str | None = None
    impact: str = ""
    recommendation: str = ""
    recommended_fixes: list[str] = Field(default_factory=list)
    preventive_measures: list[str] = Field(default_factory=list)
    related_components: list[str] = Field(default_factory=list)
    confidence_score: int = Field(default=70, ge=0, le=100)
    file_path: str | None = None
    # backward-compatible fields
    description: str = ""
    effort: str | None = None


class ReportSection(BaseModel):
    title: str
    summary: str
    findings: list[Finding] = Field(default_factory=list)


class DomainCoverage(BaseModel):
    domain: str
    status: str  # collected | partial | missing | live
    notes: str | None = None


class DevOpsReport(BaseModel):
    id: str
    job_id: str
    repo_url: str
    branch: str | None = None
    created_at: datetime
    executive_summary: str
    health_score: int = Field(ge=0, le=100)
    risk_level: Severity
    primary_root_cause: str | None = None
    correlated_timeline: list[str] = Field(default_factory=list)
    sections: list[ReportSection]
    domain_coverage: list[DomainCoverage] = Field(default_factory=list)
    quick_wins: list[str] = Field(default_factory=list)
    roadmap: list[str] = Field(default_factory=list)
    collected_facts: dict[str, Any] = Field(default_factory=dict)
    raw_ai_notes: str | None = None


class JobResponse(BaseModel):
    id: str
    status: JobStatus
    repo_url: str
    branch: str | None = None
    created_at: datetime
    updated_at: datetime
    progress: str | None = None
    error: str | None = None
    report_id: str | None = None
    trigger: str = "manual"


class JobListResponse(BaseModel):
    jobs: list[JobResponse]


class ReportListResponse(BaseModel):
    reports: list[DevOpsReport]


class HealthResponse(BaseModel):
    status: str
    app: str
    llm_configured: bool
    llm_provider: str
    llm_model: str
    gitlab_configured: bool
    analysis_mode: str  # llm_only


class WebhookAck(BaseModel):
    accepted: bool
    job_id: str | None = None
    message: str
