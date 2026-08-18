"""WSO2 API Manager analysis models."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

from app.models.schemas import Severity


class Wso2LogType(str, Enum):
    wso2carbon = "wso2carbon"
    audit = "audit"
    http_access = "http_access"
    wire = "wire"
    wire_tls = "wire_tls"
    gc = "gc"
    heapdump = "heapdump"
    catalina = "catalina"
    unknown = "unknown"


class Wso2Context(BaseModel):
    os: str | None = Field(None, description="Operating system, e.g. RHEL 8.8 / Ubuntu 22.04")
    apim_version: str | None = Field(None, description="WSO2 API Manager version, e.g. 4.3.0")
    ei_version: str | None = Field(None, description="WSO2 Enterprise Integrator / MI version")
    ip_addresses: dict[str, Any] | list[str] | str | None = Field(
        None, description="Node / VIP / LB / DB IPs"
    )
    infra_compute_consumption: dict[str, Any] | str | None = Field(
        None, description="Observed CPU/RAM/Disk/Network usage"
    )
    compute_allocation: dict[str, Any] | str | None = Field(
        None, description="Allocated vCPU/RAM/disk for APIM/EI nodes"
    )
    db_version: str | None = Field(None, description="Database product + version")
    notes: str | None = None
    environment: str | None = Field(None, description="prod|staging|dr")


class Wso2ErrorItem(BaseModel):
    id: str
    log_type: Wso2LogType
    severity: Severity
    error: str
    description: str
    possible_occurrence: str
    remedial_actions: list[str] = Field(default_factory=list)
    wso2_doc_refs: list[str] = Field(default_factory=list)
    evidence: str | None = None
    source_file: str | None = None
    affected_components: list[str] = Field(default_factory=list)
    # EI/MI interpretation fields (no centralized error catalog)
    logger: str | None = Field(None, description="Java logger class (%c)")
    subsystem: str | None = Field(
        None,
        description="synapse_mediation|synapse_endpoints|axis2|http_client|db_pool|...",
    )
    functional_error: str | None = Field(None, description="Human-readable functional message")
    exception_type: str | None = Field(None, description="Root-cause exception, e.g. SocketTimeoutException")
    error_source: str | None = Field(
        None,
        description="java_exception|wso2_component_message|synapse_error|axis2_error|hazelcast_error|tomcat_error|jdbc_driver_error",
    )
    va_correlation: str | None = Field(
        None,
        description="How this maps to findings in the Vulnerability Assessment report",
    )
    confidence_score: int = Field(default=70, ge=0, le=100)
    # Impact & plain-language RCA (user-facing)
    technical_name: str | None = Field(None, description="Original technical error / exception name")
    plain_meaning: str | None = Field(None, description="Simple explanation of what went wrong")
    call_flow: list[str] = Field(default_factory=list, description="Short client→gateway→backend flow")
    config_checks: list[str] = Field(
        default_factory=list,
        description="Config files to check and what exactly to configure",
    )
    impacted_customers: list[str] = Field(
        default_factory=list,
        description="Customers/partners impacted, e.g. Meezan, MCB, APC Partner",
    )
    failure_count: int | None = Field(None, description="How many times this failure pattern occurred")
    failure_total: int | None = Field(None, description="Total failures scanned in the uploaded logs")
    impact_pct: float | None = Field(None, description="failure_count / failure_total * 100")
    impact_summary: str | None = Field(None, description="Plain impact sentence")


class Wso2VaMapping(BaseModel):
    va_finding: str
    related_log_errors: list[str] = Field(default_factory=list)
    correlation_notes: str
    risk: Severity = Severity.medium
    recommended_actions: list[str] = Field(default_factory=list)


class Wso2Report(BaseModel):
    id: str
    job_id: str
    created_at: datetime
    executive_summary: str
    health_score: int = Field(ge=0, le=100)
    risk_level: Severity
    primary_root_cause: str | None = None
    context: Wso2Context
    log_coverage: dict[str, Any] = Field(default_factory=dict)
    errors: list[Wso2ErrorItem] = Field(default_factory=list)
    va_correlations: list[Wso2VaMapping] = Field(default_factory=list)
    correlated_timeline: list[str] = Field(default_factory=list)
    quick_wins: list[str] = Field(default_factory=list)
    roadmap: list[str] = Field(default_factory=list)
    doc_references: list[str] = Field(default_factory=list)
    raw_ai_notes: str | None = None


class Wso2AnalyzeResponse(BaseModel):
    job_id: str
    status: str
    message: str
