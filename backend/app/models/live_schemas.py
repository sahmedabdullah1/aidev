"""Live server connection + realtime snapshot models."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field


class LiveConnectRequest(BaseModel):
    mode: Literal["ssh", "local"] = "ssh"
    host: str | None = Field(None, description="SSH hostname or IP of the log server")
    port: int = Field(22, ge=1, le=65535)
    username: str | None = None
    password: str | None = None
    private_key: str | None = Field(
        None,
        description="PEM private key contents, or a local path to a key file",
    )
    key_passphrase: str | None = None
    log_dir: str = Field(
        "/opt/wso2am/repository/logs",
        description="Primary log directory on the server (APIM repository/logs)",
    )
    extra_log_dirs: list[str] = Field(
        default_factory=list,
        description="Extra dirs, e.g. MI repository/logs",
    )
    poll_seconds: float = Field(5.0, ge=1.0, le=120.0)
    report_interval_seconds: float = Field(
        180.0,
        description="How often to run a full AI report. Use a negative value to disable auto reports.",
    )
    seed_bytes: int = Field(2_000_000, ge=64_000, le=20_000_000)
    strict_host_key: bool = False
    os_name: str | None = None
    apim_version: str | None = None
    ei_version: str | None = None
    ip_addresses: dict[str, Any] | list[str] | str | None = None
    compute_allocation: dict[str, Any] | str | None = None
    db_version: str | None = None
    notes: str | None = None
    environment: str | None = None
    grid_kg_co2_per_kwh: float = Field(0.4, ge=0.0, le=2.0)
    watts_per_vcpu: float = Field(15.0, ge=1.0, le=200.0)


class LiveConnectResponse(BaseModel):
    status: str
    message: str
    mode: str
    host: str | None = None
    log_dirs: list[str] = Field(default_factory=list)
    files: list[str] = Field(default_factory=list)


class LiveFileState(BaseModel):
    name: str
    path: str
    log_type: str
    size: int = 0
    bytes_read: int = 0
    offset: int = 0
    rotated: int = 0


class LiveStatusResponse(BaseModel):
    connected: bool
    mode: str | None = None
    host: str | None = None
    username: str | None = None
    log_dirs: list[str] = Field(default_factory=list)
    started_at: datetime | None = None
    last_poll_at: datetime | None = None
    error: str | None = None
    warnings: list[str] = Field(default_factory=list)
    files: list[LiveFileState] = Field(default_factory=list)
    snapshot: dict[str, Any] = Field(default_factory=dict)
    last_report_id: str | None = None
    last_job_id: str | None = None
    analyzing: bool = False
    reports_generated: int = 0
