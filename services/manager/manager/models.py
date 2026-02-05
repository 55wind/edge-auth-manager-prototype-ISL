from __future__ import annotations

import re
from pydantic import BaseModel, Field, field_validator
from typing import Optional, Literal

# Namespace segment: 1-64 alphanumeric chars, hyphens, underscores. No slashes or whitespace.
_NS_SEGMENT_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_\-]{0,63}$")


class DeviceRegisterIn(BaseModel):
    domain: str = Field(default="default")
    site: str
    group: str
    device_id: str
    hw_fingerprint: str = Field(..., description="Lightweight device fingerprint hash")
    agent_version: str = "0.1.0"

    @field_validator("domain", "site", "group", "device_id")
    @classmethod
    def validate_ns_segment(cls, v: str, info) -> str:
        if not _NS_SEGMENT_RE.match(v):
            raise ValueError(
                f"{info.field_name} must be 1-64 alphanumeric/hyphen/underscore chars, "
                f"starting with alphanumeric. Got: {v!r}"
            )
        return v



class DeviceOut(BaseModel):
    namespace: str
    status: Literal["PENDING","APPROVED","REVOKED"]
    last_seen: Optional[str] = None
    agent_version: str

class DeviceTransferIn(BaseModel):
    namespace: str
    new_site: Optional[str] = None
    new_group: Optional[str] = None
    reason: str = Field(..., description="Reason for transfer/disposal")

    @field_validator("new_site", "new_group")
    @classmethod
    def validate_ns_segment(cls, v: str | None, info) -> str | None:
        if v is not None and not _NS_SEGMENT_RE.match(v):
            raise ValueError(
                f"{info.field_name} must be 1-64 alphanumeric/hyphen/underscore chars. Got: {v!r}"
            )
        return v


class ApproveIn(BaseModel):
    namespace: str

class TokenIn(BaseModel):
    namespace: str

class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int

class ValidateOut(BaseModel):
    ok: bool
    subject: Optional[str] = None
    roles: list[str] = []
    exp: Optional[int] = None

class CertIssueIn(BaseModel):
    namespace: str
    # In a real system, CSR-based issuance is preferred.
    csr_pem: Optional[str] = None

class CertStatusOut(BaseModel):
    namespace: str
    status: Literal["ISSUED","REVOKED","UNKNOWN"]
    not_after: Optional[str] = None


# --- Metrics models ---

class OverviewMetrics(BaseModel):
    total_devices: int
    approved_devices: int
    pending_devices: int
    revoked_devices: int
    requests_24h: int
    auth_success_rate: float
    active_incidents: int
    avg_latency_ms: float


class RequestStats(BaseModel):
    total_requests: int
    error_count: int
    error_rate: float
    latency_p50_ms: float
    latency_p95_ms: float
    latency_p99_ms: float


class HourlyVolume(BaseModel):
    hour: str
    total: int
    errors: int = 0


class EndpointStats(BaseModel):
    path: str
    count: int
    errors: int
    error_rate: float
    avg_latency_ms: float
    p95_latency_ms: float


class AuthStats(BaseModel):
    total_attempts: int
    successes: int
    failures: int
    success_rate: float
    failure_reasons: dict[str, int]
    by_event_type: dict[str, int]


class HourlyAuthStats(BaseModel):
    hour: str
    success: int
    failure: int


class DeviceAuthStats(BaseModel):
    namespace: str
    total: int
    successes: int
    failures: int
    success_rate: float


class SecurityIncidentOut(BaseModel):
    id: int
    timestamp: str
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    incident_type: str
    namespace: Optional[str] = None
    description: str
    resolved: bool


class IncidentCounts(BaseModel):
    critical: int
    high: int
    medium: int
    low: int
    total: int


class IncidentByType(BaseModel):
    type: str
    count: int


class DeviceCounts(BaseModel):
    total: int
    pending: int
    approved: int
    revoked: int


class StaleDevice(BaseModel):
    namespace: str
    last_seen: Optional[str] = None
    hours_stale: float


class RequestLogOut(BaseModel):
    id: int
    timestamp: str
    method: str
    path: str
    status_code: int
    latency_ms: float
    client_cn: Optional[str] = None
    namespace: Optional[str] = None
    error_detail: Optional[str] = None
