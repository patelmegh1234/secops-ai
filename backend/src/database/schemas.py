"""
Pydantic v2 schemas for API request/response validation and serialization.
Kept separate from ORM models to enforce clean separation of concerns.
"""

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from src.database.models import (
    AgentName,
    ApprovalDecision,
    Severity,
    ScannerType,
    VulnerabilityStatus,
)


# ─── Base ─────────────────────────────────────────────────────────────────────
class BaseSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True, use_enum_values=True)


# ─── Vulnerability ─────────────────────────────────────────────────────────────
class VulnerabilityCreate(BaseSchema):
    """Used internally when creating a vulnerability record from a parsed payload."""
    scanner: ScannerType
    cve_id: str | None = None
    severity: Severity
    title: str
    description: str
    repo_owner: str
    repo_name: str
    repo_branch: str = "main"
    file_path: str
    line_start: int | None = None
    line_end: int | None = None
    owasp_category: str | None = None
    cwe_id: str | None = None
    raw_payload: dict[str, Any] = Field(default_factory=dict)


class VulnerabilityUpdate(BaseSchema):
    status: VulnerabilityStatus | None = None
    celery_task_id: str | None = None
    owasp_category: str | None = None


class VulnerabilityResponse(BaseSchema):
    id: uuid.UUID
    scanner: ScannerType
    cve_id: str | None
    severity: Severity
    title: str
    description: str
    repo_owner: str
    repo_name: str
    repo_branch: str
    file_path: str
    line_start: int | None
    line_end: int | None
    owasp_category: str | None
    cwe_id: str | None
    status: VulnerabilityStatus
    celery_task_id: str | None
    created_at: datetime
    updated_at: datetime


class VulnerabilityListResponse(BaseSchema):
    total: int
    items: list[VulnerabilityResponse]


# ─── Patch ────────────────────────────────────────────────────────────────────
class PatchCreate(BaseSchema):
    vulnerability_id: uuid.UUID
    original_code: str
    patched_code: str
    diff_unified: str
    agent_reasoning: str
    owasp_flags: list[str] = Field(default_factory=list)


class PatchUpdate(BaseSchema):
    guardrail_approved: bool | None = None
    guardrail_notes: str | None = None
    guardrail_retry_count: int | None = None
    pr_url: str | None = None
    pr_number: int | None = None
    pr_branch: str | None = None


class PatchResponse(BaseSchema):
    id: uuid.UUID
    vulnerability_id: uuid.UUID
    original_code: str
    patched_code: str
    diff_unified: str
    agent_reasoning: str
    owasp_flags: list[str]
    guardrail_approved: bool | None
    guardrail_notes: str | None
    pr_url: str | None
    pr_number: int | None
    pr_branch: str | None
    created_at: datetime


# ─── Sandbox Run ──────────────────────────────────────────────────────────────
class SandboxRunCreate(BaseSchema):
    patch_id: uuid.UUID
    container_id: str | None = None
    exit_code: int
    stdout: str = ""
    stderr: str = ""
    tests_passed: int = 0
    tests_failed: int = 0
    tests_errored: int = 0
    duration_ms: int
    timed_out: bool = False


class SandboxRunResponse(BaseSchema):
    id: uuid.UUID
    patch_id: uuid.UUID
    exit_code: int
    stdout: str
    stderr: str
    tests_passed: int
    tests_failed: int
    tests_errored: int
    duration_ms: int
    timed_out: bool
    passed: bool
    created_at: datetime


# ─── Human Approval ───────────────────────────────────────────────────────────
class HumanApprovalCreate(BaseSchema):
    patch_id: uuid.UUID
    decision: ApprovalDecision
    approver_slack_id: str
    approver_name: str | None = None
    rejection_reason: str | None = None
    slack_message_ts: str | None = None


class HumanApprovalResponse(BaseSchema):
    id: uuid.UUID
    patch_id: uuid.UUID
    decision: ApprovalDecision
    approver_slack_id: str
    approver_name: str | None
    rejection_reason: str | None
    created_at: datetime


# ─── Agent Trace ──────────────────────────────────────────────────────────────
class AgentTraceCreate(BaseSchema):
    vulnerability_id: uuid.UUID
    agent_name: AgentName
    step: str
    model_used: str
    input_tokens: int = 0
    output_tokens: int = 0
    estimated_cost_usd: float = 0.0
    duration_ms: int
    success: bool = True
    error_message: str | None = None


class AgentTraceResponse(BaseSchema):
    id: uuid.UUID
    vulnerability_id: uuid.UUID
    agent_name: AgentName
    step: str
    model_used: str
    input_tokens: int
    output_tokens: int
    estimated_cost_usd: float
    duration_ms: int
    success: bool
    error_message: str | None
    created_at: datetime


# ─── Dashboard / Metrics ──────────────────────────────────────────────────────
class DashboardMetrics(BaseModel):
    """KPI summary for the incident command center."""
    active_incidents: int
    total_today: int
    sandbox_pass_rate: float       # 0.0 – 1.0
    prs_opened_today: int
    mean_time_to_remediate_seconds: float
    critical_count: int
    high_count: int
    medium_count: int


# ─── Webhook Payloads ──────────────────────────────────────────────────────────
class WebhookAckResponse(BaseModel):
    """Immediate 202 response sent on webhook receipt."""
    status: str = "accepted"
    task_id: str
    message: str = "Vulnerability queued for processing"


# ─── Slack Action Payload ──────────────────────────────────────────────────────
class SlackActionUser(BaseModel):
    id: str
    name: str | None = None


class SlackActionValue(BaseModel):
    patch_id: str
    action: str  # "approve" | "reject"


class SlackActionPayload(BaseModel):
    """Parsed Slack interactive component payload."""
    type: str
    user: SlackActionUser
    actions: list[dict[str, Any]]
    message_ts: str | None = None
    response_url: str | None = None
