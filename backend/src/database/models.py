"""
SQLAlchemy ORM models for SecOps-AI.

Tables:
  - workspaces        : Multi-tenant isolation unit
  - api_keys          : Hashed API keys with rotation support
  - vulnerabilities   : Incoming CVE/SAST alert records
  - patches           : AI-generated code patches
  - sandbox_runs      : Docker sandbox execution results
  - human_approvals   : Slack approval/rejection decisions
  - agent_traces      : Per-agent execution telemetry
"""

import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.sql import func

from src.database.connection import Base

# ─── Enums ────────────────────────────────────────────────────────────────────
import enum


class VulnerabilityStatus(str, enum.Enum):
    PENDING            = "PENDING"
    TRIAGING           = "TRIAGING"
    PATCHING           = "PATCHING"
    PATCH_FAILED       = "PATCH_FAILED"
    SANDBOX_RUNNING    = "SANDBOX_RUNNING"
    SANDBOX_PASSED     = "SANDBOX_PASSED"
    SANDBOX_FAILED     = "SANDBOX_FAILED"
    TRACE_ANALYZED     = "TRACE_ANALYZED"   # Failure trace extracted, will repatch
    REPATCHING         = "REPATCHING"       # Second patch attempt using failure trace
    AWAITING_APPROVAL  = "AWAITING_APPROVAL"
    APPROVED           = "APPROVED"
    REJECTED           = "REJECTED"
    PR_OPENED          = "PR_OPENED"
    PR_MERGED          = "PR_MERGED"
    PR_CLOSED          = "PR_CLOSED"
    ERROR              = "ERROR"


class Severity(str, enum.Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class ScannerType(str, enum.Enum):
    TRIVY = "TRIVY"
    BANDIT = "BANDIT"
    SONARQUBE = "SONARQUBE"
    SNYK = "SNYK"
    MANUAL = "MANUAL"


class ApprovalDecision(str, enum.Enum):
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"


class AgentName(str, enum.Enum):
    TRIAGE = "TRIAGE"
    PATCH = "PATCH"
    GUARDRAIL = "GUARDRAIL"


# ─── Mixin ────────────────────────────────────────────────────────────────────
class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )


# ─── Workspace & ApiKey (Phase 2.1 / 2.2) ────────────────────────────────────────

class Workspace(Base, TimestampMixin):
    """Multi-tenant isolation unit. Every vulnerability belongs to one workspace."""

    __tablename__ = "workspaces"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    slug: Mapped[str] = mapped_column(String(100), nullable=False, unique=True, index=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    # Relationships
    api_keys: Mapped[list["ApiKey"]] = relationship(
        "ApiKey", back_populates="workspace", cascade="all, delete-orphan"
    )
    vulnerabilities: Mapped[list["Vulnerability"]] = relationship(
        "Vulnerability", back_populates="workspace"
    )

    def __repr__(self) -> str:
        return f"<Workspace {self.slug}>"


class ApiKey(Base, TimestampMixin):
    """Hashed API key with rotation support.

    Rotation flow:
      1. Generate new key → set hashed_key, bump last_rotated_at
      2. Store previous hash in previous_key_hash for 24hr grace period
      3. After grace period expires, previous_key_hash is cleared
      4. Both hashed_key and previous_key_hash are checked on each request
    """

    __tablename__ = "api_keys"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    workspace_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("workspaces.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    key_prefix: Mapped[str] = mapped_column(
        String(12), nullable=False, index=True
    )  # First 8 chars of the raw key (for fast lookup without full scan)
    hashed_key: Mapped[str] = mapped_column(String(200), nullable=False)
    previous_key_hash: Mapped[str | None] = mapped_column(
        String(200), nullable=True
    )  # Kept for 24hr rotation grace period

    label: Mapped[str] = mapped_column(String(100), nullable=False, default="Default")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    last_rotated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )  # None = never expires

    # Relationships
    workspace: Mapped["Workspace"] = relationship("Workspace", back_populates="api_keys")

    def __repr__(self) -> str:
        return f"<ApiKey {self.key_prefix}... for Workspace {self.workspace_id}>"


# ─── Vulnerability & related ────────────────────────────────────────────────────

class Vulnerability(Base, TimestampMixin):
    """Incoming security alert from a scanner (Trivy, Bandit, etc.)."""

    __tablename__ = "vulnerabilities"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    scanner: Mapped[ScannerType] = mapped_column(
        Enum(ScannerType), nullable=False, index=True
    )
    cve_id: Mapped[str | None] = mapped_column(String(50), nullable=True, index=True)
    severity: Mapped[Severity] = mapped_column(
        Enum(Severity), nullable=False, index=True
    )
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)

    # Location of the vulnerability in the codebase
    repo_owner: Mapped[str] = mapped_column(String(200), nullable=False)
    repo_name: Mapped[str] = mapped_column(String(200), nullable=False)
    repo_branch: Mapped[str] = mapped_column(String(200), nullable=False, default="main")
    file_path: Mapped[str] = mapped_column(String(1000), nullable=False)
    line_start: Mapped[int | None] = mapped_column(Integer, nullable=True)
    line_end: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # OWASP classification
    owasp_category: Mapped[str | None] = mapped_column(String(100), nullable=True)
    cwe_id: Mapped[str | None] = mapped_column(String(20), nullable=True)

    # Raw scanner output
    raw_payload: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)

    status: Mapped[VulnerabilityStatus] = mapped_column(
        Enum(VulnerabilityStatus),
        nullable=False,
        default=VulnerabilityStatus.PENDING,
        index=True,
    )

    # Celery task ID for tracking
    celery_task_id: Mapped[str | None] = mapped_column(String(200), nullable=True)

    # Idempotency: prevent duplicate pipeline runs for the same CVE+repo+file
    idempotency_key: Mapped[str | None] = mapped_column(
        String(64), nullable=True, unique=True, index=True
    )

    # Staged MTTR timestamps (set at each pipeline transition)
    # Allows accurate per-stage latency measurement and honest MTTR reporting.
    triage_completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    patch_generated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    sandbox_completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    slack_sent_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    human_decision_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    pr_opened_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # Workspace isolation (Phase 2.1)
    # Nullable for backwards-compat with single-tenant data already in DB.
    workspace_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("workspaces.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    # Relationships
    workspace: Mapped["Workspace | None"] = relationship("Workspace", back_populates="vulnerabilities")
    patches: Mapped[list["Patch"]] = relationship(
        "Patch", back_populates="vulnerability", cascade="all, delete-orphan"
    )
    agent_traces: Mapped[list["AgentTrace"]] = relationship(
        "AgentTrace", back_populates="vulnerability", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return f"<Vulnerability {self.cve_id or self.id} [{self.severity}]>"


class Patch(Base, TimestampMixin):
    """AI-generated code patch for a vulnerability."""

    __tablename__ = "patches"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    vulnerability_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("vulnerabilities.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    original_code: Mapped[str] = mapped_column(Text, nullable=False)
    patched_code: Mapped[str] = mapped_column(Text, nullable=False)
    diff_unified: Mapped[str] = mapped_column(Text, nullable=False)

    agent_reasoning: Mapped[str] = mapped_column(Text, nullable=False)
    owasp_flags: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)

    # Guardrail result
    guardrail_approved: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    guardrail_notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    guardrail_retry_count: Mapped[int] = mapped_column(Integer, default=0)

    # GitHub PR details (populated after Slack approval)
    pr_url: Mapped[str | None] = mapped_column(String(500), nullable=True)
    pr_number: Mapped[int | None] = mapped_column(Integer, nullable=True)
    pr_branch: Mapped[str | None] = mapped_column(String(200), nullable=True)

    # Relationships
    vulnerability: Mapped["Vulnerability"] = relationship(
        "Vulnerability", back_populates="patches"
    )
    sandbox_runs: Mapped[list["SandboxRun"]] = relationship(
        "SandboxRun", back_populates="patch", cascade="all, delete-orphan"
    )
    human_approval: Mapped["HumanApproval | None"] = relationship(
        "HumanApproval", back_populates="patch", uselist=False, cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return f"<Patch {self.id} for Vuln {self.vulnerability_id}>"


class SandboxRun(Base, TimestampMixin):
    """Result of running tests in an isolated Docker sandbox."""

    __tablename__ = "sandbox_runs"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    patch_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("patches.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    container_id: Mapped[str | None] = mapped_column(String(100), nullable=True)
    exit_code: Mapped[int] = mapped_column(Integer, nullable=False)
    stdout: Mapped[str] = mapped_column(Text, nullable=False, default="")
    stderr: Mapped[str] = mapped_column(Text, nullable=False, default="")

    tests_passed: Mapped[int] = mapped_column(Integer, default=0)
    tests_failed: Mapped[int] = mapped_column(Integer, default=0)
    tests_errored: Mapped[int] = mapped_column(Integer, default=0)
    duration_ms: Mapped[int] = mapped_column(Integer, nullable=False)

    timed_out: Mapped[bool] = mapped_column(Boolean, default=False)

    # Tracks which sandbox attempt this was (1 = first, 2 = repatch retry)
    attempt_number: Mapped[int] = mapped_column(Integer, nullable=False, default=1)

    # SandboxMode enum value: pytest_passed, pytest_failed, no_tests, static_only, etc.
    sandbox_mode: Mapped[str | None] = mapped_column(String(20), nullable=True)

    # Relationships
    patch: Mapped["Patch"] = relationship("Patch", back_populates="sandbox_runs")

    @property
    def passed(self) -> bool:
        return self.exit_code == 0 and not self.timed_out

    def __repr__(self) -> str:
        return f"<SandboxRun {self.id} exit={self.exit_code}>"


class HumanApproval(Base, TimestampMixin):
    """Record of a human approve/reject decision made via Slack."""

    __tablename__ = "human_approvals"
    __table_args__ = (UniqueConstraint("patch_id", name="uq_human_approval_patch"),)

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    patch_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("patches.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    decision: Mapped[ApprovalDecision] = mapped_column(
        Enum(ApprovalDecision), nullable=False
    )
    approver_slack_id: Mapped[str] = mapped_column(String(50), nullable=False)
    approver_name: Mapped[str | None] = mapped_column(String(200), nullable=True)
    rejection_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    slack_message_ts: Mapped[str | None] = mapped_column(String(50), nullable=True)

    # Relationships
    patch: Mapped["Patch"] = relationship("Patch", back_populates="human_approval")

    def __repr__(self) -> str:
        return f"<HumanApproval {self.decision} by {self.approver_slack_id}>"


class AgentTrace(Base):
    """Per-agent execution telemetry for observability and cost tracking."""

    __tablename__ = "agent_traces"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    vulnerability_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("vulnerabilities.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    agent_name: Mapped[AgentName] = mapped_column(Enum(AgentName), nullable=False)
    step: Mapped[str] = mapped_column(String(100), nullable=False)
    model_used: Mapped[str] = mapped_column(String(100), nullable=False)

    input_tokens: Mapped[int] = mapped_column(Integer, default=0)
    output_tokens: Mapped[int] = mapped_column(Integer, default=0)
    estimated_cost_usd: Mapped[float] = mapped_column(Float, default=0.0)
    duration_ms: Mapped[int] = mapped_column(Integer, nullable=False)

    success: Mapped[bool] = mapped_column(Boolean, default=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    # Relationships
    vulnerability: Mapped["Vulnerability"] = relationship(
        "Vulnerability", back_populates="agent_traces"
    )

    def __repr__(self) -> str:
        return f"<AgentTrace {self.agent_name} for Vuln {self.vulnerability_id}>"
