"""
Async CRUD operations for all database models.
All functions accept an AsyncSession and return typed ORM instances.
"""

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from src.database.models import (
    AgentTrace,
    HumanApproval,
    Patch,
    SandboxRun,
    Severity,
    Vulnerability,
    VulnerabilityStatus,
)
from src.database.schemas import (
    AgentTraceCreate,
    HumanApprovalCreate,
    PatchCreate,
    PatchUpdate,
    SandboxRunCreate,
    VulnerabilityCreate,
    VulnerabilityUpdate,
)


# ─── Vulnerability CRUD ───────────────────────────────────────────────────────
async def create_vulnerability(
    db: AsyncSession, data: VulnerabilityCreate
) -> Vulnerability:
    vuln = Vulnerability(**data.model_dump())
    db.add(vuln)
    await db.flush()
    await db.refresh(vuln)
    return vuln


async def get_vulnerability(
    db: AsyncSession, vuln_id: uuid.UUID
) -> Vulnerability | None:
    result = await db.execute(
        select(Vulnerability)
        .where(Vulnerability.id == vuln_id)
        .options(
            selectinload(Vulnerability.patches).selectinload(Patch.sandbox_runs),
            selectinload(Vulnerability.patches).selectinload(Patch.human_approval),
            selectinload(Vulnerability.agent_traces),
        )
    )
    return result.scalar_one_or_none()


async def update_vulnerability(
    db: AsyncSession, vuln_id: uuid.UUID, data: VulnerabilityUpdate
) -> Vulnerability | None:
    await db.execute(
        update(Vulnerability)
        .where(Vulnerability.id == vuln_id)
        .values(**{k: v for k, v in data.model_dump().items() if v is not None})
    )
    return await get_vulnerability(db, vuln_id)


async def list_vulnerabilities(
    db: AsyncSession,
    status: VulnerabilityStatus | None = None,
    severity: Severity | None = None,
    limit: int = 50,
    offset: int = 0,
) -> tuple[int, list[Vulnerability]]:
    query = select(Vulnerability)
    count_query = select(func.count(Vulnerability.id))

    if status:
        query = query.where(Vulnerability.status == status)
        count_query = count_query.where(Vulnerability.status == status)
    if severity:
        query = query.where(Vulnerability.severity == severity)
        count_query = count_query.where(Vulnerability.severity == severity)

    query = query.order_by(Vulnerability.created_at.desc()).limit(limit).offset(offset)

    total_result = await db.execute(count_query)
    total = total_result.scalar_one()

    items_result = await db.execute(query)
    items = list(items_result.scalars().all())

    return total, items


# ─── Patch CRUD ───────────────────────────────────────────────────────────────
async def create_patch(db: AsyncSession, data: PatchCreate) -> Patch:
    patch = Patch(**data.model_dump())
    db.add(patch)
    await db.flush()
    await db.refresh(patch)
    return patch


async def get_patch(db: AsyncSession, patch_id: uuid.UUID) -> Patch | None:
    result = await db.execute(
        select(Patch)
        .where(Patch.id == patch_id)
        .options(
            selectinload(Patch.sandbox_runs),
            selectinload(Patch.human_approval),
        )
    )
    return result.scalar_one_or_none()


async def update_patch(
    db: AsyncSession, patch_id: uuid.UUID, data: PatchUpdate
) -> Patch | None:
    await db.execute(
        update(Patch)
        .where(Patch.id == patch_id)
        .values(**{k: v for k, v in data.model_dump().items() if v is not None})
    )
    return await get_patch(db, patch_id)


# ─── Sandbox Run CRUD ─────────────────────────────────────────────────────────
async def create_sandbox_run(db: AsyncSession, data: SandboxRunCreate) -> SandboxRun:
    run = SandboxRun(**data.model_dump())
    db.add(run)
    await db.flush()
    await db.refresh(run)
    return run


# ─── Human Approval CRUD ──────────────────────────────────────────────────────
async def create_human_approval(
    db: AsyncSession, data: HumanApprovalCreate
) -> HumanApproval:
    approval = HumanApproval(**data.model_dump())
    db.add(approval)
    await db.flush()
    await db.refresh(approval)
    return approval


# ─── Agent Trace CRUD ─────────────────────────────────────────────────────────
async def create_agent_trace(db: AsyncSession, data: AgentTraceCreate) -> AgentTrace:
    trace = AgentTrace(**data.model_dump())
    db.add(trace)
    await db.flush()
    await db.refresh(trace)
    return trace


async def get_traces_for_vuln(
    db: AsyncSession, vuln_id: uuid.UUID
) -> list[AgentTrace]:
    result = await db.execute(
        select(AgentTrace)
        .where(AgentTrace.vulnerability_id == vuln_id)
        .order_by(AgentTrace.created_at.asc())
    )
    return list(result.scalars().all())


# ─── Dashboard Metrics ────────────────────────────────────────────────────────
async def get_dashboard_metrics(db: AsyncSession) -> dict[str, Any]:
    """Compute KPI metrics for the dashboard in a single query set."""
    now = datetime.now(tz=timezone.utc)
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)

    # Active incidents (non-terminal statuses)
    active_statuses = [
        VulnerabilityStatus.PENDING,
        VulnerabilityStatus.TRIAGING,
        VulnerabilityStatus.PATCHING,
        VulnerabilityStatus.SANDBOX_RUNNING,
        VulnerabilityStatus.AWAITING_APPROVAL,
    ]
    active_result = await db.execute(
        select(func.count(Vulnerability.id)).where(
            Vulnerability.status.in_(active_statuses)
        )
    )
    active_incidents = active_result.scalar_one()

    # Total today
    total_today_result = await db.execute(
        select(func.count(Vulnerability.id)).where(
            Vulnerability.created_at >= today_start
        )
    )
    total_today = total_today_result.scalar_one()

    # PRs opened today
    prs_today_result = await db.execute(
        select(func.count(Vulnerability.id)).where(
            Vulnerability.status == VulnerabilityStatus.PR_OPENED,
            Vulnerability.updated_at >= today_start,
        )
    )
    prs_opened_today = prs_today_result.scalar_one()

    # Sandbox pass rate (last 100 runs)
    pass_result = await db.execute(
        select(
            func.count(SandboxRun.id).label("total"),
            func.sum(
                func.cast(SandboxRun.exit_code == 0, Integer if False else func.count.__class__)
            ).label("passed"),
        )
    )
    # Simplified pass rate calculation
    total_runs_result = await db.execute(select(func.count(SandboxRun.id)))
    passed_runs_result = await db.execute(
        select(func.count(SandboxRun.id)).where(SandboxRun.exit_code == 0)
    )
    total_runs = total_runs_result.scalar_one() or 1
    passed_runs = passed_runs_result.scalar_one()
    sandbox_pass_rate = passed_runs / total_runs

    # Severity counts (today)
    severity_counts: dict[str, int] = {}
    for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM]:
        sev_result = await db.execute(
            select(func.count(Vulnerability.id)).where(
                Vulnerability.severity == sev,
                Vulnerability.created_at >= today_start,
            )
        )
        severity_counts[sev.value.lower()] = sev_result.scalar_one()

    return {
        "active_incidents": active_incidents,
        "total_today": total_today,
        "sandbox_pass_rate": round(sandbox_pass_rate, 3),
        "prs_opened_today": prs_opened_today,
        "mean_time_to_remediate_seconds": 0.0,  # computed separately if needed
        "critical_count": severity_counts.get("critical", 0),
        "high_count": severity_counts.get("high", 0),
        "medium_count": severity_counts.get("medium", 0),
    }
