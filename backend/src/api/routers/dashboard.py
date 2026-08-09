"""
Dashboard API router.
Provides read endpoints for the Next.js monitoring dashboard.
All endpoints require JWT authentication.
"""

import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.middleware.rate_limiter import limiter
from src.core.logging import get_logger
from src.database.connection import get_db
from src.database import crud
from src.database.models import Severity, VulnerabilityStatus
from src.database.schemas import (
    DashboardMetrics,
    PatchResponse,
    SandboxRunResponse,
    VulnerabilityListResponse,
    VulnerabilityResponse,
    AgentTraceResponse,
)

logger = get_logger(__name__)
router = APIRouter()


@router.get(
    "/metrics",
    response_model=DashboardMetrics,
    summary="Get dashboard KPI metrics",
)
@limiter.limit("60/minute")
async def get_metrics(
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> DashboardMetrics:
    """Returns current KPI metrics for the incident command center."""
    metrics = await crud.get_dashboard_metrics(db)
    return DashboardMetrics(**metrics)


@router.get(
    "/incidents",
    response_model=VulnerabilityListResponse,
    summary="List vulnerability incidents",
)
@limiter.limit("60/minute")
async def list_incidents(
    request: Request,
    status: VulnerabilityStatus | None = Query(None, description="Filter by status"),
    severity: Severity | None = Query(None, description="Filter by severity"),
    limit: int = Query(50, ge=1, le=100, description="Max rows per page (1-100)"),
    offset: int = Query(0, ge=0, le=10000, description="Pagination offset (max 10,000)"),
    db: AsyncSession = Depends(get_db),
) -> VulnerabilityListResponse:
    """Paginated list of vulnerability incidents with optional filters."""
    total, items = await crud.list_vulnerabilities(
        db, status=status, severity=severity, limit=limit, offset=offset
    )
    return VulnerabilityListResponse(
        total=total,
        items=[VulnerabilityResponse.model_validate(i) for i in items],
    )


@router.get(
    "/incidents/{vuln_id}",
    response_model=VulnerabilityResponse,
    summary="Get a single vulnerability incident",
)
async def get_incident(
    vuln_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
) -> VulnerabilityResponse:
    vuln = await crud.get_vulnerability(db, vuln_id)
    if not vuln:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Vulnerability {vuln_id} not found.",
        )
    return VulnerabilityResponse.model_validate(vuln)


@router.get(
    "/incidents/{vuln_id}/patch",
    response_model=PatchResponse,
    summary="Get the latest patch for an incident",
)
async def get_incident_patch(
    vuln_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
) -> PatchResponse:
    vuln = await crud.get_vulnerability(db, vuln_id)
    if not vuln or not vuln.patches:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No patch found for vulnerability {vuln_id}.",
        )
    patch = vuln.patches[-1]  # Latest patch
    return PatchResponse.model_validate(patch)


@router.get(
    "/incidents/{vuln_id}/sandbox",
    response_model=SandboxRunResponse,
    summary="Get the latest sandbox run for an incident",
)
async def get_sandbox_result(
    vuln_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
) -> SandboxRunResponse:
    vuln = await crud.get_vulnerability(db, vuln_id)
    if not vuln or not vuln.patches:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No sandbox run found for vulnerability {vuln_id}.",
        )
    latest_patch = vuln.patches[-1]
    if not latest_patch.sandbox_runs:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No sandbox run found for this patch.",
        )
    run = latest_patch.sandbox_runs[-1]
    return SandboxRunResponse.model_validate(run)


@router.get(
    "/incidents/{vuln_id}/traces",
    response_model=list[AgentTraceResponse],
    summary="Get agent execution traces for an incident",
)
async def get_agent_traces(
    vuln_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
) -> list[AgentTraceResponse]:
    traces = await crud.get_traces_for_vuln(db, vuln_id)
    return [AgentTraceResponse.model_validate(t) for t in traces]


@router.get(
    "/audit",
    response_model=VulnerabilityListResponse,
    summary="Audit log — all historical incidents",
)
@limiter.limit("30/minute")
async def get_audit_log(
    request: Request,
    limit: int = Query(50, ge=1, le=100, description="Max rows per page (1-100)"),
    offset: int = Query(0, ge=0, le=10000, description="Pagination offset (max 10,000)"),
    db: AsyncSession = Depends(get_db),
) -> VulnerabilityListResponse:
    total, items = await crud.list_vulnerabilities(db, limit=limit, offset=offset)
    return VulnerabilityListResponse(
        total=total,
        items=[VulnerabilityResponse.model_validate(i) for i in items],
    )
