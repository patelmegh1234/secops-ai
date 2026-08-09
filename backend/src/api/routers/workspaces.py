"""
Workspace & API Key management router — Phase 2.1 / 2.2

Endpoints:
  POST /workspaces                    Create a workspace
  GET  /workspaces/{workspace_id}     Get workspace details
  POST /workspaces/{workspace_id}/api-keys          Create a new API key
  POST /workspaces/{workspace_id}/api-keys/{key_id}/rotate  Rotate a key
  DELETE /workspaces/{workspace_id}/api-keys/{key_id}       Revoke a key

API keys are shown in plain text exactly once (on creation / rotation).
Only the bcrypt hash is stored — lost keys must be rotated, not recovered.
"""

import uuid
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.middleware.auth import generate_api_key, require_workspace
from src.core.logging import get_logger
from src.database.connection import get_db
from src.database.models import ApiKey, Workspace

logger = get_logger(__name__)
router = APIRouter()

# Grace period during which the previous key remains valid after rotation
_ROTATION_GRACE_HOURS = 24


# ── Request / Response schemas (inline Pydantic to avoid cross-importing) ──────
from pydantic import BaseModel, Field


class WorkspaceCreateRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    slug: str = Field(..., min_length=2, max_length=100, pattern=r"^[a-z0-9\-]+$")


class WorkspaceResponse(BaseModel):
    id: uuid.UUID
    name: str
    slug: str
    is_active: bool
    created_at: datetime

    class Config:
        from_attributes = True


class ApiKeyCreateRequest(BaseModel):
    label: str = Field("Default", max_length=100)
    expires_days: int | None = Field(None, ge=1, le=3650, description="Days until expiry. None = never expires.")


class ApiKeyCreateResponse(BaseModel):
    """Returned once on creation. The raw_key is never shown again."""
    id: uuid.UUID
    label: str
    key_prefix: str
    raw_key: str    # Show to user exactly once
    expires_at: datetime | None


class ApiKeyRotateResponse(BaseModel):
    id: uuid.UUID
    label: str
    key_prefix: str
    new_raw_key: str    # New key — shown once
    grace_period_ends_at: datetime  # Old key valid until this time


class ApiKeyListItem(BaseModel):
    id: uuid.UUID
    label: str
    key_prefix: str
    is_active: bool
    last_rotated_at: datetime | None
    expires_at: datetime | None
    created_at: datetime

    class Config:
        from_attributes = True


# ── Workspace endpoints ────────────────────────────────────────────────────────

@router.post(
    "/workspaces",
    response_model=WorkspaceResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new workspace",
)
async def create_workspace(
    body: WorkspaceCreateRequest,
    db: AsyncSession = Depends(get_db),
) -> WorkspaceResponse:
    """Create a new tenant workspace. Slug must be globally unique."""
    # Check slug uniqueness
    existing = await db.execute(
        select(Workspace).where(Workspace.slug == body.slug)
    )
    if existing.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Workspace slug '{body.slug}' is already taken.",
        )

    ws = Workspace(name=body.name, slug=body.slug)
    db.add(ws)
    await db.flush()
    await db.refresh(ws)

    logger.info("workspace_created", workspace_id=str(ws.id), slug=ws.slug)
    return WorkspaceResponse.model_validate(ws)


@router.get(
    "/workspaces/{workspace_id}",
    response_model=WorkspaceResponse,
    summary="Get workspace details",
)
async def get_workspace(
    workspace_id: uuid.UUID,
    caller_workspace_id: uuid.UUID = Depends(require_workspace),
    db: AsyncSession = Depends(get_db),
) -> WorkspaceResponse:
    """Get workspace details. API key must belong to this workspace."""
    if caller_workspace_id != workspace_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied.")
    result = await db.execute(select(Workspace).where(Workspace.id == workspace_id))
    ws = result.scalar_one_or_none()
    if not ws:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Workspace not found.")
    return WorkspaceResponse.model_validate(ws)


# ── API Key endpoints ──────────────────────────────────────────────────────────

@router.post(
    "/workspaces/{workspace_id}/api-keys",
    response_model=ApiKeyCreateResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new API key for a workspace",
)
async def create_api_key(
    workspace_id: uuid.UUID,
    body: ApiKeyCreateRequest,
    caller_workspace_id: uuid.UUID = Depends(require_workspace),
    db: AsyncSession = Depends(get_db),
) -> ApiKeyCreateResponse:
    """Generate a new API key. The raw key is returned exactly once — store it safely."""
    if caller_workspace_id != workspace_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied.")

    raw_key, prefix, hashed = generate_api_key()
    expires_at = None
    if body.expires_days:
        expires_at = datetime.now(timezone.utc) + timedelta(days=body.expires_days)

    api_key = ApiKey(
        workspace_id=workspace_id,
        key_prefix=prefix,
        hashed_key=hashed,
        label=body.label,
        expires_at=expires_at,
    )
    db.add(api_key)
    await db.flush()
    await db.refresh(api_key)

    logger.info(
        "api_key_created",
        workspace_id=str(workspace_id),
        key_id=str(api_key.id),
        label=api_key.label,
    )
    return ApiKeyCreateResponse(
        id=api_key.id,
        label=api_key.label,
        key_prefix=prefix,
        raw_key=raw_key,
        expires_at=expires_at,
    )


@router.post(
    "/workspaces/{workspace_id}/api-keys/{key_id}/rotate",
    response_model=ApiKeyRotateResponse,
    summary="Rotate an API key (24hr grace period for old key)",
)
async def rotate_api_key(
    workspace_id: uuid.UUID,
    key_id: uuid.UUID,
    caller_workspace_id: uuid.UUID = Depends(require_workspace),
    db: AsyncSession = Depends(get_db),
) -> ApiKeyRotateResponse:
    """
    Rotate an API key.
    - Generates a new raw key
    - Stores the old hash as previous_key_hash (valid for 24hrs)
    - Returns the new raw key (shown once)
    """
    if caller_workspace_id != workspace_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied.")

    result = await db.execute(
        select(ApiKey).where(
            ApiKey.id == key_id,
            ApiKey.workspace_id == workspace_id,
            ApiKey.is_active == True,  # noqa: E712
        )
    )
    api_key = result.scalar_one_or_none()
    if not api_key:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="API key not found.")

    new_raw_key, new_prefix, new_hash = generate_api_key()
    now = datetime.now(timezone.utc)
    grace_ends = now + timedelta(hours=_ROTATION_GRACE_HOURS)

    # Shift current hash → previous (grace period)
    api_key.previous_key_hash = api_key.hashed_key
    api_key.hashed_key = new_hash
    api_key.key_prefix = new_prefix
    api_key.last_rotated_at = now

    await db.flush()

    logger.info(
        "api_key_rotated",
        workspace_id=str(workspace_id),
        key_id=str(key_id),
        grace_ends=grace_ends.isoformat(),
    )
    return ApiKeyRotateResponse(
        id=api_key.id,
        label=api_key.label,
        key_prefix=new_prefix,
        new_raw_key=new_raw_key,
        grace_period_ends_at=grace_ends,
    )


@router.delete(
    "/workspaces/{workspace_id}/api-keys/{key_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Revoke an API key",
)
async def revoke_api_key(
    workspace_id: uuid.UUID,
    key_id: uuid.UUID,
    caller_workspace_id: uuid.UUID = Depends(require_workspace),
    db: AsyncSession = Depends(get_db),
) -> None:
    """Immediately revoke an API key. Effect is instant — no grace period."""
    if caller_workspace_id != workspace_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied.")

    result = await db.execute(
        select(ApiKey).where(ApiKey.id == key_id, ApiKey.workspace_id == workspace_id)
    )
    api_key = result.scalar_one_or_none()
    if not api_key:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="API key not found.")

    api_key.is_active = False
    api_key.previous_key_hash = None  # Immediately clear grace period
    await db.flush()

    logger.info(
        "api_key_revoked",
        workspace_id=str(workspace_id),
        key_id=str(key_id),
    )


@router.get(
    "/workspaces/{workspace_id}/api-keys",
    response_model=list[ApiKeyListItem],
    summary="List API keys for a workspace",
)
async def list_api_keys(
    workspace_id: uuid.UUID,
    caller_workspace_id: uuid.UUID = Depends(require_workspace),
    db: AsyncSession = Depends(get_db),
) -> list[ApiKeyListItem]:
    """List all API keys for a workspace (hashes never returned)."""
    if caller_workspace_id != workspace_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied.")

    result = await db.execute(
        select(ApiKey)
        .where(ApiKey.workspace_id == workspace_id)
        .order_by(ApiKey.created_at.desc())
    )
    keys = list(result.scalars().all())
    return [ApiKeyListItem.model_validate(k) for k in keys]
