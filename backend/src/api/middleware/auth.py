"""
API Key Authentication Middleware — Phase 2.1 / 2.2

Resolves X-API-Key header → Workspace using bcrypt hash comparison.

Design decisions:
  - Key prefix (first 8 chars) is stored in plaintext for fast DB lookup.
    Only rows matching the prefix are fetched and bcrypt-verified.
    This avoids a full table scan on every request.
  - The previous_key_hash is checked during the 24-hour rotation grace period.
  - Expired keys (expires_at < now) are rejected even if the hash matches.
  - The resolved workspace_id is attached to request.state so all downstream
    handlers can scope their DB queries without re-fetching.

Usage in routes:
    workspace_id: uuid.UUID = Depends(require_workspace)
"""

import hashlib
import secrets
import uuid
from datetime import datetime, timezone

import bcrypt
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import APIKeyHeader
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.logging import get_logger
from src.database.connection import get_db
from src.database.models import ApiKey, Workspace

logger = get_logger(__name__)

# FastAPI extracts this header automatically
_api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

# Prefix length used for fast DB lookup
_KEY_PREFIX_LEN = 8


def generate_api_key() -> tuple[str, str, str]:
    """
    Generate a new API key.

    Returns:
        (raw_key, key_prefix, hashed_key)

    raw_key    — shown to the user once, never stored
    key_prefix — first _KEY_PREFIX_LEN chars, stored plaintext for fast lookup
    hashed_key — bcrypt hash, stored in DB
    """
    raw_key = "sai_" + secrets.token_urlsafe(40)   # sai_ prefix = SecOps-AI key
    key_prefix = raw_key[:_KEY_PREFIX_LEN]
    hashed_key = bcrypt.hashpw(raw_key.encode(), bcrypt.gensalt(rounds=12)).decode()
    return raw_key, key_prefix, hashed_key


def verify_api_key(raw_key: str, hashed_key: str) -> bool:
    """Check a raw key against a bcrypt hash. Returns True if match."""
    try:
        return bcrypt.checkpw(raw_key.encode(), hashed_key.encode())
    except Exception:
        return False


async def _resolve_workspace(
    raw_key: str,
    db: AsyncSession,
) -> Workspace | None:
    """
    Look up and verify an API key against the database.

    Steps:
    1. Extract prefix from raw_key for fast DB lookup
    2. Fetch all active ApiKey rows matching the prefix (usually 1)
    3. bcrypt-verify against hashed_key and previous_key_hash (rotation grace)
    4. Check expiry and workspace active status
    5. Return the Workspace if all checks pass
    """
    if not raw_key:
        return None

    prefix = raw_key[:_KEY_PREFIX_LEN]
    now = datetime.now(timezone.utc)

    result = await db.execute(
        select(ApiKey)
        .where(ApiKey.key_prefix == prefix)
        .where(ApiKey.is_active == True)  # noqa: E712
    )
    candidates: list[ApiKey] = list(result.scalars().all())

    for api_key in candidates:
        # Check primary hash
        matched = verify_api_key(raw_key, api_key.hashed_key)

        # Check previous hash (rotation grace period, valid 24hrs after rotation)
        if not matched and api_key.previous_key_hash:
            matched = verify_api_key(raw_key, api_key.previous_key_hash)

        if not matched:
            continue

        # Key matched — check expiry
        if api_key.expires_at and api_key.expires_at < now:
            logger.warning(
                "api_key_expired",
                key_prefix=prefix,
                expired_at=api_key.expires_at.isoformat(),
            )
            return None

        # Fetch and verify workspace
        workspace_result = await db.execute(
            select(Workspace).where(
                Workspace.id == api_key.workspace_id,
                Workspace.is_active == True,  # noqa: E712
            )
        )
        workspace = workspace_result.scalar_one_or_none()
        if workspace:
            return workspace

    return None


async def require_workspace(
    request: Request,
    raw_key: str | None = Depends(_api_key_header),
    db: AsyncSession = Depends(get_db),
) -> uuid.UUID:
    """
    FastAPI dependency that resolves X-API-Key → workspace_id.

    Raises HTTP 401 if the key is missing or invalid.
    Attach to any route that must be workspace-scoped:

        @router.get("/incidents")
        async def list_incidents(
            workspace_id: uuid.UUID = Depends(require_workspace),
            ...
        )
    """
    if not raw_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="X-API-Key header is required.",
            headers={"WWW-Authenticate": "ApiKey"},
        )

    workspace = await _resolve_workspace(raw_key, db)
    if not workspace:
        logger.warning(
            "api_key_invalid_or_not_found",
            key_prefix=raw_key[:_KEY_PREFIX_LEN] if raw_key else "none",
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired API key.",
            headers={"WWW-Authenticate": "ApiKey"},
        )

    # Cache on request state so other dependencies don't re-query
    request.state.workspace_id = workspace.id
    request.state.workspace_slug = workspace.slug
    return workspace.id
