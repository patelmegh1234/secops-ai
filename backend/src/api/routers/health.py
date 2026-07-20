"""
Health check endpoints for load balancers and uptime monitors.
/health  — liveness probe (always returns 200 if app is running)
/ready   — readiness probe (checks DB + Redis connectivity)
"""

import time

import redis.asyncio as aioredis
from fastapi import APIRouter, Request, status
from fastapi.responses import JSONResponse
from sqlalchemy import text

from src.core.config import get_settings
from src.core.logging import get_logger
from src.database.connection import engine

settings = get_settings()
logger = get_logger(__name__)
router = APIRouter()

START_TIME = time.time()


@router.get(
    "/health",
    status_code=status.HTTP_200_OK,
    summary="Liveness probe",
    include_in_schema=False,
)
async def health() -> JSONResponse:
    """Returns 200 if the application process is alive."""
    return JSONResponse(
        content={
            "status": "ok",
            "app": settings.app_name,
            "version": "0.1.0",
            "uptime_seconds": round(time.time() - START_TIME, 2),
        }
    )


@router.get(
    "/ready",
    status_code=status.HTTP_200_OK,
    summary="Readiness probe",
    include_in_schema=False,
)
async def ready(request: Request) -> JSONResponse:
    """
    Returns 200 only if database AND Redis are reachable.
    Returns 503 if any dependency is unavailable.
    """
    checks: dict[str, str] = {}
    all_ok = True

    # ── Database check ────────────────────────────────────────────────────
    try:
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
        checks["database"] = "ok"
    except Exception as e:
        checks["database"] = f"error: {e}"
        all_ok = False
        logger.error("readiness_db_check_failed", error=str(e))

    # ── Redis check ───────────────────────────────────────────────────────
    try:
        redis_client: aioredis.Redis = request.app.state.redis
        await redis_client.ping()
        checks["redis"] = "ok"
    except Exception as e:
        checks["redis"] = f"error: {e}"
        all_ok = False
        logger.error("readiness_redis_check_failed", error=str(e))

    response_status = status.HTTP_200_OK if all_ok else status.HTTP_503_SERVICE_UNAVAILABLE
    return JSONResponse(
        status_code=response_status,
        content={
            "status": "ready" if all_ok else "degraded",
            "checks": checks,
        },
    )
