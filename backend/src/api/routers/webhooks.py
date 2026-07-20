"""
Webhook ingestion router.
Handles incoming vulnerability payloads from Trivy and GitHub Security Alerts.

All endpoints:
  1. Validate HMAC signature (< 5ms)
  2. Return 202 Accepted immediately
  3. Enqueue Celery task for async processing
"""

import json
from typing import Annotated

from fastapi import APIRouter, BackgroundTasks, Depends, Header, HTTPException, Request, status
from fastapi.responses import JSONResponse

from src.api.middleware.rate_limiter import limiter
from src.core.config import get_settings
from src.core.logging import get_logger
from src.core.security import verify_github_signature
from src.database.schemas import WebhookAckResponse

settings = get_settings()
logger = get_logger(__name__)
router = APIRouter()


@router.post(
    "/trivy",
    response_model=WebhookAckResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Ingest Trivy vulnerability scan results",
    description=(
        "Receives Trivy JSON scan output, validates the HMAC signature, "
        "and enqueues an async processing task. Returns 202 immediately."
    ),
)
@limiter.limit("30/minute")
async def ingest_trivy_webhook(
    request: Request,
    x_hub_signature_256: Annotated[str | None, Header()] = None,
) -> JSONResponse:
    body = await request.body()

    # ── HMAC validation ────────────────────────────────────────────────────
    if not verify_github_signature(body, x_hub_signature_256):
        logger.warning(
            "trivy_webhook_invalid_signature",
            ip=request.client.host if request.client else "unknown",
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid webhook signature. Ensure X-Hub-Signature-256 is set correctly.",
        )

    # ── Parse payload ──────────────────────────────────────────────────────
    try:
        payload = json.loads(body)
    except json.JSONDecodeError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Request body must be valid JSON.",
        )

    # ── Enqueue Celery task ────────────────────────────────────────────────
    # Import here to avoid circular imports
    from src.workers.tasks import process_vulnerability

    task = process_vulnerability.apply_async(
        kwargs={"payload": payload, "scanner": "TRIVY"},
        countdown=0,
        retry=True,
    )

    logger.info(
        "trivy_webhook_accepted",
        task_id=task.id,
        payload_keys=list(payload.keys()),
    )

    return JSONResponse(
        status_code=status.HTTP_202_ACCEPTED,
        content=WebhookAckResponse(
            task_id=task.id,
            message="Trivy scan queued for AI-powered triage and patch generation.",
        ).model_dump(),
    )


@router.post(
    "/github",
    response_model=WebhookAckResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Ingest GitHub Security Alert webhooks",
    description=(
        "Receives GitHub Security Alert payloads (Dependabot / Code Scanning), "
        "validates the HMAC signature, and enqueues processing."
    ),
)
@limiter.limit("30/minute")
async def ingest_github_webhook(
    request: Request,
    x_hub_signature_256: Annotated[str | None, Header()] = None,
    x_github_event: Annotated[str | None, Header()] = None,
) -> JSONResponse:
    body = await request.body()

    # ── HMAC validation ────────────────────────────────────────────────────
    if not verify_github_signature(body, x_hub_signature_256):
        logger.warning(
            "github_webhook_invalid_signature",
            event=x_github_event,
            ip=request.client.host if request.client else "unknown",
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid webhook signature.",
        )

    # ── Filter to security-relevant events only ────────────────────────────
    relevant_events = {
        "code_scanning_alert",
        "dependabot_alert",
        "security_advisory",
        "repository_vulnerability_alert",
    }
    if x_github_event and x_github_event not in relevant_events:
        logger.info("github_webhook_ignored", event=x_github_event)
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={"status": "ignored", "event": x_github_event},
        )

    try:
        payload = json.loads(body)
    except json.JSONDecodeError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Request body must be valid JSON.",
        )

    from src.workers.tasks import process_vulnerability

    task = process_vulnerability.apply_async(
        kwargs={"payload": payload, "scanner": "GITHUB"},
        countdown=0,
        retry=True,
    )

    logger.info(
        "github_webhook_accepted",
        task_id=task.id,
        event=x_github_event,
    )

    return JSONResponse(
        status_code=status.HTTP_202_ACCEPTED,
        content=WebhookAckResponse(
            task_id=task.id,
            message=f"GitHub {x_github_event} event queued for processing.",
        ).model_dump(),
    )


@router.post(
    "/bandit",
    response_model=WebhookAckResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Ingest Bandit SAST scan results",
)
@limiter.limit("30/minute")
async def ingest_bandit_webhook(
    request: Request,
    x_hub_signature_256: Annotated[str | None, Header()] = None,
) -> JSONResponse:
    body = await request.body()

    if not verify_github_signature(body, x_hub_signature_256):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid webhook signature.",
        )

    try:
        payload = json.loads(body)
    except json.JSONDecodeError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Request body must be valid JSON.",
        )

    from src.workers.tasks import process_vulnerability

    task = process_vulnerability.apply_async(
        kwargs={"payload": payload, "scanner": "BANDIT"},
        countdown=0,
        retry=True,
    )

    logger.info("bandit_webhook_accepted", task_id=task.id)

    return JSONResponse(
        status_code=status.HTTP_202_ACCEPTED,
        content=WebhookAckResponse(
            task_id=task.id,
            message="Bandit SAST scan queued for AI-powered analysis.",
        ).model_dump(),
    )
