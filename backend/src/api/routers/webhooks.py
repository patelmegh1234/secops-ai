"""
Webhook ingestion router.
Handles incoming vulnerability payloads from Trivy, Bandit and GitHub Security Alerts.

All endpoints:
  1. Validate HMAC signature (< 5ms)
  2. Check idempotency key in Redis (dedup within 1 hour)
  3. Return 202 Accepted immediately
  4. Enqueue Celery task for async processing

Idempotency key is derived from: scanner + cve_id/rule_id + repo + file_path + line_number.
Duplicate scanner fires within the 1-hour TTL window are acknowledged but not reprocessed.
"""

import hashlib
import json
from typing import Annotated

from fastapi import APIRouter, Header, HTTPException, Request, status
from fastapi.responses import JSONResponse

from src.api.middleware.rate_limiter import limiter
from src.core.config import get_settings
from src.core.logging import get_logger
from src.core.security import verify_github_signature
from src.database.schemas import WebhookAckResponse
from src.integrations.scanner_parser import extract_idempotency_fields

settings = get_settings()
logger = get_logger(__name__)
router = APIRouter()

# Redis TTL for idempotency keys: 1 hour.
# Any duplicate webhook with the same key within this window is rejected.
_DEDUP_TTL_SECONDS = 3600


def _compute_idempotency_key(scanner: str, fields: dict) -> str:
    """
    Derive a stable SHA-256 dedup key from the core identity fields of an alert.

    Key components: scanner + cve_id/rule_id + repo_owner + repo_name + file_path + line_number
    Using SHA-256 keeps keys short (64 hex chars) and prevents injection via field values.
    """
    raw = "|".join([
        scanner,
        str(fields.get("cve_id") or fields.get("rule_id") or "unknown"),
        str(fields.get("repo_owner") or "unknown"),
        str(fields.get("repo_name") or "unknown"),
        str(fields.get("file_path") or "unknown"),
        str(fields.get("line_number") or "0"),
    ])
    return hashlib.sha256(raw.encode()).hexdigest()


async def _check_and_set_idempotency(redis_client, key: str, scanner: str) -> bool:
    """
    Check if this webhook was already processed recently.

    Returns True if this is a duplicate (should be skipped).
    Sets the key with TTL if it is new.
    """
    redis_key = f"webhook:dedup:{key}"
    existing = await redis_client.get(redis_key)
    if existing:
        return True  # Duplicate — already processing or processed
    await redis_client.setex(redis_key, _DEDUP_TTL_SECONDS, scanner)
    return False  # New — proceed with processing


@router.post(
    "/trivy",
    response_model=WebhookAckResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Ingest Trivy vulnerability scan results",
    description=(
        "Receives Trivy JSON scan output, validates the HMAC signature, "
        "deduplicates within a 1-hour window, "
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

    # ── Idempotency check ──────────────────────────────────────────────────
    import redis.asyncio as aioredis
    redis_client = aioredis.from_url(settings.redis_url, decode_responses=True)
    try:
        id_fields = extract_idempotency_fields(payload, "TRIVY")
        idem_key = _compute_idempotency_key("TRIVY", id_fields)
        is_duplicate = await _check_and_set_idempotency(redis_client, idem_key, "TRIVY")
    finally:
        await redis_client.aclose()

    if is_duplicate:
        logger.info("trivy_webhook_deduplicated", idempotency_key=idem_key)
        return JSONResponse(
            status_code=status.HTTP_202_ACCEPTED,
            content={"status": "duplicate", "message": "Already processing this alert."},
        )

    # ── Enqueue Celery task ────────────────────────────────────────────────
    from src.workers.tasks import process_vulnerability

    task = process_vulnerability.apply_async(
        kwargs={"payload": payload, "scanner": "TRIVY", "idempotency_key": idem_key},
        countdown=0,
        retry=True,
    )

    logger.info(
        "trivy_webhook_accepted",
        task_id=task.id,
        idempotency_key=idem_key,
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

    # ── Idempotency check ──────────────────────────────────────────────────
    import redis.asyncio as aioredis
    redis_client = aioredis.from_url(settings.redis_url, decode_responses=True)
    try:
        id_fields = extract_idempotency_fields(payload, "GITHUB")
        idem_key = _compute_idempotency_key("GITHUB", id_fields)
        is_duplicate = await _check_and_set_idempotency(redis_client, idem_key, "GITHUB")
    finally:
        await redis_client.aclose()

    if is_duplicate:
        logger.info("github_webhook_deduplicated", idempotency_key=idem_key)
        return JSONResponse(
            status_code=status.HTTP_202_ACCEPTED,
            content={"status": "duplicate", "message": "Already processing this alert."},
        )

    from src.workers.tasks import process_vulnerability

    task = process_vulnerability.apply_async(
        kwargs={"payload": payload, "scanner": "GITHUB", "idempotency_key": idem_key},
        countdown=0,
        retry=True,
    )

    logger.info(
        "github_webhook_accepted",
        task_id=task.id,
        idempotency_key=idem_key,
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

    # ── Idempotency check ──────────────────────────────────────────────────
    import redis.asyncio as aioredis
    redis_client = aioredis.from_url(settings.redis_url, decode_responses=True)
    try:
        id_fields = extract_idempotency_fields(payload, "BANDIT")
        idem_key = _compute_idempotency_key("BANDIT", id_fields)
        is_duplicate = await _check_and_set_idempotency(redis_client, idem_key, "BANDIT")
    finally:
        await redis_client.aclose()

    if is_duplicate:
        logger.info("bandit_webhook_deduplicated", idempotency_key=idem_key)
        return JSONResponse(
            status_code=status.HTTP_202_ACCEPTED,
            content={"status": "duplicate", "message": "Already processing this alert."},
        )

    from src.workers.tasks import process_vulnerability

    task = process_vulnerability.apply_async(
        kwargs={"payload": payload, "scanner": "BANDIT", "idempotency_key": idem_key},
        countdown=0,
        retry=True,
    )

    logger.info("bandit_webhook_accepted", task_id=task.id, idempotency_key=idem_key)

    return JSONResponse(
        status_code=status.HTTP_202_ACCEPTED,
        content=WebhookAckResponse(
            task_id=task.id,
            message="Bandit SAST scan queued for AI-powered analysis.",
        ).model_dump(),
    )
