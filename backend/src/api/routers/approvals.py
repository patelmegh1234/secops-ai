"""
Slack interactive action handler.
Receives POST callbacks when engineers click Approve/Reject buttons in Slack.
Verifies Slack signature before processing any action.
"""

import json
import urllib.parse
from typing import Annotated

from fastapi import APIRouter, Header, HTTPException, Request, status
from fastapi.responses import JSONResponse

from src.core.logging import get_logger
from src.core.security import verify_slack_signature

logger = get_logger(__name__)
router = APIRouter()


@router.post(
    "/actions",
    status_code=status.HTTP_200_OK,
    summary="Slack interactive component action callback",
    description=(
        "Receives action payloads from Slack when engineers click "
        "Approve or Reject buttons on vulnerability alert cards."
    ),
)
async def handle_slack_action(
    request: Request,
    x_slack_signature: Annotated[str | None, Header()] = None,
    x_slack_request_timestamp: Annotated[str | None, Header()] = None,
) -> JSONResponse:
    body = await request.body()

    # ── Slack signature verification ───────────────────────────────────────
    if not verify_slack_signature(
        payload_body=body,
        timestamp_header=x_slack_request_timestamp,
        signature_header=x_slack_signature,
    ):
        logger.warning(
            "slack_action_invalid_signature",
            ip=request.client.host if request.client else "unknown",
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid Slack signature.",
        )

    # ── Parse URL-encoded payload ──────────────────────────────────────────
    body_str = body.decode("utf-8")
    parsed = urllib.parse.parse_qs(body_str)
    payload_str = parsed.get("payload", ["{}"])[0]

    try:
        payload = json.loads(payload_str)
    except json.JSONDecodeError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid Slack action payload.",
        )

    payload_type = payload.get("type")
    if payload_type != "block_actions":
        # Acknowledge non-action payloads (e.g., shortcut, view_submission)
        return JSONResponse(content={"status": "ignored"})

    # ── Extract action details ─────────────────────────────────────────────
    actions = payload.get("actions", [])
    if not actions:
        return JSONResponse(content={"status": "no_actions"})

    action = actions[0]
    action_id = action.get("action_id", "")  # "approve_patch" | "reject_patch"
    action_value = action.get("value", "{}")

    try:
        value_data = json.loads(action_value)
    except json.JSONDecodeError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Malformed action value JSON.",
        )

    patch_id = value_data.get("patch_id")
    if not patch_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Missing patch_id in action value.",
        )

    user = payload.get("user", {})
    approver_id = user.get("id", "unknown")
    approver_name = user.get("name") or user.get("username")
    message_ts = payload.get("container", {}).get("message_ts")
    response_url = payload.get("response_url")

    logger.info(
        "slack_action_received",
        action_id=action_id,
        patch_id=patch_id,
        approver=approver_id,
    )

    # ── Dispatch to Celery ─────────────────────────────────────────────────
    if action_id == "approve_patch":
        from src.workers.tasks import create_pull_request

        task = create_pull_request.apply_async(
            kwargs={
                "patch_id": patch_id,
                "approver_slack_id": approver_id,
                "approver_name": approver_name,
                "slack_message_ts": message_ts,
                "response_url": response_url,
            },
            countdown=0,
        )
        logger.info("pr_creation_task_queued", task_id=task.id, patch_id=patch_id)

        return JSONResponse(
            content={
                "response_type": "in_channel",
                "replace_original": True,
                "text": f"✅ *{approver_name}* approved the patch. Creating GitHub PR...",
            }
        )

    elif action_id == "reject_patch":
        from src.workers.tasks import record_rejection

        task = record_rejection.apply_async(
            kwargs={
                "patch_id": patch_id,
                "approver_slack_id": approver_id,
                "approver_name": approver_name,
                "slack_message_ts": message_ts,
            },
            countdown=0,
        )
        logger.info("rejection_recorded", task_id=task.id, patch_id=patch_id)

        return JSONResponse(
            content={
                "response_type": "in_channel",
                "replace_original": True,
                "text": f"❌ *{approver_name}* rejected the patch. Incident closed.",
            }
        )

    else:
        logger.warning("unknown_slack_action", action_id=action_id)
        return JSONResponse(content={"status": "unknown_action"})
