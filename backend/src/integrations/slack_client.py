"""
Slack integration using slack-sdk.
Sends interactive Block Kit vulnerability alert cards with Approve/Reject buttons.
"""

import json
from typing import Any

from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError

from src.core.config import get_settings
from src.core.logging import get_logger

settings = get_settings()
logger = get_logger(__name__)


def _get_slack_client() -> WebClient:
    return WebClient(token=settings.slack_bot_token)


def _severity_emoji(severity: str) -> str:
    return {
        "CRITICAL": "🚨",
        "HIGH": "🔴",
        "MEDIUM": "🟡",
        "LOW": "🔵",
        "INFO": "⚪",
    }.get(severity.upper(), "❓")


def _severity_color(severity: str) -> str:
    return {
        "CRITICAL": "#FF0000",
        "HIGH": "#FF4D4D",
        "MEDIUM": "#FFB000",
        "LOW": "#06B6D4",
        "INFO": "#64748B",
    }.get(severity.upper(), "#64748B")


async def send_vulnerability_alert(
    vuln: object,
    patch: object,
    sandbox_result: object,
) -> str | None:
    """
    Send a rich Slack Block Kit card to the security channel.
    The card includes:
      - CVE details with severity badge
      - AI reasoning summary
      - Sandbox test result
      - Approve / Reject interactive buttons

    Returns the Slack message timestamp (ts) for later updates.
    """
    import asyncio
    return await asyncio.get_event_loop().run_in_executor(
        None, _send_alert_sync, vuln, patch, sandbox_result
    )


def _send_alert_sync(vuln: object, patch: object, sandbox_result: object) -> str | None:
    client = _get_slack_client()

    sev_emoji = _severity_emoji(vuln.severity)
    sev_color = _severity_color(vuln.severity)

    sandbox_icon = "✅" if sandbox_result.passed else "❌"
    sandbox_text = (
        f"{sandbox_icon} *{sandbox_result.tests_passed}* passed, "
        f"*{sandbox_result.tests_failed}* failed "
        f"({sandbox_result.duration_ms}ms)"
    )

    # Truncate diff for Slack display (Slack has 3000 char limit per block)
    diff_preview = patch.diff_unified[:800] if patch.diff_unified else "No diff available."

    patch_id_str = str(patch.id)
    vuln_id_str = str(vuln.id)
    cve_display = vuln.cve_id or "SECURITY ISSUE"

    approve_value = json.dumps({"patch_id": patch_id_str, "action": "approve"})
    reject_value = json.dumps({"patch_id": patch_id_str, "action": "reject"})

    blocks: list[dict[str, Any]] = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"{sev_emoji} [{vuln.severity}] {cve_display} — Human Approval Required",
            },
        },
        {"type": "divider"},
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*CVE/Issue:*\n`{cve_display}`"},
                {"type": "mrkdwn", "text": f"*Severity:*\n`{vuln.severity}`"},
                {"type": "mrkdwn", "text": f"*Scanner:*\n`{vuln.scanner}`"},
                {"type": "mrkdwn", "text": f"*OWASP:*\n{vuln.owasp_category or 'N/A'}"},
                {"type": "mrkdwn", "text": f"*File:*\n`{vuln.file_path}`"},
                {"type": "mrkdwn", "text": f"*Repo:*\n`{vuln.repo_owner}/{vuln.repo_name}`"},
            ],
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*📋 Vulnerability Description*\n{vuln.description[:400]}",
            },
        },
        {"type": "divider"},
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*🤖 AI Patch Reasoning*\n{patch.agent_reasoning[:500]}",
            },
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*📝 Patch Diff Preview*\n```{diff_preview}```",
            },
        },
        {"type": "divider"},
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*🧪 Sandbox Verification*\n{sandbox_text}",
            },
        },
        {
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": (
                        f"🔒 Tests ran in isolated, network-disabled Docker container. "
                        f"Container auto-removed after execution."
                    ),
                }
            ],
        },
        {"type": "divider"},
        {
            "type": "actions",
            "elements": [
                {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "✅ Approve & Create PR", "emoji": True},
                    "style": "primary",
                    "value": approve_value,
                    "action_id": "approve_patch",
                    "confirm": {
                        "title": {"type": "plain_text", "text": "Confirm Approval"},
                        "text": {
                            "type": "mrkdwn",
                            "text": (
                                f"This will create a GitHub PR for `{vuln.repo_owner}/{vuln.repo_name}`. "
                                "Are you sure?"
                            ),
                        },
                        "confirm": {"type": "plain_text", "text": "Yes, Create PR"},
                        "deny": {"type": "plain_text", "text": "Cancel"},
                    },
                },
                {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "❌ Reject", "emoji": True},
                    "style": "danger",
                    "value": reject_value,
                    "action_id": "reject_patch",
                },
                {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "🔍 View Full Diff", "emoji": True},
                    "url": f"{settings.slack_app_base_url}/review/{vuln_id_str}",
                    "action_id": "view_full_diff",
                },
            ],
        },
        {
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": (
                        f"*Incident ID:* `{vuln_id_str[:8]}` | "
                        f"*Patch ID:* `{patch_id_str[:8]}` | "
                        f"_SecOps-AI Autonomous Security Agent_"
                    ),
                }
            ],
        },
    ]

    try:
        response = client.chat_postMessage(
            channel=settings.slack_alert_channel_id,
            blocks=blocks,
            attachments=[{"color": sev_color, "fallback": f"New {vuln.severity} vulnerability: {cve_display}"}],
            text=f"{sev_emoji} [{vuln.severity}] {cve_display} — Human approval required",
            unfurl_links=False,
            unfurl_media=False,
        )
        ts = response.get("ts")
        logger.info("slack_alert_sent", ts=ts, channel=settings.slack_alert_channel_id)
        return ts

    except SlackApiError as e:
        logger.error("slack_alert_failed", error=str(e))
        return None


async def update_slack_message_approved(
    message_ts: str | None,
    pr_url: str,
    pr_number: int,
    approver_name: str,
) -> None:
    """Update the original Slack message to show PR was created."""
    if not message_ts:
        return

    import asyncio
    await asyncio.get_event_loop().run_in_executor(
        None,
        _update_message_sync,
        message_ts,
        pr_url,
        pr_number,
        approver_name,
    )


def _update_message_sync(
    message_ts: str,
    pr_url: str,
    pr_number: int,
    approver_name: str,
) -> None:
    client = _get_slack_client()

    try:
        client.chat_postMessage(
            channel=settings.slack_alert_channel_id,
            thread_ts=message_ts,
            text=(
                f"✅ *PR #{pr_number} Created!*\n"
                f"Approved by *{approver_name}*\n"
                f"<{pr_url}|🔗 View Pull Request>"
            ),
        )
        logger.info("slack_pr_thread_reply_sent", pr_number=pr_number)
    except SlackApiError as e:
        logger.error("slack_update_failed", error=str(e))
