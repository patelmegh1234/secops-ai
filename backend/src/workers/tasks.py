"""
Celery task definitions for the SecOps-AI pipeline.

Tasks:
  process_vulnerability  — Full triage → patch → sandbox → Slack notification
  create_pull_request    — GitHub PR creation after Slack approval
  record_rejection       — Log rejection decision
"""

import asyncio
import json
from datetime import datetime, timezone
from typing import Any

from celery import Task
from celery.utils.log import get_task_logger

from src.workers.celery_app import celery_app

logger = get_task_logger(__name__)

# Maximum sandbox attempts per vulnerability (initial + retries)
MAX_SANDBOX_ATTEMPTS = 2


def run_async(coro: Any) -> Any:
    """Run an async coroutine from a sync Celery task context."""
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


# ── Main Pipeline Task ────────────────────────────────────────────────────────
@celery_app.task(
    bind=True,
    name="src.workers.tasks.process_vulnerability",
    max_retries=2,
    default_retry_delay=5,
    queue="vulnerability",
)
def process_vulnerability(
    self: Task,
    payload: dict[str, Any],
    scanner: str,
    idempotency_key: str | None = None,
) -> dict[str, Any]:
    """
    Full SecOps-AI pipeline:
    1. Parse scanner payload -> VulnerabilityCreate records
    2. Persist to PostgreSQL (status=PENDING, idempotency_key set)
    3. Run CrewAI multi-agent pipeline (triage -> patch -> guardrail)
    4. Persist patch to DB
    5. Execute Docker sandbox verification (with trace-based retry)
    6. Update DB status
    7. Send Slack Block Kit notification with Approve/Reject buttons
    8. Publish real-time event to Redis pub/sub for dashboard

    Returns summary dict for Celery result backend.
    """
    logger.info(f"[process_vulnerability] Starting pipeline for scanner={scanner}")

    try:
        return run_async(_process_vulnerability_async(self, payload, scanner, idempotency_key))
    except Exception as exc:
        logger.error(f"[process_vulnerability] Pipeline failed: {exc}")
        raise self.retry(exc=exc)


async def _process_vulnerability_async(
    task: Task,
    payload: dict[str, Any],
    scanner: str,
    idempotency_key: str | None = None,
) -> dict[str, Any]:
    import redis.asyncio as aioredis

    from src.core.config import get_settings
    from src.database.connection import get_db_context
    from src.database import crud
    from src.database.schemas import VulnerabilityUpdate
    from src.database.models import VulnerabilityStatus
    from src.integrations.scanner_parser import parse_scanner_payload
    from src.agents.crew import run_security_crew
    from src.sandbox.controller import run_sandbox
    from src.integrations.slack_client import send_vulnerability_alert

    settings = get_settings()
    results = []

    # ── Step 1: Parse payload ──────────────────────────────────────────────
    vuln_creates = parse_scanner_payload(payload, scanner)
    if not vuln_creates:
        logger.warning("[process_vulnerability] No actionable vulnerabilities parsed.")
        return {"status": "no_vulnerabilities_found", "scanner": scanner}

    for vuln_create in vuln_creates[:5]:  # Process up to 5 per payload burst
        async with get_db_context() as db:
            # ── Step 2: Persist vulnerability ──────────────────────────────
            vuln = await crud.create_vulnerability(db, vuln_create)
            vuln_id = vuln.id
            logger.info(f"[process_vulnerability] Created vulnerability {vuln_id}")

            # Update status to TRIAGING and stamp idempotency key
            await crud.update_vulnerability(
                db, vuln_id,
                VulnerabilityUpdate(
                    status=VulnerabilityStatus.TRIAGING,
                    celery_task_id=task.request.id,
                    idempotency_key=idempotency_key,
                )
            )

        # ── Step 3: Publish event to dashboard ────────────────────────────
        redis_client = aioredis.from_url(settings.redis_url, decode_responses=True)
        event = {
            "type": "vulnerability_update",
            "vuln_id": str(vuln_id),
            "status": VulnerabilityStatus.TRIAGING,
            "severity": vuln_create.severity,
            "title": vuln_create.title,
        }
        await redis_client.publish("secops:events", json.dumps(event))

        try:
            # ── Step 4: Run CrewAI pipeline ───────────────────────────────
            async with get_db_context() as db:
                await crud.update_vulnerability(
                    db, vuln_id, VulnerabilityUpdate(status=VulnerabilityStatus.PATCHING)
                )
            await redis_client.publish("secops:events", json.dumps({
                **event, "status": VulnerabilityStatus.PATCHING
            }))

            crew_result = await run_security_crew(vuln_create, vuln_id)

            if not crew_result.success:
                async with get_db_context() as db:
                    await crud.update_vulnerability(
                        db, vuln_id, VulnerabilityUpdate(status=VulnerabilityStatus.PATCH_FAILED)
                    )
                logger.error(f"[process_vulnerability] Crew failed for {vuln_id}: {crew_result.error}")
                continue

            # ── Step 5: Persist patch ──────────────────────────────────────
            from src.database.schemas import PatchCreate
            async with get_db_context() as db:
                patch = await crud.create_patch(
                    db,
                    PatchCreate(
                        vulnerability_id=vuln_id,
                        original_code=crew_result.original_code,
                        patched_code=crew_result.patched_code,
                        diff_unified=crew_result.diff,
                        agent_reasoning=crew_result.reasoning,
                        owasp_flags=crew_result.owasp_flags,
                    ),
                )
                patch_id = patch.id

                # Save agent traces
                for trace_data in crew_result.traces:
                    from src.database.schemas import AgentTraceCreate
                    await crud.create_agent_trace(
                        db, AgentTraceCreate(vulnerability_id=vuln_id, **trace_data)
                    )

            # ── Step 6: Sandbox retry loop ─────────────────────────────────
            # On first sandbox failure, extract a failure trace and feed it
            # back to the patch agent for one corrective attempt.
            # Both runs are stored in sandbox_runs with attempt_number.

            from src.sandbox.result_parser import SandboxFailureTrace, SandboxMode, build_failure_trace

            current_crew_result = crew_result
            sandbox_result = None
            failure_trace: SandboxFailureTrace | None = None

            for sandbox_attempt in range(1, MAX_SANDBOX_ATTEMPTS + 1):

                # On retry: re-run patch agent with failure trace, save new patch
                if sandbox_attempt > 1 and failure_trace is not None:
                    async with get_db_context() as db:
                        await crud.update_vulnerability(
                            db, vuln_id,
                            VulnerabilityUpdate(status=VulnerabilityStatus.REPATCHING),
                        )
                    await redis_client.publish("secops:events", json.dumps({
                        **event, "status": VulnerabilityStatus.REPATCHING,
                    }))

                    current_crew_result = await run_security_crew(
                        vuln_create, vuln_id, repatch_context=failure_trace
                    )

                    if not current_crew_result.success:
                        logger.warning(
                            f"[process_vulnerability] Repatch crew failed for {vuln_id}: "
                            f"{current_crew_result.error}"
                        )
                        break

                    # Save the repatch as a new Patch record on the same vuln
                    async with get_db_context() as db:
                        from src.database.schemas import PatchCreate as _PatchCreate
                        repatch = await crud.create_patch(
                            db,
                            _PatchCreate(
                                vulnerability_id=vuln_id,
                                original_code=current_crew_result.original_code,
                                patched_code=current_crew_result.patched_code,
                                diff_unified=current_crew_result.diff,
                                agent_reasoning=current_crew_result.reasoning,
                                owasp_flags=current_crew_result.owasp_flags,
                            ),
                        )
                        patch_id = repatch.id

                # Mark sandbox as running
                async with get_db_context() as db:
                    await crud.update_vulnerability(
                        db, vuln_id,
                        VulnerabilityUpdate(status=VulnerabilityStatus.SANDBOX_RUNNING),
                    )
                await redis_client.publish("secops:events", json.dumps({
                    **event, "status": VulnerabilityStatus.SANDBOX_RUNNING,
                }))

                sandbox_result = await run_sandbox(
                    repo_owner=vuln_create.repo_owner,
                    repo_name=vuln_create.repo_name,
                    branch=vuln_create.repo_branch,
                    file_path=vuln_create.file_path,
                    patched_code=current_crew_result.patched_code,
                )

                # Stamp sandbox_completed_at on first completion
                sandbox_completed_ts = datetime.now(timezone.utc)

                # Build a typed failure trace regardless (used below if needed)
                failure_trace = build_failure_trace(
                    stdout=sandbox_result.stdout,
                    stderr=sandbox_result.stderr,
                    exit_code=sandbox_result.exit_code,
                    timed_out=sandbox_result.timed_out,
                )

                # Store this sandbox run with its attempt number
                async with get_db_context() as db:
                    from src.database.schemas import SandboxRunCreate as _SandboxRunCreate
                    await crud.create_sandbox_run(
                        db,
                        _SandboxRunCreate(
                            patch_id=patch_id,
                            container_id=sandbox_result.container_id,
                            exit_code=sandbox_result.exit_code,
                            stdout=sandbox_result.stdout,
                            stderr=sandbox_result.stderr,
                            tests_passed=sandbox_result.tests_passed,
                            tests_failed=sandbox_result.tests_failed,
                            duration_ms=sandbox_result.duration_ms,
                            timed_out=sandbox_result.timed_out,
                            attempt_number=sandbox_attempt,
                            sandbox_mode=failure_trace.mode.value,
                        ),
                    )
                    await crud.update_vulnerability(
                        db, vuln_id,
                        VulnerabilityUpdate(sandbox_completed_at=sandbox_completed_ts),
                    )

                if sandbox_result.passed:
                    # Sandbox passed — move forward to Slack
                    logger.info(
                        f"[process_vulnerability] Sandbox passed on attempt {sandbox_attempt} "
                        f"for {vuln_id}"
                    )
                    break

                # Sandbox failed — decide whether to retry
                sandbox_status = VulnerabilityStatus.SANDBOX_FAILED

                if sandbox_attempt < MAX_SANDBOX_ATTEMPTS:
                    logger.warning(
                        f"[process_vulnerability] Sandbox failed (attempt {sandbox_attempt}), "
                        f"extracting trace for repatch: {vuln_id}"
                    )
                    async with get_db_context() as db:
                        await crud.update_vulnerability(
                            db, vuln_id,
                            VulnerabilityUpdate(status=VulnerabilityStatus.TRACE_ANALYZED),
                        )
                    await redis_client.publish("secops:events", json.dumps({
                        **event, "status": VulnerabilityStatus.TRACE_ANALYZED,
                        "failure_mode": failure_trace.mode.value,
                    }))
                    # Loop continues: failure_trace is passed to run_security_crew() above
                else:
                    # All attempts exhausted — mark final failure
                    async with get_db_context() as db:
                        await crud.update_vulnerability(
                            db, vuln_id, VulnerabilityUpdate(status=sandbox_status)
                        )
                    await redis_client.publish("secops:events", json.dumps({
                        **event,
                        "status": sandbox_status,
                        "sandbox_passed": False,
                        "tests_passed": sandbox_result.tests_passed,
                        "tests_failed": sandbox_result.tests_failed,
                        "sandbox_mode": failure_trace.mode.value,
                    }))

            # ── Step 7: Send Slack notification ────────────────────────────
            if sandbox_result is None:
                continue

            sandbox_passed = sandbox_result.passed

            # Set final sandbox status (PASSED or FAILED)
            final_sandbox_status = (
                VulnerabilityStatus.SANDBOX_PASSED
                if sandbox_passed
                else VulnerabilityStatus.SANDBOX_FAILED
            )
            async with get_db_context() as db:
                await crud.update_vulnerability(
                    db, vuln_id, VulnerabilityUpdate(status=final_sandbox_status)
                )
            await redis_client.publish("secops:events", json.dumps({
                **event,
                "status": final_sandbox_status,
                "sandbox_passed": sandbox_passed,
                "tests_passed": sandbox_result.tests_passed,
                "tests_failed": sandbox_result.tests_failed,
                "sandbox_mode": failure_trace.mode.value if failure_trace else None,
            }))

            # Reload objects for Slack notification
            async with get_db_context() as db:
                vuln_obj = await crud.get_vulnerability(db, vuln_id)
                patch_obj = await crud.get_patch(db, patch_id)

            slack_ts = await send_vulnerability_alert(
                vuln=vuln_obj,
                patch=patch_obj,
                sandbox_result=sandbox_result,
            )

            # Stamp Slack sent timestamp + AWAITING_APPROVAL
            slack_sent_ts = datetime.now(timezone.utc)
            async with get_db_context() as db:
                await crud.update_vulnerability(
                    db, vuln_id,
                    VulnerabilityUpdate(
                        status=VulnerabilityStatus.AWAITING_APPROVAL,
                        slack_sent_at=slack_sent_ts,
                    ),
                )

            results.append({
                "vuln_id": str(vuln_id),
                "patch_id": str(patch_id),
                "sandbox_passed": sandbox_result.passed,
                "slack_ts": slack_ts,
            })

        except Exception as exc:
            logger.error(f"[process_vulnerability] Error processing {vuln_id}: {exc}")
            async with get_db_context() as db:
                await crud.update_vulnerability(
                    db, vuln_id, VulnerabilityUpdate(status=VulnerabilityStatus.ERROR)
                )
        finally:
            await redis_client.aclose()

    return {"status": "completed", "processed": len(results), "results": results}


# ── GitHub PR Creation Task ────────────────────────────────────────────────────
@celery_app.task(
    bind=True,
    name="src.workers.tasks.create_pull_request",
    max_retries=2,
    default_retry_delay=10,
    queue="github",
)
def create_pull_request(
    self: Task,
    patch_id: str,
    approver_slack_id: str,
    approver_name: str | None,
    slack_message_ts: str | None,
    response_url: str | None,
) -> dict[str, Any]:
    """
    Create a GitHub PR after human approval via Slack.
    """
    logger.info(f"[create_pull_request] Creating PR for patch {patch_id}")
    try:
        return run_async(
            _create_pr_async(
                patch_id, approver_slack_id, approver_name, slack_message_ts, response_url
            )
        )
    except Exception as exc:
        logger.error(f"[create_pull_request] Failed: {exc}")
        raise self.retry(exc=exc)


async def _create_pr_async(
    patch_id: str,
    approver_slack_id: str,
    approver_name: str | None,
    slack_message_ts: str | None,
    response_url: str | None,
) -> dict[str, Any]:
    import uuid as _uuid

    from src.database.connection import get_db_context
    from src.database import crud
    from src.database.models import VulnerabilityStatus, ApprovalDecision
    from src.database.schemas import HumanApprovalCreate, PatchUpdate, VulnerabilityUpdate
    from src.integrations.github_client import create_github_pr
    from src.integrations.slack_client import update_slack_message_approved

    patch_uuid = _uuid.UUID(patch_id)

    async with get_db_context() as db:
        patch = await crud.get_patch(db, patch_uuid)
        if not patch:
            raise ValueError(f"Patch {patch_id} not found")

        vuln = await crud.get_vulnerability(db, patch.vulnerability_id)
        if not vuln:
            raise ValueError(f"Vulnerability for patch {patch_id} not found")

        # Record approval
        await crud.create_human_approval(
            db,
            HumanApprovalCreate(
                patch_id=patch_uuid,
                decision=ApprovalDecision.APPROVED,
                approver_slack_id=approver_slack_id,
                approver_name=approver_name,
                slack_message_ts=slack_message_ts,
            ),
        )

        # Create GitHub PR
        pr_result = await create_github_pr(vuln=vuln, patch=patch)

        # Update patch with PR details
        await crud.update_patch(
            db,
            patch_uuid,
            PatchUpdate(
                pr_url=pr_result.html_url,
                pr_number=pr_result.number,
                pr_branch=pr_result.head.ref,
            ),
        )

        # Update vuln status
        await crud.update_vulnerability(
            db, vuln.id, VulnerabilityUpdate(status=VulnerabilityStatus.PR_OPENED)
        )

    # Update Slack message to show PR created
    await update_slack_message_approved(
        message_ts=slack_message_ts,
        pr_url=pr_result.html_url,
        pr_number=pr_result.number,
        approver_name=approver_name or approver_slack_id,
    )

    logger.info(f"[create_pull_request] PR #{pr_result.number} created: {pr_result.html_url}")
    return {"pr_url": pr_result.html_url, "pr_number": pr_result.number}


# ── Rejection Task ────────────────────────────────────────────────────────────
@celery_app.task(
    name="src.workers.tasks.record_rejection",
    queue="github",
)
def record_rejection(
    patch_id: str,
    approver_slack_id: str,
    approver_name: str | None,
    slack_message_ts: str | None,
) -> dict[str, Any]:
    """Record a human rejection decision."""
    return run_async(
        _record_rejection_async(patch_id, approver_slack_id, approver_name, slack_message_ts)
    )


async def _record_rejection_async(
    patch_id: str,
    approver_slack_id: str,
    approver_name: str | None,
    slack_message_ts: str | None,
) -> dict[str, Any]:
    import uuid as _uuid

    from src.database.connection import get_db_context
    from src.database import crud
    from src.database.models import VulnerabilityStatus, ApprovalDecision
    from src.database.schemas import HumanApprovalCreate, VulnerabilityUpdate

    patch_uuid = _uuid.UUID(patch_id)
    async with get_db_context() as db:
        patch = await crud.get_patch(db, patch_uuid)
        if not patch:
            raise ValueError(f"Patch {patch_id} not found")

        await crud.create_human_approval(
            db,
            HumanApprovalCreate(
                patch_id=patch_uuid,
                decision=ApprovalDecision.REJECTED,
                approver_slack_id=approver_slack_id,
                approver_name=approver_name,
                slack_message_ts=slack_message_ts,
            ),
        )
        await crud.update_vulnerability(
            db,
            patch.vulnerability_id,
            VulnerabilityUpdate(status=VulnerabilityStatus.REJECTED),
        )

    logger.info(f"[record_rejection] Patch {patch_id} rejected by {approver_slack_id}")
    return {"status": "rejected", "patch_id": patch_id}
