"""
SecurityRemediationCrew — orchestrates the full triage → patch → guardrail pipeline.
Returns a CrewResult with all agent outputs, traces, and the final patch.
"""

import uuid
from dataclasses import dataclass, field
from typing import Any

from src.agents.guardrail_agent import GuardrailResult, run_guardrail_agent
from src.agents.patch_agent import PatchResult, run_patch_agent
from src.agents.triage_agent import TriageResult, run_triage_agent
from src.core.config import get_settings
from src.core.logging import get_logger
from src.database.models import AgentName
from src.database.schemas import VulnerabilityCreate
from src.sandbox.result_parser import SandboxFailureTrace

settings = get_settings()
logger = get_logger(__name__)

MAX_GUARDRAIL_RETRIES = 2


@dataclass
class CrewResult:
    """Final result of the full multi-agent pipeline."""
    success: bool
    original_code: str = ""
    patched_code: str = ""
    diff: str = ""
    reasoning: str = ""
    owasp_flags: list[str] = field(default_factory=list)
    error: str | None = None
    traces: list[dict[str, Any]] = field(default_factory=list)


async def run_security_crew(
    vuln: VulnerabilityCreate,
    vuln_id: uuid.UUID,
    repatch_context: SandboxFailureTrace | None = None,
) -> CrewResult:
    """
    Orchestrates the full security remediation pipeline:
    1. Triage Agent — analyze and fetch vulnerable code
    2. Patch Agent — generate a code fix (uses repatch_context on sandbox-retry)
    3. Guardrail Agent — validate the patch (up to MAX_GUARDRAIL_RETRIES)

    Args:
        vuln: The vulnerability to remediate.
        vuln_id: DB primary key for audit trace records.
        repatch_context: When provided, the previous sandbox run failed.
            The failure trace is passed directly to the patch agent so it
            can correct the specific test failures before re-running the sandbox.

    All agent telemetry is collected in `traces` for DB persistence.
    """
    traces: list[dict[str, Any]] = []

    # ── Step 1: Triage ────────────────────────────────────────────────────────
    logger.info("crew_triage_start", vuln_id=str(vuln_id))
    triage: TriageResult = await run_triage_agent(vuln)

    traces.append({
        "vulnerability_id": vuln_id,
        "agent_name": AgentName.TRIAGE,
        "step": "triage",
        "model_used": settings.openai_secondary_model,
        "input_tokens": triage.input_tokens,
        "output_tokens": triage.output_tokens,
        "estimated_cost_usd": _estimate_cost(
            triage.input_tokens, triage.output_tokens, settings.openai_secondary_model
        ),
        "duration_ms": triage.duration_ms,
        "success": triage.success,
        "error_message": triage.error,
    })

    if not triage.success:
        logger.error("crew_triage_failed", vuln_id=str(vuln_id), error=triage.error)
        return CrewResult(
            success=False,
            error=f"Triage agent failed: {triage.error}",
            traces=traces,
        )

    # ── Step 2: Patch (with guardrail retry loop) ─────────────────────────────
    patch: PatchResult | None = None
    guardrail: GuardrailResult | None = None

    for attempt in range(1, MAX_GUARDRAIL_RETRIES + 2):  # +2 for initial + retries
        logger.info("crew_patch_start", vuln_id=str(vuln_id), attempt=attempt)

        # On the first guardrail attempt, pass sandbox repatch context if provided.
        # On subsequent guardrail retries, repatch_context is cleared (new issue is
        # now a guardrail rejection, not a sandbox failure).
        context = repatch_context if attempt == 1 else None
        patch = await run_patch_agent(vuln, triage, repatch_context=context)

        traces.append({
            "vulnerability_id": vuln_id,
            "agent_name": AgentName.PATCH,
            "step": f"patch_attempt_{attempt}",
            "model_used": settings.openai_primary_model,
            "input_tokens": patch.input_tokens,
            "output_tokens": patch.output_tokens,
            "estimated_cost_usd": _estimate_cost(
                patch.input_tokens, patch.output_tokens, settings.openai_primary_model
            ),
            "duration_ms": patch.duration_ms,
            "success": patch.success,
            "error_message": patch.error,
        })

        if not patch.success:
            logger.error(
                "crew_patch_failed", vuln_id=str(vuln_id), attempt=attempt, error=patch.error
            )
            if attempt > MAX_GUARDRAIL_RETRIES:
                return CrewResult(
                    success=False,
                    error=f"Patch agent failed after {attempt} attempts: {patch.error}",
                    traces=traces,
                )
            continue

        # ── Step 3: Guardrail validation ──────────────────────────────────────
        logger.info("crew_guardrail_start", vuln_id=str(vuln_id), attempt=attempt)
        guardrail = await run_guardrail_agent(vuln, triage, patch)

        traces.append({
            "vulnerability_id": vuln_id,
            "agent_name": AgentName.GUARDRAIL,
            "step": f"guardrail_attempt_{attempt}",
            "model_used": settings.openai_secondary_model,
            "input_tokens": guardrail.input_tokens,
            "output_tokens": guardrail.output_tokens,
            "estimated_cost_usd": _estimate_cost(
                guardrail.input_tokens, guardrail.output_tokens, settings.openai_secondary_model
            ),
            "duration_ms": guardrail.duration_ms,
            "success": guardrail.success,
            "error_message": guardrail.error,
        })

        if guardrail.approved:
            logger.info(
                "crew_guardrail_approved",
                vuln_id=str(vuln_id),
                attempt=attempt,
                duration_ms=guardrail.duration_ms,
            )
            break

        logger.warning(
            "crew_guardrail_rejected",
            vuln_id=str(vuln_id),
            attempt=attempt,
            notes=guardrail.notes[:200],
        )

        if attempt > MAX_GUARDRAIL_RETRIES:
            logger.error(
                "crew_guardrail_max_retries_exceeded",
                vuln_id=str(vuln_id),
            )
            return CrewResult(
                success=False,
                error=(
                    f"Guardrail rejected patch after {MAX_GUARDRAIL_RETRIES} retries. "
                    f"Reason: {guardrail.notes}"
                ),
                traces=traces,
            )

    if not patch or not guardrail or not guardrail.approved:
        return CrewResult(
            success=False,
            error="Pipeline did not converge on an approved patch.",
            traces=traces,
        )

    logger.info(
        "crew_pipeline_complete",
        vuln_id=str(vuln_id),
        total_traces=len(traces),
    )

    return CrewResult(
        success=True,
        original_code=patch.original_code,
        patched_code=patch.patched_code,
        diff=patch.diff,
        reasoning=f"{patch.reasoning}\n\n---\nGuardrail Notes: {guardrail.notes}",
        owasp_flags=patch.owasp_flags,
        traces=traces,
    )


def _estimate_cost(
    input_tokens: int, output_tokens: int, model: str
) -> float:
    """
    Estimate USD cost for a model call.
    Prices as of 2024 (per 1M tokens).
    """
    pricing: dict[str, tuple[float, float]] = {
        "gpt-4o": (5.00, 15.00),           # (input_per_1M, output_per_1M)
        "gpt-4o-mini": (0.15, 0.60),
        "claude-sonnet-4-5": (3.00, 15.00),
    }
    rates = pricing.get(model, (5.00, 15.00))
    return round(
        (input_tokens / 1_000_000) * rates[0] + (output_tokens / 1_000_000) * rates[1],
        6,
    )
