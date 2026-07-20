"""
Agent 3: Security Patch Auditor (Guardrail)
Validates that the generated patch actually fixes the vulnerability
and doesn't introduce new security issues. Can reject and request retries.
"""

import json
import re
import time
from dataclasses import dataclass

from crewai import Agent, Task
from langchain_openai import ChatOpenAI

from src.agents.patch_agent import PatchResult
from src.agents.triage_agent import TriageResult
from src.agents.tools.owasp_checker import OWASPSecurityCheckerTool
from src.core.config import get_settings
from src.core.logging import get_logger
from src.database.schemas import VulnerabilityCreate

settings = get_settings()
logger = get_logger(__name__)


@dataclass
class GuardrailResult:
    success: bool
    approved: bool = False
    notes: str = ""
    error: str | None = None
    duration_ms: int = 0
    input_tokens: int = 0
    output_tokens: int = 0


def build_guardrail_agent() -> Agent:
    """Create the guardrail agent with GPT-4o-mini (fast validation)."""
    llm = ChatOpenAI(
        model=settings.openai_secondary_model,  # gpt-4o-mini
        temperature=0.05,
        max_tokens=2000,
        api_key=settings.openai_api_key,
        model_kwargs={"response_format": {"type": "json_object"}},
    )

    return Agent(
        role="Security Patch Auditor",
        goal=(
            "Rigorously validate security patches to ensure: "
            "(1) the original vulnerability is fully remediated, "
            "(2) no new security vulnerabilities are introduced, "
            "(3) existing functionality is preserved, "
            "(4) the patch adheres to OWASP secure coding guidelines. "
            "Be strict but fair — only approve genuinely secure patches."
        ),
        backstory=(
            "You are a lead security auditor responsible for the final gate "
            "before security patches are deployed to production. "
            "You have reviewed thousands of patches and caught subtle re-introductions "
            "of vulnerabilities that slip past junior engineers. "
            "You are methodical, skeptical, and precise. You never rubber-stamp patches."
        ),
        tools=[OWASPSecurityCheckerTool()],
        llm=llm,
        verbose=False,
        allow_delegation=False,
        max_iter=2,
    )


def build_guardrail_task(
    agent: Agent,
    vuln: VulnerabilityCreate,
    triage: TriageResult,
    patch: PatchResult,
) -> Task:
    return Task(
        description=f"""
Perform a security audit on the following patch. You must approve or reject it.

## Original Vulnerability
- CVE/Issue: {vuln.cve_id or "N/A"} | Severity: {vuln.severity}
- OWASP: {triage.owasp_category or "Unknown"}
- Description: {triage.context_summary}

## Original (Vulnerable) Code
```python
{patch.original_code}
```

## Proposed Patch
```python
{patch.patched_code}
```

## Patch Reasoning (from patch agent)
{patch.reasoning}

## Unified Diff
```diff
{patch.diff}
```

## Audit Checklist — evaluate ALL of these:
1. ✅/❌ Does the patch FULLY fix the stated vulnerability?
2. ✅/❌ Does the patch introduce ANY new security vulnerabilities?
3. ✅/❌ Are function signatures and return types preserved?
4. ✅/❌ Is the patch minimal (no unnecessary changes)?
5. ✅/❌ Does the patch use secure, idiomatic coding practices?
6. Use `owasp_security_checker` on BOTH the original and patched code.

## Output Format (JSON only):
{{
  "approved": true/false,
  "checklist": {{
    "fixes_vulnerability": true/false,
    "no_new_vulnerabilities": true/false,
    "preserves_signatures": true/false,
    "minimal_change": true/false,
    "secure_practices": true/false
  }},
  "notes": "<detailed explanation of your decision — cite specific lines if rejecting>",
  "rejection_reason": "<if rejected, specific reason why — what must change>"
}}
""",
        expected_output=(
            "A JSON object with keys: approved (bool), checklist (dict), "
            "notes (str), rejection_reason (str or null)."
        ),
        agent=agent,
    )


async def run_guardrail_agent(
    vuln: VulnerabilityCreate,
    triage: TriageResult,
    patch: PatchResult,
) -> GuardrailResult:
    """Execute the guardrail agent and return an approval decision."""
    start_ms = int(time.time() * 1000)

    try:
        from crewai import Crew, Process

        agent = build_guardrail_agent()
        task = build_guardrail_task(agent, vuln, triage, patch)

        crew = Crew(
            agents=[agent],
            tasks=[task],
            process=Process.sequential,
            verbose=False,
        )

        result = crew.kickoff()
        raw_output = str(result)

        json_match = re.search(r"\{.*\}", raw_output, re.DOTALL)
        if not json_match:
            raise ValueError(f"No JSON in guardrail output: {raw_output[:200]}")

        data = json.loads(json_match.group())
        approved = bool(data.get("approved", False))
        notes = data.get("notes", "")
        rejection = data.get("rejection_reason", "")

        if not approved and rejection:
            notes = f"{notes}\n\nRejection reason: {rejection}"

        duration = int(time.time() * 1000) - start_ms
        logger.info(
            "guardrail_agent_complete",
            approved=approved,
            duration_ms=duration,
        )

        return GuardrailResult(
            success=True,
            approved=approved,
            notes=notes,
            duration_ms=duration,
        )

    except Exception as exc:
        duration = int(time.time() * 1000) - start_ms
        logger.error("guardrail_agent_failed", error=str(exc), duration_ms=duration)
        return GuardrailResult(
            success=False,
            approved=False,
            error=str(exc),
            duration_ms=duration,
        )
