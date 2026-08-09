"""
Agent 2: Security Patch Engineer
Generates precise, minimal, non-breaking code fixes for confirmed vulnerabilities.
Uses GPT-4o for maximum code reasoning quality.
"""

import json
import re
import time
from dataclasses import dataclass, field

from crewai import Agent, Task
from langchain_openai import ChatOpenAI

from src.agents.tools.diff_generator import UnifiedDiffTool
from src.agents.tools.owasp_checker import OWASPSecurityCheckerTool
from src.agents.triage_agent import TriageResult
from src.core.config import get_settings
from src.core.logging import get_logger
from src.database.schemas import VulnerabilityCreate
from src.sandbox.result_parser import SandboxFailureTrace

settings = get_settings()
logger = get_logger(__name__)


@dataclass
class PatchResult:
    success: bool
    original_code: str = ""
    patched_code: str = ""
    diff: str = ""
    reasoning: str = ""
    owasp_flags: list[str] = field(default_factory=list)
    error: str | None = None
    duration_ms: int = 0
    input_tokens: int = 0
    output_tokens: int = 0


def build_patch_agent() -> Agent:
    """Create the patch agent with GPT-4o (premium code reasoning)."""
    llm = ChatOpenAI(
        model=settings.openai_primary_model,  # gpt-4o
        temperature=0.1,
        max_tokens=4000,
        api_key=settings.openai_api_key,
        model_kwargs={"response_format": {"type": "json_object"}},
    )

    return Agent(
        role="Expert Security Code Refactoring Engineer",
        goal=(
            "Generate minimal, precise, production-safe code patches that eliminate "
            "security vulnerabilities without breaking existing functionality. "
            "Every patch must: preserve function signatures, not change behaviour, "
            "add security without removing features, and be the smallest change possible."
        ),
        backstory=(
            "You are a principal security engineer who has patched hundreds of CVEs "
            "in production systems at major tech companies. You write clean, idiomatic "
            "code. You never over-engineer patches — you fix exactly the vulnerability "
            "and nothing more. You understand that broken production code is as bad "
            "as vulnerable code. Your patches always pass existing test suites."
        ),
        tools=[UnifiedDiffTool(), OWASPSecurityCheckerTool()],
        llm=llm,
        verbose=False,
        allow_delegation=False,
        max_iter=2,
    )


def build_patch_task(
    agent: Agent,
    vuln: VulnerabilityCreate,
    triage: TriageResult,
    repatch_context: "SandboxFailureTrace | None" = None,
) -> Task:
    """Create the patch generation task.

    Args:
        agent: The CrewAI patch agent.
        vuln: The original vulnerability record.
        triage: Output from the triage agent (contains vulnerable code).
        repatch_context: When provided, the previous patch failed sandbox tests.
            The failure trace is injected into the prompt so the agent can
            correct its approach on this second attempt.
    """
    # Build optional repatch section
    repatch_section = ""
    if repatch_context is not None:
        failure_summary = repatch_context.as_prompt_context()
        repatch_section = f"""

## IMPORTANT: Previous Patch Failed Sandbox Tests
Your previous patch was rejected by the automated test suite.
You MUST address the failure below in your new patch.

### Failure Details
{failure_summary}

### Instructions for This Repatch Attempt
- Do NOT repeat the same change that caused the failure.
- Read the failing test names carefully — they tell you what behaviour broke.
- The patch must be minimal: fix the security issue without breaking the tests above.
- If the test failure suggests the patch changed control flow, revert that change.
"""

    return Task(
        description=f"""
You must generate a security patch for the following confirmed vulnerability.

## Vulnerability Information
- CVE/Issue ID: {vuln.cve_id or "N/A"}
- Severity: {vuln.severity}
- OWASP Category: {triage.owasp_category or "Unknown"}
- Summary: {triage.context_summary}
- File: {triage.file_path}
- Lines: {triage.line_start} – {triage.line_end}

## Vulnerable Code
```python
{triage.vulnerable_code}
```
{repatch_section}
## Patch Requirements (NON-NEGOTIABLE)
1. Fix the EXACT security issue identified — no more, no less.
2. Preserve all existing function signatures and return types.
3. Do not break any existing functionality or tests.
4. Use language-idiomatic, production-quality code.
5. Do not introduce new dependencies unless absolutely necessary.
6. Add a comment explaining WHY the change was made (e.g., # Fixed: SQL injection via parameterized query).

## Steps
1. Write the complete patched version of the vulnerable code section.
2. Use `unified_diff_generator` tool to generate the diff.
3. Use `owasp_security_checker` tool on your patched code to verify no new issues.
4. Return a JSON response:
{{
  "original_code": "<exact original code>",
  "patched_code": "<your complete patched code>",
  "diff_unified": "<unified diff output>",
  "reasoning": "<step-by-step explanation of what was changed and why>",
  "owasp_flags": ["<any remaining OWASP flags if any, or empty list>"]
}}
""",
        expected_output=(
            "A JSON object with keys: original_code, patched_code, diff_unified, "
            "reasoning, owasp_flags."
        ),
        agent=agent,
    )


async def run_patch_agent(
    vuln: VulnerabilityCreate,
    triage: TriageResult,
    repatch_context: "SandboxFailureTrace | None" = None,
) -> PatchResult:
    """Execute the patch agent and return a structured PatchResult.

    Args:
        vuln: The vulnerability to fix.
        triage: Triage agent output containing the vulnerable code.
        repatch_context: When provided, this is a retry triggered by sandbox
            failure. The trace is injected into the task prompt so the agent
            can correct its previous attempt.
    """
    start_ms = int(time.time() * 1000)

    try:
        from crewai import Crew, Process

        agent = build_patch_agent()
        task = build_patch_task(agent, vuln, triage, repatch_context=repatch_context)

        crew = Crew(
            agents=[agent],
            tasks=[task],
            process=Process.sequential,
            verbose=False,
        )

        result = crew.kickoff()
        raw_output = str(result)

        # Extract JSON
        json_match = re.search(r"\{.*\}", raw_output, re.DOTALL)
        if not json_match:
            raise ValueError(f"No JSON in patch output: {raw_output[:200]}")

        data = json.loads(json_match.group())

        # Generate diff if agent didn't call the tool properly
        original = data.get("original_code", triage.vulnerable_code)
        patched = data.get("patched_code", "")
        diff = data.get("diff_unified", "")

        if not diff and original and patched:
            from src.agents.tools.diff_generator import generate_diff
            diff = generate_diff(original, patched, triage.file_path)

        duration = int(time.time() * 1000) - start_ms
        logger.info("patch_agent_complete", duration_ms=duration)

        return PatchResult(
            success=True,
            original_code=original,
            patched_code=patched,
            diff=diff,
            reasoning=data.get("reasoning", ""),
            owasp_flags=data.get("owasp_flags", []),
            duration_ms=duration,
        )

    except Exception as exc:
        duration = int(time.time() * 1000) - start_ms
        logger.error("patch_agent_failed", error=str(exc), duration_ms=duration)
        return PatchResult(
            success=False,
            error=str(exc),
            duration_ms=duration,
        )
