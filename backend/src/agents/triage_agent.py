"""
Agent 1: CVE Triage Analyst
Parses raw vulnerability alerts into structured, actionable information
and fetches the exact vulnerable code from the repository.
"""

import time
from dataclasses import dataclass, field

from crewai import Agent, Task
from langchain_openai import ChatOpenAI

from src.agents.tools.file_reader import GitHubFileReaderTool
from src.agents.tools.owasp_checker import OWASPSecurityCheckerTool
from src.core.config import get_settings
from src.core.logging import get_logger
from src.database.schemas import VulnerabilityCreate

settings = get_settings()
logger = get_logger(__name__)


@dataclass
class TriageResult:
    success: bool
    vulnerable_code: str = ""
    file_path: str = ""
    line_start: int | None = None
    line_end: int | None = None
    owasp_category: str | None = None
    context_summary: str = ""
    reasoning: str = ""
    error: str | None = None
    duration_ms: int = 0
    input_tokens: int = 0
    output_tokens: int = 0


def build_triage_agent() -> Agent:
    """Create the triage agent with GPT-4o-mini (fast, cost-effective)."""
    llm = ChatOpenAI(
        model=settings.openai_secondary_model,  # gpt-4o-mini
        temperature=0.05,
        max_tokens=2000,
        api_key=settings.openai_api_key,
    )

    return Agent(
        role="Senior CVE Triage Analyst",
        goal=(
            "Parse raw vulnerability scan alerts into precise, actionable security reports. "
            "Identify the exact file, function, and line(s) of vulnerable code. "
            "Classify the issue using OWASP Top 10 categories. "
            "Never fabricate code — only report what you can verify."
        ),
        backstory=(
            "You are a senior security engineer with 10+ years of experience in "
            "vulnerability triage for Fortune 500 companies. You specialize in "
            "rapidly analyzing CVE reports, SAST output, and dependency scan results. "
            "You are known for your precision — you never guess, and you always "
            "cite exact file paths and line numbers from the actual codebase."
        ),
        tools=[GitHubFileReaderTool(), OWASPSecurityCheckerTool()],
        llm=llm,
        verbose=False,
        allow_delegation=False,
        max_iter=3,
    )


def build_triage_task(agent: Agent, vuln: VulnerabilityCreate) -> Task:
    """Create the triage task for a specific vulnerability."""
    return Task(
        description=f"""
Analyze the following security vulnerability alert and produce a structured triage report.

## Vulnerability Details
- Scanner: {vuln.scanner}
- CVE ID: {vuln.cve_id or "N/A"}
- Severity: {vuln.severity}
- Title: {vuln.title}
- Description: {vuln.description}
- Repository: {vuln.repo_owner}/{vuln.repo_name} (branch: {vuln.repo_branch})
- File Path: {vuln.file_path}
- Lines: {vuln.line_start or "N/A"} – {vuln.line_end or "N/A"}

## Your Tasks
1. Use the `github_file_reader` tool to fetch the vulnerable file content:
   - owner="{vuln.repo_owner}", repo="{vuln.repo_name}", path="{vuln.file_path}",
     ref="{vuln.repo_branch}", start_line={vuln.line_start or 'None'}, end_line={vuln.line_end or 'None'}
2. Use the `owasp_security_checker` tool to classify the vulnerability.
3. Produce a JSON report with these exact keys:
   {{
     "vulnerable_code": "<exact vulnerable code snippet>",
     "file_path": "<confirmed file path>",
     "line_start": <line number or null>,
     "line_end": <line number or null>,
     "owasp_category": "<OWASP category string>",
     "context_summary": "<1-2 sentence description of what makes this code vulnerable>",
     "reasoning": "<your analysis and confidence level>"
   }}
""",
        expected_output=(
            "A JSON object with keys: vulnerable_code, file_path, line_start, "
            "line_end, owasp_category, context_summary, reasoning."
        ),
        agent=agent,
    )


async def run_triage_agent(vuln: VulnerabilityCreate) -> TriageResult:
    """
    Execute the triage agent and return a structured TriageResult.
    Handles timeout, parsing errors, and token tracking.
    """
    import json

    start_ms = int(time.time() * 1000)

    try:
        from crewai import Crew, Process

        agent = build_triage_agent()
        task = build_triage_task(agent, vuln)

        crew = Crew(
            agents=[agent],
            tasks=[task],
            process=Process.sequential,
            verbose=False,
        )

        result = crew.kickoff()
        raw_output = str(result)

        # Extract JSON from the output
        import re
        json_match = re.search(r"\{.*\}", raw_output, re.DOTALL)
        if not json_match:
            raise ValueError(f"No JSON found in triage output: {raw_output[:200]}")

        data = json.loads(json_match.group())

        duration = int(time.time() * 1000) - start_ms
        logger.info("triage_agent_complete", duration_ms=duration)

        return TriageResult(
            success=True,
            vulnerable_code=data.get("vulnerable_code", ""),
            file_path=data.get("file_path", vuln.file_path),
            line_start=data.get("line_start"),
            line_end=data.get("line_end"),
            owasp_category=data.get("owasp_category"),
            context_summary=data.get("context_summary", ""),
            reasoning=data.get("reasoning", ""),
            duration_ms=duration,
        )

    except Exception as exc:
        duration = int(time.time() * 1000) - start_ms
        logger.error("triage_agent_failed", error=str(exc), duration_ms=duration)
        return TriageResult(
            success=False,
            error=str(exc),
            duration_ms=duration,
        )
