"""
CrewAI tool: Validates code against OWASP Top 10 patterns.
Used by the guardrail agent to check if patches introduce new vulnerabilities.
"""

import re
from typing import Any

from crewai.tools import BaseTool
from pydantic import BaseModel, Field


class OWASPCheckerInput(BaseModel):
    code: str = Field(description="The code snippet to analyze for OWASP vulnerabilities")
    language: str = Field(default="python", description="Programming language of the code")


# ─── OWASP Top 10 Pattern Library ─────────────────────────────────────────────
PYTHON_PATTERNS: list[dict[str, Any]] = [
    # A03:2021 - Injection
    {
        "id": "A03-SQL-INJECT",
        "owasp": "A03:2021 - Injection",
        "pattern": re.compile(
            r'execute\s*\(\s*["\'].*%s.*["\']|execute\s*\(\s*f["\']|execute\s*\(\s*.*format\s*\(',
            re.IGNORECASE,
        ),
        "description": "Possible SQL injection via string formatting in execute()",
        "severity": "HIGH",
    },
    {
        "id": "A03-CMD-INJECT",
        "owasp": "A03:2021 - Injection",
        "pattern": re.compile(
            r'os\.system\s*\(|subprocess\.call\s*\(.*shell\s*=\s*True|eval\s*\(|exec\s*\(',
            re.IGNORECASE,
        ),
        "description": "Possible command injection via shell=True or eval/exec",
        "severity": "CRITICAL",
    },
    # A02:2021 - Cryptographic Failures
    {
        "id": "A02-WEAK-HASH",
        "owasp": "A02:2021 - Cryptographic Failures",
        "pattern": re.compile(r'hashlib\.md5\s*\(|hashlib\.sha1\s*\(', re.IGNORECASE),
        "description": "Weak hash algorithm (MD5 or SHA1) detected",
        "severity": "MEDIUM",
    },
    {
        "id": "A02-HARDCODED-SECRET",
        "owasp": "A02:2021 - Cryptographic Failures",
        "pattern": re.compile(
            r'(password|secret|api_key|token|passwd)\s*=\s*["\'][^"\']{6,}["\']',
            re.IGNORECASE,
        ),
        "description": "Hardcoded secret or password detected",
        "severity": "CRITICAL",
    },
    # A01:2021 - Broken Access Control
    {
        "id": "A01-PATH-TRAVERSAL",
        "owasp": "A01:2021 - Broken Access Control",
        "pattern": re.compile(r'open\s*\(.*\.\./|os\.path\.join\s*\(.*request', re.IGNORECASE),
        "description": "Possible path traversal vulnerability",
        "severity": "HIGH",
    },
    # A08:2021 - Software and Data Integrity Failures
    {
        "id": "A08-UNSAFE-DESERIALIZE",
        "owasp": "A08:2021 - Software and Data Integrity Failures",
        "pattern": re.compile(r'pickle\.loads\s*\(|pickle\.load\s*\(|yaml\.load\s*\((?!.*Loader)',
                               re.IGNORECASE),
        "description": "Unsafe deserialization (pickle or yaml.load without SafeLoader)",
        "severity": "HIGH",
    },
    # A05:2021 - Security Misconfiguration
    {
        "id": "A05-DEBUG-TRUE",
        "owasp": "A05:2021 - Security Misconfiguration",
        "pattern": re.compile(r'debug\s*=\s*True', re.IGNORECASE),
        "description": "Debug mode enabled — should not be in production code",
        "severity": "MEDIUM",
    },
    # A10:2021 - SSRF
    {
        "id": "A10-SSRF",
        "owasp": "A10:2021 - Server-Side Request Forgery",
        "pattern": re.compile(
            r'requests\.get\s*\(\s*.*request\.|httpx\.get\s*\(\s*.*request\.',
            re.IGNORECASE,
        ),
        "description": "Possible SSRF — URL constructed from user input",
        "severity": "HIGH",
    },
]


class OWASPSecurityCheckerTool(BaseTool):
    name: str = "owasp_security_checker"
    description: str = (
        "Analyzes code for OWASP Top 10 vulnerability patterns. "
        "Returns a list of detected security issues with severity and OWASP category. "
        "Use this on both the original code (to confirm the vulnerability) "
        "and the patched code (to ensure no new issues are introduced)."
    )
    args_schema: type[BaseModel] = OWASPCheckerInput

    def _run(self, code: str, language: str = "python") -> str:
        findings: list[dict[str, str]] = []

        patterns = PYTHON_PATTERNS  # Extend with JS/Go patterns as needed

        for check in patterns:
            if check["pattern"].search(code):
                findings.append({
                    "id": check["id"],
                    "owasp": check["owasp"],
                    "severity": check["severity"],
                    "description": check["description"],
                })

        if not findings:
            return "✅ No OWASP Top 10 patterns detected in this code snippet."

        lines = [f"⚠️ {len(findings)} OWASP issue(s) detected:\n"]
        for f in findings:
            lines.append(
                f"  [{f['severity']}] {f['id']} — {f['owasp']}\n"
                f"    → {f['description']}\n"
            )
        return "\n".join(lines)

    async def _arun(self, **kwargs: Any) -> str:
        return self._run(**kwargs)


def check_owasp(code: str, language: str = "python") -> list[dict[str, str]]:
    """Standalone utility for checking OWASP patterns — returns structured list."""
    findings = []
    patterns = PYTHON_PATTERNS
    for check in patterns:
        if check["pattern"].search(code):
            findings.append({
                "id": check["id"],
                "owasp": check["owasp"],
                "severity": check["severity"],
                "description": check["description"],
            })
    return findings
