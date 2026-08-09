"""
Secret Scanner — Phase 2.6
Scans AI-generated patch code for hardcoded secrets before it reaches the
guardrail agent or the sandbox. If secrets are detected, the patch is
immediately rejected without calling any LLM.

Why this matters:
  The patch agent may inadvertently copy secret-looking values from the
  original vulnerable code (e.g., a hardcoded API key that *is* the
  vulnerability). If those values survive into the patched_code and then
  into the DB / Slack message, they become a secondary secret leak.

Detection strategy:
  1. Regex patterns for common high-confidence secret formats
     (AWS keys, GitHub tokens, Stripe keys, private key PEM headers, etc.)
  2. Entropy check for long high-entropy strings (catches generic tokens)

False positive philosophy:
  We err on the side of caution. A false positive costs one manual review.
  A false negative leaks a secret into Slack and GitHub.
"""

import math
import re
from dataclasses import dataclass, field


# ── High-confidence regex patterns ────────────────────────────────────────────
# Each pattern is a (name, compiled_regex) pair.
# Patterns are ordered from highest to lowest confidence.
_SECRET_PATTERNS: list[tuple[str, re.Pattern]] = [
    # AWS
    ("AWS Access Key ID",    re.compile(r"(?<![A-Z0-9])(AKIA|ASIA|AROA)[A-Z0-9]{16}(?![A-Z0-9])")),
    ("AWS Secret Key",       re.compile(r"(?i)aws.{0,20}secret.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]")),

    # GitHub / GitLab
    ("GitHub Personal Token",     re.compile(r"ghp_[A-Za-z0-9]{36}")),
    ("GitHub OAuth Token",        re.compile(r"gho_[A-Za-z0-9]{36}")),
    ("GitHub Actions Token",      re.compile(r"ghs_[A-Za-z0-9]{36}")),
    ("GitHub Refresh Token",      re.compile(r"ghr_[A-Za-z0-9]{36}")),
    ("GitLab Personal Token",     re.compile(r"glpat-[A-Za-z0-9\-_]{20}")),

    # Stripe
    ("Stripe Live Secret Key",  re.compile(r"sk_live_[A-Za-z0-9]{24,}")),
    ("Stripe Test Secret Key",  re.compile(r"sk_test_[A-Za-z0-9]{24,}")),

    # Slack
    ("Slack Bot Token",       re.compile(r"xoxb-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24}")),
    ("Slack User Token",      re.compile(r"xoxp-[0-9]{10,13}-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{32}")),
    ("Slack Webhook URL",     re.compile(r"https://hooks\.slack\.com/services/T[A-Za-z0-9_]{8}/B[A-Za-z0-9_]{8}/[A-Za-z0-9_]{24}")),

    # OpenAI
    ("OpenAI API Key",        re.compile(r"sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}")),
    ("OpenAI Project Key",    re.compile(r"sk-proj-[A-Za-z0-9\-_]{40,}")),

    # Private keys (PEM)
    ("Private Key PEM",       re.compile(r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----")),
    ("Private Key (PKCS8)",   re.compile(r"-----BEGIN ENCRYPTED PRIVATE KEY-----")),

    # Generic password assignments — lower confidence, only triggers on long values
    ("Hardcoded Password",    re.compile(
        r"""(?i)(password|passwd|pwd|secret|token|api[_-]?key)\s*=\s*['"]((?!\{)[^'"]{12,})['"]\s*$""",
        re.MULTILINE,
    )),
]

# ── Entropy threshold ──────────────────────────────────────────────────────────
# Shannon entropy >= this on a string of >= MIN_ENTROPY_LENGTH chars
# is flagged as a potential high-entropy secret.
_ENTROPY_THRESHOLD = 4.5
_MIN_ENTROPY_LENGTH = 20
_MAX_ENTROPY_LENGTH = 120   # Avoid false-positives on long prose strings

# Characters commonly found in secrets but not in English prose
_HIGH_ENTROPY_CHARS = re.compile(r"[A-Za-z0-9+/=_\-]{%d,%d}" % (_MIN_ENTROPY_LENGTH, _MAX_ENTROPY_LENGTH))


def _shannon_entropy(s: str) -> float:
    """Compute Shannon entropy (bits per character) of a string."""
    if not s:
        return 0.0
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(s)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


@dataclass
class SecretMatch:
    """A single detected secret in the patched code."""
    pattern_name: str
    matched_value: str         # Truncated for safety — never log the full value
    line_number: int


@dataclass
class SecretScanResult:
    """Result of scanning patched code for hardcoded secrets."""
    clean: bool                            # True if no secrets found
    matches: list[SecretMatch] = field(default_factory=list)
    error: str | None = None

    def rejection_message(self) -> str:
        """Format a human-readable rejection reason for Slack / logs."""
        if self.clean:
            return ""
        descriptions = []
        for m in self.matches[:3]:   # Cap at 3 to avoid bloating Slack messages
            descriptions.append(
                f"  • Line {m.line_number}: {m.pattern_name} detected"
            )
        return (
            "Patch rejected: hardcoded secrets detected in patched code.\n"
            + "\n".join(descriptions)
            + "\n\nThe patch agent must remove or replace hardcoded credentials "
            "with environment variables or secrets manager references."
        )


def scan_for_secrets(patched_code: str) -> SecretScanResult:
    """
    Scan patched_code for hardcoded secrets.

    Args:
        patched_code: The complete patched file content generated by the patch agent.

    Returns:
        SecretScanResult with clean=True if no secrets found.

    Called by guardrail_agent.run_guardrail_agent() as the second pre-check
    (after validate_patch_scope, before LLM invocation).
    """
    if not patched_code or not patched_code.strip():
        return SecretScanResult(clean=True)

    matches: list[SecretMatch] = []
    lines = patched_code.splitlines()

    # ── Phase 1: Regex pattern scan ───────────────────────────────────────
    for line_no, line in enumerate(lines, start=1):
        # Skip comment lines — they often contain example values in documentation
        stripped = line.strip()
        if stripped.startswith(("#", "//", "*", "<!--", '"')):
            continue

        for pattern_name, pattern in _SECRET_PATTERNS:
            match = pattern.search(line)
            if match:
                raw_value = match.group(0)
                # Truncate matched value for safe logging (never store full secret)
                safe_preview = raw_value[:6] + "..." if len(raw_value) > 6 else "***"
                matches.append(SecretMatch(
                    pattern_name=pattern_name,
                    matched_value=safe_preview,
                    line_number=line_no,
                ))
                break  # One match per line is enough

    # ── Phase 2: Entropy scan (catches generic tokens) ─────────────────────
    for line_no, line in enumerate(lines, start=1):
        stripped = line.strip()
        if stripped.startswith(("#", "//", "*", "<!--")):
            continue

        for candidate in _HIGH_ENTROPY_CHARS.findall(line):
            entropy = _shannon_entropy(candidate)
            if entropy >= _ENTROPY_THRESHOLD:
                # Avoid duplicate matches on same line
                if not any(m.line_number == line_no for m in matches):
                    matches.append(SecretMatch(
                        pattern_name="High-entropy string",
                        matched_value=candidate[:6] + "...",
                        line_number=line_no,
                    ))
                break  # One entropy match per line

    return SecretScanResult(
        clean=len(matches) == 0,
        matches=matches,
    )
