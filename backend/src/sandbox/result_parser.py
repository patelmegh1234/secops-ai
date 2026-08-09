"""
Parse pytest output from sandbox container logs.
Handles both verbose and quiet (-q) pytest output formats.
Detects exit code 5 (no tests collected) and extracts failure traces
for the sandbox-trace feedback loop in tasks.py.
"""

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


# ── Sandbox execution mode ────────────────────────────────────────────────────
class SandboxMode(str, Enum):
    """Describes the actual test-execution mode detected inside the sandbox."""
    PYTEST_PASSED = "pytest_passed"    # All tests passed (exit code 0)
    PYTEST_FAILED = "pytest_failed"    # One or more tests failed (exit code 1)
    NO_TESTS      = "no_tests"         # pytest exit code 5 — no tests collected
    STATIC_ONLY   = "static_only"      # Fallback: py_compile + bandit only
    TIMED_OUT     = "timed_out"        # Container killed on timeout
    SETUP_ERROR   = "setup_error"      # pip install failed / import error before tests
    ERROR         = "error"            # Unexpected sandbox controller error


# ── Failure trace (fed back to patch agent on retry) ─────────────────────────
@dataclass
class SandboxFailureTrace:
    """
    Structured failure information extracted from a failing sandbox run.
    Passed as `repatch_context` to run_security_crew() so the patch agent
    can see exactly what broke and attempt a corrected patch.
    """
    mode: SandboxMode
    exit_code: int
    failed_test_names: list[str] = field(default_factory=list)
    error_messages: list[str] = field(default_factory=list)
    # Tail of stderr / stdout — capped at 2KB to fit comfortably in LLM context
    stderr_tail: str = ""
    stdout_tail: str = ""
    timed_out: bool = False

    def as_prompt_context(self) -> str:
        """
        Format the failure trace as a compact, LLM-readable summary.
        Injected into the patch agent system prompt on repatch attempts.
        """
        parts: list[str] = []

        if self.timed_out:
            parts.append("The previous patch caused the test container to time out (SIGKILL).")
        elif self.mode == SandboxMode.PYTEST_FAILED:
            if self.failed_test_names:
                names = ", ".join(self.failed_test_names[:5])
                parts.append(f"The following tests FAILED: {names}")
            if self.error_messages:
                errors = "\n".join(self.error_messages[:3])
                parts.append(f"Failure output:\n{errors}")
        elif self.mode == SandboxMode.SETUP_ERROR:
            parts.append(
                "The patch caused an import/setup error before any tests ran. "
                "Check for broken imports or missing dependencies."
            )
            if self.stderr_tail:
                parts.append(f"Setup stderr:\n{self.stderr_tail}")
        elif self.mode == SandboxMode.NO_TESTS:
            parts.append(
                "No tests were collected (pytest exit code 5). "
                "This may mean the patch broke the test discovery or test file structure."
            )

        if self.stdout_tail and self.mode != SandboxMode.NO_TESTS:
            parts.append(f"Full output tail:\n{self.stdout_tail}")

        return "\n\n".join(parts) if parts else "Sandbox failed with no actionable output."


# ── Pytest output parser ──────────────────────────────────────────────────────
def parse_pytest_output(output: str) -> dict[str, int]:
    """
    Extract test pass/fail/error counts from pytest output.

    Handles formats like:
      - "5 passed, 2 failed, 1 error in 3.24s"
      - "5 passed in 1.23s"
      - "FAILED test_foo.py::test_bar - AssertionError"
      - "ERROR test_baz.py::test_qux"

    Returns:
        dict with keys: passed, failed, errored
    """
    if not output:
        return {"passed": 0, "failed": 0, "errored": 0}

    lines = output.splitlines()
    passed = 0
    failed = 0
    errored = 0

    # Look for the summary line (last few lines are most reliable)
    for line in reversed(lines[-10:]):
        if "passed" in line.lower() or "failed" in line.lower() or "error" in line.lower():
            p = re.search(r"(\d+)\s+passed", line, re.IGNORECASE)
            f = re.search(r"(\d+)\s+failed", line, re.IGNORECASE)
            e = re.search(r"(\d+)\s+error", line, re.IGNORECASE)

            if p:
                passed = int(p.group(1))
            if f:
                failed = int(f.group(1))
            if e:
                errored = int(e.group(1))

            if passed or failed or errored:
                break

    # Fallback: count PASSED/FAILED/ERROR markers
    if passed == 0 and failed == 0 and errored == 0:
        passed = len(re.findall(r"^PASSED", output, re.MULTILINE))
        failed = len(re.findall(r"^FAILED", output, re.MULTILINE))
        errored = len(re.findall(r"^ERROR", output, re.MULTILINE))

    return {
        "passed": passed,
        "failed": failed,
        "errored": errored,
    }


def extract_failed_test_names(output: str) -> list[str]:
    """Extract individual failing test node IDs from pytest output."""
    # Matches lines like: "FAILED tests/test_foo.py::test_bar - AssertionError"
    pattern = re.compile(r"^FAILED\s+(\S+)", re.MULTILINE)
    return pattern.findall(output)


def extract_error_messages(output: str) -> list[str]:
    """Extract short assertion / error messages from pytest output."""
    messages: list[str] = []
    # Match lines after "E " prefix (pytest error detail lines)
    error_lines = re.findall(r"^\s+E\s+(.+)$", output, re.MULTILINE)
    # Deduplicate and cap
    seen: set[str] = set()
    for line in error_lines[:20]:
        stripped = line.strip()
        if stripped and stripped not in seen:
            messages.append(stripped)
            seen.add(stripped)
            if len(messages) >= 5:
                break
    return messages


def detect_setup_error(output: str, exit_code: int) -> bool:
    """
    Detect if pip install or module import failed before tests ran.
    This is different from a test failure — it means the repo itself
    could not be set up, not that the patch broke a test.
    """
    if exit_code not in (1, 2, 3, 4):
        return False
    setup_error_signals = [
        "ModuleNotFoundError",
        "ImportError",
        "ERROR: Could not find a version",
        "ERROR: pip's dependency resolver",
        "No module named",
        "SyntaxError",
    ]
    return any(signal in output for signal in setup_error_signals)


def build_failure_trace(
    stdout: str,
    stderr: str,
    exit_code: int,
    timed_out: bool,
) -> SandboxFailureTrace:
    """
    Build a SandboxFailureTrace from raw sandbox output.
    Called in controller.py after every non-passing run.

    The trace is passed to run_security_crew() as repatch_context
    on the second sandbox attempt.
    """
    combined = stdout + "\n" + stderr

    if timed_out:
        return SandboxFailureTrace(
            mode=SandboxMode.TIMED_OUT,
            exit_code=exit_code,
            timed_out=True,
            stderr_tail=stderr[-1500:],
            stdout_tail=stdout[-500:],
        )

    if exit_code == 5:
        # pytest exit code 5 = no tests collected
        return SandboxFailureTrace(
            mode=SandboxMode.NO_TESTS,
            exit_code=5,
            stderr_tail=stderr[-1500:],
            stdout_tail=stdout[-500:],
        )

    if detect_setup_error(combined, exit_code):
        return SandboxFailureTrace(
            mode=SandboxMode.SETUP_ERROR,
            exit_code=exit_code,
            stderr_tail=stderr[-1500:],
            stdout_tail=stdout[-500:],
        )

    # Standard pytest failure
    return SandboxFailureTrace(
        mode=SandboxMode.PYTEST_FAILED,
        exit_code=exit_code,
        failed_test_names=extract_failed_test_names(stdout),
        error_messages=extract_error_messages(stdout),
        stderr_tail=stderr[-1500:],
        stdout_tail=stdout[-1000:],
    )


# ── Human-readable summary ────────────────────────────────────────────────────
def format_sandbox_summary(
    passed: int,
    failed: int,
    errored: int,
    duration_ms: int,
    timed_out: bool,
    mode: SandboxMode = SandboxMode.PYTEST_PASSED,
) -> str:
    """Format a human-readable sandbox execution summary for Slack cards."""
    if timed_out:
        return f"⏱️ TIMEOUT — Container killed after {duration_ms // 1000}s. No results."

    if mode == SandboxMode.NO_TESTS:
        return (
            "⚠️ NO TESTS DETECTED — pytest found no tests (exit code 5). "
            "Static syntax check used as fallback. Human review confidence is LOWER."
        )

    if mode == SandboxMode.STATIC_ONLY:
        return "🔍 STATIC CHECK ONLY — No test suite available. py_compile + bandit passed."

    if mode == SandboxMode.SETUP_ERROR:
        return "❌ SETUP ERROR — pip install or module import failed before tests ran."

    total = passed + failed + errored
    if total == 0:
        return "⚠️ No tests found or pytest could not run."

    status = "✅ PASSED" if failed == 0 and errored == 0 else "❌ FAILED"
    return (
        f"{status} — "
        f"{passed}/{total} tests passed "
        f"({failed} failed, {errored} errored) "
        f"in {duration_ms / 1000:.1f}s"
    )
