"""
Parse pytest output from sandbox container logs.
Handles both verbose and quiet (-q) pytest output formats.
"""

import re
from typing import Any


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

    # Try the summary line first (most reliable)
    # Patterns: "5 passed", "2 failed", "1 error"
    summary_pattern = re.compile(
        r"(\d+)\s+passed|(\d+)\s+failed|(\d+)\s+error",
        re.IGNORECASE,
    )

    # Try the single-line summary at the end: "5 passed, 2 failed in 3.24s"
    oneline_pattern = re.compile(
        r"(?:(\d+)\s+passed)?[,\s]*(?:(\d+)\s+failed)?[,\s]*(?:(\d+)\s+error(?:s)?)?",
        re.IGNORECASE,
    )

    lines = output.splitlines()
    passed = 0
    failed = 0
    errored = 0

    # Look for the summary line (last few lines are most reliable)
    for line in reversed(lines[-10:]):
        if "passed" in line.lower() or "failed" in line.lower() or "error" in line.lower():
            # Try to extract numbers
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


def format_sandbox_summary(
    passed: int,
    failed: int,
    errored: int,
    duration_ms: int,
    timed_out: bool,
) -> str:
    """Format a human-readable sandbox execution summary."""
    if timed_out:
        return f"⏱️ TIMEOUT — Container killed after {duration_ms // 1000}s. No results."

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
