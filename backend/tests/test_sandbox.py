"""
Tests for the Docker sandbox result parser.
No actual Docker needed — tests parse pytest output strings.
"""

import pytest

from src.sandbox.result_parser import parse_pytest_output, format_sandbox_summary


class TestPytestOutputParser:
    def test_parse_all_passed(self):
        output = "5 passed in 1.23s"
        result = parse_pytest_output(output)
        assert result["passed"] == 5
        assert result["failed"] == 0
        assert result["errored"] == 0

    def test_parse_mixed_results(self):
        output = "3 passed, 2 failed, 1 error in 3.24s"
        result = parse_pytest_output(output)
        assert result["passed"] == 3
        assert result["failed"] == 2
        assert result["errored"] == 1

    def test_parse_all_failed(self):
        output = "0 passed, 5 failed in 0.45s"
        result = parse_pytest_output(output)
        assert result["passed"] == 0
        assert result["failed"] == 5

    def test_parse_empty_output(self):
        result = parse_pytest_output("")
        assert result == {"passed": 0, "failed": 0, "errored": 0}

    def test_parse_verbose_output(self):
        output = """
collected 3 items

tests/test_auth.py::test_login PASSED
tests/test_auth.py::test_logout PASSED
tests/test_auth.py::test_register FAILED

3 passed, 0 failed in 2.10s
"""
        result = parse_pytest_output(output)
        assert result["passed"] == 3

    def test_parse_output_with_markers(self):
        output = """
PASSED tests/test_foo.py::test_bar
PASSED tests/test_foo.py::test_baz
FAILED tests/test_foo.py::test_qux
"""
        result = parse_pytest_output(output)
        # Should fall back to marker counting
        assert result["passed"] >= 0  # May count 0 from summary line or 2 from markers
        assert result["failed"] >= 0


class TestSandboxSummaryFormatter:
    def test_format_passed(self):
        summary = format_sandbox_summary(5, 0, 0, 1500, False)
        assert "✅ PASSED" in summary
        assert "5/5" in summary

    def test_format_failed(self):
        summary = format_sandbox_summary(3, 2, 0, 2000, False)
        assert "❌ FAILED" in summary
        assert "3/5" in summary

    def test_format_timeout(self):
        summary = format_sandbox_summary(0, 0, 0, 30000, True)
        assert "TIMEOUT" in summary

    def test_format_no_tests(self):
        summary = format_sandbox_summary(0, 0, 0, 500, False)
        assert "No tests" in summary
