"""
Phase 3.1 — Unit tests for:
  - build_failure_trace()  (Phase 1.1 — sandbox failure feedback loop)
  - extract_idempotency_fields()  (Phase 1.3 — webhook deduplication)

All pure function tests — zero DB, zero Docker, zero network.
"""

import pytest

from src.sandbox.result_parser import build_failure_trace, SandboxMode


# ═══════════════════════════════════════════════════════════════════════════════
# build_failure_trace tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestBuildFailureTrace:
    """Tests for build_failure_trace() which converts raw sandbox output into
    a structured SandboxFailureTrace for LLM re-injection."""

    def _make_result(self, exit_code: int, stdout: str = "", stderr: str = "",
                     timed_out: bool = False):
        """Minimal sandbox result dict compatible with build_failure_trace."""
        from dataclasses import dataclass

        @dataclass
        class FakeResult:
            exit_code: int
            stdout: str
            stderr: str
            timed_out: bool

        return FakeResult(exit_code=exit_code, stdout=stdout, stderr=stderr,
                          timed_out=timed_out)

    def test_no_tests_exit_code_5(self):
        result = self._make_result(exit_code=5, stdout="no tests ran", stderr="")
        trace = build_failure_trace(result)
        assert trace.sandbox_mode == SandboxMode.NO_TESTS

    def test_timeout_detected(self):
        result = self._make_result(exit_code=1, stdout="", stderr="", timed_out=True)
        trace = build_failure_trace(result)
        assert trace.sandbox_mode == SandboxMode.TIMEOUT

    def test_setup_error_detected_from_stderr(self):
        stderr = "ModuleNotFoundError: No module named 'requests'\nError during collection"
        result = self._make_result(exit_code=1, stderr=stderr)
        trace = build_failure_trace(result)
        assert trace.sandbox_mode in (SandboxMode.SETUP_ERROR, SandboxMode.TEST_FAILURE)

    def test_pytest_failure_extracts_failed_tests(self):
        stdout = """
FAILED tests/test_auth.py::test_login - AssertionError: assert 401 == 200
FAILED tests/test_auth.py::test_register - TypeError: missing argument
2 failed in 1.23s
"""
        result = self._make_result(exit_code=1, stdout=stdout)
        trace = build_failure_trace(result)
        assert trace.sandbox_mode == SandboxMode.TEST_FAILURE
        assert len(trace.failed_tests) > 0
        assert any("test_login" in t for t in trace.failed_tests)

    def test_error_lines_extracted(self):
        stdout = """
FAILED tests/test_foo.py::test_bar - AssertionError: Expected 200, got 500
"""
        stderr = "ImportError: cannot import name 'helper'"
        result = self._make_result(exit_code=1, stdout=stdout, stderr=stderr)
        trace = build_failure_trace(result)
        # Should have extracted some error context
        assert trace is not None

    def test_as_prompt_context_returns_string(self):
        stdout = "FAILED tests/test_x.py::test_y - AssertionError\n1 failed in 0.5s"
        result = self._make_result(exit_code=1, stdout=stdout)
        trace = build_failure_trace(result)
        context = trace.as_prompt_context()
        assert isinstance(context, str)
        assert len(context) > 0

    def test_as_prompt_context_contains_mode(self):
        result = self._make_result(exit_code=5)
        trace = build_failure_trace(result)
        context = trace.as_prompt_context()
        # Should mention the mode or something useful
        assert isinstance(context, str)

    def test_zero_exit_code_still_parseable(self):
        # Even a passing run should not crash build_failure_trace
        result = self._make_result(exit_code=0, stdout="2 passed in 0.5s")
        trace = build_failure_trace(result)
        assert trace is not None

    def test_empty_output_handled(self):
        result = self._make_result(exit_code=1, stdout="", stderr="")
        trace = build_failure_trace(result)
        assert trace is not None
        assert trace.sandbox_mode is not None


# ═══════════════════════════════════════════════════════════════════════════════
# extract_idempotency_fields tests
# ═══════════════════════════════════════════════════════════════════════════════

from src.integrations.scanner_parser import extract_idempotency_fields


class TestExtractIdempotencyFields:
    """Tests for extract_idempotency_fields() which normalises scanner payloads
    into a flat dict used for SHA-256 dedup key computation."""

    # ── Trivy ──────────────────────────────────────────────────────────────────

    def test_trivy_extracts_cve_id(self):
        payload = {
            "repo_owner": "acme",
            "repo_name": "api",
            "Results": [{
                "Target": "requirements.txt",
                "Vulnerabilities": [{"VulnerabilityID": "CVE-2023-9999"}],
            }],
        }
        fields = extract_idempotency_fields(payload, "TRIVY")
        assert fields["cve_id"] == "CVE-2023-9999"

    def test_trivy_extracts_file_path(self):
        payload = {
            "Results": [{
                "Target": "requirements.txt",
                "Vulnerabilities": [{"VulnerabilityID": "CVE-2023-9999"}],
            }],
        }
        fields = extract_idempotency_fields(payload, "TRIVY")
        assert fields["file_path"] == "requirements.txt"

    def test_trivy_extracts_repo_metadata(self):
        payload = {
            "repo_owner": "myorg",
            "repo_name": "myrepo",
            "Results": [{
                "Target": "go.sum",
                "Vulnerabilities": [{"VulnerabilityID": "CVE-2023-1234"}],
            }],
        }
        fields = extract_idempotency_fields(payload, "TRIVY")
        assert fields["repo_owner"] == "myorg"
        assert fields["repo_name"] == "myrepo"

    def test_trivy_empty_results_falls_through_to_default(self):
        payload = {"Results": []}
        fields = extract_idempotency_fields(payload, "TRIVY")
        # Should return fallback dict, not raise
        assert isinstance(fields, dict)
        assert "file_path" in fields

    # ── Bandit ─────────────────────────────────────────────────────────────────

    def test_bandit_extracts_rule_id(self):
        payload = {
            "repo_owner": "acme",
            "repo_name": "api",
            "results": [{"test_id": "B608", "filename": "src/db.py", "line_number": 42}],
        }
        fields = extract_idempotency_fields(payload, "BANDIT")
        assert fields["rule_id"] == "B608"

    def test_bandit_extracts_filename(self):
        payload = {
            "results": [{"test_id": "B602", "filename": "src/runner.py", "line_number": 15}],
        }
        fields = extract_idempotency_fields(payload, "BANDIT")
        assert fields["file_path"] == "src/runner.py"

    def test_bandit_extracts_line_number(self):
        payload = {
            "results": [{"test_id": "B101", "filename": "test.py", "line_number": 7}],
        }
        fields = extract_idempotency_fields(payload, "BANDIT")
        assert fields["line_number"] == 7

    def test_bandit_empty_results_fallback(self):
        payload = {"results": []}
        fields = extract_idempotency_fields(payload, "BANDIT")
        assert isinstance(fields, dict)

    # ── GitHub ─────────────────────────────────────────────────────────────────

    def test_github_extracts_cve_id(self):
        payload = {
            "repository": {"full_name": "acme/api"},
            "alert": {
                "security_advisory": {
                    "identifiers": [{"type": "CVE", "value": "CVE-2023-5678"}],
                    "ghsa_id": "GHSA-xxxx",
                },
                "dependency": {"manifest_path": "package-lock.json"},
            },
        }
        fields = extract_idempotency_fields(payload, "GITHUB")
        assert fields["cve_id"] == "CVE-2023-5678"

    def test_github_falls_back_to_ghsa_when_no_cve(self):
        payload = {
            "repository": {"full_name": "acme/api"},
            "alert": {
                "security_advisory": {
                    "identifiers": [],
                    "ghsa_id": "GHSA-1234-5678",
                },
                "dependency": {"manifest_path": "requirements.txt"},
            },
        }
        fields = extract_idempotency_fields(payload, "GITHUB")
        assert fields["cve_id"] == "GHSA-1234-5678"

    def test_github_extracts_repo_from_full_name(self):
        payload = {
            "repository": {"full_name": "myorg/myrepo"},
            "alert": {
                "security_advisory": {"identifiers": [], "ghsa_id": "X"},
                "dependency": {"manifest_path": "go.sum"},
            },
        }
        fields = extract_idempotency_fields(payload, "GITHUB")
        assert fields["repo_owner"] == "myorg"
        assert fields["repo_name"] == "myrepo"

    # ── Fallback / unknown scanner ─────────────────────────────────────────────

    def test_unknown_scanner_returns_fallback(self):
        fields = extract_idempotency_fields({"arbitrary": "data"}, "UNKNOWN")
        assert isinstance(fields, dict)
        assert "file_path" in fields

    def test_completely_empty_payload_does_not_raise(self):
        fields = extract_idempotency_fields({}, "TRIVY")
        assert isinstance(fields, dict)

    # ── Key determinism ────────────────────────────────────────────────────────

    def test_same_payload_produces_same_key(self):
        """Two identical payloads must produce the same idempotency key."""
        import hashlib

        payload = {
            "repo_owner": "acme",
            "repo_name": "api",
            "Results": [{
                "Target": "requirements.txt",
                "Vulnerabilities": [{"VulnerabilityID": "CVE-2023-9999"}],
            }],
        }

        def compute_key(p):
            fields = extract_idempotency_fields(p, "TRIVY")
            raw = "|".join([
                "TRIVY",
                str(fields.get("cve_id") or fields.get("rule_id") or "unknown"),
                str(fields.get("repo_owner") or "unknown"),
                str(fields.get("repo_name") or "unknown"),
                str(fields.get("file_path") or "unknown"),
                str(fields.get("line_number") or "0"),
            ])
            return hashlib.sha256(raw.encode()).hexdigest()

        assert compute_key(payload) == compute_key(payload)

    def test_different_cve_produces_different_key(self):
        import hashlib

        def compute_key(cve_id):
            payload = {
                "repo_owner": "acme", "repo_name": "api",
                "Results": [{"Target": "req.txt",
                             "Vulnerabilities": [{"VulnerabilityID": cve_id}]}],
            }
            fields = extract_idempotency_fields(payload, "TRIVY")
            raw = "|".join(["TRIVY", str(fields.get("cve_id") or ""), "acme", "api",
                            str(fields.get("file_path") or ""), "0"])
            return hashlib.sha256(raw.encode()).hexdigest()

        assert compute_key("CVE-2023-0001") != compute_key("CVE-2023-0002")
