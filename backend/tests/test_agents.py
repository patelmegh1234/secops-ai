"""
Tests for the scanner payload parser.
Verifies normalization of Trivy and Bandit JSON into VulnerabilityCreate schemas.
"""

import json
from pathlib import Path

import pytest

from src.integrations.scanner_parser import (
    parse_bandit_payload,
    parse_trivy_payload,
    parse_scanner_payload,
)
from src.database.models import Severity, ScannerType


FIXTURES = Path("tests/fixtures")


@pytest.fixture
def trivy_payload():
    return json.loads((FIXTURES / "trivy_payload.json").read_text())


@pytest.fixture
def bandit_payload():
    return json.loads((FIXTURES / "bandit_payload.json").read_text())


class TestTrivyParser:
    def test_parses_vulnerabilities(self, trivy_payload):
        alerts = parse_trivy_payload(trivy_payload)
        assert len(alerts) == 2

    def test_cve_id_extracted(self, trivy_payload):
        alerts = parse_trivy_payload(trivy_payload)
        cve_ids = [a.cve_id for a in alerts]
        assert "CVE-2023-32681" in cve_ids

    def test_severity_normalized(self, trivy_payload):
        alerts = parse_trivy_payload(trivy_payload)
        severities = {a.severity for a in alerts}
        assert Severity.MEDIUM in severities
        assert Severity.HIGH in severities

    def test_scanner_type_is_trivy(self, trivy_payload):
        alerts = parse_trivy_payload(trivy_payload)
        assert all(a.scanner == ScannerType.TRIVY for a in alerts)

    def test_repo_metadata_extracted(self, trivy_payload):
        alerts = parse_trivy_payload(trivy_payload)
        assert all(a.repo_owner == "test-org" for a in alerts)
        assert all(a.repo_name == "vulnerable-app" for a in alerts)


class TestBanditParser:
    def test_parses_vulnerabilities(self, bandit_payload):
        alerts = parse_bandit_payload(bandit_payload)
        assert len(alerts) == 2

    def test_test_id_set_as_cve_id(self, bandit_payload):
        alerts = parse_bandit_payload(bandit_payload)
        test_ids = [a.cve_id for a in alerts]
        assert "B602" in test_ids

    def test_severity_normalized(self, bandit_payload):
        alerts = parse_bandit_payload(bandit_payload)
        severities = {a.severity for a in alerts}
        assert Severity.HIGH in severities
        assert Severity.MEDIUM in severities

    def test_file_path_extracted(self, bandit_payload):
        alerts = parse_bandit_payload(bandit_payload)
        file_paths = [a.file_path for a in alerts]
        assert "src/utils/runner.py" in file_paths

    def test_line_number_extracted(self, bandit_payload):
        alerts = parse_bandit_payload(bandit_payload)
        b602_alert = next(a for a in alerts if a.cve_id == "B602")
        assert b602_alert.line_start == 15

    def test_cwe_mapped_correctly(self, bandit_payload):
        alerts = parse_bandit_payload(bandit_payload)
        b602_alert = next(a for a in alerts if a.cve_id == "B602")
        assert b602_alert.cwe_id == "CWE-78"


class TestUnifiedDispatcher:
    def test_dispatches_trivy(self, trivy_payload):
        alerts = parse_scanner_payload(trivy_payload, "TRIVY")
        assert len(alerts) > 0

    def test_dispatches_bandit(self, bandit_payload):
        alerts = parse_scanner_payload(bandit_payload, "BANDIT")
        assert len(alerts) > 0

    def test_unknown_scanner_returns_empty(self):
        alerts = parse_scanner_payload({}, "UNKNOWN_SCANNER")
        assert alerts == []

    def test_malformed_payload_returns_empty(self):
        alerts = parse_scanner_payload(None, "TRIVY")  # type: ignore
        assert alerts == []
