"""
Scanner payload normalizer.
Converts raw JSON output from Trivy, Bandit, and GitHub Security Alerts
into a unified VulnerabilityCreate schema.
"""

import re
from typing import Any

from src.core.logging import get_logger
from src.database.models import ScannerType, Severity
from src.database.schemas import VulnerabilityCreate

logger = get_logger(__name__)


def extract_idempotency_fields(payload: dict[str, Any], scanner: str) -> dict[str, Any]:
    """
    Extract the minimal identity fields needed to compute a dedup key.

    Each scanner puts the same information in different JSON locations.
    This function normalises them into a flat dict with predictable keys:
      cve_id, rule_id, repo_owner, repo_name, file_path, line_number

    Used by webhooks.py to compute SHA-256 idempotency keys.
    """
    try:
        if scanner == "TRIVY":
            # Trivy JSON: {"Results": [{"Target": "...", "Vulnerabilities": [...]}]}
            results = payload.get("Results", [])
            if results and results[0].get("Vulnerabilities"):
                vuln = results[0]["Vulnerabilities"][0]
                return {
                    "cve_id": vuln.get("VulnerabilityID", ""),
                    "rule_id": None,
                    "repo_owner": payload.get("repo_owner", ""),
                    "repo_name": payload.get("repo_name", ""),
                    "file_path": results[0].get("Target", ""),
                    "line_number": None,
                }
        elif scanner == "BANDIT":
            # Bandit JSON: {"results": [{"test_id": "B608", "filename": "...", "line_number": 42}]}
            results = payload.get("results", [])
            if results:
                issue = results[0]
                return {
                    "cve_id": None,
                    "rule_id": issue.get("test_id", ""),
                    "repo_owner": payload.get("repo_owner", ""),
                    "repo_name": payload.get("repo_name", ""),
                    "file_path": issue.get("filename", ""),
                    "line_number": issue.get("line_number"),
                }
        elif scanner == "GITHUB":
            # GitHub dependabot_alert: {"alert": {"dependency": {...}, "security_advisory": {...}}}
            alert = payload.get("alert", {})
            advisory = alert.get("security_advisory", {})
            identifiers = advisory.get("identifiers", [])
            cve_id = next(
                (i["value"] for i in identifiers if i.get("type") == "CVE"),
                advisory.get("ghsa_id", ""),
            )
            repo = payload.get("repository", {})
            full_name = repo.get("full_name", "/")
            parts = full_name.split("/", 1)
            return {
                "cve_id": cve_id,
                "rule_id": None,
                "repo_owner": parts[0] if len(parts) > 0 else "",
                "repo_name": parts[1] if len(parts) > 1 else "",
                "file_path": alert.get("dependency", {}).get("manifest_path", ""),
                "line_number": None,
            }
    except Exception:
        pass  # Fall through to default
    # Fallback: use a hash of the entire payload to guarantee uniqueness
    return {
        "cve_id": None,
        "rule_id": None,
        "repo_owner": payload.get("repo_owner", ""),
        "repo_name": payload.get("repo_name", ""),
        "file_path": str(hash(str(payload)))[:16],
        "line_number": None,
    }


# ─── OWASP Top 10 keyword mapping ─────────────────────────────────────────────
OWASP_KEYWORDS: dict[str, str] = {
    "sql": "A03:2021 - Injection",
    "injection": "A03:2021 - Injection",
    "xss": "A03:2021 - Injection",
    "command": "A03:2021 - Injection",
    "path traversal": "A01:2021 - Broken Access Control",
    "directory traversal": "A01:2021 - Broken Access Control",
    "auth": "A07:2021 - Identification and Authentication Failures",
    "crypto": "A02:2021 - Cryptographic Failures",
    "md5": "A02:2021 - Cryptographic Failures",
    "sha1": "A02:2021 - Cryptographic Failures",
    "hardcoded": "A02:2021 - Cryptographic Failures",
    "secret": "A02:2021 - Cryptographic Failures",
    "deserialization": "A08:2021 - Software and Data Integrity Failures",
    "xxe": "A05:2021 - Security Misconfiguration",
    "ssrf": "A10:2021 - Server-Side Request Forgery",
    "open redirect": "A01:2021 - Broken Access Control",
}


def _infer_owasp_category(text: str) -> str | None:
    text_lower = text.lower()
    for keyword, category in OWASP_KEYWORDS.items():
        if keyword in text_lower:
            return category
    return None


def _normalize_severity(raw: str) -> Severity:
    mapping = {
        "critical": Severity.CRITICAL,
        "high": Severity.HIGH,
        "medium": Severity.MEDIUM,
        "moderate": Severity.MEDIUM,
        "low": Severity.LOW,
        "informational": Severity.INFO,
        "info": Severity.INFO,
        "note": Severity.INFO,
        "warning": Severity.MEDIUM,
        "error": Severity.HIGH,
    }
    return mapping.get(raw.lower(), Severity.MEDIUM)


# ─── Trivy Parser ─────────────────────────────────────────────────────────────
def parse_trivy_payload(payload: dict[str, Any]) -> list[VulnerabilityCreate]:
    """
    Parse Trivy JSON scan output (filesystem or image scan).
    Trivy structure: { "Results": [ { "Target": "...", "Vulnerabilities": [...] } ] }
    """
    results = payload.get("Results", [])
    if not results and "ArtifactName" in payload:
        # Some Trivy versions wrap differently
        results = payload.get("results", [])

    alerts: list[VulnerabilityCreate] = []

    # Extract repo info from payload metadata
    repo_owner = payload.get("metadata", {}).get("repo_owner", "unknown")
    repo_name = payload.get("metadata", {}).get("repo_name", "unknown")
    repo_branch = payload.get("metadata", {}).get("branch", "main")

    for result in results:
        target = result.get("Target", "")
        vulns = result.get("Vulnerabilities") or []

        for vuln in vulns:
            cve_id = vuln.get("VulnerabilityID", "")
            severity_raw = vuln.get("Severity", "MEDIUM")
            title = vuln.get("Title", vuln.get("PkgName", "Unknown Vulnerability"))
            description = vuln.get("Description", "No description available.")
            pkg_name = vuln.get("PkgName", "")
            installed_version = vuln.get("InstalledVersion", "")
            fixed_version = vuln.get("FixedVersion", "")

            # For dependency CVEs, the "file" is requirements.txt / package.json
            file_path = vuln.get("PrimaryURL", target)
            if not file_path:
                file_path = target

            owasp = _infer_owasp_category(f"{title} {description}")
            cwe_ids = vuln.get("CweIDs", [])
            cwe_id = cwe_ids[0] if cwe_ids else None

            alerts.append(
                VulnerabilityCreate(
                    scanner=ScannerType.TRIVY,
                    cve_id=cve_id or None,
                    severity=_normalize_severity(severity_raw),
                    title=f"{title} in {pkg_name} {installed_version}",
                    description=(
                        f"{description}\n\n"
                        f"Package: {pkg_name} {installed_version} → Fix: {fixed_version or 'N/A'}"
                    ),
                    repo_owner=repo_owner,
                    repo_name=repo_name,
                    repo_branch=repo_branch,
                    file_path=file_path,
                    owasp_category=owasp,
                    cwe_id=cwe_id,
                    raw_payload=vuln,
                )
            )

    logger.info("trivy_payload_parsed", alerts_found=len(alerts))
    return alerts


# ─── Bandit Parser ────────────────────────────────────────────────────────────
def parse_bandit_payload(payload: dict[str, Any]) -> list[VulnerabilityCreate]:
    """
    Parse Bandit SAST JSON output.
    Bandit structure: { "results": [ { "issue_text": "...", "filename": "...", ... } ] }
    """
    results = payload.get("results", [])
    alerts: list[VulnerabilityCreate] = []

    repo_owner = payload.get("metadata", {}).get("repo_owner", "unknown")
    repo_name = payload.get("metadata", {}).get("repo_name", "unknown")
    repo_branch = payload.get("metadata", {}).get("branch", "main")

    # Map Bandit severity: LOW | MEDIUM | HIGH
    # Map Bandit confidence: LOW | MEDIUM | HIGH
    for issue in results:
        severity_raw = issue.get("issue_severity", "MEDIUM")
        confidence = issue.get("issue_confidence", "MEDIUM")

        # Downgrade if confidence is LOW
        if confidence == "LOW" and severity_raw == "HIGH":
            severity_raw = "MEDIUM"

        title = issue.get("issue_text", "Security Issue Detected")
        test_id = issue.get("test_id", "")
        test_name = issue.get("test_name", "")
        file_path = issue.get("filename", "")
        line_number = issue.get("line_number")
        col_offset = issue.get("col_offset")
        more_info = issue.get("more_info", "")

        owasp = _infer_owasp_category(f"{title} {test_name}")
        cwe_id = _extract_cwe_from_bandit(test_id)

        alerts.append(
            VulnerabilityCreate(
                scanner=ScannerType.BANDIT,
                cve_id=test_id or None,
                severity=_normalize_severity(severity_raw),
                title=f"[{test_id}] {test_name or title[:100]}",
                description=(
                    f"{title}\n\n"
                    f"Test: {test_id} — {test_name}\n"
                    f"Confidence: {confidence}\n"
                    f"More info: {more_info}"
                ),
                repo_owner=repo_owner,
                repo_name=repo_name,
                repo_branch=repo_branch,
                file_path=file_path,
                line_start=line_number,
                line_end=line_number,
                owasp_category=owasp,
                cwe_id=cwe_id,
                raw_payload=issue,
            )
        )

    logger.info("bandit_payload_parsed", alerts_found=len(alerts))
    return alerts


def _extract_cwe_from_bandit(test_id: str) -> str | None:
    """Map common Bandit test IDs to CWE IDs."""
    mapping = {
        "B101": "CWE-703",
        "B102": "CWE-78",
        "B103": "CWE-732",
        "B104": "CWE-605",
        "B105": "CWE-259",
        "B106": "CWE-259",
        "B107": "CWE-259",
        "B108": "CWE-377",
        "B110": "CWE-391",
        "B112": "CWE-391",
        "B201": "CWE-94",
        "B301": "CWE-502",
        "B303": "CWE-327",
        "B304": "CWE-327",
        "B305": "CWE-327",
        "B306": "CWE-377",
        "B307": "CWE-78",
        "B310": "CWE-601",
        "B311": "CWE-330",
        "B312": "CWE-605",
        "B313": "CWE-611",
        "B320": "CWE-611",
        "B321": "CWE-319",
        "B322": "CWE-134",
        "B323": "CWE-295",
        "B324": "CWE-327",
        "B401": "CWE-319",
        "B411": "CWE-319",
        "B501": "CWE-295",
        "B502": "CWE-326",
        "B503": "CWE-295",
        "B504": "CWE-295",
        "B505": "CWE-326",
        "B506": "CWE-20",
        "B601": "CWE-78",
        "B602": "CWE-78",
        "B603": "CWE-78",
        "B604": "CWE-78",
        "B605": "CWE-78",
        "B606": "CWE-78",
        "B607": "CWE-78",
        "B608": "CWE-89",
        "B609": "CWE-78",
        "B610": "CWE-89",
        "B611": "CWE-89",
        "B612": "CWE-319",
        "B701": "CWE-94",
        "B702": "CWE-79",
        "B703": "CWE-79",
    }
    return mapping.get(test_id.upper())


# ─── GitHub Security Alert Parser ─────────────────────────────────────────────
def parse_github_security_payload(payload: dict[str, Any]) -> list[VulnerabilityCreate]:
    """
    Parse GitHub code scanning / Dependabot alert webhook payloads.
    """
    alerts: list[VulnerabilityCreate] = []
    alert = payload.get("alert", {})
    repo = payload.get("repository", {})
    action = payload.get("action", "")

    # Only process new/reopened alerts
    if action not in ("created", "reopened", "fixed"):
        return []

    repo_owner = repo.get("owner", {}).get("login", "unknown")
    repo_name = repo.get("name", "unknown")
    default_branch = repo.get("default_branch", "main")

    rule = alert.get("rule", {})
    most_recent_instance = alert.get("most_recent_instance", {})
    location = most_recent_instance.get("location", {})

    cve_id = rule.get("id", "")
    severity_raw = rule.get("severity") or alert.get("severity", "medium")
    title = rule.get("name", "GitHub Security Alert")
    description = rule.get("full_description") or rule.get("help", "No description.")
    file_path = location.get("path", "")
    line_start = location.get("start_line")
    line_end = location.get("end_line")
    owasp = _infer_owasp_category(description)

    alerts.append(
        VulnerabilityCreate(
            scanner=ScannerType.SNYK,
            cve_id=cve_id or None,
            severity=_normalize_severity(severity_raw),
            title=title,
            description=description,
            repo_owner=repo_owner,
            repo_name=repo_name,
            repo_branch=default_branch,
            file_path=file_path,
            line_start=line_start,
            line_end=line_end,
            owasp_category=owasp,
            raw_payload=payload,
        )
    )

    logger.info("github_alert_parsed", alerts_found=len(alerts))
    return alerts


# ─── Unified dispatcher ───────────────────────────────────────────────────────
def parse_scanner_payload(
    payload: dict[str, Any], scanner: str
) -> list[VulnerabilityCreate]:
    """
    Route payload to the correct scanner-specific parser.

    Args:
        payload: Raw scanner JSON payload.
        scanner: Scanner type string ("TRIVY", "BANDIT", "GITHUB").

    Returns:
        List of normalized VulnerabilityCreate objects.
    """
    parser_map = {
        "TRIVY": parse_trivy_payload,
        "BANDIT": parse_bandit_payload,
        "GITHUB": parse_github_security_payload,
    }

    parser = parser_map.get(scanner.upper())
    if not parser:
        logger.warning("unknown_scanner_type", scanner=scanner)
        return []

    try:
        return parser(payload)
    except Exception as exc:
        logger.error("scanner_parse_failed", scanner=scanner, error=str(exc))
        return []
