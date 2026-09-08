#!/usr/bin/env python3
"""
GuardMind Scanner Integration: Bandit (Python SAST)

Runs Bandit on a Python project and forwards HIGH/MEDIUM severity findings
to your GuardMind instance as a signed webhook.

Usage:
  python scripts/send_bandit_report.py --target ./src --api-url https://api-production-ac9f.up.railway.app

Requirements:
  pip install bandit requests
"""

import argparse
import hashlib
import hmac
import json
import os
import subprocess
import sys
import tempfile

try:
    import requests
except ImportError:
    print("ERROR: requests not installed. Run: pip install requests")
    sys.exit(1)


def run_bandit_scan(target_path: str) -> dict:
    """Run bandit on a Python codebase and return structured JSON results."""
    print(f"[guardmind] Running Bandit SAST on: {target_path}")

    cmd = [
        sys.executable, "-m", "bandit",
        "-r", target_path,
        "-f", "json",
        "-l",           # Only HIGH severity
        "-i",           # Only HIGH confidence
        "--quiet",
    ]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        # Bandit returns exit code 1 when findings exist (that's expected)
        if result.stdout:
            return json.loads(result.stdout)
        raise RuntimeError("No output from bandit")
    except FileNotFoundError:
        print("[guardmind] Bandit not installed. Run: pip install bandit")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"[guardmind] Failed to parse bandit output: {e}")
        print(f"[guardmind] Stdout: {result.stdout[:500]}")
        sys.exit(1)


def send_to_guardmind(payload: dict, api_url: str, secret: str) -> None:
    """Sign and POST the payload to GuardMind Bandit webhook."""
    endpoint = f"{api_url.rstrip('/')}/webhooks/bandit"
    body = json.dumps(payload, separators=(",", ":")).encode()

    sig = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()

    print(f"[guardmind] Sending {len(payload.get('results', []))} findings to {endpoint}")
    resp = requests.post(
        endpoint,
        data=body,
        headers={
            "Content-Type": "application/json",
            "X-GuardMind-Signature": sig,
        },
        timeout=30,
    )

    if resp.status_code == 202:
        data = resp.json()
        print(f"[guardmind] ✓ Accepted. Response: {json.dumps(data, indent=2)}")
        print("[guardmind] → Watch the dashboard for real-time remediation updates.")
    else:
        print(f"[guardmind] ✗ Error {resp.status_code}: {resp.text}")
        sys.exit(1)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Send a Bandit SAST report to GuardMind",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan your project source directory
  python scripts/send_bandit_report.py --target ./src

  # Use a pre-existing Bandit JSON report
  python scripts/send_bandit_report.py --report-file bandit-report.json

  # Continuous integration usage
  bandit -r ./src -f json -o /tmp/bandit.json; \\
  python scripts/send_bandit_report.py --report-file /tmp/bandit.json
        """,
    )
    parser.add_argument("--target", help="Python source path to scan (directory or file)")
    parser.add_argument("--report-file", help="Path to existing Bandit JSON report file")
    parser.add_argument("--api-url",
                        default=os.environ.get("GUARDMIND_API_URL", "https://api-production-ac9f.up.railway.app"),
                        help="GuardMind API base URL")
    parser.add_argument("--secret",
                        default=os.environ.get("GUARDMIND_WEBHOOK_SECRET"),
                        help="Webhook HMAC signing secret (or set GUARDMIND_WEBHOOK_SECRET env var)")
    parser.add_argument("--min-severity", default="HIGH", choices=["LOW", "MEDIUM", "HIGH"],
                        help="Minimum severity to forward (default: HIGH)")

    args = parser.parse_args()

    if not args.secret:
        parser.error("Webhook secret required. Provide --secret <SECRET> or set GUARDMIND_WEBHOOK_SECRET env var.")

    if not args.target and not args.report_file:
        parser.error("Provide --target (path to scan) or --report-file (existing report)")

    if args.report_file:
        print(f"[guardmind] Loading Bandit report from {args.report_file}")
        with open(args.report_file) as f:
            payload = json.load(f)
    else:
        payload = run_bandit_scan(args.target)

    # Filter by severity
    sev_order = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}
    min_sev = sev_order[args.min_severity]
    original_count = len(payload.get("results", []))
    payload["results"] = [
        r for r in payload.get("results", [])
        if sev_order.get(r.get("issue_severity", "LOW"), 0) >= min_sev
    ]
    filtered = original_count - len(payload["results"])
    print(f"[guardmind] {len(payload['results'])} findings (filtered {filtered} below {args.min_severity})")

    if not payload["results"]:
        print(f"[guardmind] ✓ No {args.min_severity}+ findings. Nothing to send.")
        return

    send_to_guardmind(payload, args.api_url, args.secret)


if __name__ == "__main__":
    main()
