#!/usr/bin/env python3
"""
GuardMind Scanner Integration: Trivy

Runs a Trivy container scan on a target image/directory and forwards the
results to your GuardMind instance as a signed webhook.

Usage:
  python scripts/send_trivy_report.py --target myapp:latest --api-url https://api-production-ac9f.up.railway.app --secret your_webhook_secret

Requirements:
  pip install requests
  docker (for running Trivy)

  OR: Install Trivy directly: https://aquasecurity.github.io/trivy/
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


def run_trivy_scan(target: str, scan_type: str = "image") -> dict:
    """Run trivy and return parsed JSON results."""
    print(f"[guardmind] Running Trivy {scan_type} scan on: {target}")

    cmd = [
        "trivy", scan_type,
        "--format", "json",
        "--severity", "HIGH,CRITICAL",
        "--quiet",
        target,
    ]

    # Try Docker-based Trivy if binary not found
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        if result.returncode not in (0, 1):  # 1 = found vulns (expected)
            # Fallback to Docker
            raise FileNotFoundError("trivy not in PATH")
        return json.loads(result.stdout)
    except (FileNotFoundError, json.JSONDecodeError):
        print("[guardmind] Trivy binary not found — trying Docker...")
        docker_cmd = [
            "docker", "run", "--rm",
            "-v", "/var/run/docker.sock:/var/run/docker.sock",
            "aquasec/trivy:latest",
            scan_type, "--format", "json", "--severity", "HIGH,CRITICAL", "--quiet",
            target,
        ]
        result = subprocess.run(docker_cmd, capture_output=True, text=True, timeout=180)
        return json.loads(result.stdout)


def send_to_guardmind(payload: dict, api_url: str, secret: str) -> None:
    """Sign and POST the payload to GuardMind webhook endpoint."""
    endpoint = f"{api_url.rstrip('/')}/webhooks/trivy"
    body = json.dumps(payload, separators=(",", ":")).encode()

    # Generate HMAC-SHA256 signature
    sig = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()

    print(f"[guardmind] POSTing to {endpoint}")
    resp = requests.post(
        endpoint,
        data=body,
        headers={
            "Content-Type": "application/json",
            "X-GuardMind-Signature": sig,
            "X-Hub-Signature-256": sig,  # GitHub-compatible header
        },
        timeout=30,
    )

    if resp.status_code == 202:
        data = resp.json()
        status = data.get("status", "accepted")
        if status == "duplicate":
            print("[guardmind] ✓ Duplicate — this vulnerability is already being processed.")
        else:
            task_id = data.get("task_id", "unknown")
            count = data.get("vulnerabilities_queued", 1)
            print(f"[guardmind] ✓ {count} vulnerability/-ies queued. Task ID: {task_id}")
            print(f"[guardmind] → Watch the dashboard for real-time updates.")
    elif resp.status_code == 200:
        print(f"[guardmind] ✓ Response: {resp.json()}")
    else:
        print(f"[guardmind] ✗ Error {resp.status_code}: {resp.text}")
        sys.exit(1)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Send a Trivy scan report to GuardMind",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan a Docker image
  python scripts/send_trivy_report.py --target myapp:latest

  # Scan a local filesystem directory
  python scripts/send_trivy_report.py --target ./src --scan-type fs

  # Use a pre-existing Trivy JSON report
  python scripts/send_trivy_report.py --report-file trivy-report.json

  # Custom GuardMind instance
  python scripts/send_trivy_report.py --target myapp:latest \\
    --api-url https://your-api.railway.app \\
    --secret your_webhook_secret
        """,
    )
    parser.add_argument("--target", help="Docker image tag or filesystem path to scan")
    parser.add_argument("--scan-type", default="image", choices=["image", "fs", "repo", "config"],
                        help="Trivy scan type (default: image)")
    parser.add_argument("--report-file", help="Path to existing Trivy JSON report (skips scan)")
    parser.add_argument("--api-url",
                        default=os.environ.get("GUARDMIND_API_URL", "https://api-production-ac9f.up.railway.app"),
                        help="GuardMind API URL")
    parser.add_argument("--secret",
                        default=os.environ.get("GUARDMIND_WEBHOOK_SECRET"),
                        help="Webhook HMAC signing secret (or set GUARDMIND_WEBHOOK_SECRET env var)")

    args = parser.parse_args()

    if not args.secret:
        parser.error("Webhook secret required. Provide --secret <SECRET> or set GUARDMIND_WEBHOOK_SECRET env var.")

    if not args.target and not args.report_file:
        parser.error("Provide --target or --report-file")

    # Get the scan result
    if args.report_file:
        print(f"[guardmind] Loading report from {args.report_file}")
        with open(args.report_file) as f:
            payload = json.load(f)
    else:
        payload = run_trivy_scan(args.target, args.scan_type)

    # Count vulnerabilities found
    total = sum(
        len(r.get("Vulnerabilities") or [])
        for r in payload.get("Results", [])
    )
    print(f"[guardmind] Found {total} HIGH/CRITICAL vulnerability/-ies")

    if total == 0:
        print("[guardmind] ✓ No HIGH/CRITICAL vulnerabilities found. Nothing to send.")
        return

    send_to_guardmind(payload, args.api_url, args.secret)


if __name__ == "__main__":
    main()
