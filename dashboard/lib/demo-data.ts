/**
 * Enhanced demo data — 20 realistic incidents across all pipeline stages,
 * severity levels, and repository types. Used when backend API is unavailable.
 * Realistic enough to serve as a compelling product demo.
 */

import type {
  Vulnerability,
  DashboardMetrics,
  AgentTrace,
  Patch,
  SandboxRun,
} from "./types";

export const DEMO_METRICS: DashboardMetrics = {
  active_incidents: 7,
  total_today: 23,
  sandbox_pass_rate: 0.87,
  prs_opened_today: 11,
  mean_time_to_remediate_seconds: 214,
  critical_count: 2,
  high_count: 8,
  medium_count: 13,
};

const now = new Date();
const minsAgo = (m: number) =>
  new Date(now.getTime() - m * 60 * 1000).toISOString();
const hoursAgo = (h: number) => minsAgo(h * 60);

export const DEMO_INCIDENTS: Vulnerability[] = [
  // ── CRITICAL ───────────────────────────────────────────────────────────────
  {
    id: "a1b2c3d4-0000-0000-0000-000000000001",
    scanner: "TRIVY",
    cve_id: "CVE-2023-32681",
    severity: "CRITICAL",
    title: "requests: Proxy-Authorization header leaked on cross-origin redirect",
    description:
      "Requests library leaks Proxy-Authorization headers when following cross-origin redirects to HTTPS. An attacker can intercept credentials via MITM.",
    repo_owner: "acme-corp",
    repo_name: "api-gateway",
    repo_branch: "main",
    file_path: "src/clients/http_client.py",
    line_start: 42,
    line_end: 58,
    owasp_category: "A02:2021 — Cryptographic Failures",
    cwe_id: "CWE-601",
    status: "AWAITING_APPROVAL",
    celery_task_id: "celery-task-001",
    created_at: minsAgo(8),
    updated_at: minsAgo(2),
  },
  {
    id: "a1b2c3d4-0000-0000-0000-000000000005",
    scanner: "TRIVY",
    cve_id: "CVE-2024-21626",
    severity: "CRITICAL",
    title: "runc: container escape via /proc/self/fd directory traversal",
    description:
      "runc through 1.1.11 allows a container to reach and cause harm to the host filesystem via /proc/self/fd. Affects all container runtimes using this runc version.",
    repo_owner: "acme-corp",
    repo_name: "container-infra",
    repo_branch: "main",
    file_path: "Dockerfile",
    line_start: null,
    line_end: null,
    owasp_category: "A05:2021 — Security Misconfiguration",
    cwe_id: "CWE-22",
    status: "PR_MERGED",
    celery_task_id: "celery-task-005",
    created_at: hoursAgo(2),
    updated_at: hoursAgo(1),
  },
  // ── HIGH ────────────────────────────────────────────────────────────────────
  {
    id: "a1b2c3d4-0000-0000-0000-000000000002",
    scanner: "BANDIT",
    cve_id: "B602",
    severity: "HIGH",
    title: "subprocess.call with shell=True — arbitrary command injection risk",
    description:
      "Use of subprocess with shell=True allows command injection if any part of the command is derived from user input. Replace with subprocess.run() and a list of arguments.",
    repo_owner: "acme-corp",
    repo_name: "build-runner",
    repo_branch: "main",
    file_path: "src/utils/runner.py",
    line_start: 15,
    line_end: 15,
    owasp_category: "A03:2021 — Injection",
    cwe_id: "CWE-78",
    status: "SANDBOX_PASSED",
    celery_task_id: "celery-task-002",
    created_at: minsAgo(22),
    updated_at: minsAgo(5),
  },
  {
    id: "a1b2c3d4-0000-0000-0000-000000000003",
    scanner: "TRIVY",
    cve_id: "CVE-2023-28119",
    severity: "HIGH",
    title: "crytic-compile: code injection via malicious config file",
    description:
      "crytic-compile 0.2.2 allows code injection via a crafted .crytic_compile.config.json file. Upgrade to 0.3.1 or later.",
    repo_owner: "acme-corp",
    repo_name: "smart-contracts",
    repo_branch: "develop",
    file_path: "requirements.txt",
    line_start: 18,
    line_end: 18,
    owasp_category: "A08:2021 — Software and Data Integrity Failures",
    cwe_id: "CWE-94",
    status: "PR_OPENED",
    celery_task_id: "celery-task-003",
    created_at: minsAgo(45),
    updated_at: minsAgo(10),
  },
  {
    id: "a1b2c3d4-0000-0000-0000-000000000006",
    scanner: "BANDIT",
    cve_id: "B605",
    severity: "HIGH",
    title: "os.system() call with user-controlled input — shell injection",
    description:
      "Direct use of os.system() with potentially user-controlled input allows arbitrary command execution on the host system.",
    repo_owner: "acme-corp",
    repo_name: "deploy-scripts",
    repo_branch: "main",
    file_path: "scripts/deploy.py",
    line_start: 33,
    line_end: 33,
    owasp_category: "A03:2021 — Injection",
    cwe_id: "CWE-78",
    status: "TRIAGING",
    celery_task_id: "celery-task-006",
    created_at: minsAgo(1),
    updated_at: minsAgo(0),
  },
  {
    id: "a1b2c3d4-0000-0000-0000-000000000007",
    scanner: "TRIVY",
    cve_id: "CVE-2023-44270",
    severity: "HIGH",
    title: "PostCSS: line return parsing error allows CSS injection",
    description:
      "PostCSS before 8.4.31 allows an attacker to inject arbitrary CSS via specially crafted input containing CR characters.",
    repo_owner: "acme-corp",
    repo_name: "frontend-app",
    repo_branch: "main",
    file_path: "package.json",
    line_start: 24,
    line_end: 24,
    owasp_category: "A03:2021 — Injection",
    cwe_id: "CWE-74",
    status: "PATCHING",
    celery_task_id: "celery-task-007",
    created_at: minsAgo(3),
    updated_at: minsAgo(1),
  },
  {
    id: "a1b2c3d4-0000-0000-0000-000000000008",
    scanner: "BANDIT",
    cve_id: "B108",
    severity: "HIGH",
    title: "Hardcoded /tmp path — insecure temporary file creation",
    description:
      "Use of a hardcoded /tmp path is predictable and can be exploited by symlink attacks. Use tempfile.mkstemp() for secure temporary file creation.",
    repo_owner: "acme-corp",
    repo_name: "data-pipeline",
    repo_branch: "main",
    file_path: "src/etl/processor.py",
    line_start: 87,
    line_end: 89,
    owasp_category: "A01:2021 — Broken Access Control",
    cwe_id: "CWE-377",
    status: "SANDBOX_FAILED",
    celery_task_id: "celery-task-008",
    created_at: minsAgo(15),
    updated_at: minsAgo(7),
  },
  {
    id: "a1b2c3d4-0000-0000-0000-000000000009",
    scanner: "TRIVY",
    cve_id: "CVE-2024-0727",
    severity: "HIGH",
    title: "OpenSSL: PKCS12 parsing null pointer dereference (DoS)",
    description:
      "Processing a maliciously formatted PKCS12 file may lead OpenSSL to crash, causing a denial of service. Affects all versions before 3.2.1.",
    repo_owner: "acme-corp",
    repo_name: "auth-service",
    repo_branch: "main",
    file_path: "go.sum",
    line_start: null,
    line_end: null,
    owasp_category: "A06:2021 — Vulnerable and Outdated Components",
    cwe_id: "CWE-476",
    status: "PR_OPENED",
    celery_task_id: "celery-task-009",
    created_at: hoursAgo(3),
    updated_at: hoursAgo(1),
  },
  // ── MEDIUM ──────────────────────────────────────────────────────────────────
  {
    id: "a1b2c3d4-0000-0000-0000-000000000004",
    scanner: "BANDIT",
    cve_id: "B303",
    severity: "MEDIUM",
    title: "Use of MD5 — weak cryptographic hash for password storage",
    description:
      "MD5 is considered cryptographically broken. Replace with SHA-256 for checksums or bcrypt/argon2 for password hashing.",
    repo_owner: "acme-corp",
    repo_name: "auth-service",
    repo_branch: "main",
    file_path: "src/auth/password.py",
    line_start: 8,
    line_end: 8,
    owasp_category: "A02:2021 — Cryptographic Failures",
    cwe_id: "CWE-327",
    status: "PATCHING",
    celery_task_id: "celery-task-004",
    created_at: minsAgo(3),
    updated_at: minsAgo(1),
  },
  {
    id: "a1b2c3d4-0000-0000-0000-000000000010",
    scanner: "BANDIT",
    cve_id: "B501",
    severity: "MEDIUM",
    title: "SSL verification disabled — MITM attack vector",
    description:
      "Setting verify=False on HTTPS requests disables certificate validation, making connections vulnerable to man-in-the-middle attacks.",
    repo_owner: "acme-corp",
    repo_name: "integration-service",
    repo_branch: "main",
    file_path: "src/connectors/salesforce.py",
    line_start: 52,
    line_end: 52,
    owasp_category: "A02:2021 — Cryptographic Failures",
    cwe_id: "CWE-295",
    status: "AWAITING_APPROVAL",
    celery_task_id: "celery-task-010",
    created_at: minsAgo(18),
    updated_at: minsAgo(6),
  },
  {
    id: "a1b2c3d4-0000-0000-0000-000000000011",
    scanner: "TRIVY",
    cve_id: "CVE-2023-45133",
    severity: "MEDIUM",
    title: "@babel/traverse: code execution via malicious package",
    description:
      "Malicious packages in the Babel ecosystem can exploit @babel/traverse to execute arbitrary code during module parsing.",
    repo_owner: "acme-corp",
    repo_name: "frontend-app",
    repo_branch: "main",
    file_path: "package-lock.json",
    line_start: null,
    line_end: null,
    owasp_category: "A08:2021 — Software and Data Integrity Failures",
    cwe_id: "CWE-94",
    status: "PR_MERGED",
    celery_task_id: "celery-task-011",
    created_at: hoursAgo(5),
    updated_at: hoursAgo(3),
  },
  {
    id: "a1b2c3d4-0000-0000-0000-000000000012",
    scanner: "BANDIT",
    cve_id: "B608",
    severity: "MEDIUM",
    title: "Possible SQL injection via string concatenation in query builder",
    description:
      "SQL query is constructed via string formatting rather than parameterized queries. User-controlled input could inject arbitrary SQL.",
    repo_owner: "acme-corp",
    repo_name: "reporting-service",
    repo_branch: "main",
    file_path: "src/reports/query_builder.py",
    line_start: 74,
    line_end: 76,
    owasp_category: "A03:2021 — Injection",
    cwe_id: "CWE-89",
    status: "SANDBOX_PASSED",
    celery_task_id: "celery-task-012",
    created_at: hoursAgo(1),
    updated_at: minsAgo(20),
  },
  {
    id: "a1b2c3d4-0000-0000-0000-000000000013",
    scanner: "TRIVY",
    cve_id: "CVE-2024-1141",
    severity: "MEDIUM",
    title: "python-glances: unsafe deserialization of pickle data",
    description:
      "glances before 3.4.0.3 allows unsafe deserialization of pickle data that could execute arbitrary code if an attacker controls the data source.",
    repo_owner: "acme-corp",
    repo_name: "monitoring-agent",
    repo_branch: "main",
    file_path: "requirements.txt",
    line_start: 7,
    line_end: 7,
    owasp_category: "A08:2021 — Software and Data Integrity Failures",
    cwe_id: "CWE-502",
    status: "TRIAGING",
    celery_task_id: "celery-task-013",
    created_at: minsAgo(4),
    updated_at: minsAgo(2),
  },
  {
    id: "a1b2c3d4-0000-0000-0000-000000000014",
    scanner: "BANDIT",
    cve_id: "B101",
    severity: "MEDIUM",
    title: "assert statement used for security check — bypassable in optimized mode",
    description:
      "Python assert statements are stripped when running with optimization flags (-O). Security checks using assert can be bypassed silently.",
    repo_owner: "acme-corp",
    repo_name: "api-gateway",
    repo_branch: "feature/rate-limiting",
    file_path: "src/middleware/auth_check.py",
    line_start: 29,
    line_end: 29,
    owasp_category: "A07:2021 — Identification and Authentication Failures",
    cwe_id: "CWE-617",
    status: "PR_OPENED",
    celery_task_id: "celery-task-014",
    created_at: hoursAgo(4),
    updated_at: hoursAgo(2),
  },
  // ── LOW ─────────────────────────────────────────────────────────────────────
  {
    id: "a1b2c3d4-0000-0000-0000-000000000015",
    scanner: "BANDIT",
    cve_id: "B311",
    severity: "LOW",
    title: "Use of random.random() for security context — not cryptographically secure",
    description:
      "Standard pseudo-random generators are predictable. Use secrets.token_hex() or os.urandom() for cryptographic operations.",
    repo_owner: "acme-corp",
    repo_name: "auth-service",
    repo_branch: "main",
    file_path: "src/auth/token_generator.py",
    line_start: 14,
    line_end: 14,
    owasp_category: "A02:2021 — Cryptographic Failures",
    cwe_id: "CWE-338",
    status: "PR_MERGED",
    celery_task_id: "celery-task-015",
    created_at: hoursAgo(8),
    updated_at: hoursAgo(6),
  },
  {
    id: "a1b2c3d4-0000-0000-0000-000000000016",
    scanner: "TRIVY",
    cve_id: "CVE-2023-38325",
    severity: "LOW",
    title: "cryptography: null byte injected in certificate OID fields",
    description:
      "The cryptography package before 41.0.2 allows null byte injection into X.509 certificates under specific conditions.",
    repo_owner: "acme-corp",
    repo_name: "pki-service",
    repo_branch: "main",
    file_path: "requirements.txt",
    line_start: 3,
    line_end: 3,
    owasp_category: "A02:2021 — Cryptographic Failures",
    cwe_id: "CWE-295",
    status: "PR_MERGED",
    celery_task_id: "celery-task-016",
    created_at: hoursAgo(12),
    updated_at: hoursAgo(10),
  },
  {
    id: "a1b2c3d4-0000-0000-0000-000000000017",
    scanner: "BANDIT",
    cve_id: "B113",
    severity: "LOW",
    title: "requests.get without timeout — denial of service via slow response",
    description:
      "HTTP requests without an explicit timeout can hang indefinitely, causing resource exhaustion and denial of service.",
    repo_owner: "acme-corp",
    repo_name: "notification-service",
    repo_branch: "main",
    file_path: "src/notifiers/webhook.py",
    line_start: 63,
    line_end: 63,
    owasp_category: "A05:2021 — Security Misconfiguration",
    cwe_id: "CWE-400",
    status: "SANDBOX_PASSED",
    celery_task_id: "celery-task-017",
    created_at: hoursAgo(6),
    updated_at: hoursAgo(4),
  },
  {
    id: "a1b2c3d4-0000-0000-0000-000000000018",
    scanner: "TRIVY",
    cve_id: "CVE-2023-41419",
    severity: "LOW",
    title: "gevent: HTTP request smuggling via malformed chunked encoding",
    description:
      "Gevent before 23.9.1 does not properly handle chunked HTTP encoding, potentially allowing request smuggling attacks.",
    repo_owner: "acme-corp",
    repo_name: "websocket-service",
    repo_branch: "main",
    file_path: "requirements.txt",
    line_start: 12,
    line_end: 12,
    owasp_category: "A07:2021 — Identification and Authentication Failures",
    cwe_id: "CWE-444",
    status: "AWAITING_APPROVAL",
    celery_task_id: "celery-task-018",
    created_at: hoursAgo(2),
    updated_at: minsAgo(30),
  },
  {
    id: "a1b2c3d4-0000-0000-0000-000000000019",
    scanner: "BANDIT",
    cve_id: "B324",
    severity: "LOW",
    title: "hashlib.new called with hardcoded MD5 — insecure for security use",
    description:
      "Use of MD5 via hashlib.new is insecure for cryptographic purposes. Consider SHA-256 or SHA-3 for integrity checks.",
    repo_owner: "acme-corp",
    repo_name: "file-storage",
    repo_branch: "main",
    file_path: "src/checksums/verifier.py",
    line_start: 21,
    line_end: 21,
    owasp_category: "A02:2021 — Cryptographic Failures",
    cwe_id: "CWE-327",
    status: "TRIAGING",
    celery_task_id: "celery-task-019",
    created_at: minsAgo(2),
    updated_at: minsAgo(0),
  },
  {
    id: "a1b2c3d4-0000-0000-0000-000000000020",
    scanner: "TRIVY",
    cve_id: "CVE-2024-22195",
    severity: "LOW",
    title: "Jinja2: HTML attribute injection via user-controlled values",
    description:
      "Jinja2 before 3.1.3 does not properly escape HTML attribute values when rendering in certain contexts, allowing XSS.",
    repo_owner: "acme-corp",
    repo_name: "template-engine",
    repo_branch: "main",
    file_path: "requirements.txt",
    line_start: 5,
    line_end: 5,
    owasp_category: "A03:2021 — Injection",
    cwe_id: "CWE-116",
    status: "PR_MERGED",
    celery_task_id: "celery-task-020",
    created_at: hoursAgo(10),
    updated_at: hoursAgo(8),
  },
];

// ── Detailed data for the first incident (used in review page) ────────────────

export const DEMO_PATCH: Patch = {
  id: "patch-001-0000-0000-0000-000000000001",
  vulnerability_id: "a1b2c3d4-0000-0000-0000-000000000001",
  original_code: `import requests

def fetch_resource(url: str, proxy: str | None = None) -> dict:
    """Fetch a remote resource, optionally via proxy."""
    proxies = {"http": proxy, "https": proxy} if proxy else None
    
    # BUG: allow_redirects=True by default leaks Proxy-Authorization
    # headers when redirected from HTTP to HTTPS
    response = requests.get(
        url,
        proxies=proxies,
        timeout=30,
    )
    response.raise_for_status()
    return response.json()`,
  patched_code: `import requests
from requests import Session

def fetch_resource(url: str, proxy: str | None = None) -> dict:
    """Fetch a remote resource, optionally via proxy."""
    proxies = {"http": proxy, "https": proxy} if proxy else None
    
    # Fixed: CVE-2023-32681 — Use a Session with rebuild_proxies disabled
    # to prevent Proxy-Authorization header leakage on cross-origin redirects
    with Session() as session:
        session.max_redirects = 5
        # Disable automatic proxy auth on redirect (security fix)
        session.rebuild_proxies = lambda r, proxies: {}  # type: ignore[method-assign]
        response = session.get(
            url,
            proxies=proxies,
            timeout=30,
        )
    response.raise_for_status()
    return response.json()`,
  diff_unified: `--- a/src/clients/http_client.py
+++ b/src/clients/http_client.py
@@ -1,4 +1,5 @@
 import requests
+from requests import Session
 
 def fetch_resource(url: str, proxy: str | None = None) -> dict:
     """Fetch a remote resource, optionally via proxy."""
@@ -6,10 +7,14 @@ def fetch_resource(url: str, proxy: str | None = None) -> dict:
     proxies = {"http": proxy, "https": proxy} if proxy else None
     
-    # BUG: allow_redirects=True by default leaks Proxy-Authorization
-    # headers when redirected from HTTP to HTTPS
-    response = requests.get(
-        url,
-        proxies=proxies,
-        timeout=30,
-    )
+    # Fixed: CVE-2023-32681 — Use a Session with rebuild_proxies disabled
+    # to prevent Proxy-Authorization header leakage on cross-origin redirects
+    with Session() as session:
+        session.max_redirects = 5
+        # Disable automatic proxy auth on redirect (security fix)
+        session.rebuild_proxies = lambda r, proxies: {}  # type: ignore[method-assign]
+        response = session.get(
+            url,
+            proxies=proxies,
+            timeout=30,
+        )
     response.raise_for_status()
     return response.json()`,
  agent_reasoning:
    "The vulnerability stems from the default behavior of `requests.get()` which preserves the `Proxy-Authorization` header when following redirects across different origins (HTTP→HTTPS). The fix wraps the request in a `Session` object and overrides `rebuild_proxies` to return an empty dict on redirect, preventing credential leakage. This is the minimal change that addresses the CVE without altering the function signature or any downstream behavior.",
  owasp_flags: [],
  guardrail_approved: true,
  guardrail_notes:
    "✅ Patch approved. Vulnerability fully remediated. No new security issues introduced. Function signature preserved. Change is minimal and targeted.",
  pr_url: "https://github.com/acme-corp/api-gateway/pull/142",
  pr_number: 142,
  pr_branch: "guardmind/cve-2023-32681-20240115120000",
  created_at: minsAgo(5),
};

export const DEMO_SANDBOX: SandboxRun = {
  id: "sandbox-001-0000-0000-0000",
  patch_id: "patch-001-0000-0000-0000-000000000001",
  exit_code: 0,
  stdout: `============================= test session starts ==============================
platform linux -- Python 3.11.8, pytest-7.4.3, pluggy-1.3.0
rootdir: /workspace
collected 18 items

tests/test_http_client.py::test_fetch_resource_basic PASSED               [  5%]
tests/test_http_client.py::test_fetch_resource_with_proxy PASSED           [ 11%]
tests/test_http_client.py::test_fetch_resource_timeout PASSED              [ 16%]
tests/test_http_client.py::test_fetch_resource_no_proxy_auth_leak PASSED   [ 22%]
tests/test_http_client.py::test_fetch_resource_redirect_safe PASSED        [ 27%]
tests/test_http_client.py::test_fetch_resource_raises_on_4xx PASSED        [ 33%]
tests/test_http_client.py::test_fetch_resource_raises_on_5xx PASSED        [ 38%]
tests/test_auth.py::test_login_success PASSED                              [ 44%]
tests/test_auth.py::test_login_invalid_credentials PASSED                  [ 50%]
tests/test_auth.py::test_token_validation PASSED                           [ 55%]
tests/test_auth.py::test_refresh_token PASSED                              [ 61%]
tests/test_api.py::test_health_check PASSED                                [ 66%]
tests/test_api.py::test_create_resource_authenticated PASSED               [ 72%]
tests/test_api.py::test_create_resource_unauthenticated PASSED             [ 77%]
tests/test_api.py::test_list_resources_pagination PASSED                   [ 83%]
tests/test_api.py::test_search_resources PASSED                            [ 88%]
tests/test_api.py::test_delete_resource PASSED                             [ 94%]
tests/test_api.py::test_update_resource PASSED                             [100%]

============================== 18 passed in 2.84s ==============================`,
  stderr: "",
  tests_passed: 18,
  tests_failed: 0,
  tests_errored: 0,
  duration_ms: 2840,
  timed_out: false,
  passed: true,
  created_at: minsAgo(4),
};

export const DEMO_TRACES: AgentTrace[] = [
  {
    id: "trace-001",
    vulnerability_id: "a1b2c3d4-0000-0000-0000-000000000001",
    agent_name: "TRIAGE",
    step: "triage",
    model_used: "gpt-4o-mini",
    input_tokens: 1842,
    output_tokens: 387,
    estimated_cost_usd: 0.000509,
    duration_ms: 2341,
    success: true,
    error_message: null,
    created_at: minsAgo(7),
  },
  {
    id: "trace-002",
    vulnerability_id: "a1b2c3d4-0000-0000-0000-000000000001",
    agent_name: "PATCH",
    step: "patch_attempt_1",
    model_used: "gpt-4o",
    input_tokens: 3210,
    output_tokens: 892,
    estimated_cost_usd: 0.02946,
    duration_ms: 7823,
    success: true,
    error_message: null,
    created_at: minsAgo(6),
  },
  {
    id: "trace-003",
    vulnerability_id: "a1b2c3d4-0000-0000-0000-000000000001",
    agent_name: "GUARDRAIL",
    step: "guardrail_attempt_1",
    model_used: "gpt-4o-mini",
    input_tokens: 2105,
    output_tokens: 241,
    estimated_cost_usd: 0.000461,
    duration_ms: 1987,
    success: true,
    error_message: null,
    created_at: minsAgo(5),
  },
];

export const IS_DEMO_MODE =
  !process.env.NEXT_PUBLIC_API_URL ||
  process.env.NEXT_PUBLIC_API_URL === "" ||
  process.env.NEXT_PUBLIC_DEMO_MODE === "true";
