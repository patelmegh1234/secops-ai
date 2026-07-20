/**
 * Mock/demo data used when the backend API is unavailable.
 * This makes the Vercel demo fully functional without a live backend.
 */

import type {
  Vulnerability,
  DashboardMetrics,
  AgentTrace,
  Patch,
  SandboxRun,
} from "./types";

export const DEMO_METRICS: DashboardMetrics = {
  active_incidents: 3,
  total_today: 12,
  sandbox_pass_rate: 0.83,
  prs_opened_today: 7,
  mean_time_to_remediate_seconds: 187,
  critical_count: 1,
  high_count: 4,
  medium_count: 7,
};

const now = new Date();
const minsAgo = (m: number) =>
  new Date(now.getTime() - m * 60 * 1000).toISOString();

export const DEMO_INCIDENTS: Vulnerability[] = [
  {
    id: "a1b2c3d4-0000-0000-0000-000000000001",
    scanner: "TRIVY",
    cve_id: "CVE-2023-32681",
    severity: "CRITICAL",
    title: "requests: Proxy-Authorization header leaked in cross-origin redirect",
    description:
      "Requests library leaks Proxy-Authorization headers when following cross-origin redirects to HTTPS endpoints. An attacker can intercept credentials via MITM.",
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
    id: "a1b2c3d4-0000-0000-0000-000000000002",
    scanner: "BANDIT",
    cve_id: "B602",
    severity: "HIGH",
    title: "subprocess.call with shell=True — command injection risk",
    description:
      "Use of subprocess with shell=True allows command injection if any part of the command is derived from user input.",
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
      "crytic-compile 0.2.2 allows code injection via a crafted .crytic_compile.config.json file. Upgrade to 0.3.1.",
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
    id: "a1b2c3d4-0000-0000-0000-000000000004",
    scanner: "BANDIT",
    cve_id: "B303",
    severity: "MEDIUM",
    title: "Use of MD5 — weak cryptographic hash algorithm",
    description:
      "MD5 is considered cryptographically broken. Replace with SHA-256 or bcrypt for password hashing.",
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
    id: "a1b2c3d4-0000-0000-0000-000000000005",
    scanner: "TRIVY",
    cve_id: "CVE-2024-21626",
    severity: "CRITICAL",
    title: "runc: container escape via /proc/self/fd leak",
    description:
      "runc through 1.1.11 allows a container to reach and cause harm to the host filesystem via /proc/self/fd.",
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
    created_at: minsAgo(120),
    updated_at: minsAgo(60),
  },
  {
    id: "a1b2c3d4-0000-0000-0000-000000000006",
    scanner: "BANDIT",
    cve_id: "B605",
    severity: "HIGH",
    title: "os.system() call — shell injection vulnerability",
    description:
      "Direct use of os.system() with potentially user-controlled input allows arbitrary command execution.",
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
];

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
  pr_branch: "secops-ai/cve-2023-32681-20240115120000",
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
