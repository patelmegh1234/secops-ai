/**
 * Shared TypeScript types for SecOps-AI dashboard.
 * Mirrors the backend Pydantic schemas.
 */

export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
export type ScannerType = "TRIVY" | "BANDIT" | "SONARQUBE" | "SNYK" | "MANUAL";
export type ApprovalDecision = "APPROVED" | "REJECTED";
export type AgentName = "TRIAGE" | "PATCH" | "GUARDRAIL";

export type VulnerabilityStatus =
  | "PENDING"
  | "TRIAGING"
  | "PATCHING"
  | "PATCH_FAILED"
  | "SANDBOX_RUNNING"
  | "SANDBOX_PASSED"
  | "SANDBOX_FAILED"
  | "AWAITING_APPROVAL"
  | "APPROVED"
  | "REJECTED"
  | "PR_OPENED"
  | "PR_MERGED"
  | "ERROR";

export interface Vulnerability {
  id: string;
  scanner: ScannerType;
  cve_id: string | null;
  severity: Severity;
  title: string;
  description: string;
  repo_owner: string;
  repo_name: string;
  repo_branch: string;
  file_path: string;
  line_start: number | null;
  line_end: number | null;
  owasp_category: string | null;
  cwe_id: string | null;
  status: VulnerabilityStatus;
  celery_task_id: string | null;
  created_at: string;
  updated_at: string;
}

export interface Patch {
  id: string;
  vulnerability_id: string;
  original_code: string;
  patched_code: string;
  diff_unified: string;
  agent_reasoning: string;
  owasp_flags: string[];
  guardrail_approved: boolean | null;
  guardrail_notes: string | null;
  pr_url: string | null;
  pr_number: number | null;
  pr_branch: string | null;
  created_at: string;
}

export interface SandboxRun {
  id: string;
  patch_id: string;
  exit_code: number;
  stdout: string;
  stderr: string;
  tests_passed: number;
  tests_failed: number;
  tests_errored: number;
  duration_ms: number;
  timed_out: boolean;
  passed: boolean;
  created_at: string;
}

export interface HumanApproval {
  id: string;
  patch_id: string;
  decision: ApprovalDecision;
  approver_slack_id: string;
  approver_name: string | null;
  rejection_reason: string | null;
  created_at: string;
}

export interface AgentTrace {
  id: string;
  vulnerability_id: string;
  agent_name: AgentName;
  step: string;
  model_used: string;
  input_tokens: number;
  output_tokens: number;
  estimated_cost_usd: number;
  duration_ms: number;
  success: boolean;
  error_message: string | null;
  created_at: string;
}

export interface DashboardMetrics {
  active_incidents: number;
  total_today: number;
  sandbox_pass_rate: number;
  prs_opened_today: number;
  mean_time_to_remediate_seconds: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
}

export interface VulnerabilityListResponse {
  total: number;
  items: Vulnerability[];
}

// WebSocket event types
export interface WsEvent {
  type: "vulnerability_update" | "ping";
  vuln_id?: string;
  status?: VulnerabilityStatus;
  severity?: Severity;
  title?: string;
  sandbox_passed?: boolean;
  tests_passed?: number;
  tests_failed?: number;
}
