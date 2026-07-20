import { clsx } from "clsx";
import type { Severity, VulnerabilityStatus } from "@/lib/types";

const SEVERITY_CLASSES: Record<Severity, string> = {
  CRITICAL: "badge-critical",
  HIGH: "badge bg-red-900/20 text-red-400 border border-red-400/30",
  MEDIUM: "badge-medium",
  LOW: "badge-low",
  INFO: "badge-info",
};

const STATUS_CLASSES: Record<string, string> = {
  PENDING: "status-pending",
  TRIAGING: "status-running",
  PATCHING: "status-running",
  PATCH_FAILED: "status-failed",
  SANDBOX_RUNNING: "status-running",
  SANDBOX_PASSED: "status-passed",
  SANDBOX_FAILED: "status-failed",
  AWAITING_APPROVAL: "status-pending",
  APPROVED: "status-passed",
  REJECTED: "status-failed",
  PR_OPENED: "status-passed",
  PR_MERGED: "status-passed",
  ERROR: "status-failed",
};

const STATUS_LABELS: Record<string, string> = {
  PENDING: "Pending",
  TRIAGING: "Triaging...",
  PATCHING: "Patching...",
  PATCH_FAILED: "Patch Failed",
  SANDBOX_RUNNING: "Testing...",
  SANDBOX_PASSED: "Tests Passed",
  SANDBOX_FAILED: "Tests Failed",
  AWAITING_APPROVAL: "Awaiting Approval",
  APPROVED: "Approved",
  REJECTED: "Rejected",
  PR_OPENED: "PR Opened",
  PR_MERGED: "PR Merged",
  ERROR: "Error",
};

interface SeverityBadgeProps {
  severity: Severity;
  className?: string;
}

export function SeverityBadge({ severity, className }: SeverityBadgeProps) {
  return (
    <span className={clsx(SEVERITY_CLASSES[severity], className)}>
      {severity}
    </span>
  );
}

interface StatusBadgeProps {
  status: VulnerabilityStatus;
  className?: string;
}

export function StatusBadge({ status, className }: StatusBadgeProps) {
  const isAnimated = status.includes("ING");
  return (
    <span className={clsx(STATUS_CLASSES[status] || "badge-info", className)}>
      {isAnimated && <span className="animate-blink mr-1">●</span>}
      {STATUS_LABELS[status] || status}
    </span>
  );
}
