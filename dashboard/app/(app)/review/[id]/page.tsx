import type { Metadata } from "next";
import Link from "next/link";
import { notFound } from "next/navigation";
import { ArrowLeft, GitPullRequest, ExternalLink } from "lucide-react";
import { SeverityBadge, StatusBadge } from "@/components/ui/StatusBadge";
import { DiffViewer } from "@/components/ui/DiffViewer";
import { TerminalLog } from "@/components/ui/TerminalLog";
import { AgentTimeline } from "@/components/ui/AgentTimeline";
import {
  getIncident,
  getIncidentPatch,
  getSandboxResult,
  getAgentTraces,
} from "@/lib/api";

interface PageProps {
  params: Promise<{ id: string }>;
}

export async function generateMetadata({ params }: PageProps): Promise<Metadata> {
  try {
    const { id } = await params;
    const incident = await getIncident(id);
    return {
      title: `Review: ${incident.cve_id || "Security Issue"}`,
      description: incident.title,
    };
  } catch {
    return { title: "Patch Review" };
  }
}

export const dynamic = "force-dynamic";

export default async function PatchReviewPage({ params }: PageProps) {
  const { id } = await params;
  let incident, patch, sandbox, traces;

  try {
    incident = await getIncident(id);
  } catch {
    notFound();
  }

  try { patch = await getIncidentPatch(id); } catch {}
  try { sandbox = await getSandboxResult(id); } catch {}
  try { traces = await getAgentTraces(id); } catch {}

  return (
    <div className="space-y-6 animate-fade-in max-w-6xl">
      {/* Header */}
      <div className="flex items-start justify-between flex-wrap gap-4">
        <div>
          <Link
            href="/dashboard"
            className="text-text-muted hover:text-accent-cyan text-sm font-mono flex items-center gap-1 mb-3 transition-colors"
          >
            <ArrowLeft className="w-3.5 h-3.5" /> Back to Dashboard
          </Link>
          <h1 className="text-lg font-bold text-text-primary flex items-center gap-2 flex-wrap">
            <SeverityBadge severity={incident.severity} />
            {incident.cve_id && (
              <span className="font-mono text-accent-cyan">{incident.cve_id}</span>
            )}
            <span className="text-text-secondary">{incident.title}</span>
          </h1>
          <div className="flex items-center gap-3 mt-2 flex-wrap">
            <StatusBadge status={incident.status} />
            <span className="text-xs font-mono text-text-muted">
              {incident.repo_owner}/{incident.repo_name} @ {incident.repo_branch}
            </span>
            {incident.owasp_category && (
              <span className="text-xs font-mono text-accent-amber">
                {incident.owasp_category}
              </span>
            )}
          </div>
        </div>
        {patch?.pr_url && (
          <a
            href={patch.pr_url}
            target="_blank"
            rel="noopener noreferrer"
            className="btn-primary flex items-center gap-2 text-sm"
          >
            <GitPullRequest className="w-4 h-4" />
            View PR #{patch.pr_number}
            <ExternalLink className="w-3 h-3" />
          </a>
        )}
      </div>

      {/* Description */}
      <div className="card">
        <h2 className="text-xs font-mono text-text-muted uppercase tracking-wider mb-2">
          Vulnerability Description
        </h2>
        <p className="text-sm text-text-secondary leading-relaxed">{incident.description}</p>
        <div className="mt-3 grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs font-mono">
          <div>
            <span className="text-text-muted">File</span>
            <p className="text-accent-cyan truncate mt-0.5">{incident.file_path}</p>
          </div>
          <div>
            <span className="text-text-muted">Lines</span>
            <p className="text-text-secondary mt-0.5">
              {incident.line_start ?? "?"} – {incident.line_end ?? "?"}
            </p>
          </div>
          <div>
            <span className="text-text-muted">Scanner</span>
            <p className="text-text-secondary mt-0.5">{incident.scanner}</p>
          </div>
          <div>
            <span className="text-text-muted">CWE</span>
            <p className="text-text-secondary mt-0.5">{incident.cwe_id || "N/A"}</p>
          </div>
        </div>
      </div>

      {/* Main Grid */}
      <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
        {/* Diff Viewer */}
        <div className="xl:col-span-2">
          {patch ? (
            <>
              <h2 className="text-sm font-semibold text-text-primary mb-3 flex items-center gap-2">
                AI-Generated Patch
                {patch.guardrail_approved && (
                  <span className="badge bg-accent-emerald/20 text-accent-emerald border border-accent-emerald/30">
                    ✓ Guardrail Approved
                  </span>
                )}
              </h2>
              <DiffViewer
                diff={patch.diff_unified}
                originalCode={patch.original_code}
                patchedCode={patch.patched_code}
                filename={incident.file_path}
              />
              {patch.agent_reasoning && (
                <div className="card mt-4">
                  <h3 className="text-xs font-mono text-text-muted uppercase tracking-wider mb-2">
                    AI Reasoning
                  </h3>
                  <p className="text-sm text-text-secondary leading-relaxed">
                    {patch.agent_reasoning}
                  </p>
                </div>
              )}
            </>
          ) : (
            <div className="card text-center py-10 text-text-muted text-sm font-mono">
              Patch generation in progress...
            </div>
          )}
        </div>

        {/* Sandbox Result */}
        <div>
          <h2 className="text-sm font-semibold text-text-primary mb-3">
            Sandbox Verification
          </h2>
          {sandbox ? (
            <>
              <div className="grid grid-cols-3 gap-3 mb-4">
                <div className="card text-center">
                  <div className="text-xl font-bold font-mono text-accent-emerald">
                    {sandbox.tests_passed}
                  </div>
                  <div className="text-xs text-text-muted font-mono">Passed</div>
                </div>
                <div className="card text-center">
                  <div className="text-xl font-bold font-mono text-accent-rose">
                    {sandbox.tests_failed}
                  </div>
                  <div className="text-xs text-text-muted font-mono">Failed</div>
                </div>
                <div className="card text-center">
                  <div className="text-xl font-bold font-mono text-text-muted">
                    {sandbox.duration_ms}ms
                  </div>
                  <div className="text-xs text-text-muted font-mono">Duration</div>
                </div>
              </div>
              <TerminalLog
                content={sandbox.stdout || "No output captured."}
                title="pytest output"
                passed={sandbox.passed}
              />
            </>
          ) : (
            <div className="card text-center py-10 text-text-muted text-sm font-mono">
              Sandbox not run yet.
            </div>
          )}
        </div>

        {/* Agent Timeline */}
        <div>
          <h2 className="text-sm font-semibold text-text-primary mb-3">
            Agent Execution Timeline
          </h2>
          <AgentTimeline traces={traces || []} />
        </div>
      </div>
    </div>
  );
}
