import type { Metadata } from "next";
import {
  AlertTriangle,
  Activity,
  GitPullRequest,
  Zap,
  ShieldCheck,
  TrendingDown,
} from "lucide-react";
import { MetricCard } from "@/components/ui/MetricCard";
import { IncidentFeed } from "@/components/dashboard/IncidentFeed";
import { MTTRChart } from "@/components/dashboard/MTTRChart";
import { SandboxGauge } from "@/components/dashboard/SandboxGauge";
import { PipelineStatusBar } from "@/components/dashboard/PipelineStatusBar";
import { SetupWizard } from "@/components/onboarding/SetupWizard";
import { getMetrics, IS_UNCONFIGURED } from "@/lib/api";

export const metadata: Metadata = {
  title: "Command Center",
  description:
    "Real-time AI-driven vulnerability remediation pipeline — live incident monitoring, automated patch tracking, and human-in-the-loop approval.",
};

export const revalidate = 30;

export default async function DashboardPage() {
  const metrics = await getMetrics(); // null when backend unavailable
  const backendOffline = metrics === null;

  // Only compute display values from real data — never from fabricated defaults
  const mttrSeconds = metrics?.mean_time_to_remediate_seconds ?? 0;
  const mttrMinutes = Math.round(mttrSeconds / 60);
  const mttrDisplay =
    mttrSeconds === 0
      ? "—"
      : mttrMinutes < 60
      ? `${mttrMinutes}m`
      : `${Math.round(mttrMinutes / 60)}h ${mttrMinutes % 60}m`;

  const sandboxPct =
    metrics ? Math.round(metrics.sandbox_pass_rate * 100) : null;

  const totalThreats =
    metrics
      ? (metrics.critical_count ?? 0) + (metrics.high_count ?? 0) + (metrics.medium_count ?? 0)
      : null;

  return (
    <div className="space-y-5 animate-fade-in">

      {/* ── Backend offline: show full setup wizard ──────────────────────── */}
      {backendOffline && (
        <SetupWizard />
      )}

      {/* ── Critical alert banner (real data only) ────────────────────────── */}
      {metrics && (metrics.critical_count ?? 0) > 0 && (
        <div className="flex items-center gap-3 p-3.5 rounded-xl bg-accent-rose/5 border border-accent-rose/25 animate-fade-in">
          <div className="w-7 h-7 rounded-lg bg-accent-rose/15 border border-accent-rose/30 flex items-center justify-center flex-shrink-0">
            <AlertTriangle className="w-3.5 h-3.5 text-accent-rose" />
          </div>
          <div className="flex-1">
            <span className="text-sm font-semibold text-accent-rose">
              {metrics.critical_count}{" "}
              {metrics.critical_count === 1 ? "critical vulnerability" : "critical vulnerabilities"} active
            </span>
            {(metrics.high_count ?? 0) > 0 && (
              <span className="text-sm text-text-muted ml-2">
                · {metrics.high_count} High
              </span>
            )}
          </div>
          <span className="text-[10px] font-mono text-accent-rose/70 uppercase tracking-wider">
            Requires immediate review
          </span>
        </div>
      )}

      {/* ── KPI Row ───────────────────────────────────────────────────────── */}
      <div className="grid grid-cols-2 xl:grid-cols-4 gap-4">
        <MetricCard
          title="Active Incidents"
          value={metrics ? metrics.active_incidents : "—"}
          subtitle={backendOffline ? "Backend offline" : "In pipeline now"}
          icon={Activity}
          variant="rose"
        />
        <MetricCard
          title="Ingested Today"
          value={metrics ? metrics.total_today : "—"}
          subtitle={backendOffline ? "Backend offline" : "Vulnerabilities detected"}
          icon={AlertTriangle}
          variant="amber"
        />
        <MetricCard
          title="Avg MTTR"
          value={mttrDisplay}
          subtitle={backendOffline ? "Backend offline" : "Mean time to remediate"}
          icon={Zap}
          variant="cyan"
        />
        <MetricCard
          title="PRs Opened"
          value={metrics ? metrics.prs_opened_today : "—"}
          subtitle={backendOffline ? "Backend offline" : "Auto-patches merged"}
          icon={GitPullRequest}
          variant="emerald"
        />
      </div>

      {/* ── Secondary KPI row ─────────────────────────────────────────────── */}
      <div className="grid grid-cols-3 gap-4">
        <div className="card flex items-center gap-3">
          <div className="w-9 h-9 rounded-lg bg-accent-emerald/10 border border-accent-emerald/20 flex items-center justify-center flex-shrink-0">
            <ShieldCheck className="w-4 h-4 text-accent-emerald" />
          </div>
          <div>
            <p className="text-xl font-bold font-mono text-accent-emerald">
              {sandboxPct !== null ? `${sandboxPct}%` : "—"}
            </p>
            <p className="text-xs text-text-muted">Sandbox pass rate</p>
          </div>
        </div>

        <div className="card flex items-center gap-3">
          <div className="w-9 h-9 rounded-lg bg-accent-rose/10 border border-accent-rose/20 flex items-center justify-center flex-shrink-0">
            <AlertTriangle className="w-4 h-4 text-accent-rose" />
          </div>
          <div>
            <p className="text-xl font-bold font-mono text-text-primary">
              {totalThreats !== null ? totalThreats : "—"}
            </p>
            <p className="text-xs text-text-muted">
              Open threats
              {metrics && (metrics.critical_count ?? 0) > 0 && (
                <span className="text-accent-rose ml-1">{metrics.critical_count}C</span>
              )}
              {metrics && (metrics.high_count ?? 0) > 0 && (
                <span className="text-red-400 ml-1">{metrics.high_count}H</span>
              )}
            </p>
          </div>
        </div>

        <div className="card flex items-center gap-3">
          <div className="w-9 h-9 rounded-lg bg-accent-cyan/10 border border-accent-cyan/20 flex items-center justify-center flex-shrink-0">
            <TrendingDown className="w-4 h-4 text-accent-cyan" />
          </div>
          <div>
            <p className="text-xl font-bold font-mono text-accent-cyan">
              {metrics
                ? `$${(metrics.prs_opened_today * 0.034).toFixed(2)}`
                : "—"}
            </p>
            <p className="text-xs text-text-muted">AI cost today</p>
          </div>
        </div>
      </div>

      {/* ── Pipeline stage summary ─────────────────────────────────────────── */}
      <PipelineStatusBar backendOffline={backendOffline} />

      {/* ── Main content grid ─────────────────────────────────────────────── */}
      <div className="grid grid-cols-1 xl:grid-cols-3 gap-5">
        <div className="xl:col-span-2">
          <IncidentFeed />
        </div>
        <div className="space-y-4">
          <SandboxGauge passRate={metrics?.sandbox_pass_rate ?? null} />
          <MTTRChart />
        </div>
      </div>
    </div>
  );
}
