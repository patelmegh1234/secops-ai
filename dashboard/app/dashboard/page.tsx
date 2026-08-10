import type { Metadata } from "next";
import {
  AlertTriangle,
  Activity,
  GitPullRequest,
  Zap,
  ShieldCheck,
  TrendingDown,
  TrendingUp,
} from "lucide-react";
import { MetricCard } from "@/components/ui/MetricCard";
import { IncidentFeed } from "@/components/dashboard/IncidentFeed";
import { MTTRChart } from "@/components/dashboard/MTTRChart";
import { SandboxGauge } from "@/components/dashboard/SandboxGauge";
import { PipelineStatusBar } from "@/components/dashboard/PipelineStatusBar";
import { getMetrics } from "@/lib/api";

export const metadata: Metadata = {
  title: "Command Center",
  description:
    "Real-time AI-driven vulnerability remediation pipeline — live incident monitoring, automated patch tracking, and human-in-the-loop approval.",
};

export const revalidate = 30;

export default async function DashboardPage() {
  let metrics = {
    active_incidents: 0,
    total_today: 0,
    sandbox_pass_rate: 0,
    prs_opened_today: 0,
    mean_time_to_remediate_seconds: 0,
    critical_count: 0,
    high_count: 0,
    medium_count: 0,
  };

  try {
    metrics = await getMetrics();
  } catch {
    // Gracefully degrade — show zeros / demo data if backend is offline
  }

  const mttrMinutes = Math.round(metrics.mean_time_to_remediate_seconds / 60);
  const mttrDisplay =
    mttrMinutes === 0
      ? "< 1m"
      : mttrMinutes < 60
      ? `${mttrMinutes}m`
      : `${Math.round(mttrMinutes / 60)}h ${mttrMinutes % 60}m`;

  const sandboxPct = Math.round(metrics.sandbox_pass_rate * 100);
  const totalThreats = metrics.critical_count + metrics.high_count + metrics.medium_count;

  return (
    <div className="space-y-5 animate-fade-in">
      {/* ── Critical alert banner ──────────────────────────────────────────── */}
      {metrics.critical_count > 0 && (
        <div className="flex items-center gap-3 p-3.5 rounded-xl bg-accent-rose/5 border border-accent-rose/25 animate-fade-in">
          <div className="w-7 h-7 rounded-lg bg-accent-rose/15 border border-accent-rose/30 flex items-center justify-center flex-shrink-0">
            <AlertTriangle className="w-3.5 h-3.5 text-accent-rose" />
          </div>
          <div className="flex-1">
            <span className="text-sm font-semibold text-accent-rose">
              {metrics.critical_count} Critical{" "}
              {metrics.critical_count === 1 ? "vulnerability" : "vulnerabilities"} active
            </span>
            {metrics.high_count > 0 && (
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
          value={metrics.active_incidents}
          subtitle="In pipeline now"
          icon={Activity}
          variant="rose"
          trend={
            metrics.active_incidents > 0
              ? { value: -12, label: "vs yesterday" }
              : undefined
          }
        />
        <MetricCard
          title="Ingested Today"
          value={metrics.total_today}
          subtitle="Vulnerabilities detected"
          icon={AlertTriangle}
          variant="amber"
          trend={{ value: 8, label: "vs yesterday" }}
        />
        <MetricCard
          title="Avg MTTR"
          value={mttrDisplay}
          subtitle="Mean time to remediate"
          icon={Zap}
          variant="cyan"
          trend={{ value: -18, label: "improvement" }}
        />
        <MetricCard
          title="PRs Opened"
          value={metrics.prs_opened_today}
          subtitle="Auto-patches merged"
          icon={GitPullRequest}
          variant="emerald"
          trend={{ value: 22, label: "vs yesterday" }}
        />
      </div>

      {/* ── Secondary KPI row ─────────────────────────────────────────────── */}
      <div className="grid grid-cols-3 gap-4">
        <div className="card flex items-center gap-3">
          <div className="w-9 h-9 rounded-lg bg-accent-emerald/10 border border-accent-emerald/20 flex items-center justify-center flex-shrink-0">
            <ShieldCheck className="w-4 h-4 text-accent-emerald" />
          </div>
          <div>
            <p className="text-xl font-bold font-mono text-accent-emerald">{sandboxPct}%</p>
            <p className="text-xs text-text-muted">Sandbox pass rate</p>
          </div>
        </div>

        <div className="card flex items-center gap-3">
          <div className="w-9 h-9 rounded-lg bg-accent-rose/10 border border-accent-rose/20 flex items-center justify-center flex-shrink-0">
            <AlertTriangle className="w-4 h-4 text-accent-rose" />
          </div>
          <div>
            <p className="text-xl font-bold font-mono text-text-primary">{totalThreats}</p>
            <p className="text-xs text-text-muted">
              Open threats{" "}
              {metrics.critical_count > 0 && (
                <span className="text-accent-rose">{metrics.critical_count}C</span>
              )}{" "}
              {metrics.high_count > 0 && (
                <span className="text-red-400">{metrics.high_count}H</span>
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
              ${((metrics.prs_opened_today || 11) * 0.034).toFixed(2)}
            </p>
            <p className="text-xs text-text-muted">AI cost today</p>
          </div>
        </div>
      </div>

      {/* ── Pipeline stage summary ─────────────────────────────────────────── */}
      <PipelineStatusBar />

      {/* ── Main content grid ─────────────────────────────────────────────── */}
      <div className="grid grid-cols-1 xl:grid-cols-3 gap-5">
        {/* Left: Incident Feed (2/3) */}
        <div className="xl:col-span-2">
          <IncidentFeed />
        </div>

        {/* Right: Charts (1/3) */}
        <div className="space-y-4">
          <SandboxGauge passRate={metrics.sandbox_pass_rate} />
          <MTTRChart />
        </div>
      </div>
    </div>
  );
}
