import type { Metadata } from "next";
import {
  AlertTriangle,
  Activity,
  GitPullRequest,
  FlaskConical,
  Zap,
} from "lucide-react";
import { MetricCard } from "@/components/ui/MetricCard";
import { IncidentFeed } from "@/components/dashboard/IncidentFeed";
import { MTTRChart } from "@/components/dashboard/MTTRChart";
import { SandboxGauge } from "@/components/dashboard/SandboxGauge";
import { getMetrics } from "@/lib/api";

export const metadata: Metadata = {
  title: "Incident Command Center",
  description: "Real-time security incident monitoring and AI remediation tracking.",
};

// ISR: revalidate every 30 seconds
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
    // Silently degrade — show zeros if backend is offline
  }

  const mttrMinutes = Math.round(metrics.mean_time_to_remediate_seconds / 60);

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Page header */}
      <div>
        <h1 className="text-xl font-bold text-text-primary flex items-center gap-2">
          <Zap className="w-5 h-5 text-accent-cyan" />
          Incident Command Center
        </h1>
        <p className="text-sm text-text-muted mt-1">
          Real-time AI-driven vulnerability remediation pipeline
        </p>
      </div>

      {/* Severity breakdown */}
      {(metrics.critical_count > 0 || metrics.high_count > 0) && (
        <div className="flex items-center gap-3 p-3 rounded-lg bg-accent-rose/5 border border-accent-rose/20">
          <AlertTriangle className="w-4 h-4 text-accent-rose flex-shrink-0" />
          <span className="text-sm font-mono text-text-secondary">
            Active threats today:{" "}
            {metrics.critical_count > 0 && (
              <span className="text-accent-rose font-semibold">
                {metrics.critical_count} CRITICAL
              </span>
            )}
            {metrics.critical_count > 0 && metrics.high_count > 0 && " · "}
            {metrics.high_count > 0 && (
              <span className="text-red-400 font-semibold">
                {metrics.high_count} HIGH
              </span>
            )}
          </span>
        </div>
      )}

      {/* KPI Row */}
      <div className="grid grid-cols-2 xl:grid-cols-4 gap-4">
        <MetricCard
          title="Active Incidents"
          value={metrics.active_incidents}
          subtitle="In pipeline now"
          icon={Activity}
          variant="rose"
        />
        <MetricCard
          title="Total Today"
          value={metrics.total_today}
          subtitle="Vulnerabilities ingested"
          icon={AlertTriangle}
          variant="amber"
        />
        <MetricCard
          title="Avg MTTR"
          value={mttrMinutes > 0 ? `${mttrMinutes}m` : "< 1m"}
          subtitle="Mean time to remediate"
          icon={Zap}
          variant="cyan"
        />
        <MetricCard
          title="PRs Opened"
          value={metrics.prs_opened_today}
          subtitle="Patches merged today"
          icon={GitPullRequest}
          variant="emerald"
        />
      </div>

      {/* Main content grid */}
      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
        {/* Left: Incident Feed (2/3 width) */}
        <div className="xl:col-span-2">
          <IncidentFeed />
        </div>

        {/* Right: Charts (1/3 width) */}
        <div className="space-y-4">
          <SandboxGauge passRate={metrics.sandbox_pass_rate} />
          <MTTRChart />
        </div>
      </div>
    </div>
  );
}
