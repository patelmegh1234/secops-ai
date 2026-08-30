import type { Metadata } from "next";
import {
  Github,
  MessageSquare,
  Shield,
  Package,
  Bug,
  CheckCircle2,
  XCircle,
  Clock,
  ExternalLink,
  Zap,
} from "lucide-react";

export const metadata: Metadata = {
  title: "Integrations",
  description: "Connected scanners, source control, and notification channels.",
};

const integrations = [
  {
    id: "github",
    name: "GitHub",
    description: "Source control, PR creation, and code scanning alerts",
    icon: Github,
    category: "Source Control",
    status: "connected" as const,
    lastEvent: "2 minutes ago",
    details: "acme-corp organization · 12 repos monitored",
    docs: "https://docs.github.com/webhooks",
    color: "text-text-primary",
    bg: "bg-bg-secondary",
    border: "border-border-subtle",
  },
  {
    id: "slack",
    name: "Slack",
    description: "Human-in-the-loop approval notifications and patch reviews",
    icon: MessageSquare,
    category: "Notifications",
    status: "connected" as const,
    lastEvent: "5 minutes ago",
    details: "#secops-alerts channel · 3 approvers configured",
    docs: "https://api.slack.com/messaging/webhooks",
    color: "text-accent-emerald",
    bg: "bg-accent-emerald/5",
    border: "border-accent-emerald/20",
  },
  {
    id: "trivy",
    name: "Trivy",
    description: "Container and dependency vulnerability scanning (Aqua Security)",
    icon: Package,
    category: "Scanner",
    status: "connected" as const,
    lastEvent: "8 minutes ago",
    details: "v0.48.3 · JSON output · GitHub Actions integration",
    docs: "https://trivy.dev",
    color: "text-accent-cyan",
    bg: "bg-accent-cyan/5",
    border: "border-accent-cyan/20",
  },
  {
    id: "bandit",
    name: "Bandit",
    description: "Python static analysis security testing (PyCQA)",
    icon: Bug,
    category: "Scanner",
    status: "connected" as const,
    lastEvent: "15 minutes ago",
    details: "v1.7.7 · SARIF + JSON output · CI/CD integrated",
    docs: "https://bandit.readthedocs.io",
    color: "text-accent-amber",
    bg: "bg-accent-amber/5",
    border: "border-accent-amber/20",
  },
  {
    id: "openai",
    name: "OpenAI",
    description: "GPT-4o for patch generation and guardrail review",
    icon: Zap,
    category: "AI Model",
    status: "connected" as const,
    lastEvent: "just now",
    details: "GPT-4o + GPT-4o-mini · $0.37 spent today",
    docs: "https://platform.openai.com/docs",
    color: "text-accent-emerald",
    bg: "bg-accent-emerald/5",
    border: "border-accent-emerald/20",
  },
  {
    id: "sonarqube",
    name: "SonarQube",
    description: "Code quality and security analysis (coming soon)",
    icon: Shield,
    category: "Scanner",
    status: "coming_soon" as const,
    lastEvent: null,
    details: "Webhook integration planned for Q2 2025",
    docs: null,
    color: "text-text-muted",
    bg: "bg-bg-secondary",
    border: "border-border-subtle",
  },
];

function StatusPill({ status }: { status: "connected" | "disconnected" | "coming_soon" }) {
  if (status === "connected") {
    return (
      <span className="inline-flex items-center gap-1 text-[10px] font-mono font-semibold px-2 py-0.5 rounded-full bg-accent-emerald/15 text-accent-emerald border border-accent-emerald/25">
        <CheckCircle2 className="w-2.5 h-2.5" />
        Connected
      </span>
    );
  }
  if (status === "disconnected") {
    return (
      <span className="inline-flex items-center gap-1 text-[10px] font-mono font-semibold px-2 py-0.5 rounded-full bg-accent-rose/15 text-accent-rose border border-accent-rose/25">
        <XCircle className="w-2.5 h-2.5" />
        Disconnected
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-1 text-[10px] font-mono font-semibold px-2 py-0.5 rounded-full bg-bg-secondary text-text-muted border border-border-subtle">
      <Clock className="w-2.5 h-2.5" />
      Coming Soon
    </span>
  );
}

export default function IntegrationsPage() {
  const categories = [...new Set(integrations.map((i) => i.category))];

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <p className="text-sm text-text-muted mt-1">
            {integrations.filter((i) => i.status === "connected").length} of{" "}
            {integrations.length} integrations active
          </p>
        </div>
        <button className="btn-primary text-sm flex items-center gap-2">
          <Zap className="w-3.5 h-3.5" />
          Add Integration
        </button>
      </div>

      {/* Webhook endpoint info */}
      <div className="card bg-accent-cyan/5 border-accent-cyan/20">
        <div className="flex items-start gap-3">
          <div className="w-8 h-8 rounded-lg bg-accent-cyan/15 border border-accent-cyan/25 flex items-center justify-center flex-shrink-0">
            <Zap className="w-4 h-4 text-accent-cyan" />
          </div>
          <div className="flex-1">
            <p className="text-sm font-semibold text-text-primary">Your Webhook Endpoints</p>
            <p className="text-xs text-text-muted mt-0.5 mb-3">
              Point your scanners to these URLs to start ingesting vulnerabilities automatically.
            </p>
            <div className="space-y-2">
              {[
                { label: "Trivy", path: "/webhooks/trivy" },
                { label: "Bandit", path: "/webhooks/bandit" },
                { label: "GitHub Security Alerts", path: "/webhooks/github" },
              ].map((wh) => (
                <div key={wh.path} className="flex items-center gap-2">
                  <span className="text-xs font-mono text-text-muted w-32 flex-shrink-0">{wh.label}:</span>
                  <code className="text-xs font-mono text-accent-cyan bg-bg-tertiary border border-border-subtle px-2 py-1 rounded flex-1">
                    https://your-backend.railway.app{wh.path}
                  </code>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* Integration cards by category */}
      {categories.map((category) => (
        <div key={category}>
          <h2 className="text-xs font-mono text-text-muted uppercase tracking-wider mb-3">
            {category}
          </h2>
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            {integrations
              .filter((i) => i.category === category)
              .map((integration) => {
                const Icon = integration.icon;
                const isComingSoon = integration.status === "coming_soon";

                return (
                  <div
                    key={integration.id}
                    className={`card flex items-start gap-4 ${isComingSoon ? "opacity-60" : ""}`}
                  >
                    <div
                      className={`w-10 h-10 rounded-xl border flex items-center justify-center flex-shrink-0 ${integration.bg} ${integration.border}`}
                    >
                      <Icon className={`w-5 h-5 ${integration.color}`} />
                    </div>

                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="text-sm font-semibold text-text-primary">
                          {integration.name}
                        </span>
                        <StatusPill status={integration.status} />
                      </div>
                      <p className="text-xs text-text-muted mt-0.5 leading-relaxed">
                        {integration.description}
                      </p>
                      {integration.details && (
                        <p className="text-[10px] font-mono text-text-muted/70 mt-1.5">
                          {integration.details}
                        </p>
                      )}
                      {integration.lastEvent && (
                        <div className="flex items-center gap-1 mt-1.5">
                          <span className="w-1.5 h-1.5 rounded-full bg-accent-emerald" />
                          <span className="text-[10px] text-text-muted font-mono">
                            Last event: {integration.lastEvent}
                          </span>
                        </div>
                      )}
                    </div>

                    {integration.docs && !isComingSoon && (
                      <a
                        href={integration.docs}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="p-1.5 text-text-muted hover:text-text-secondary transition-colors flex-shrink-0"
                        title="Documentation"
                      >
                        <ExternalLink className="w-3.5 h-3.5" />
                      </a>
                    )}
                  </div>
                );
              })}
          </div>
        </div>
      ))}
    </div>
  );
}
