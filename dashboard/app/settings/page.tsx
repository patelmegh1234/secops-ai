import type { Metadata } from "next";
import {
  Key,
  Bell,
  Shield,
  RotateCcw,
  Trash2,
  Plus,
  ChevronRight,
  Info,
} from "lucide-react";

export const metadata: Metadata = {
  title: "Settings",
  description: "Workspace configuration, API keys, and guardrail settings.",
};

const MOCK_API_KEYS = [
  {
    id: "key-001",
    label: "CI/CD Pipeline",
    prefix: "gm_xK9m",
    createdAt: "2025-01-15",
    lastUsed: "2 minutes ago",
    status: "active" as const,
  },
  {
    id: "key-002",
    label: "Staging Monitor",
    prefix: "gm_pQ2r",
    createdAt: "2025-01-20",
    lastUsed: "1 hour ago",
    status: "active" as const,
  },
  {
    id: "key-003",
    label: "Local Dev",
    prefix: "gm_fJ8v",
    createdAt: "2024-12-01",
    lastUsed: "3 days ago",
    status: "active" as const,
  },
];

const GUARDRAIL_MODES = [
  {
    id: "strict",
    label: "Strict",
    description: "Max 50 diff lines. Blocks all config files. Full OWASP check.",
    recommended: false,
  },
  {
    id: "standard",
    label: "Standard",
    description: "Max 150 diff lines. Blocks secret files. OWASP check.",
    recommended: true,
  },
  {
    id: "permissive",
    label: "Permissive",
    description: "Max 300 diff lines. Allows config files. Basic check only.",
    recommended: false,
  },
];

function SectionCard({
  icon: Icon,
  title,
  description,
  children,
}: {
  icon: React.ComponentType<{ className?: string }>;
  title: string;
  description: string;
  children: React.ReactNode;
}) {
  return (
    <div className="card p-0 overflow-hidden">
      <div className="flex items-center gap-3 px-5 py-4 border-b border-border-subtle">
        <div className="w-8 h-8 rounded-lg bg-accent-cyan/10 border border-accent-cyan/20 flex items-center justify-center flex-shrink-0">
          <Icon className="w-4 h-4 text-accent-cyan" />
        </div>
        <div>
          <h2 className="text-sm font-semibold text-text-primary">{title}</h2>
          <p className="text-xs text-text-muted">{description}</p>
        </div>
      </div>
      <div className="px-5 py-4">{children}</div>
    </div>
  );
}

export default function SettingsPage() {
  return (
    <div className="space-y-5 animate-fade-in max-w-3xl">
      {/* Workspace info */}
      <SectionCard
        icon={Shield}
        title="Workspace"
        description="Your organization and plan details"
      >
        <div className="grid grid-cols-2 gap-4 text-sm">
          <div>
            <p className="text-xs text-text-muted mb-1">Organization Name</p>
            <p className="text-text-primary font-medium">Acme Corp</p>
          </div>
          <div>
            <p className="text-xs text-text-muted mb-1">Workspace Slug</p>
            <p className="font-mono text-accent-cyan">acme-corp</p>
          </div>
          <div>
            <p className="text-xs text-text-muted mb-1">Plan</p>
            <span className="inline-flex items-center gap-1 text-xs font-mono px-2 py-0.5 rounded bg-accent-amber/15 text-accent-amber border border-accent-amber/25">
              Free Plan
            </span>
          </div>
          <div>
            <p className="text-xs text-text-muted mb-1">Workspace ID</p>
            <p className="font-mono text-xs text-text-muted">ws_xk9mp2n...</p>
          </div>
        </div>
      </SectionCard>

      {/* API Keys */}
      <SectionCard
        icon={Key}
        title="API Keys"
        description="Keys used by CI/CD pipelines and external tools to send webhooks"
      >
        <div className="space-y-2 mb-4">
          {MOCK_API_KEYS.map((key) => (
            <div
              key={key.id}
              className="flex items-center gap-3 p-3 rounded-lg bg-bg-secondary border border-border-subtle hover:border-accent-cyan/20 transition-colors"
            >
              <div className="w-2 h-2 rounded-full bg-accent-emerald flex-shrink-0" />
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2">
                  <span className="text-sm font-medium text-text-primary">{key.label}</span>
                </div>
                <div className="flex items-center gap-3 mt-0.5">
                  <span className="text-[10px] font-mono text-text-muted">{key.prefix}••••••••</span>
                  <span className="text-[10px] text-text-muted">Last used: {key.lastUsed}</span>
                </div>
              </div>
              <div className="flex items-center gap-1">
                <button
                  className="p-1.5 text-text-muted hover:text-accent-amber transition-colors rounded"
                  title="Rotate key"
                >
                  <RotateCcw className="w-3.5 h-3.5" />
                </button>
                <button
                  className="p-1.5 text-text-muted hover:text-accent-rose transition-colors rounded"
                  title="Revoke key"
                >
                  <Trash2 className="w-3.5 h-3.5" />
                </button>
              </div>
            </div>
          ))}
        </div>
        <button className="flex items-center gap-2 text-sm text-accent-cyan hover:text-accent-cyan/80 transition-colors font-medium">
          <Plus className="w-3.5 h-3.5" />
          Create new API key
        </button>
      </SectionCard>

      {/* Guardrail mode */}
      <SectionCard
        icon={Shield}
        title="Guardrail Configuration"
        description="Controls how strictly the AI validates generated patches before sending to Slack"
      >
        <div className="space-y-2">
          {GUARDRAIL_MODES.map((mode) => (
            <label
              key={mode.id}
              className={`flex items-start gap-3 p-3.5 rounded-lg border cursor-pointer transition-all ${
                mode.id === "standard"
                  ? "bg-accent-cyan/5 border-accent-cyan/25"
                  : "bg-bg-secondary border-border-subtle hover:border-accent-cyan/15"
              }`}
            >
              <input
                type="radio"
                name="guardrail"
                value={mode.id}
                defaultChecked={mode.id === "standard"}
                className="mt-1 accent-cyan-400"
              />
              <div className="flex-1">
                <div className="flex items-center gap-2">
                  <span className="text-sm font-semibold text-text-primary">{mode.label}</span>
                  {mode.recommended && (
                    <span className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-accent-cyan/15 text-accent-cyan border border-accent-cyan/25 uppercase tracking-wider">
                      Recommended
                    </span>
                  )}
                </div>
                <p className="text-xs text-text-muted mt-0.5">{mode.description}</p>
              </div>
            </label>
          ))}
        </div>
      </SectionCard>

      {/* Notifications */}
      <SectionCard
        icon={Bell}
        title="Notification Preferences"
        description="When GuardMind should send Slack alerts"
      >
        <div className="space-y-3">
          {[
            { label: "Critical vulnerabilities detected", default: true },
            { label: "Patch ready for Slack approval", default: true },
            { label: "Sandbox test failure", default: true },
            { label: "PR merged successfully", default: false },
            { label: "Daily remediation summary", default: false },
          ].map((pref) => (
            <div key={pref.label} className="flex items-center justify-between">
              <span className="text-sm text-text-secondary">{pref.label}</span>
              <button
                className={`w-10 h-5 rounded-full border transition-colors ${
                  pref.default
                    ? "bg-accent-emerald/80 border-accent-emerald"
                    : "bg-bg-secondary border-border-subtle"
                }`}
              >
                <span
                  className={`block w-4 h-4 rounded-full bg-white transition-transform mx-0.5 ${
                    pref.default ? "translate-x-4" : "translate-x-0"
                  }`}
                />
              </button>
            </div>
          ))}
        </div>
      </SectionCard>

      {/* Danger zone */}
      <div className="card border-accent-rose/20 bg-accent-rose/3">
        <div className="flex items-start gap-3">
          <Info className="w-4 h-4 text-accent-rose mt-0.5 flex-shrink-0" />
          <div className="flex-1">
            <h3 className="text-sm font-semibold text-accent-rose mb-1">Danger Zone</h3>
            <p className="text-xs text-text-muted mb-3">
              These actions are irreversible. Proceed with caution.
            </p>
            <div className="flex gap-2">
              <button className="btn-danger text-xs px-3 py-1.5">
                Reset Workspace
              </button>
              <button className="btn-ghost text-xs px-3 py-1.5 text-accent-rose border-accent-rose/30 hover:border-accent-rose">
                Delete All Data
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
