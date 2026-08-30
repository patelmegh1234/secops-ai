"use client";

import { useState } from "react";
import { CheckCircle2, Circle, ChevronDown, ChevronRight, Copy, Check, ExternalLink, Zap } from "lucide-react";

const BACKEND_URL = process.env.NEXT_PUBLIC_API_URL || "https://api-production-ac9f.up.railway.app";

interface Step {
  id: string;
  title: string;
  description: string;
  required: boolean;
  envVars?: { key: string; description: string; example: string; link?: string }[];
  command?: string;
  note?: string;
}

const SETUP_STEPS: Step[] = [
  {
    id: "openai",
    title: "Connect OpenAI API",
    description: "Powers the Triage Agent (GPT-4o-mini) and Patch Agent (GPT-4o).",
    required: true,
    envVars: [
      {
        key: "OPENAI_API_KEY",
        description: "Your OpenAI API key",
        example: "sk-proj-...",
        link: "https://platform.openai.com/api-keys",
      },
    ],
  },
  {
    id: "github",
    title: "Connect GitHub",
    description: "Allows GuardMind to create branches and open Pull Requests with verified fixes.",
    required: true,
    envVars: [
      {
        key: "GITHUB_TOKEN",
        description: "Personal Access Token with repo write scope",
        example: "ghp_...",
        link: "https://github.com/settings/tokens/new?scopes=repo",
      },
      {
        key: "GITHUB_DEFAULT_OWNER",
        description: "Your GitHub username or org",
        example: "your-username",
      },
      {
        key: "GITHUB_DEFAULT_REPO",
        description: "Target repository name",
        example: "my-api",
      },
    ],
  },
  {
    id: "slack",
    title: "Connect Slack (Human Approval)",
    description: "Sends interactive patch approval cards to your security team before any PR is opened.",
    required: true,
    envVars: [
      {
        key: "SLACK_BOT_TOKEN",
        description: "Bot token from your Slack app (starts with xoxb-)",
        example: "xoxb-...",
        link: "https://api.slack.com/apps",
      },
      {
        key: "SLACK_ALERT_CHANNEL_ID",
        description: "Channel ID where approval requests are sent",
        example: "C0123456789",
      },
    ],
    note: "Create a Slack App at api.slack.com/apps, add the `chat:write` and `chat:write.public` Bot Token scopes, install to workspace, then copy the Bot Token.",
  },
  {
    id: "scanner",
    title: "Send Your First Scan",
    description: "Run Trivy or Bandit on your codebase and forward results to GuardMind.",
    required: false,
    command: `# Install Trivy
brew install trivy  # macOS
# or: https://aquasecurity.github.io/trivy/

# Scan & forward to GuardMind
python scripts/send_trivy_report.py \\
  --target ./your-app \\
  --scan-type fs \\
  --api-url ${BACKEND_URL}`,
    note: "Or use the demo trigger: POST /api/demo/trigger-scan to test the full pipeline without a real scanner.",
  },
  {
    id: "demo",
    title: "Fire a Demo Run",
    description: "Test the full pipeline end-to-end without setting up a real scanner.",
    required: false,
    command: `curl -X POST "${BACKEND_URL}/api/demo/trigger-scan?scanner=trivy" \\
  -H "Content-Type: application/json"`,
  },
];

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      onClick={() => {
        navigator.clipboard.writeText(text);
        setCopied(true);
        setTimeout(() => setCopied(false), 2000);
      }}
      style={{
        background: "none", border: "none", cursor: "pointer",
        color: copied ? "#34d399" : "#64748b",
        padding: "0.25rem", borderRadius: 4,
        display: "flex", alignItems: "center", gap: "0.25rem",
        fontSize: "0.75rem", transition: "color 0.2s"
      }}
      title="Copy"
    >
      {copied ? <Check size={13} /> : <Copy size={13} />}
    </button>
  );
}

function SetupStep({ step, index }: { step: Step; index: number }) {
  const [open, setOpen] = useState(index === 0);

  return (
    <div style={{
      border: "1px solid rgba(255,255,255,0.06)",
      borderRadius: 10,
      overflow: "hidden",
      background: open ? "rgba(255,255,255,0.02)" : "transparent",
    }}>
      <button
        onClick={() => setOpen(!open)}
        style={{
          width: "100%", display: "flex", alignItems: "center", gap: "0.75rem",
          padding: "0.875rem 1rem", background: "none", border: "none",
          cursor: "pointer", textAlign: "left",
        }}
      >
        <span style={{
          width: 22, height: 22, borderRadius: "50%",
          background: "rgba(99,102,241,0.15)", border: "1px solid rgba(99,102,241,0.3)",
          display: "flex", alignItems: "center", justifyContent: "center",
          fontSize: "0.7rem", fontWeight: 700, color: "#818cf8", flexShrink: 0
        }}>
          {index + 1}
        </span>
        <span style={{ flex: 1, fontSize: "0.9rem", fontWeight: 600, color: "#e2e8f0" }}>
          {step.title}
          {!step.required && (
            <span style={{
              marginLeft: "0.5rem", fontSize: "0.65rem", padding: "1px 6px",
              borderRadius: 100, background: "rgba(255,255,255,0.06)",
              color: "#64748b", fontWeight: 500
            }}>Optional</span>
          )}
        </span>
        {open ? <ChevronDown size={15} color="#475569" /> : <ChevronRight size={15} color="#475569" />}
      </button>

      {open && (
        <div style={{ padding: "0 1rem 1rem 3.25rem" }}>
          <p style={{ fontSize: "0.8rem", color: "#64748b", marginBottom: "1rem", lineHeight: 1.6 }}>
            {step.description}
          </p>

          {step.envVars?.map((v) => (
            <div key={v.key} style={{
              marginBottom: "0.75rem",
              background: "rgba(0,0,0,0.3)",
              borderRadius: 8, padding: "0.75rem",
              border: "1px solid rgba(255,255,255,0.05)"
            }}>
              <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "0.3rem" }}>
                <code style={{ fontSize: "0.8rem", color: "#a78bfa", fontFamily: "'JetBrains Mono', monospace" }}>
                  {v.key}
                </code>
                <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
                  {v.link && (
                    <a href={v.link} target="_blank" rel="noreferrer"
                      style={{ color: "#475569", display: "flex", alignItems: "center" }}>
                      <ExternalLink size={12} />
                    </a>
                  )}
                  <CopyButton text={v.key} />
                </div>
              </div>
              <p style={{ fontSize: "0.75rem", color: "#64748b", margin: "0 0 0.25rem" }}>{v.description}</p>
              <code style={{ fontSize: "0.7rem", color: "#334155", fontFamily: "'JetBrains Mono', monospace" }}>
                e.g. {v.example}
              </code>
            </div>
          ))}

          {step.command && (
            <div style={{
              background: "#0d1117", borderRadius: 8, overflow: "hidden",
              border: "1px solid rgba(255,255,255,0.06)", marginBottom: "0.75rem"
            }}>
              <div style={{
                display: "flex", justifyContent: "space-between", alignItems: "center",
                padding: "0.4rem 0.75rem",
                background: "#161b22", borderBottom: "1px solid rgba(255,255,255,0.04)"
              }}>
                <span style={{ fontSize: "0.7rem", color: "#484f58" }}>shell</span>
                <CopyButton text={step.command} />
              </div>
              <pre style={{
                padding: "0.875rem 0.875rem", margin: 0,
                fontSize: "0.75rem", lineHeight: 1.7,
                color: "#8b949e", overflowX: "auto",
                fontFamily: "'JetBrains Mono', monospace"
              }}>
                {step.command}
              </pre>
            </div>
          )}

          {step.note && (
            <p style={{
              fontSize: "0.75rem", color: "#475569", lineHeight: 1.6,
              padding: "0.5rem 0.75rem",
              background: "rgba(255,255,255,0.02)", borderRadius: 6,
              border: "1px solid rgba(255,255,255,0.04)"
            }}>
              💡 {step.note}
            </p>
          )}
        </div>
      )}
    </div>
  );
}

export function SetupWizard() {
  const [triggering, setTriggering] = useState(false);
  const [triggerResult, setTriggerResult] = useState<string | null>(null);

  const triggerDemo = async () => {
    setTriggering(true);
    setTriggerResult(null);
    try {
      const res = await fetch(`${BACKEND_URL}/api/demo/trigger-scan?scanner=trivy`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
      });
      const data = await res.json();
      setTriggerResult(data.message || data.status || "Triggered");
    } catch {
      setTriggerResult("Backend not reachable. Set NEXT_PUBLIC_API_URL in Vercel.");
    } finally {
      setTriggering(false);
    }
  };

  return (
    <div style={{
      borderRadius: 14, overflow: "hidden",
      border: "1px solid rgba(99,102,241,0.2)",
      background: "linear-gradient(180deg, rgba(99,102,241,0.04) 0%, rgba(8,11,18,0) 100%)"
    }}>
      {/* Header */}
      <div style={{
        padding: "1.25rem 1.5rem",
        borderBottom: "1px solid rgba(255,255,255,0.06)",
        display: "flex", alignItems: "center", justifyContent: "space-between"
      }}>
        <div>
          <h2 style={{ fontWeight: 700, fontSize: "1rem", margin: 0, color: "#e2e8f0" }}>
            Quick Setup Guide
          </h2>
          <p style={{ fontSize: "0.8rem", color: "#64748b", margin: "0.25rem 0 0" }}>
            Connect your integrations to start the autonomous remediation pipeline
          </p>
        </div>
        <button
          onClick={triggerDemo}
          disabled={triggering}
          style={{
            display: "flex", alignItems: "center", gap: "0.4rem",
            padding: "0.5rem 1rem",
            background: triggering ? "rgba(99,102,241,0.1)" : "rgba(99,102,241,0.15)",
            border: "1px solid rgba(99,102,241,0.3)",
            borderRadius: 8, cursor: triggering ? "wait" : "pointer",
            color: "#818cf8", fontSize: "0.8rem", fontWeight: 600,
            transition: "all 0.2s"
          }}
        >
          <Zap size={13} />
          {triggering ? "Triggering..." : "Fire Demo Run"}
        </button>
      </div>

      {triggerResult && (
        <div style={{
          padding: "0.75rem 1.5rem", fontSize: "0.8rem",
          background: "rgba(16,185,129,0.08)", color: "#34d399",
          borderBottom: "1px solid rgba(16,185,129,0.15)"
        }}>
          ✓ {triggerResult}
        </div>
      )}

      {/* Steps */}
      <div style={{ padding: "1rem 1.25rem", display: "flex", flexDirection: "column", gap: "0.5rem" }}>
        {SETUP_STEPS.map((step, i) => (
          <SetupStep key={step.id} step={step} index={i} />
        ))}
      </div>
    </div>
  );
}
