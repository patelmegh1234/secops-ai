"use client";

import Link from "next/link";
import { useEffect, useState } from "react";

const FEATURES = [
  {
    icon: "⚡",
    title: "Alert → Patch in < 5 Minutes",
    desc: "From CVE webhook to a verified, human-approved GitHub PR. Zero manual triage.",
  },
  {
    icon: "🛡️",
    title: "Hardened Sandbox Verification",
    desc: "Every AI patch runs your full test suite in an isolated Docker container before any human sees it.",
  },
  {
    icon: "🔄",
    title: "Self-Healing Retry Loop",
    desc: "When tests fail, the agent reads the stack trace and writes a better fix—automatically.",
  },
  {
    icon: "🔐",
    title: "Secret Scanner in Guardrail",
    desc: "15+ secret patterns + Shannon entropy detection stop credentials from reaching version control.",
  },
  {
    icon: "👤",
    title: "Human-in-the-Loop Approval",
    desc: "Slack interactive buttons with unified diff preview. You stay in control—always.",
  },
  {
    icon: "📊",
    title: "Real MTTR Telemetry",
    desc: "6 staged timestamps per vulnerability. Know exactly where time is spent—triage, patch, or review.",
  },
];

const SCANNERS = ["Trivy", "Bandit", "GitHub Alerts", "Custom SAST"];

const PIPELINE_STEPS = [
  { label: "Triage", color: "#6366f1", time: "~3s" },
  { label: "Patch Gen", color: "#8b5cf6", time: "~18s" },
  { label: "Sandbox", color: "#ec4899", time: "~8s" },
  { label: "Guardrail", color: "#f59e0b", time: "~4s" },
  { label: "Slack → PR", color: "#10b981", time: "~6s" },
];

function AnimatedCounter({ target, suffix = "" }: { target: number; suffix?: string }) {
  const [count, setCount] = useState(0);
  useEffect(() => {
    const step = Math.ceil(target / 60);
    const interval = setInterval(() => {
      setCount((prev) => {
        if (prev + step >= target) {
          clearInterval(interval);
          return target;
        }
        return prev + step;
      });
    }, 25);
    return () => clearInterval(interval);
  }, [target]);
  return <span>{count}{suffix}</span>;
}

export default function LandingPage() {
  const [activePipeline, setActivePipeline] = useState(0);

  useEffect(() => {
    const interval = setInterval(() => {
      setActivePipeline((p) => (p + 1) % PIPELINE_STEPS.length);
    }, 1200);
    return () => clearInterval(interval);
  }, []);

  return (
    <div style={{ background: "#080b12", color: "#e2e8f0", fontFamily: "'Inter', sans-serif", minHeight: "100vh" }}>

      {/* ─── Nav ─────────────────────────────────────────────────────────────── */}
      <nav style={{
        display: "flex", alignItems: "center", justifyContent: "space-between",
        padding: "1rem 2rem", borderBottom: "1px solid rgba(255,255,255,0.06)",
        backdropFilter: "blur(12px)", position: "sticky", top: 0, zIndex: 50,
        background: "rgba(8,11,18,0.85)"
      }}>
        <div style={{ display: "flex", alignItems: "center", gap: "0.6rem" }}>
          <div style={{
            width: 32, height: 32, borderRadius: 8,
            background: "linear-gradient(135deg, #6366f1, #8b5cf6)",
            display: "flex", alignItems: "center", justifyContent: "center",
            fontSize: 16
          }}>🛡️</div>
          <span style={{ fontWeight: 700, fontSize: "1.1rem", letterSpacing: "-0.02em" }}>GuardMind</span>
          <span style={{
            fontSize: "0.65rem", fontWeight: 600, padding: "2px 8px",
            borderRadius: 100, background: "rgba(99,102,241,0.15)",
            color: "#818cf8", border: "1px solid rgba(99,102,241,0.3)"
          }}>BETA</span>
        </div>
        <div style={{ display: "flex", gap: "2rem", fontSize: "0.875rem", color: "#94a3b8" }}>
          <a href="#features" style={{ color: "inherit", textDecoration: "none" }}>Features</a>
          <a href="#how-it-works" style={{ color: "inherit", textDecoration: "none" }}>How it works</a>
          <a href="https://github.com/patelmegh1234/secops-ai" target="_blank" rel="noreferrer" style={{ color: "inherit", textDecoration: "none" }}>GitHub</a>
        </div>
        <Link href="/dashboard" style={{
          background: "linear-gradient(135deg, #6366f1, #8b5cf6)",
          color: "#fff", textDecoration: "none", padding: "0.5rem 1.25rem",
          borderRadius: 8, fontSize: "0.875rem", fontWeight: 600,
          boxShadow: "0 0 20px rgba(99,102,241,0.4)"
        }}>
          Open Dashboard →
        </Link>
      </nav>

      {/* ─── Hero ────────────────────────────────────────────────────────────── */}
      <section style={{ textAlign: "center", padding: "7rem 2rem 5rem" }}>
        <div style={{
          display: "inline-flex", alignItems: "center", gap: "0.5rem",
          padding: "0.4rem 1rem", borderRadius: 100,
          background: "rgba(16,185,129,0.1)", border: "1px solid rgba(16,185,129,0.25)",
          color: "#34d399", fontSize: "0.8rem", fontWeight: 600, marginBottom: "2rem"
        }}>
          <span style={{ width: 7, height: 7, borderRadius: "50%", background: "#10b981", display: "inline-block" }} />
          Active · CVE-to-PR pipeline running
        </div>

        <h1 style={{
          fontSize: "clamp(2.5rem, 6vw, 4.5rem)", fontWeight: 800,
          lineHeight: 1.1, letterSpacing: "-0.04em", marginBottom: "1.5rem",
          background: "linear-gradient(135deg, #e2e8f0 30%, #94a3b8)",
          WebkitBackgroundClip: "text", WebkitTextFillColor: "transparent"
        }}>
          Your security scanner found a bug.<br />
          <span style={{
            background: "linear-gradient(135deg, #6366f1, #a78bfa)",
            WebkitBackgroundClip: "text", WebkitTextFillColor: "transparent"
          }}>
            GuardMind already fixed it.
          </span>
        </h1>

        <p style={{
          fontSize: "1.2rem", color: "#94a3b8", maxWidth: 620, margin: "0 auto 3rem",
          lineHeight: 1.7
        }}>
          Autonomous AI agent that ingests CVE alerts, writes a verified patch, 
          tests it in a hardened sandbox, and opens a GitHub PR — with your approval via Slack.
        </p>

        <div style={{ display: "flex", gap: "1rem", justifyContent: "center", flexWrap: "wrap" }}>
          <Link href="/dashboard" style={{
            background: "linear-gradient(135deg, #6366f1, #8b5cf6)",
            color: "#fff", textDecoration: "none", padding: "0.875rem 2rem",
            borderRadius: 10, fontSize: "1rem", fontWeight: 700,
            boxShadow: "0 0 40px rgba(99,102,241,0.5)",
            transition: "transform 0.15s", display: "inline-block"
          }}>
            Open Command Center
          </Link>
          <a href="https://github.com/patelmegh1234/secops-ai" target="_blank" rel="noreferrer" style={{
            background: "rgba(255,255,255,0.05)", border: "1px solid rgba(255,255,255,0.12)",
            color: "#e2e8f0", textDecoration: "none", padding: "0.875rem 2rem",
            borderRadius: 10, fontSize: "1rem", fontWeight: 600,
            display: "inline-block"
          }}>
            ⭐ Star on GitHub
          </a>
        </div>

        {/* Scanner badges */}
        <div style={{ marginTop: "3rem", display: "flex", gap: "0.75rem", justifyContent: "center", flexWrap: "wrap" }}>
          <span style={{ fontSize: "0.8rem", color: "#64748b" }}>Works with</span>
          {SCANNERS.map((s) => (
            <span key={s} style={{
              padding: "0.3rem 0.75rem", borderRadius: 100,
              background: "rgba(255,255,255,0.04)", border: "1px solid rgba(255,255,255,0.08)",
              fontSize: "0.8rem", color: "#94a3b8"
            }}>{s}</span>
          ))}
        </div>
      </section>

      {/* ─── Stats ───────────────────────────────────────────────────────────── */}
      <section style={{
        display: "flex", gap: "2px", maxWidth: 800, margin: "0 auto 6rem",
        padding: "0 2rem"
      }}>
        {[
          { value: 5, suffix: " min", label: "Avg. time to PR" },
          { value: 95, suffix: "%", label: "Sandbox pass rate" },
          { value: 15, suffix: "+", label: "Secret types detected" },
          { value: 90, suffix: "+", label: "Unit tests" },
        ].map((stat, i) => (
          <div key={i} style={{
            flex: 1, textAlign: "center", padding: "2rem 1rem",
            background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.06)",
            borderRadius: i === 0 ? "12px 0 0 12px" : i === 3 ? "0 12px 12px 0" : 0
          }}>
            <div style={{ fontSize: "2.25rem", fontWeight: 800, color: "#a78bfa" }}>
              <AnimatedCounter target={stat.value} suffix={stat.suffix} />
            </div>
            <div style={{ fontSize: "0.8rem", color: "#64748b", marginTop: "0.25rem" }}>{stat.label}</div>
          </div>
        ))}
      </section>

      {/* ─── Live Pipeline Visualization ─────────────────────────────────────── */}
      <section id="how-it-works" style={{ maxWidth: 900, margin: "0 auto 6rem", padding: "0 2rem" }}>
        <h2 style={{ textAlign: "center", fontSize: "1.75rem", fontWeight: 700, marginBottom: "0.75rem", letterSpacing: "-0.02em" }}>
          From alert to PR in one automated pipeline
        </h2>
        <p style={{ textAlign: "center", color: "#64748b", marginBottom: "3rem", fontSize: "0.95rem" }}>
          Every stage is measured, logged, and observable. Nothing is a black box.
        </p>

        <div style={{ display: "flex", alignItems: "center", gap: "0.5rem", overflowX: "auto", paddingBottom: "1rem" }}>
          {/* Webhook input */}
          <div style={{
            padding: "0.75rem 1rem", borderRadius: 8,
            background: "rgba(255,255,255,0.04)", border: "1px solid rgba(255,255,255,0.08)",
            fontSize: "0.8rem", color: "#64748b", whiteSpace: "nowrap"
          }}>
            🔔 Scanner Webhook
          </div>

          {PIPELINE_STEPS.map((step, i) => (
            <div key={step.label} style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
              <span style={{ color: "#334155", fontSize: "1.2rem" }}>→</span>
              <div style={{
                padding: "0.75rem 1.25rem", borderRadius: 10, whiteSpace: "nowrap",
                background: activePipeline === i ? `${step.color}20` : "rgba(255,255,255,0.03)",
                border: `1px solid ${activePipeline === i ? step.color + "60" : "rgba(255,255,255,0.06)"}`,
                boxShadow: activePipeline === i ? `0 0 20px ${step.color}30` : "none",
                transition: "all 0.3s ease",
                cursor: "default"
              }}>
                <div style={{ fontSize: "0.875rem", fontWeight: 600, color: activePipeline === i ? "#e2e8f0" : "#64748b" }}>
                  {step.label}
                </div>
                <div style={{ fontSize: "0.7rem", color: activePipeline === i ? step.color : "#334155", marginTop: 2 }}>
                  {step.time}
                </div>
              </div>
            </div>
          ))}

          <span style={{ color: "#334155", fontSize: "1.2rem" }}>→</span>
          <div style={{
            padding: "0.75rem 1rem", borderRadius: 8,
            background: "rgba(16,185,129,0.08)", border: "1px solid rgba(16,185,129,0.25)",
            fontSize: "0.8rem", color: "#34d399", whiteSpace: "nowrap"
          }}>
            ✓ GitHub PR
          </div>
        </div>

        {/* Code terminal mockup */}
        <div style={{
          marginTop: "2.5rem", borderRadius: 12, overflow: "hidden",
          border: "1px solid rgba(255,255,255,0.08)",
          background: "#0d1117"
        }}>
          <div style={{
            padding: "0.75rem 1rem", background: "#161b22",
            borderBottom: "1px solid rgba(255,255,255,0.06)",
            display: "flex", gap: "0.4rem", alignItems: "center"
          }}>
            <div style={{ width: 12, height: 12, borderRadius: "50%", background: "#ff5f57" }} />
            <div style={{ width: 12, height: 12, borderRadius: "50%", background: "#febc2e" }} />
            <div style={{ width: 12, height: 12, borderRadius: "50%", background: "#28c840" }} />
            <span style={{ marginLeft: "0.5rem", fontSize: "0.8rem", color: "#484f58" }}>guardmind — patch agent</span>
          </div>
          <pre style={{
            padding: "1.5rem", margin: 0, fontSize: "0.8rem", lineHeight: 1.7,
            color: "#8b949e", overflowX: "auto", fontFamily: "'JetBrains Mono', monospace"
          }}>{`[15:02:01] ✓ Webhook received: CVE-2024-23917 (CRITICAL) · repo: acme-corp/api
[15:02:03] → Triage Agent (GPT-4o-mini): SQL injection in auth.py:L47 — CONFIRMED
[15:02:21] → Patch Agent (GPT-4o): Generated 23-line fix for parameterized query
[15:02:24] → Secret Scanner: No credentials detected ✓
[15:02:24] → Scope Check: 23 lines, path safe ✓
[15:02:26] → Guardrail (GPT-4o-mini): Patch is logically correct, OWASP A03 resolved ✓
[15:02:34] → Sandbox: Running pytest (18 tests) in hardened container...
[15:02:42] ✓ Sandbox PASSED (18/18 tests, 8.2s)
[15:02:43] → Slack: Approval request sent to #security-team
[15:06:11] → Engineer approved patch (4m 28s human review)
[15:06:18] ✓ GitHub PR #847 opened: fix(auth): parameterize SQL query to prevent injection`}</pre>
        </div>
      </section>

      {/* ─── Features Grid ───────────────────────────────────────────────────── */}
      <section id="features" style={{ maxWidth: 1100, margin: "0 auto 6rem", padding: "0 2rem" }}>
        <h2 style={{ textAlign: "center", fontSize: "1.75rem", fontWeight: 700, marginBottom: "0.75rem", letterSpacing: "-0.02em" }}>
          Built for production. Not a demo.
        </h2>
        <p style={{ textAlign: "center", color: "#64748b", marginBottom: "3rem" }}>
          Every feature exists because a real attack vector required it.
        </p>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(300px, 1fr))", gap: "1px", border: "1px solid rgba(255,255,255,0.06)", borderRadius: 16, overflow: "hidden" }}>
          {FEATURES.map((f) => (
            <div key={f.title} style={{
              padding: "2rem", background: "rgba(255,255,255,0.02)",
              borderRight: "1px solid rgba(255,255,255,0.06)",
              borderBottom: "1px solid rgba(255,255,255,0.06)",
              transition: "background 0.2s"
            }}>
              <div style={{ fontSize: "1.75rem", marginBottom: "0.75rem" }}>{f.icon}</div>
              <h3 style={{ fontWeight: 700, marginBottom: "0.5rem", fontSize: "1rem", color: "#e2e8f0" }}>{f.title}</h3>
              <p style={{ color: "#64748b", fontSize: "0.875rem", lineHeight: 1.6, margin: 0 }}>{f.desc}</p>
            </div>
          ))}
        </div>
      </section>

      {/* ─── VS Comparison ───────────────────────────────────────────────────── */}
      <section style={{ maxWidth: 800, margin: "0 auto 6rem", padding: "0 2rem" }}>
        <h2 style={{ textAlign: "center", fontSize: "1.75rem", fontWeight: 700, marginBottom: "3rem", letterSpacing: "-0.02em" }}>
          How GuardMind compares
        </h2>
        <div style={{ border: "1px solid rgba(255,255,255,0.08)", borderRadius: 12, overflow: "hidden" }}>
          <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "0.875rem" }}>
            <thead>
              <tr style={{ background: "rgba(255,255,255,0.04)" }}>
                <th style={{ padding: "1rem 1.5rem", textAlign: "left", color: "#64748b", fontWeight: 600, borderBottom: "1px solid rgba(255,255,255,0.06)" }}>Capability</th>
                <th style={{ padding: "1rem 1.5rem", textAlign: "center", color: "#a78bfa", fontWeight: 700, borderBottom: "1px solid rgba(255,255,255,0.06)" }}>GuardMind</th>
                <th style={{ padding: "1rem 1.5rem", textAlign: "center", color: "#64748b", fontWeight: 600, borderBottom: "1px solid rgba(255,255,255,0.06)" }}>Dependabot / Snyk</th>
              </tr>
            </thead>
            <tbody>
              {[
                ["Writes the actual fix", "✅ Custom code patch", "❌ Version bump only"],
                ["Tests fix before you see it", "✅ Sandboxed test run", "❌ No verification"],
                ["Self-corrects on test failure", "✅ Trace feedback loop", "❌ No feedback"],
                ["Blocks secrets in patches", "✅ 15+ pattern scanner", "❌ Not applicable"],
                ["Human approval before merge", "✅ Slack interactive", "❌ PR immediately"],
                ["Per-stage latency metrics", "✅ 6-stage MTTR", "❌ Black box"],
              ].map(([cap, ours, theirs]) => (
                <tr key={cap} style={{ borderBottom: "1px solid rgba(255,255,255,0.04)" }}>
                  <td style={{ padding: "0.875rem 1.5rem", color: "#94a3b8" }}>{cap}</td>
                  <td style={{ padding: "0.875rem 1.5rem", textAlign: "center", color: "#34d399", fontWeight: 500 }}>{ours}</td>
                  <td style={{ padding: "0.875rem 1.5rem", textAlign: "center", color: "#64748b" }}>{theirs}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      {/* ─── CTA ─────────────────────────────────────────────────────────────── */}
      <section style={{
        textAlign: "center", padding: "5rem 2rem",
        background: "linear-gradient(180deg, transparent, rgba(99,102,241,0.08))",
        borderTop: "1px solid rgba(255,255,255,0.06)"
      }}>
        <h2 style={{ fontSize: "2rem", fontWeight: 800, marginBottom: "1rem", letterSpacing: "-0.03em" }}>
          Ready to automate your vuln pipeline?
        </h2>
        <p style={{ color: "#64748b", marginBottom: "2.5rem", fontSize: "1rem" }}>
          Open the command center and connect your first scanner in minutes.
        </p>
        <Link href="/dashboard" style={{
          background: "linear-gradient(135deg, #6366f1, #8b5cf6)",
          color: "#fff", textDecoration: "none", padding: "1rem 2.5rem",
          borderRadius: 10, fontSize: "1.1rem", fontWeight: 700,
          boxShadow: "0 0 60px rgba(99,102,241,0.5)",
          display: "inline-block"
        }}>
          Open Dashboard →
        </Link>
      </section>

      {/* ─── Footer ──────────────────────────────────────────────────────────── */}
      <footer style={{
        textAlign: "center", padding: "2rem", fontSize: "0.8rem",
        color: "#334155", borderTop: "1px solid rgba(255,255,255,0.04)"
      }}>
        <span>GuardMind © 2026 · </span>
        <a href="https://github.com/patelmegh1234/secops-ai" target="_blank" rel="noreferrer"
          style={{ color: "#475569", textDecoration: "none" }}>
          Open Source on GitHub
        </a>
        <span> · Built with FastAPI, Next.js 15, CrewAI</span>
      </footer>
    </div>
  );
}
