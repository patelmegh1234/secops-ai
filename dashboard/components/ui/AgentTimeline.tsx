"use client";

import { clsx } from "clsx";
import type { AgentTrace, AgentName } from "@/lib/types";
import { CheckCircle2, XCircle, Loader2, Brain, Shield, Bug } from "lucide-react";

interface AgentTimelineProps {
  traces: AgentTrace[];
  className?: string;
}

const AGENT_CONFIG: Record<AgentName, {
  label: string;
  icon: React.ElementType;
  color: string;
  bg: string;
}> = {
  TRIAGE: {
    label: "Triage Analyst",
    icon: Bug,
    color: "text-accent-amber",
    bg: "bg-accent-amber/10 border-accent-amber/30",
  },
  PATCH: {
    label: "Patch Engineer",
    icon: Brain,
    color: "text-accent-cyan",
    bg: "bg-accent-cyan/10 border-accent-cyan/30",
  },
  GUARDRAIL: {
    label: "Security Auditor",
    icon: Shield,
    color: "text-accent-emerald",
    bg: "bg-accent-emerald/10 border-accent-emerald/30",
  },
};

export function AgentTimeline({ traces, className }: AgentTimelineProps) {
  if (!traces.length) {
    return (
      <div className={clsx("text-text-muted text-sm font-mono text-center py-6", className)}>
        No agent traces yet.
      </div>
    );
  }

  return (
    <div className={clsx("space-y-2", className)}>
      {traces.map((trace, index) => {
        const config = AGENT_CONFIG[trace.agent_name] || AGENT_CONFIG.TRIAGE;
        const AgentIcon = config.icon;

        return (
          <div
            key={trace.id}
            className={clsx(
              "flex gap-4 items-start p-3 rounded-lg border transition-all duration-200",
              config.bg,
              "hover:scale-[1.01]"
            )}
          >
            {/* Icon */}
            <div className={clsx("w-8 h-8 rounded-md border flex items-center justify-center flex-shrink-0", config.bg)}>
              <AgentIcon className={clsx("w-4 h-4", config.color)} />
            </div>

            {/* Content */}
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2 flex-wrap">
                <span className={clsx("text-xs font-mono font-semibold", config.color)}>
                  {config.label}
                </span>
                <span className="text-xs text-text-muted font-mono">
                  {trace.step}
                </span>
                {trace.success ? (
                  <CheckCircle2 className="w-3.5 h-3.5 text-accent-emerald ml-auto" />
                ) : (
                  <XCircle className="w-3.5 h-3.5 text-accent-rose ml-auto" />
                )}
              </div>
              <div className="flex items-center gap-4 mt-1 flex-wrap">
                <span className="text-xs text-text-muted font-mono">
                  {trace.model_used}
                </span>
                <span className="text-xs text-text-muted font-mono">
                  {trace.duration_ms}ms
                </span>
                <span className="text-xs text-text-muted font-mono">
                  {trace.input_tokens + trace.output_tokens} tokens
                </span>
                <span className="text-xs text-text-muted font-mono">
                  ~${trace.estimated_cost_usd.toFixed(4)}
                </span>
              </div>
              {trace.error_message && (
                <div className="mt-1 text-xs font-mono text-accent-rose truncate">
                  {trace.error_message}
                </div>
              )}
            </div>
          </div>
        );
      })}
    </div>
  );
}
