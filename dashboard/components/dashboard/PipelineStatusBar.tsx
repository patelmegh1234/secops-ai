"use client";

import { useEffect, useState } from "react";
import { listIncidents } from "@/lib/api";
import type { VulnerabilityStatus } from "@/lib/types";

const PIPELINE_STAGES: {
  key: VulnerabilityStatus;
  label: string;
  color: string;
}[] = [
  { key: "TRIAGING", label: "Triaging", color: "bg-text-muted" },
  { key: "PATCHING", label: "Patching", color: "bg-accent-cyan" },
  { key: "SANDBOX_PASSED", label: "Sandbox ✓", color: "bg-accent-emerald" },
  { key: "SANDBOX_FAILED", label: "Sandbox ✗", color: "bg-accent-rose" },
  { key: "AWAITING_APPROVAL", label: "Awaiting", color: "bg-accent-amber" },
  { key: "PR_OPENED", label: "PR Open", color: "bg-accent-emerald" },
  { key: "PR_MERGED", label: "Merged", color: "bg-text-muted/50" },
];

interface PipelineStatusBarProps {
  /** True when getMetrics() returned null (backend not reachable) */
  backendOffline: boolean;
}

export function PipelineStatusBar({ backendOffline }: PipelineStatusBarProps) {
  const [counts, setCounts] = useState<Record<string, number>>({});
  const [total, setTotal] = useState(0);
  const [loaded, setLoaded] = useState(false);

  useEffect(() => {
    if (backendOffline) {
      setLoaded(true);
      return;
    }
    // Fetch a large slice; counts derived client-side from the items
    listIncidents({ limit: 200 }).then((data) => {
      const c: Record<string, number> = {};
      data.items.forEach((i) => {
        c[i.status] = (c[i.status] ?? 0) + 1;
      });
      setCounts(c);
      setTotal(data.total);
      setLoaded(true);
    });
  }, [backendOffline]);

  return (
    <div className="card p-0 overflow-hidden">
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-3 border-b border-border-subtle">
        <span className="text-sm font-semibold text-text-primary">
          Pipeline Overview
        </span>
        <span className="text-xs font-mono text-text-muted">
          {backendOffline
            ? "No backend connected"
            : loaded
            ? `${total} total incident${total !== 1 ? "s" : ""}`
            : "Loading…"}
        </span>
      </div>

      {/* Stage columns */}
      <div className="grid grid-cols-7 divide-x divide-border-subtle">
        {PIPELINE_STAGES.map((stage) => {
          const count = backendOffline ? null : (counts[stage.key] ?? 0);
          const pct =
            !backendOffline && total > 0 && count !== null
              ? Math.round((count / total) * 100)
              : 0;

          return (
            <div
              key={stage.key}
              className="px-3 py-3 flex flex-col items-center gap-1.5 hover:bg-bg-hover transition-colors cursor-default"
            >
              <div className="text-[10px] font-mono text-text-muted text-center leading-tight">
                {stage.label}
              </div>

              <div className="text-lg font-bold font-mono text-text-primary">
                {count !== null ? count : "—"}
              </div>

              {/* Mini progress bar */}
              <div className="w-full h-1 bg-bg-secondary rounded-full overflow-hidden">
                {!backendOffline && (
                  <div
                    className={`h-full rounded-full transition-all duration-700 ${stage.color}`}
                    style={{ width: `${pct}%` }}
                  />
                )}
              </div>

              <div className="text-[9px] font-mono text-text-muted">
                {count !== null ? `${pct}%` : "—"}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
