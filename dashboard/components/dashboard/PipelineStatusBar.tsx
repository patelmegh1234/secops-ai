"use client";

import { DEMO_INCIDENTS } from "@/lib/demo-data";

const PIPELINE_STAGES = [
  { key: "TRIAGING", label: "Triaging", color: "bg-text-muted" },
  { key: "PATCHING", label: "Patching", color: "bg-accent-cyan" },
  { key: "SANDBOX_PASSED", label: "Sandbox ✓", color: "bg-accent-emerald" },
  { key: "SANDBOX_FAILED", label: "Sandbox ✗", color: "bg-accent-rose" },
  { key: "AWAITING_APPROVAL", label: "Awaiting", color: "bg-accent-amber" },
  { key: "PR_OPENED", label: "PR Open", color: "bg-accent-emerald" },
  { key: "PR_MERGED", label: "Merged", color: "bg-text-muted/50" },
] as const;

export function PipelineStatusBar() {
  const counts: Record<string, number> = {};
  DEMO_INCIDENTS.forEach((i) => {
    counts[i.status] = (counts[i.status] ?? 0) + 1;
  });

  const total = DEMO_INCIDENTS.length;

  return (
    <div className="card p-0 overflow-hidden">
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-3 border-b border-border-subtle">
        <span className="text-sm font-semibold text-text-primary">Pipeline Overview</span>
        <span className="text-xs font-mono text-text-muted">{total} total incidents</span>
      </div>

      {/* Stage columns */}
      <div className="grid grid-cols-7 divide-x divide-border-subtle">
        {PIPELINE_STAGES.map((stage) => {
          const count = counts[stage.key] ?? 0;
          const pct = total > 0 ? Math.round((count / total) * 100) : 0;

          return (
            <div
              key={stage.key}
              className="px-3 py-3 flex flex-col items-center gap-1.5 hover:bg-bg-hover transition-colors cursor-default"
            >
              <div className="text-[10px] font-mono text-text-muted text-center leading-tight">
                {stage.label}
              </div>
              <div className="text-lg font-bold font-mono text-text-primary">{count}</div>
              {/* Mini bar */}
              <div className="w-full h-1 bg-bg-secondary rounded-full overflow-hidden">
                <div
                  className={`h-full rounded-full transition-all duration-700 ${stage.color}`}
                  style={{ width: `${pct}%` }}
                />
              </div>
              <div className="text-[9px] font-mono text-text-muted">{pct}%</div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
