"use client";

import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer } from "recharts";

interface SandboxGaugeProps {
  passRate: number | null; // 0.0 – 1.0, or null when backend offline
  className?: string;
}

export function SandboxGauge({ passRate, className }: SandboxGaugeProps) {
  // Offline / unconfigured state
  if (passRate === null) {
    return (
      <div className={`card ${className || ""}`}>
        <div className="mb-2">
          <h3 className="text-sm font-semibold text-text-primary">Sandbox Pass Rate</h3>
          <p className="text-xs text-text-muted">Docker test verification</p>
        </div>
        <div className="flex flex-col items-center justify-center gap-2 py-10">
          <span className="text-2xl font-bold font-mono text-text-muted">—</span>
          <span className="text-xs text-text-muted font-mono">No data yet</span>
        </div>
      </div>
    );
  }

  const passed = Math.round(passRate * 100);
  const failed = 100 - passed;

  const data = [
    { name: "Passed", value: passed },
    { name: "Failed", value: failed },
  ];

  return (
    <div className={`card ${className || ""}`}>
      <div className="mb-2">
        <h3 className="text-sm font-semibold text-text-primary">Sandbox Pass Rate</h3>
        <p className="text-xs text-text-muted">Docker test verification</p>
      </div>
      <div className="relative flex items-center justify-center" style={{ height: 160 }}>
        <ResponsiveContainer width="100%" height={160}>
          <PieChart>
            <Pie
              data={data}
              cx="50%"
              cy="50%"
              innerRadius={55}
              outerRadius={72}
              startAngle={90}
              endAngle={-270}
              dataKey="value"
              strokeWidth={0}
            >
              <Cell fill="#10B981" />
              <Cell fill="#1E293B" />
            </Pie>
            <Tooltip
              formatter={(val: number, name: string) => [`${val}%`, name]}
              contentStyle={{
                background: "#162032",
                border: "1px solid #334155",
                borderRadius: "8px",
                fontFamily: "JetBrains Mono",
                fontSize: "11px",
              }}
            />
          </PieChart>
        </ResponsiveContainer>
        {/* Center label */}
        <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
          <span className="text-2xl font-bold font-mono text-accent-emerald">
            {passed}%
          </span>
          <span className="text-xs text-text-muted font-mono">pass rate</span>
        </div>
      </div>
      <div className="flex justify-center gap-6 mt-1">
        <div className="flex items-center gap-1.5">
          <span className="w-2 h-2 rounded-full bg-accent-emerald inline-block" />
          <span className="text-xs text-text-muted font-mono">Passed</span>
        </div>
        <div className="flex items-center gap-1.5">
          <span className="w-2 h-2 rounded-full bg-bg-secondary border border-border-dim inline-block" />
          <span className="text-xs text-text-muted font-mono">Failed</span>
        </div>
      </div>
    </div>
  );
}
