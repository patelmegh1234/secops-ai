"use client";

import { useEffect, useState } from "react";
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from "recharts";
import { format, subDays } from "date-fns";

// Generate mock MTTR data for last 7 days (replace with real API)
function generateMockData() {
  return Array.from({ length: 7 }, (_, i) => ({
    date: format(subDays(new Date(), 6 - i), "MMM d"),
    mttr: Math.floor(20 + Math.random() * 30),
    incidents: Math.floor(2 + Math.random() * 8),
  }));
}

const CustomTooltip = ({ active, payload, label }: any) => {
  if (active && payload && payload.length) {
    return (
      <div className="glass rounded-lg px-3 py-2 border border-border-dim text-xs font-mono">
        <p className="text-text-muted mb-1">{label}</p>
        {payload.map((p: any) => (
          <p key={p.name} style={{ color: p.color }}>
            {p.name}: {p.value}{p.name === "mttr" ? "s" : ""}
          </p>
        ))}
      </div>
    );
  }
  return null;
};

export function MTTRChart({ className }: { className?: string }) {
  const [data, setData] = useState(generateMockData());

  useEffect(() => {
    // In production: fetch real MTTR data from /api/metrics/history
    setData(generateMockData());
  }, []);

  return (
    <div className={`card ${className || ""}`}>
      <div className="flex items-center justify-between mb-4">
        <div>
          <h3 className="text-sm font-semibold text-text-primary">MTTR Trend</h3>
          <p className="text-xs text-text-muted">Mean Time to Remediate — 7 days</p>
        </div>
      </div>
      <ResponsiveContainer width="100%" height={180}>
        <AreaChart data={data} margin={{ top: 4, right: 4, left: -20, bottom: 0 }}>
          <defs>
            <linearGradient id="mttrGradient" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor="#06B6D4" stopOpacity={0.3} />
              <stop offset="95%" stopColor="#06B6D4" stopOpacity={0} />
            </linearGradient>
            <linearGradient id="incidentGradient" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor="#10B981" stopOpacity={0.2} />
              <stop offset="95%" stopColor="#10B981" stopOpacity={0} />
            </linearGradient>
          </defs>
          <CartesianGrid strokeDasharray="3 3" stroke="#1E293B" />
          <XAxis
            dataKey="date"
            tick={{ fontSize: 10, fill: "#64748B", fontFamily: "JetBrains Mono" }}
            axisLine={{ stroke: "#1E293B" }}
          />
          <YAxis
            tick={{ fontSize: 10, fill: "#64748B", fontFamily: "JetBrains Mono" }}
            axisLine={{ stroke: "#1E293B" }}
          />
          <Tooltip content={<CustomTooltip />} />
          <Area
            type="monotone"
            dataKey="mttr"
            name="mttr"
            stroke="#06B6D4"
            strokeWidth={2}
            fill="url(#mttrGradient)"
          />
          <Area
            type="monotone"
            dataKey="incidents"
            name="incidents"
            stroke="#10B981"
            strokeWidth={1.5}
            strokeDasharray="4 2"
            fill="url(#incidentGradient)"
          />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}
