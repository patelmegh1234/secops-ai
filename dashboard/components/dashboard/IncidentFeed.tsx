"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { formatDistanceToNow } from "date-fns";
import { clsx } from "clsx";
import { SeverityBadge, StatusBadge } from "@/components/ui/StatusBadge";
import { useRealtimeFeed } from "@/lib/websocket";
import { listIncidents } from "@/lib/api";
import type { Vulnerability, WsEvent } from "@/lib/types";
import {
  ExternalLink,
  RefreshCw,
  ChevronRight,
  Bug,
  Package,
} from "lucide-react";

const IS_DEMO =
  !process.env.NEXT_PUBLIC_API_URL || process.env.NEXT_PUBLIC_DEMO_MODE === "true";

const SEVERITY_PRIORITY: Record<string, number> = {
  CRITICAL: 0,
  HIGH: 1,
  MEDIUM: 2,
  LOW: 3,
};

// Pipeline stage ordering for secondary sort
const STATUS_PRIORITY: Record<string, number> = {
  TRIAGING: 0,
  PATCHING: 1,
  SANDBOX_FAILED: 2,
  SANDBOX_PASSED: 3,
  AWAITING_APPROVAL: 4,
  PR_OPENED: 5,
  PR_MERGED: 6,
};

function sortIncidents(items: Vulnerability[]): Vulnerability[] {
  return [...items].sort((a, b) => {
    const sevA = SEVERITY_PRIORITY[a.severity] ?? 99;
    const sevB = SEVERITY_PRIORITY[b.severity] ?? 99;
    if (sevA !== sevB) return sevA - sevB;

    const staA = STATUS_PRIORITY[a.status] ?? 99;
    const staB = STATUS_PRIORITY[b.status] ?? 99;
    if (staA !== staB) return staA - staB;

    return new Date(b.created_at).getTime() - new Date(a.created_at).getTime();
  });
}

function ScannerBadge({ scanner }: { scanner: string }) {
  const isBandit = scanner === "BANDIT";
  return (
    <span
      className={clsx(
        "inline-flex items-center gap-1 text-[9px] font-mono font-semibold px-1.5 py-0.5 rounded uppercase tracking-wider",
        isBandit
          ? "bg-accent-amber/15 text-accent-amber border border-accent-amber/25"
          : "bg-accent-cyan/15 text-accent-cyan border border-accent-cyan/25"
      )}
    >
      {isBandit ? <Bug className="w-2.5 h-2.5" /> : <Package className="w-2.5 h-2.5" />}
      {scanner}
    </span>
  );
}

interface IncidentFeedProps {
  className?: string;
}

export function IncidentFeed({ className }: IncidentFeedProps) {
  const [incidents, setIncidents] = useState<Vulnerability[]>([]);
  const [loading, setLoading] = useState(true);
  const [newIds, setNewIds] = useState<Set<string>>(new Set());
  const [refreshing, setRefreshing] = useState(false);

  const fetchIncidents = async (quiet = false) => {
    if (!quiet) setLoading(true);
    else setRefreshing(true);
    try {
      const data = await listIncidents({ limit: 20 });
      setIncidents(sortIncidents(data.items));
    } catch (e) {
      console.error("Failed to load incidents", e);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => {
    fetchIncidents();
  }, []);

  useRealtimeFeed({
    onMessage: (event: WsEvent) => {
      if (event.type === "vulnerability_update" && event.vuln_id) {
        setNewIds((prev) => new Set([...prev, event.vuln_id!]));
        setTimeout(() => fetchIncidents(true), 500);
      }
    },
    enabled: !IS_DEMO,
  });

  if (loading) {
    return (
      <div className={clsx("card p-0 overflow-hidden", className)}>
        <div className="px-4 py-3 border-b border-border-subtle flex items-center gap-2">
          <div className="h-4 bg-bg-hover rounded w-28 animate-pulse" />
        </div>
        <div className="divide-y divide-border-subtle">
          {[...Array(6)].map((_, i) => (
            <div key={i} className="px-4 py-3 flex items-start gap-3">
              <div className="w-10 h-10 bg-bg-hover rounded-lg animate-pulse flex-shrink-0" style={{ opacity: 1 - i * 0.12 }} />
              <div className="flex-1 space-y-2">
                <div className="h-3 bg-bg-hover rounded w-3/4 animate-pulse" style={{ opacity: 1 - i * 0.12 }} />
                <div className="h-2.5 bg-bg-hover rounded w-1/2 animate-pulse" style={{ opacity: 1 - i * 0.12 }} />
              </div>
            </div>
          ))}
        </div>
      </div>
    );
  }

  return (
    <div className={clsx("card p-0 overflow-hidden", className)}>
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-3 border-b border-border-subtle">
        <div className="flex items-center gap-2.5">
          <span className="w-2 h-2 rounded-full bg-accent-emerald animate-pulse" />
          <span className="text-sm font-semibold text-text-primary">Live Incident Feed</span>
          <span className="text-[10px] font-mono text-text-muted bg-bg-secondary border border-border-subtle px-1.5 py-0.5 rounded-full">
            {incidents.length}
          </span>
        </div>
        <button
          onClick={() => fetchIncidents(true)}
          className={clsx(
            "p-1.5 text-text-muted hover:text-text-secondary transition-all rounded-md hover:bg-bg-hover",
            refreshing && "animate-spin text-accent-cyan"
          )}
          title="Refresh"
          disabled={refreshing}
        >
          <RefreshCw className="w-3.5 h-3.5" />
        </button>
      </div>

      {/* Column headers */}
      <div className="grid grid-cols-[1fr_auto] px-4 py-2 border-b border-border-subtle bg-bg-tertiary/50">
        <span className="text-[10px] font-mono text-text-muted uppercase tracking-wider">Incident</span>
        <span className="text-[10px] font-mono text-text-muted uppercase tracking-wider">Status</span>
      </div>

      {/* Feed rows */}
      <div className="divide-y divide-border-subtle overflow-auto max-h-[520px]">
        {incidents.length === 0 ? (
          <div className="text-center py-16 text-text-muted">
            <div className="text-3xl mb-3">🛡️</div>
            <p className="text-sm font-semibold">No incidents detected</p>
            <p className="text-xs font-mono mt-1">Waiting for webhook triggers...</p>
          </div>
        ) : (
          incidents.map((incident) => {
            const isNew = newIds.has(incident.id);
            const isCritical = incident.severity === "CRITICAL";

            return (
              <Link
                key={incident.id}
                href={`/review/${incident.id}`}
                className={clsx(
                  "flex items-start gap-3 px-4 py-3.5 hover:bg-bg-hover transition-all duration-150 group block",
                  isNew && "animate-fade-in bg-accent-cyan/3",
                  isCritical && "border-l-2 border-accent-rose"
                )}
              >
                {/* Severity icon column */}
                <div
                  className={clsx(
                    "w-8 h-8 rounded-lg flex items-center justify-center flex-shrink-0 mt-0.5 text-xs font-bold font-mono border",
                    incident.severity === "CRITICAL"
                      ? "bg-accent-rose/15 border-accent-rose/30 text-accent-rose"
                      : incident.severity === "HIGH"
                      ? "bg-red-900/20 border-red-400/25 text-red-400"
                      : incident.severity === "MEDIUM"
                      ? "bg-accent-amber/15 border-accent-amber/25 text-accent-amber"
                      : "bg-accent-cyan/10 border-accent-cyan/20 text-accent-cyan"
                  )}
                >
                  {incident.severity[0]}
                </div>

                {/* Main content */}
                <div className="flex-1 min-w-0">
                  {/* Top line: badges */}
                  <div className="flex items-center gap-1.5 flex-wrap mb-1">
                    <ScannerBadge scanner={incident.scanner} />
                    <span className="text-[10px] font-mono text-text-muted">
                      {incident.cve_id}
                    </span>
                    {isNew && (
                      <span className="text-[9px] font-mono text-accent-cyan bg-accent-cyan/10 border border-accent-cyan/20 px-1.5 py-0.5 rounded-full uppercase">
                        New
                      </span>
                    )}
                  </div>

                  {/* Title */}
                  <p className="text-sm font-medium text-text-secondary group-hover:text-text-primary transition-colors leading-tight line-clamp-1">
                    {incident.title}
                  </p>

                  {/* Repo + time */}
                  <div className="flex items-center gap-2.5 mt-1">
                    <span className="text-[10px] text-text-muted font-mono">
                      {incident.repo_owner}/{incident.repo_name}
                    </span>
                    {incident.file_path && (
                      <>
                        <span className="text-text-muted/40">·</span>
                        <span className="text-[10px] text-text-muted font-mono truncate max-w-[120px]">
                          {incident.file_path.split("/").pop()}
                        </span>
                      </>
                    )}
                    <span className="text-text-muted/40">·</span>
                    <span className="text-[10px] text-text-muted">
                      {formatDistanceToNow(new Date(incident.created_at), {
                        addSuffix: true,
                      })}
                    </span>
                  </div>
                </div>

                {/* Status + arrow */}
                <div className="flex items-center gap-2 flex-shrink-0">
                  <StatusBadge status={incident.status} />
                  <ChevronRight className="w-3.5 h-3.5 text-text-muted opacity-0 group-hover:opacity-100 transition-opacity" />
                </div>
              </Link>
            );
          })
        )}
      </div>
    </div>
  );
}
