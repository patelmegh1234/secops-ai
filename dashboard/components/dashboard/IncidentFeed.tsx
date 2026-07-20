"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { formatDistanceToNow } from "date-fns";
import { clsx } from "clsx";
import { SeverityBadge, StatusBadge } from "@/components/ui/StatusBadge";
import { useRealtimeFeed } from "@/lib/websocket";
import { listIncidents } from "@/lib/api";
import type { Vulnerability, WsEvent } from "@/lib/types";
import { ExternalLink, RefreshCw, FlaskConical } from "lucide-react";

const IS_DEMO = !process.env.NEXT_PUBLIC_API_URL || process.env.NEXT_PUBLIC_DEMO_MODE === "true";

interface IncidentFeedProps {
  className?: string;
}

export function IncidentFeed({ className }: IncidentFeedProps) {
  const [incidents, setIncidents] = useState<Vulnerability[]>([]);
  const [loading, setLoading] = useState(true);
  const [newIds, setNewIds] = useState<Set<string>>(new Set());

  const fetchIncidents = async () => {
    try {
      const data = await listIncidents({ limit: 20 });
      setIncidents(data.items);
    } catch (e) {
      console.error("Failed to load incidents", e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchIncidents();
  }, []);

  // Real-time updates — only when connected to live backend
  useRealtimeFeed({
    onMessage: (event: WsEvent) => {
      if (event.type === "vulnerability_update" && event.vuln_id) {
        setNewIds((prev) => new Set([...prev, event.vuln_id!]));
        setTimeout(fetchIncidents, 500);
      }
    },
    enabled: !IS_DEMO,
  });

  if (loading) {
    return (
      <div className={clsx("card overflow-hidden", className)}>
        <div className="px-4 py-3 border-b border-border-subtle">
          <div className="h-4 bg-bg-hover rounded w-32 animate-pulse" />
        </div>
        <div className="p-4 space-y-3">
          {[...Array(5)].map((_, i) => (
            <div key={i} className="h-14 bg-bg-hover rounded-lg animate-pulse" style={{ opacity: 1 - i * 0.15 }} />
          ))}
        </div>
      </div>
    );
  }

  return (
    <div className={clsx("card p-0 overflow-hidden", className)}>
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-3 border-b border-border-subtle">
        <div className="flex items-center gap-2">
          <span className="status-dot active" />
          <span className="text-sm font-semibold text-text-primary">Live Incident Feed</span>
          {IS_DEMO && (
            <span className="flex items-center gap-1 text-xs font-mono text-accent-amber bg-accent-amber/10 border border-accent-amber/30 px-2 py-0.5 rounded-full">
              <FlaskConical className="w-3 h-3" />
              DEMO
            </span>
          )}
        </div>
        <button
          onClick={fetchIncidents}
          className="text-text-muted hover:text-text-primary transition-colors"
          title="Refresh"
        >
          <RefreshCw className="w-3.5 h-3.5" />
        </button>
      </div>

      {/* Feed */}
      <div className="divide-y divide-border-subtle overflow-auto max-h-[480px]">
        {incidents.length === 0 ? (
          <div className="text-center py-10 text-text-muted text-sm font-mono">
            No incidents yet. Waiting for webhook triggers...
          </div>
        ) : (
          incidents.map((incident) => (
            <Link
              key={incident.id}
              href={`/review/${incident.id}`}
              className={clsx(
                "flex items-start gap-3 px-4 py-3 hover:bg-bg-hover transition-all duration-200 group block",
                newIds.has(incident.id) && "animate-slide-in bg-accent-cyan/5"
              )}
            >
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 flex-wrap">
                  <SeverityBadge severity={incident.severity} />
                  <span className="text-xs font-mono text-text-muted">
                    {incident.cve_id || incident.scanner}
                  </span>
                </div>
                <p className="text-sm text-text-primary mt-1 truncate group-hover:text-accent-cyan transition-colors">
                  {incident.title}
                </p>
                <div className="flex items-center gap-3 mt-1">
                  <span className="text-xs text-text-muted font-mono truncate">
                    {incident.repo_owner}/{incident.repo_name}
                  </span>
                  <span className="text-xs text-text-muted">
                    {formatDistanceToNow(new Date(incident.created_at), { addSuffix: true })}
                  </span>
                </div>
              </div>
              <div className="flex items-center gap-2 flex-shrink-0">
                <StatusBadge status={incident.status} />
                <ExternalLink className="w-3 h-3 text-text-muted opacity-0 group-hover:opacity-100 transition-opacity" />
              </div>
            </Link>
          ))
        )}
      </div>
    </div>
  );
}
