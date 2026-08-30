import type { Metadata } from "next";
import { ScrollText } from "lucide-react";
import { SeverityBadge, StatusBadge } from "@/components/ui/StatusBadge";
import { getAuditLog } from "@/lib/api";
import { formatDistanceToNow } from "date-fns";
import Link from "next/link";

export const metadata: Metadata = {
  title: "Audit Logs",
  description: "Full history of all SecOps-AI vulnerability incidents, patches, and decisions.",
};

export const revalidate = 60;

export default async function AuditPage() {
  let data = { total: 0, items: [] as any[] };
  try {
    data = await getAuditLog({ limit: 100 });
  } catch {}

  return (
    <div className="space-y-6 animate-fade-in">
      <div>
        <h1 className="text-xl font-bold text-text-primary flex items-center gap-2">
          <ScrollText className="w-5 h-5 text-accent-cyan" />
          Audit Logs
        </h1>
        <p className="text-sm text-text-muted mt-1">
          {data.total} total incidents — immutable record for SOC2 compliance
        </p>
      </div>

      <div className="card p-0 overflow-hidden">
        <div className="overflow-auto">
          <table className="data-table">
            <thead>
              <tr>
                <th>Incident ID</th>
                <th>CVE / Issue</th>
                <th>Severity</th>
                <th>Scanner</th>
                <th>Repository</th>
                <th>Status</th>
                <th>Created</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              {data.items.length === 0 ? (
                <tr>
                  <td colSpan={8} className="text-center py-12 text-text-muted font-mono">
                    No incidents recorded yet.
                  </td>
                </tr>
              ) : (
                data.items.map((vuln) => (
                  <tr key={vuln.id}>
                    <td>
                      <span className="font-mono text-xs text-text-muted">
                        {vuln.id.slice(0, 8)}…
                      </span>
                    </td>
                    <td>
                      <span className="font-mono text-xs text-accent-cyan">
                        {vuln.cve_id || vuln.scanner}
                      </span>
                    </td>
                    <td>
                      <SeverityBadge severity={vuln.severity} />
                    </td>
                    <td>
                      <span className="font-mono text-xs">{vuln.scanner}</span>
                    </td>
                    <td>
                      <span className="font-mono text-xs text-text-muted truncate max-w-[200px] block">
                        {vuln.repo_owner}/{vuln.repo_name}
                      </span>
                    </td>
                    <td>
                      <StatusBadge status={vuln.status} />
                    </td>
                    <td className="text-text-muted text-xs">
                      {formatDistanceToNow(new Date(vuln.created_at), { addSuffix: true })}
                    </td>
                    <td>
                      <Link
                        href={`/review/${vuln.id}`}
                        className="text-xs text-accent-cyan hover:underline font-mono"
                      >
                        Review →
                      </Link>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
