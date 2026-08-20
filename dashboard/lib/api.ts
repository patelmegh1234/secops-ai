/**
 * Backend API client.
 *
 * Behaviour by configuration:
 *   - NEXT_PUBLIC_API_URL set   → calls the real backend; throws on failure
 *   - NEXT_PUBLIC_API_URL unset → immediately throws ApiError(503) so callers
 *     can render honest empty states instead of fabricated numbers.
 *
 * Demo/review data is kept ONLY for the /review/[id] detail page so the
 * single pre-wired demo incident remains explorable. All KPI surfaces
 * (metrics, incident lists, audit log) show real data or an empty state.
 */

import type {
  AgentTrace,
  DashboardMetrics,
  Patch,
  SandboxRun,
  Vulnerability,
  VulnerabilityListResponse,
  VulnerabilityStatus,
  Severity,
} from "./types";

import { DEMO_INCIDENTS, DEMO_PATCH, DEMO_SANDBOX, DEMO_TRACES } from "./demo-data";

const API_BASE =
  process.env.NEXT_PUBLIC_API_URL?.replace(/\/$/, "") || "";

/** True when no backend URL is configured at all */
export const IS_UNCONFIGURED = !API_BASE;

/** True when URL is set but we haven't confirmed connectivity yet */
export const IS_CONFIGURED = !!API_BASE;

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
    public detail?: string
  ) {
    super(message);
    this.name = "ApiError";
  }
}

async function apiFetch<T>(
  path: string,
  options?: RequestInit,
  revalidate: number = 30
): Promise<T> {
  if (IS_UNCONFIGURED) {
    throw new ApiError(
      503,
      "Backend not configured — set NEXT_PUBLIC_API_URL to connect."
    );
  }

  const url = `${API_BASE}${path}`;

  const response = await fetch(url, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...options?.headers,
    },
    next: { revalidate },
  });

  if (!response.ok) {
    let detail: string | undefined;
    try {
      const body = await response.json();
      detail = body?.detail;
    } catch {}
    throw new ApiError(response.status, `API error: ${response.status}`, detail);
  }

  return response.json() as Promise<T>;
}

// ─── Dashboard ────────────────────────────────────────────────────────────────
// Returns null when backend is unavailable — callers render empty state.
export async function getMetrics(): Promise<DashboardMetrics | null> {
  try {
    return await apiFetch<DashboardMetrics>("/api/metrics", undefined, 10);
  } catch {
    return null;
  }
}

// ─── Incidents ────────────────────────────────────────────────────────────────
// Returns empty list when backend is unavailable — no fake data injected.
export async function listIncidents(params?: {
  status?: VulnerabilityStatus;
  severity?: Severity;
  limit?: number;
  offset?: number;
}): Promise<VulnerabilityListResponse> {
  try {
    const qs = new URLSearchParams();
    if (params?.status) qs.set("status", params.status);
    if (params?.severity) qs.set("severity", params.severity);
    if (params?.limit) qs.set("limit", String(params.limit));
    if (params?.offset) qs.set("offset", String(params.offset));
    const query = qs.toString() ? `?${qs}` : "";
    return await apiFetch<VulnerabilityListResponse>(`/api/incidents${query}`, undefined, 0);
  } catch {
    return { total: 0, items: [] };
  }
}

// ─── Incident detail ──────────────────────────────────────────────────────────
// Falls back to demo data ONLY for the pre-wired demo incident ID so the
// /review/[id] page remains explorable without a backend.
export async function getIncident(id: string): Promise<Vulnerability> {
  try {
    return await apiFetch<Vulnerability>(`/api/incidents/${id}`, undefined, 0);
  } catch {
    const found = DEMO_INCIDENTS.find((i) => i.id === id);
    if (!found) throw new ApiError(404, "Incident not found");
    return found;
  }
}

export async function getIncidentPatch(id: string): Promise<Patch> {
  try {
    return await apiFetch<Patch>(`/api/incidents/${id}/patch`, undefined, 0);
  } catch {
    if (id === DEMO_INCIDENTS[0].id) return DEMO_PATCH;
    throw new ApiError(404, "Patch not found for this incident");
  }
}

export async function getSandboxResult(id: string): Promise<SandboxRun> {
  try {
    return await apiFetch<SandboxRun>(`/api/incidents/${id}/sandbox`, undefined, 0);
  } catch {
    if (id === DEMO_INCIDENTS[0].id) return DEMO_SANDBOX;
    throw new ApiError(404, "Sandbox result not found");
  }
}

export async function getAgentTraces(id: string): Promise<AgentTrace[]> {
  try {
    return await apiFetch<AgentTrace[]>(`/api/incidents/${id}/traces`, undefined, 0);
  } catch {
    if (id === DEMO_INCIDENTS[0].id) return DEMO_TRACES;
    return [];
  }
}

// ─── Audit ────────────────────────────────────────────────────────────────────
// Returns empty list when backend is unavailable — no fake data injected.
export async function getAuditLog(params?: {
  limit?: number;
  offset?: number;
}): Promise<VulnerabilityListResponse> {
  try {
    const qs = new URLSearchParams();
    if (params?.limit) qs.set("limit", String(params.limit));
    if (params?.offset) qs.set("offset", String(params.offset));
    const query = qs.toString() ? `?${qs}` : "";
    return await apiFetch<VulnerabilityListResponse>(`/api/audit${query}`, undefined, 0);
  } catch {
    return { total: 0, items: [] };
  }
}

// ─── Backend health probe (used by TopBar for status indicator) ───────────────
export async function probeHealth(): Promise<"live" | "offline" | "unconfigured"> {
  if (IS_UNCONFIGURED) return "unconfigured";
  try {
    const r = await fetch(`${API_BASE}/health`, {
      next: { revalidate: 0 },
      signal: AbortSignal.timeout(4000),
    });
    return r.ok ? "live" : "offline";
  } catch {
    return "offline";
  }
}
