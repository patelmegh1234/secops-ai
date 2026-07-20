/**
 * Backend API client with typed methods, error handling, and demo mode fallback.
 * When NEXT_PUBLIC_API_URL is not set or the backend is unreachable,
 * the client automatically returns realistic demo data so Vercel deployments
 * look fully functional without a live backend.
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

import {
  DEMO_METRICS,
  DEMO_INCIDENTS,
  DEMO_PATCH,
  DEMO_SANDBOX,
  DEMO_TRACES,
} from "./demo-data";

const API_BASE =
  process.env.NEXT_PUBLIC_API_URL?.replace(/\/$/, "") || "";

const IS_DEMO = !API_BASE || process.env.NEXT_PUBLIC_DEMO_MODE === "true";

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
  if (IS_DEMO) {
    // Simulate network latency in demo mode
    await new Promise((r) => setTimeout(r, 100));
    throw new ApiError(503, "Demo mode — backend not configured");
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

// ─── Dashboard ──────────────────────────────────────────────────────────────
export async function getMetrics(): Promise<DashboardMetrics> {
  try {
    return await apiFetch<DashboardMetrics>("/api/metrics", undefined, 10);
  } catch {
    return DEMO_METRICS;
  }
}

// ─── Incidents ──────────────────────────────────────────────────────────────
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
    let items = DEMO_INCIDENTS;
    if (params?.severity) {
      items = items.filter((i) => i.severity === params.severity);
    }
    if (params?.status) {
      items = items.filter((i) => i.status === params.status);
    }
    const limit = params?.limit ?? 20;
    const offset = params?.offset ?? 0;
    return { total: items.length, items: items.slice(offset, offset + limit) };
  }
}

export async function getIncident(id: string): Promise<Vulnerability> {
  try {
    return await apiFetch<Vulnerability>(`/api/incidents/${id}`, undefined, 0);
  } catch {
    const found = DEMO_INCIDENTS.find((i) => i.id === id);
    if (!found) throw new ApiError(404, "Not found");
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

// ─── Audit ──────────────────────────────────────────────────────────────────
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
    const limit = params?.limit ?? 100;
    const offset = params?.offset ?? 0;
    return {
      total: DEMO_INCIDENTS.length,
      items: DEMO_INCIDENTS.slice(offset, offset + limit),
    };
  }
}
