"""
Phase 3.4 — Prometheus metrics endpoint.

Exposes /metrics in the standard Prometheus text format.
Consumed by Grafana / alertmanager for production monitoring.

Metrics exposed:
  secops_vulnerabilities_total{status, severity}    — count per status/severity
  secops_mttr_seconds{stage}                        — per-stage latency gauge
  secops_sandbox_runs_total{outcome}                — passed / failed / timeout
  secops_agent_cost_usd_total{agent}               — cumulative OpenAI spend
  secops_pipeline_errors_total{step}               — error counts per pipeline step

Install:
    poetry add prometheus-client

Usage:
    curl http://localhost:8000/metrics
"""

from prometheus_client import (
    CollectorRegistry,
    Counter,
    Gauge,
    Histogram,
    generate_latest,
    CONTENT_TYPE_LATEST,
)
from fastapi import APIRouter, Response

router = APIRouter()

# ── Registry ───────────────────────────────────────────────────────────────────
# Use a custom registry to avoid conflicts with default global registry
# in test environments where the app is instantiated multiple times.
registry = CollectorRegistry()

# ── Counters ───────────────────────────────────────────────────────────────────

VULN_TOTAL = Counter(
    "secops_vulnerabilities_total",
    "Total vulnerability records by status and severity",
    labelnames=["status", "severity"],
    registry=registry,
)

SANDBOX_RUNS_TOTAL = Counter(
    "secops_sandbox_runs_total",
    "Total sandbox executions by outcome",
    labelnames=["outcome"],   # passed | failed | timeout | no_tests
    registry=registry,
)

AGENT_COST_USD = Counter(
    "secops_agent_cost_usd_total",
    "Cumulative OpenAI spend in USD by agent",
    labelnames=["agent"],     # triage | patch | guardrail
    registry=registry,
)

PIPELINE_ERRORS_TOTAL = Counter(
    "secops_pipeline_errors_total",
    "Pipeline errors by step",
    labelnames=["step"],      # triage | patch | sandbox | slack | github
    registry=registry,
)

PR_OPENED_TOTAL = Counter(
    "secops_prs_opened_total",
    "Total GitHub PRs opened",
    registry=registry,
)

PR_REJECTED_TOTAL = Counter(
    "secops_prs_rejected_total",
    "Total patches rejected by human reviewers",
    registry=registry,
)

SECRET_DETECTIONS_TOTAL = Counter(
    "secops_secret_detections_total",
    "Patches rejected by secret scanner before reaching LLM guardrail",
    registry=registry,
)

# ── Histograms (latency) ───────────────────────────────────────────────────────

STAGE_LATENCY = Histogram(
    "secops_stage_latency_seconds",
    "Pipeline stage latency in seconds",
    labelnames=["stage"],     # triage | patch | sandbox | slack | human | pr_open
    buckets=[1, 5, 10, 30, 60, 120, 300, 600, 1800, 3600],
    registry=registry,
)

SANDBOX_DURATION = Histogram(
    "secops_sandbox_duration_seconds",
    "Docker sandbox execution time in seconds",
    buckets=[0.5, 1, 2, 5, 10, 15, 20, 30, 60],
    registry=registry,
)

# ── Gauges (current state) ─────────────────────────────────────────────────────

ACTIVE_PIPELINES = Gauge(
    "secops_active_pipelines",
    "Number of vulnerability pipelines currently in progress",
    registry=registry,
)

PENDING_APPROVALS = Gauge(
    "secops_pending_approvals",
    "Number of patches waiting for human Slack approval",
    registry=registry,
)

REDIS_QUEUE_SIZE = Gauge(
    "secops_redis_queue_size",
    "Number of tasks currently in the Celery vulnerability queue",
    registry=registry,
)


# ── Helper functions (called by workers) ─────────────────────────────────────

def record_vulnerability_ingested(status: str, severity: str) -> None:
    """Call when a new vulnerability record is created."""
    VULN_TOTAL.labels(status=status, severity=severity).inc()


def record_stage_latency(stage: str, duration_ms: int) -> None:
    """Call at each pipeline stage transition with measured duration."""
    STAGE_LATENCY.labels(stage=stage).observe(duration_ms / 1000)


def record_sandbox_run(outcome: str, duration_ms: int) -> None:
    """Call after each sandbox execution completes.
    outcome: 'passed' | 'failed' | 'timeout' | 'no_tests'
    """
    SANDBOX_RUNS_TOTAL.labels(outcome=outcome).inc()
    SANDBOX_DURATION.observe(duration_ms / 1000)


def record_agent_cost(agent: str, cost_usd: float) -> None:
    """Call after each LLM agent invocation with measured cost."""
    AGENT_COST_USD.labels(agent=agent).inc(cost_usd)


def record_pipeline_error(step: str) -> None:
    """Call when a pipeline step raises an unhandled exception."""
    PIPELINE_ERRORS_TOTAL.labels(step=step).inc()


def record_pr_opened() -> None:
    PR_OPENED_TOTAL.inc()


def record_pr_rejected() -> None:
    PR_REJECTED_TOTAL.inc()


def record_secret_detection() -> None:
    """Call when secret scanner rejects a patch."""
    SECRET_DETECTIONS_TOTAL.inc()


def set_active_pipelines(count: int) -> None:
    ACTIVE_PIPELINES.set(count)


def set_pending_approvals(count: int) -> None:
    PENDING_APPROVALS.set(count)


def set_redis_queue_size(size: int) -> None:
    REDIS_QUEUE_SIZE.set(size)


# ── FastAPI endpoint ───────────────────────────────────────────────────────────

@router.get(
    "/metrics",
    include_in_schema=False,  # Hide from Swagger UI (not a user-facing endpoint)
    response_class=Response,
    summary="Prometheus metrics",
)
async def metrics_endpoint() -> Response:
    """
    Prometheus-compatible metrics endpoint.

    Scraped by Prometheus every 15s. Protected by network policy in production
    (should NOT be publicly accessible — add IP allowlist in your reverse proxy).
    """
    data = generate_latest(registry)
    return Response(content=data, media_type=CONTENT_TYPE_LATEST)
