"""
Phase 3.3 — MTTR Benchmark Script

Measures honest per-stage latency using real staged MTTR timestamps stored
in the database. Does NOT use estimated "manual time" as a baseline.

Usage:
    cd backend
    poetry run python -m scripts.benchmark_mttr [--limit 50] [--output results.json]

Output:
    - Per-stage p50/p95 latency (triage, patch, sandbox, slack, human, PR)
    - Overall MTTR p50/p95
    - Pipeline success/failure breakdown
    - Cost per vulnerability (from agent_traces)

Note: Only vulnerabilities with status=PR_OPENED or PR_MERGED have all
timestamps populated. Other statuses will have partial data.
"""

import argparse
import asyncio
import json
import statistics
from datetime import datetime, timezone
from typing import Any

# ── Stage definitions ──────────────────────────────────────────────────────────

STAGES = [
    ("created_at",         "triage_completed_at",   "triage_ms"),
    ("triage_completed_at","patch_generated_at",    "patch_ms"),
    ("patch_generated_at", "sandbox_completed_at",  "sandbox_ms"),
    ("sandbox_completed_at","slack_sent_at",         "slack_ms"),
    ("slack_sent_at",      "human_decision_at",     "human_decision_ms"),
    ("human_decision_at",  "pr_opened_at",          "pr_open_ms"),
]


def _delta_ms(start: datetime | None, end: datetime | None) -> int | None:
    """Return milliseconds between two timestamps, or None if either is missing."""
    if start is None or end is None:
        return None
    return int((end - start).total_seconds() * 1000)


def _percentile(data: list[float], pct: float) -> float | None:
    """Return the pct-th percentile of a list, or None if empty."""
    if not data:
        return None
    sorted_data = sorted(data)
    index = int(len(sorted_data) * pct / 100)
    return sorted_data[min(index, len(sorted_data) - 1)]


def _format_ms(ms: float | None) -> str:
    """Format milliseconds as human-readable string."""
    if ms is None:
        return "N/A"
    if ms < 1000:
        return f"{ms:.0f}ms"
    if ms < 60000:
        return f"{ms / 1000:.1f}s"
    return f"{ms / 60000:.1f}min"


async def run_benchmark(limit: int = 100) -> dict[str, Any]:
    """Query DB and compute MTTR metrics for the last `limit` completed vulns."""
    from sqlalchemy import select
    from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
    from sqlalchemy.orm import sessionmaker

    from src.core.config import get_settings
    from src.database.models import Vulnerability, VulnerabilityStatus, AgentTrace

    settings = get_settings()
    engine = create_async_engine(settings.database_url, echo=False)
    SessionLocal = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    results: dict[str, list[float]] = {name: [] for _, _, name in STAGES}
    results["total_ms"] = []
    cost_per_vuln: list[float] = []
    status_counts: dict[str, int] = {}
    sample_count = 0

    async with SessionLocal() as db:
        # Fetch completed vulnerabilities with full timestamp chain
        stmt = (
            select(Vulnerability)
            .where(
                Vulnerability.status.in_([
                    VulnerabilityStatus.PR_OPENED,
                    VulnerabilityStatus.PR_MERGED,
                    VulnerabilityStatus.APPROVED,
                ])
            )
            .order_by(Vulnerability.created_at.desc())
            .limit(limit)
        )
        rows = (await db.execute(stmt)).scalars().all()

        for vuln in rows:
            sample_count += 1
            status_counts[vuln.status.value] = status_counts.get(vuln.status.value, 0) + 1

            # Per-stage latency
            for start_field, end_field, metric_name in STAGES:
                start = getattr(vuln, start_field, None)
                end = getattr(vuln, end_field, None)
                delta = _delta_ms(start, end)
                if delta is not None and delta >= 0:
                    results[metric_name].append(float(delta))

            # Total MTTR (created → PR opened)
            total = _delta_ms(vuln.created_at, vuln.pr_opened_at)
            if total is not None and total >= 0:
                results["total_ms"].append(float(total))

            # Cost from agent_traces
            traces_stmt = select(AgentTrace).where(AgentTrace.vulnerability_id == vuln.id)
            traces = (await db.execute(traces_stmt)).scalars().all()
            vuln_cost = sum(t.estimated_cost_usd for t in traces)
            if vuln_cost > 0:
                cost_per_vuln.append(vuln_cost)

    await engine.dispose()

    # Build report
    report: dict[str, Any] = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "sample_size": sample_count,
        "status_breakdown": status_counts,
        "per_stage_latency": {},
        "total_mttr": {},
        "cost_per_vulnerability": {},
    }

    stage_labels = {
        "triage_ms": "Triage (receive → triage done)",
        "patch_ms": "Patch generation (triage → patch ready)",
        "sandbox_ms": "Sandbox verification (patch → sandbox done)",
        "slack_ms": "Slack notification (sandbox → Slack sent)",
        "human_decision_ms": "Human decision (Slack → approved/rejected)",
        "pr_open_ms": "PR creation (decision → PR opened)",
        "total_ms": "Total MTTR (receive → PR opened)",
    }

    all_metric_names = [name for _, _, name in STAGES] + ["total_ms"]
    for metric_name in all_metric_names:
        data = results[metric_name]
        p50 = _percentile(data, 50)
        p95 = _percentile(data, 95)
        label = stage_labels.get(metric_name, metric_name)

        bucket = report["per_stage_latency"] if metric_name != "total_ms" else report
        bucket_key = metric_name if metric_name != "total_ms" else "total_mttr"

        report[bucket_key if metric_name == "total_ms" else "per_stage_latency"][metric_name] = {
            "label": label,
            "n": len(data),
            "p50_ms": p50,
            "p95_ms": p95,
            "p50_human": _format_ms(p50),
            "p95_human": _format_ms(p95),
        }

    # Cost stats
    if cost_per_vuln:
        report["cost_per_vulnerability"] = {
            "n": len(cost_per_vuln),
            "mean_usd": round(statistics.mean(cost_per_vuln), 6),
            "p50_usd": round(_percentile(cost_per_vuln, 50) or 0, 6),
            "p95_usd": round(_percentile(cost_per_vuln, 95) or 0, 6),
            "total_usd": round(sum(cost_per_vuln), 4),
        }
    else:
        report["cost_per_vulnerability"] = {"n": 0, "note": "No agent_traces with cost data found"}

    return report


def print_report(report: dict[str, Any]) -> None:
    """Print a formatted human-readable benchmark report to stdout."""
    print("\n" + "=" * 60)
    print("  SecOps-AI — MTTR Benchmark Report")
    print("=" * 60)
    print(f"  Generated:   {report['generated_at']}")
    print(f"  Sample size: {report['sample_size']} vulnerabilities")
    print(f"  Statuses:    {report['status_breakdown']}")
    print()
    print("  Per-Stage Latency")
    print("  " + "-" * 56)
    print(f"  {'Stage':<45} {'p50':>7}  {'p95':>7}")
    print("  " + "-" * 56)

    for _, metrics in report["per_stage_latency"].items():
        label = metrics["label"][:44]
        print(f"  {label:<45} {metrics['p50_human']:>7}  {metrics['p95_human']:>7}")

    print("  " + "-" * 56)
    total = report.get("total_mttr", {})
    if total:
        print(f"  {'TOTAL MTTR':<45} {total.get('p50_human', 'N/A'):>7}  {total.get('p95_human', 'N/A'):>7}")

    print()
    cost = report.get("cost_per_vulnerability", {})
    if cost.get("n", 0) > 0:
        print(f"  Cost/vuln (mean): ${cost['mean_usd']:.6f}")
        print(f"  Cost/vuln (p95):  ${cost['p95_usd']:.6f}")
    print("=" * 60 + "\n")


def main() -> None:
    parser = argparse.ArgumentParser(description="SecOps-AI MTTR Benchmark")
    parser.add_argument("--limit", type=int, default=100,
                        help="Max vulnerabilities to analyse (default: 100)")
    parser.add_argument("--output", type=str, default=None,
                        help="Write JSON report to this file path")
    args = parser.parse_args()

    report = asyncio.run(run_benchmark(limit=args.limit))
    print_report(report)

    if args.output:
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2)
        print(f"Report written to {args.output}")


if __name__ == "__main__":
    main()
