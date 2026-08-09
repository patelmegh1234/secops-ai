"""Phase 1 schema additions.

Adds to vulnerabilities:
  - idempotency_key (VARCHAR 64, UNIQUE) for deduplication
  - staged MTTR timestamps (triage_completed_at, patch_generated_at,
    sandbox_completed_at, slack_sent_at, human_decision_at, pr_opened_at)

Adds to sandbox_runs:
  - attempt_number (INTEGER NOT NULL DEFAULT 1)
  - sandbox_mode (VARCHAR 20)

Extends vulnerabilitystatus enum:
  - TRACE_ANALYZED, REPATCHING, PR_CLOSED

Revision ID: 001_phase1_additions
Revises: (initial)
Create Date: 2026-08-09
"""

from alembic import op
import sqlalchemy as sa


# revision identifiers
revision = "001_phase1_additions"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ── Extend VulnerabilityStatus enum ──────────────────────────────────────
    # PostgreSQL requires ALTER TYPE to add values; cannot be done inside a transaction
    # so we use execute() with COMMIT-free approach.
    op.execute("ALTER TYPE vulnerabilitystatus ADD VALUE IF NOT EXISTS 'TRACE_ANALYZED'")
    op.execute("ALTER TYPE vulnerabilitystatus ADD VALUE IF NOT EXISTS 'REPATCHING'")
    op.execute("ALTER TYPE vulnerabilitystatus ADD VALUE IF NOT EXISTS 'PR_CLOSED'")

    # ── vulnerabilities: add idempotency_key ─────────────────────────────────
    op.add_column(
        "vulnerabilities",
        sa.Column("idempotency_key", sa.String(64), nullable=True),
    )
    op.create_unique_constraint(
        "uq_vulnerabilities_idempotency_key",
        "vulnerabilities",
        ["idempotency_key"],
    )
    op.create_index(
        "ix_vulnerabilities_idempotency_key",
        "vulnerabilities",
        ["idempotency_key"],
    )

    # ── vulnerabilities: staged MTTR timestamps ───────────────────────────────
    for col_name in [
        "triage_completed_at",
        "patch_generated_at",
        "sandbox_completed_at",
        "slack_sent_at",
        "human_decision_at",
        "pr_opened_at",
    ]:
        op.add_column(
            "vulnerabilities",
            sa.Column(col_name, sa.DateTime(timezone=True), nullable=True),
        )

    # ── sandbox_runs: attempt tracking ────────────────────────────────────────
    op.add_column(
        "sandbox_runs",
        sa.Column("attempt_number", sa.Integer(), nullable=False, server_default="1"),
    )
    op.add_column(
        "sandbox_runs",
        sa.Column("sandbox_mode", sa.String(20), nullable=True),
    )


def downgrade() -> None:
    # Remove sandbox_runs additions
    op.drop_column("sandbox_runs", "sandbox_mode")
    op.drop_column("sandbox_runs", "attempt_number")

    # Remove staged MTTR timestamps
    for col_name in [
        "pr_opened_at",
        "human_decision_at",
        "slack_sent_at",
        "sandbox_completed_at",
        "patch_generated_at",
        "triage_completed_at",
    ]:
        op.drop_column("vulnerabilities", col_name)

    # Remove idempotency_key
    op.drop_index("ix_vulnerabilities_idempotency_key", table_name="vulnerabilities")
    op.drop_constraint("uq_vulnerabilities_idempotency_key", "vulnerabilities")
    op.drop_column("vulnerabilities", "idempotency_key")

    # Note: PostgreSQL does not support removing enum values.
    # TRACE_ANALYZED, REPATCHING, PR_CLOSED remain in the enum type after downgrade.
