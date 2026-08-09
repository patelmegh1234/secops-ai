"""
Phase 2.1 / 2.2 — Workspace isolation & API key rotation.

Creates:
  - workspaces table
  - api_keys table
  - vulnerabilities.workspace_id FK column (nullable for backwards-compat)

Revision: 002_workspace_isolation
Previous: 001_phase1_additions
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID

revision = "002_workspace_isolation"
down_revision = "001_phase1_additions"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ── workspaces ─────────────────────────────────────────────────────────
    op.create_table(
        "workspaces",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, nullable=False,
                  server_default=sa.text("gen_random_uuid()")),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("slug", sa.String(100), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
    )
    op.create_index("ix_workspaces_slug", "workspaces", ["slug"], unique=True)

    # ── api_keys ───────────────────────────────────────────────────────────
    op.create_table(
        "api_keys",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, nullable=False,
                  server_default=sa.text("gen_random_uuid()")),
        sa.Column("workspace_id", UUID(as_uuid=True), nullable=False),
        sa.Column("key_prefix", sa.String(12), nullable=False),
        sa.Column("hashed_key", sa.String(200), nullable=False),
        sa.Column("previous_key_hash", sa.String(200), nullable=True),
        sa.Column("label", sa.String(100), nullable=False, server_default="Default"),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("last_rotated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
        sa.ForeignKeyConstraint(
            ["workspace_id"], ["workspaces.id"],
            ondelete="CASCADE",
            name="fk_api_keys_workspace_id",
        ),
    )
    op.create_index("ix_api_keys_workspace_id", "api_keys", ["workspace_id"])
    op.create_index("ix_api_keys_key_prefix", "api_keys", ["key_prefix"])

    # ── vulnerabilities.workspace_id ───────────────────────────────────────
    # Nullable so existing rows are not broken (SET NULL on workspace delete)
    op.add_column(
        "vulnerabilities",
        sa.Column("workspace_id", UUID(as_uuid=True), nullable=True),
    )
    op.create_foreign_key(
        "fk_vulnerabilities_workspace_id",
        "vulnerabilities", "workspaces",
        ["workspace_id"], ["id"],
        ondelete="SET NULL",
    )
    op.create_index("ix_vulnerabilities_workspace_id", "vulnerabilities", ["workspace_id"])


def downgrade() -> None:
    op.drop_index("ix_vulnerabilities_workspace_id", table_name="vulnerabilities")
    op.drop_constraint("fk_vulnerabilities_workspace_id", "vulnerabilities", type_="foreignkey")
    op.drop_column("vulnerabilities", "workspace_id")

    op.drop_index("ix_api_keys_key_prefix", table_name="api_keys")
    op.drop_index("ix_api_keys_workspace_id", table_name="api_keys")
    op.drop_table("api_keys")

    op.drop_index("ix_workspaces_slug", table_name="workspaces")
    op.drop_table("workspaces")
