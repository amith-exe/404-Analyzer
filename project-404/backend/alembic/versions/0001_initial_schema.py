"""Initial schema

Revision ID: 0001
Revises:
Create Date: 2024-01-01 00:00:00
"""
from alembic import op
import sqlalchemy as sa

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "targets",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("root_domain", sa.String(255), nullable=False, unique=True),
        sa.Column("ownership_status", sa.String(64), default="unknown"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_targets_root_domain", "targets", ["root_domain"])

    op.create_table(
        "scans",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("target_id", sa.Integer(), sa.ForeignKey("targets.id"), nullable=False),
        sa.Column("status", sa.String(32), default="pending", nullable=False),
        sa.Column("scan_config_json", sa.Text(), default="{}"),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("posture_score", sa.Float(), nullable=True),
        sa.Column("progress", sa.Integer(), default=0),
        sa.Column("current_step", sa.String(128), default="queued"),
    )

    op.create_table(
        "assets",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("scan_id", sa.Integer(), sa.ForeignKey("scans.id"), nullable=False),
        sa.Column("type", sa.String(32), nullable=False),
        sa.Column("value", sa.String(512), nullable=False),
        sa.Column("metadata_json", sa.Text(), default="{}"),
    )
    op.create_index("ix_assets_scan_id", "assets", ["scan_id"])

    op.create_table(
        "endpoints",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("scan_id", sa.Integer(), sa.ForeignKey("scans.id"), nullable=False),
        sa.Column("host", sa.String(512), nullable=False),
        sa.Column("url", sa.Text(), nullable=False),
        sa.Column("method", sa.String(16), default="GET"),
        sa.Column("source", sa.String(64), default="crawl"),
        sa.Column("requires_auth", sa.String(16), default="unknown"),
        sa.Column("status_code", sa.Integer(), nullable=True),
        sa.Column("title", sa.String(512), nullable=True),
        sa.Column("headers_json", sa.Text(), default="{}"),
    )
    op.create_index("ix_endpoints_scan_id", "endpoints", ["scan_id"])

    op.create_table(
        "findings",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("scan_id", sa.Integer(), sa.ForeignKey("scans.id"), nullable=False),
        sa.Column("title", sa.String(256), nullable=False),
        sa.Column("severity", sa.String(32), nullable=False),
        sa.Column("confidence", sa.String(32), nullable=False),
        sa.Column("category", sa.String(64), nullable=False),
        sa.Column("affected_url", sa.Text(), nullable=True),
        sa.Column("evidence_json", sa.Text(), default="{}"),
        sa.Column("recommendation", sa.Text(), nullable=True),
        sa.Column("fingerprint_hash", sa.String(64), nullable=True),
    )
    op.create_index("ix_findings_scan_id", "findings", ["scan_id"])
    op.create_index("ix_findings_fingerprint_hash", "findings", ["fingerprint_hash"])

    op.create_table(
        "artifacts",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("scan_id", sa.Integer(), sa.ForeignKey("scans.id"), nullable=False),
        sa.Column("kind", sa.String(64), nullable=False),
        sa.Column("path_or_url", sa.Text(), nullable=True),
        sa.Column("metadata_json", sa.Text(), default="{}"),
    )
    op.create_index("ix_artifacts_scan_id", "artifacts", ["scan_id"])


def downgrade() -> None:
    op.drop_table("artifacts")
    op.drop_table("findings")
    op.drop_table("endpoints")
    op.drop_table("assets")
    op.drop_table("scans")
    op.drop_table("targets")
