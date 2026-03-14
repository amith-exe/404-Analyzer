"""Expand schema for auth deltas, context, scheduling, and diffs.

Revision ID: 0002
Revises: 0001
Create Date: 2026-03-14 00:40:00
"""
from alembic import op
import sqlalchemy as sa

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "endpoints",
        sa.Column("discovered_via", sa.String(length=16), nullable=False, server_default="unauth"),
    )
    op.add_column("endpoints", sa.Column("unauth_status_code", sa.Integer(), nullable=True))
    op.add_column("endpoints", sa.Column("auth_status_code", sa.Integer(), nullable=True))
    op.add_column("endpoints", sa.Column("content_similarity", sa.Float(), nullable=True))
    op.add_column(
        "endpoints",
        sa.Column("auth_only_navigation", sa.Boolean(), nullable=False, server_default=sa.text("false")),
    )

    op.create_table(
        "company_contexts",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("target_id", sa.Integer(), sa.ForeignKey("targets.id"), nullable=False),
        sa.Column("scan_id", sa.Integer(), sa.ForeignKey("scans.id"), nullable=True),
        sa.Column("source_url", sa.Text(), nullable=False),
        sa.Column("description_raw", sa.Text(), nullable=False),
        sa.Column("industry", sa.String(length=64), nullable=True),
        sa.Column("business_model", sa.String(length=64), nullable=True),
        sa.Column("keywords_json", sa.Text(), nullable=True, server_default="[]"),
        sa.Column("likely_attack_surface_json", sa.Text(), nullable=True, server_default="[]"),
        sa.Column("where_to_look_first", sa.Text(), nullable=True),
        sa.Column("summary_hash", sa.String(length=64), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_company_contexts_target_id", "company_contexts", ["target_id"])
    op.create_index("ix_company_contexts_scan_id", "company_contexts", ["scan_id"])
    op.create_index("ix_company_contexts_summary_hash", "company_contexts", ["summary_hash"])

    op.create_table(
        "scheduled_scan_jobs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("target_id", sa.Integer(), sa.ForeignKey("targets.id"), nullable=False),
        sa.Column("scan_config_json", sa.Text(), nullable=True, server_default="{}"),
        sa.Column("interval_minutes", sa.Integer(), nullable=True),
        sa.Column("cron_expr", sa.String(length=128), nullable=True),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("last_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("next_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_scan_id", sa.Integer(), sa.ForeignKey("scans.id"), nullable=True),
        sa.Column("alert_webhook_url", sa.Text(), nullable=True),
        sa.Column("diff_threshold_json", sa.Text(), nullable=True, server_default="{}"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_scheduled_scan_jobs_target_id", "scheduled_scan_jobs", ["target_id"])
    op.create_index("ix_scheduled_scan_jobs_next_run_at", "scheduled_scan_jobs", ["next_run_at"])

    op.create_table(
        "scan_diffs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("target_id", sa.Integer(), sa.ForeignKey("targets.id"), nullable=False),
        sa.Column("scan_id", sa.Integer(), sa.ForeignKey("scans.id"), nullable=False),
        sa.Column("previous_scan_id", sa.Integer(), sa.ForeignKey("scans.id"), nullable=True),
        sa.Column("summary_json", sa.Text(), nullable=True, server_default="{}"),
        sa.Column("webhook_sent", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_scan_diffs_target_id", "scan_diffs", ["target_id"])
    op.create_index("ix_scan_diffs_scan_id", "scan_diffs", ["scan_id"])
    op.create_index("ix_scan_diffs_previous_scan_id", "scan_diffs", ["previous_scan_id"])


def downgrade() -> None:
    op.drop_index("ix_scan_diffs_previous_scan_id", table_name="scan_diffs")
    op.drop_index("ix_scan_diffs_scan_id", table_name="scan_diffs")
    op.drop_index("ix_scan_diffs_target_id", table_name="scan_diffs")
    op.drop_table("scan_diffs")

    op.drop_index("ix_scheduled_scan_jobs_next_run_at", table_name="scheduled_scan_jobs")
    op.drop_index("ix_scheduled_scan_jobs_target_id", table_name="scheduled_scan_jobs")
    op.drop_table("scheduled_scan_jobs")

    op.drop_index("ix_company_contexts_summary_hash", table_name="company_contexts")
    op.drop_index("ix_company_contexts_scan_id", table_name="company_contexts")
    op.drop_index("ix_company_contexts_target_id", table_name="company_contexts")
    op.drop_table("company_contexts")

    op.drop_column("endpoints", "auth_only_navigation")
    op.drop_column("endpoints", "content_similarity")
    op.drop_column("endpoints", "auth_status_code")
    op.drop_column("endpoints", "unauth_status_code")
    op.drop_column("endpoints", "discovered_via")
