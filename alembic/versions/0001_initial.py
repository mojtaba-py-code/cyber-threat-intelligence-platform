"""initial schema

Revision ID: 0001
Revises:
Create Date: 2026-08-22

Creates every table backing the platform: users and their API keys, the audit
log, indicators with their per-provider enrichments, alert rules and alerts,
threat actors and the correlation graph. Tables are created parents-first so
the foreign keys resolve, and dropped in the reverse order.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # --- users -------------------------------------------------------------
    op.create_table(
        "users",
        sa.Column("id", sa.String(length=32), nullable=False),
        sa.Column("email", sa.String(length=320), nullable=False),
        sa.Column("password_hash", sa.String(length=255), nullable=False),
        sa.Column("role", sa.String(length=20), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_users_email"), "users", ["email"], unique=True)

    # --- indicators --------------------------------------------------------
    op.create_table(
        "iocs",
        sa.Column("id", sa.String(length=32), nullable=False),
        sa.Column("type", sa.String(length=32), nullable=False),
        sa.Column("value", sa.String(length=2048), nullable=False),
        sa.Column("defanged_value", sa.String(length=2100), nullable=False),
        sa.Column("source", sa.String(length=64), nullable=False),
        sa.Column("confidence", sa.String(length=16), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("threat_score", sa.Integer(), nullable=False),
        sa.Column("threat_level", sa.String(length=16), nullable=False),
        sa.Column("sightings", sa.Integer(), nullable=False),
        sa.Column("tags", sa.JSON(), nullable=False),
        sa.Column("references", sa.JSON(), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("type", "value", name="uq_ioc_type_value"),
    )
    op.create_index(op.f("ix_iocs_source"), "iocs", ["source"], unique=False)
    op.create_index(op.f("ix_iocs_status"), "iocs", ["status"], unique=False)
    op.create_index(op.f("ix_iocs_threat_level"), "iocs", ["threat_level"], unique=False)
    op.create_index(op.f("ix_iocs_threat_score"), "iocs", ["threat_score"], unique=False)
    op.create_index(op.f("ix_iocs_type"), "iocs", ["type"], unique=False)
    op.create_index(op.f("ix_iocs_value"), "iocs", ["value"], unique=False)

    # --- alert rules -------------------------------------------------------
    op.create_table(
        "alert_rules",
        sa.Column("id", sa.String(length=32), nullable=False),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("metric", sa.String(length=32), nullable=False),
        sa.Column("operator", sa.String(length=4), nullable=False),
        sa.Column("threshold", sa.Integer(), nullable=False),
        sa.Column("channel", sa.String(length=16), nullable=False),
        sa.Column("channel_config", sa.JSON(), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.PrimaryKeyConstraint("id"),
    )

    # --- threat actors -----------------------------------------------------
    op.create_table(
        "threat_actors",
        sa.Column("id", sa.String(length=32), nullable=False),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("actor_type", sa.String(length=32), nullable=False),
        sa.Column("country", sa.String(length=4), nullable=True),
        sa.Column("aliases", sa.JSON(), nullable=False),
        sa.Column("motivations", sa.JSON(), nullable=False),
        sa.Column("techniques", sa.JSON(), nullable=False),
        sa.Column("known_malware", sa.JSON(), nullable=False),
        sa.Column("targets", sa.JSON(), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_threat_actors_name"), "threat_actors", ["name"], unique=True)

    # --- correlation graph -------------------------------------------------
    op.create_table(
        "correlation_edges",
        sa.Column("id", sa.String(length=32), nullable=False),
        sa.Column("source_ref", sa.String(length=2100), nullable=False),
        sa.Column("target_ref", sa.String(length=2100), nullable=False),
        sa.Column("relationship", sa.String(length=32), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("source", sa.String(length=64), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("source_ref", "target_ref", "relationship", name="uq_edge_triple"),
    )
    op.create_index(
        op.f("ix_correlation_edges_source_ref"), "correlation_edges", ["source_ref"], unique=False
    )
    op.create_index(
        op.f("ix_correlation_edges_target_ref"), "correlation_edges", ["target_ref"], unique=False
    )

    # --- API keys (users) --------------------------------------------------
    op.create_table(
        "api_keys",
        sa.Column("id", sa.String(length=32), nullable=False),
        sa.Column("user_id", sa.String(length=32), nullable=False),
        sa.Column("name", sa.String(length=64), nullable=False),
        sa.Column("key_hash", sa.String(length=64), nullable=False),
        sa.Column("prefix", sa.String(length=16), nullable=False),
        sa.Column("role", sa.String(length=20), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_api_keys_key_hash"), "api_keys", ["key_hash"], unique=True)
    op.create_index(op.f("ix_api_keys_prefix"), "api_keys", ["prefix"], unique=False)
    op.create_index(op.f("ix_api_keys_user_id"), "api_keys", ["user_id"], unique=False)

    # --- audit log (users) -------------------------------------------------
    op.create_table(
        "audit_logs",
        sa.Column("id", sa.String(length=32), nullable=False),
        sa.Column("user_id", sa.String(length=32), nullable=True),
        sa.Column("action", sa.String(length=64), nullable=False),
        sa.Column("ip_address", sa.String(length=64), nullable=True),
        sa.Column("detail", sa.JSON(), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_audit_logs_action"), "audit_logs", ["action"], unique=False)
    op.create_index(op.f("ix_audit_logs_user_id"), "audit_logs", ["user_id"], unique=False)

    # --- enrichments (iocs) ------------------------------------------------
    op.create_table(
        "enrichments",
        sa.Column("id", sa.String(length=32), nullable=False),
        sa.Column("ioc_id", sa.String(length=32), nullable=False),
        sa.Column("provider", sa.String(length=48), nullable=False),
        sa.Column("data", sa.JSON(), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.ForeignKeyConstraint(["ioc_id"], ["iocs.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("ioc_id", "provider", name="uq_enrichment_ioc_provider"),
    )
    op.create_index(op.f("ix_enrichments_ioc_id"), "enrichments", ["ioc_id"], unique=False)

    # --- alerts (alert_rules, iocs) ----------------------------------------
    op.create_table(
        "alerts",
        sa.Column("id", sa.String(length=32), nullable=False),
        sa.Column("rule_id", sa.String(length=32), nullable=True),
        sa.Column("ioc_id", sa.String(length=32), nullable=True),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("title", sa.String(length=256), nullable=False),
        sa.Column("message", sa.Text(), nullable=True),
        sa.Column("delivered", sa.Boolean(), nullable=False),
        sa.Column("acknowledged", sa.Boolean(), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.ForeignKeyConstraint(["ioc_id"], ["iocs.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["rule_id"], ["alert_rules.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_alerts_ioc_id"), "alerts", ["ioc_id"], unique=False)
    op.create_index(op.f("ix_alerts_severity"), "alerts", ["severity"], unique=False)


def downgrade() -> None:
    op.drop_index(op.f("ix_alerts_severity"), table_name="alerts")
    op.drop_index(op.f("ix_alerts_ioc_id"), table_name="alerts")
    op.drop_table("alerts")

    op.drop_index(op.f("ix_enrichments_ioc_id"), table_name="enrichments")
    op.drop_table("enrichments")

    op.drop_index(op.f("ix_audit_logs_user_id"), table_name="audit_logs")
    op.drop_index(op.f("ix_audit_logs_action"), table_name="audit_logs")
    op.drop_table("audit_logs")

    op.drop_index(op.f("ix_api_keys_user_id"), table_name="api_keys")
    op.drop_index(op.f("ix_api_keys_prefix"), table_name="api_keys")
    op.drop_index(op.f("ix_api_keys_key_hash"), table_name="api_keys")
    op.drop_table("api_keys")

    op.drop_index(op.f("ix_correlation_edges_target_ref"), table_name="correlation_edges")
    op.drop_index(op.f("ix_correlation_edges_source_ref"), table_name="correlation_edges")
    op.drop_table("correlation_edges")

    op.drop_index(op.f("ix_threat_actors_name"), table_name="threat_actors")
    op.drop_table("threat_actors")

    op.drop_table("alert_rules")

    op.drop_index(op.f("ix_iocs_value"), table_name="iocs")
    op.drop_index(op.f("ix_iocs_type"), table_name="iocs")
    op.drop_index(op.f("ix_iocs_threat_score"), table_name="iocs")
    op.drop_index(op.f("ix_iocs_threat_level"), table_name="iocs")
    op.drop_index(op.f("ix_iocs_status"), table_name="iocs")
    op.drop_index(op.f("ix_iocs_source"), table_name="iocs")
    op.drop_table("iocs")

    op.drop_index(op.f("ix_users_email"), table_name="users")
    op.drop_table("users")
