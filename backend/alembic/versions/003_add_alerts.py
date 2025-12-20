"""Add alerts tables

Revision ID: 003
Revises: 002
Create Date: 2024-12-18

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "003"
down_revision: Union[str, None] = "002"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Create alert type enum
    op.execute(
        """
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'alerttype') THEN
                CREATE TYPE alerttype AS ENUM (
                    'coverage_threshold', 'gap_detected', 'scan_completed',
                    'scan_failed', 'stale_detection', 'new_technique'
                );
            END IF;
        END $$;
    """
    )

    # Create notification channel enum
    op.execute(
        """
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'notificationchannel') THEN
                CREATE TYPE notificationchannel AS ENUM ('email', 'webhook', 'slack');
            END IF;
        END $$;
    """
    )

    # Create alert severity enum
    op.execute(
        """
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'alertseverity') THEN
                CREATE TYPE alertseverity AS ENUM ('info', 'warning', 'critical');
            END IF;
        END $$;
    """
    )

    # Alert Configs
    op.create_table(
        "alert_configs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "cloud_account_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("cloud_accounts.id"),
            nullable=True,
        ),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("description", sa.String(500), nullable=True),
        sa.Column(
            "alert_type",
            postgresql.ENUM(
                "coverage_threshold",
                "gap_detected",
                "scan_completed",
                "scan_failed",
                "stale_detection",
                "new_technique",
                name="alerttype",
                create_type=False,
            ),
            nullable=False,
        ),
        sa.Column(
            "severity",
            postgresql.ENUM(
                "info", "warning", "critical", name="alertseverity", create_type=False
            ),
            default="warning",
        ),
        sa.Column("threshold_value", sa.Float, nullable=True),
        sa.Column("threshold_operator", sa.String(10), nullable=True),
        sa.Column("channels", postgresql.JSONB, default=list),
        sa.Column("cooldown_minutes", sa.Integer, default=60),
        sa.Column("last_triggered_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("is_active", sa.Boolean, default=True),
        sa.Column("trigger_count", sa.Integer, default=0),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now()
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()
        ),
    )
    op.create_index(
        "ix_alert_configs_cloud_account_id", "alert_configs", ["cloud_account_id"]
    )
    op.create_index("ix_alert_configs_alert_type", "alert_configs", ["alert_type"])
    op.create_index("ix_alert_configs_is_active", "alert_configs", ["is_active"])

    # Alert History
    op.create_table(
        "alert_history",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "alert_config_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("alert_configs.id"),
            nullable=False,
        ),
        sa.Column(
            "cloud_account_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("cloud_accounts.id"),
            nullable=True,
        ),
        sa.Column(
            "severity",
            postgresql.ENUM(
                "info", "warning", "critical", name="alertseverity", create_type=False
            ),
            nullable=False,
        ),
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column("message", sa.String(2000), nullable=False),
        sa.Column("details", postgresql.JSONB, nullable=True),
        sa.Column("channels_notified", postgresql.JSONB, default=list),
        sa.Column("notification_errors", postgresql.JSONB, nullable=True),
        sa.Column("is_resolved", sa.Boolean, default=False),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "triggered_at", sa.DateTime(timezone=True), server_default=sa.func.now()
        ),
    )
    op.create_index(
        "ix_alert_history_alert_config_id", "alert_history", ["alert_config_id"]
    )
    op.create_index(
        "ix_alert_history_cloud_account_id", "alert_history", ["cloud_account_id"]
    )
    op.create_index("ix_alert_history_triggered_at", "alert_history", ["triggered_at"])


def downgrade() -> None:
    op.drop_table("alert_history")
    op.drop_table("alert_configs")
    op.execute("DROP TYPE IF EXISTS alerttype")
    op.execute("DROP TYPE IF EXISTS notificationchannel")
    op.execute("DROP TYPE IF EXISTS alertseverity")
