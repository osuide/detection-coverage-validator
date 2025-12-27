"""Add detection evaluation history tables.

Revision ID: 038_add_detection_evaluation_history
Revises: 037_add_evaluation_summary
Create Date: 2025-12-27

This migration adds tables for tracking historical changes to detection
evaluation/compliance status over time:

1. detection_evaluation_history - Time-series table for evaluation snapshots
2. detection_evaluation_daily_summary - Pre-computed daily aggregates
3. detection_evaluation_alerts - Alerts for significant state changes

Design considerations:
- BRIN index on timestamp for efficient time-series queries
- Partial indexes for common query patterns (state changes, non-compliant)
- Denormalised cloud_account_id for query performance
- Unique constraint on daily summary to prevent duplicates
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID, JSONB


# revision identifiers, used by Alembic.
revision = "038_add_detection_evaluation_history"
down_revision = "037_add_evaluation_summary"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Create evaluation_type enum if not exists using pure SQL
    # This approach works reliably with asyncpg
    op.execute(
        """
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'evaluationtype') THEN
                CREATE TYPE evaluationtype AS ENUM (
                    'config_compliance',
                    'alarm_state',
                    'eventbridge_state',
                    'guardduty_state',
                    'gcp_scc_state',
                    'gcp_logging_state'
                );
            END IF;
        END
        $$;
        """
    )

    # Create evaluation alert severity enum if not exists
    op.execute(
        """
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'evaluationalertseverity') THEN
                CREATE TYPE evaluationalertseverity AS ENUM (
                    'info',
                    'warning',
                    'critical'
                );
            END IF;
        END
        $$;
        """
    )

    # Check for existing tables to ensure idempotency
    conn = op.get_bind()
    inspector = sa.inspect(conn)
    existing_tables = inspector.get_table_names()

    # 1. Create detection_evaluation_history table
    if "detection_evaluation_history" not in existing_tables:
        op.create_table(
            "detection_evaluation_history",
            sa.Column("id", UUID(as_uuid=True), primary_key=True),
            sa.Column(
                "detection_id",
                UUID(as_uuid=True),
                sa.ForeignKey("detections.id", ondelete="CASCADE"),
                nullable=False,
            ),
            # Denormalised for query performance
            sa.Column("cloud_account_id", UUID(as_uuid=True), nullable=False),
            sa.Column("detection_type", sa.String(64), nullable=False),
            # Evaluation state
            sa.Column(
                "evaluation_type",
                sa.Enum(
                    "config_compliance",
                    "alarm_state",
                    "eventbridge_state",
                    "guardduty_state",
                    "gcp_scc_state",
                    "gcp_logging_state",
                    name="evaluationtype",
                    create_type=False,
                ),
                nullable=False,
            ),
            sa.Column("previous_state", sa.String(32), nullable=True),
            sa.Column("current_state", sa.String(32), nullable=False),
            sa.Column(
                "state_changed",
                sa.Boolean(),
                nullable=False,
                server_default="false",
            ),
            # Full evaluation snapshot
            sa.Column(
                "evaluation_summary",
                JSONB,
                nullable=False,
                server_default="{}",
            ),
            # Optional scan reference
            sa.Column(
                "scan_id",
                UUID(as_uuid=True),
                sa.ForeignKey("scans.id", ondelete="SET NULL"),
                nullable=True,
            ),
            # Timestamp
            sa.Column(
                "recorded_at",
                sa.DateTime(timezone=True),
                nullable=False,
                server_default=sa.func.now(),
            ),
        )

        # Create indexes for detection_evaluation_history
        # B-tree index on detection_id + recorded_at for trend queries
        op.create_index(
            "ix_eval_history_detection_time",
            "detection_evaluation_history",
            ["detection_id", sa.text("recorded_at DESC")],
        )

        # B-tree index on cloud_account_id + recorded_at for account queries
        op.create_index(
            "ix_eval_history_account_time",
            "detection_evaluation_history",
            ["cloud_account_id", sa.text("recorded_at DESC")],
        )

        # BRIN index on recorded_at for efficient time-range queries
        op.execute(
            """
            CREATE INDEX ix_eval_history_recorded_at_brin
            ON detection_evaluation_history USING BRIN (recorded_at);
        """
        )

        # Partial index for state changes only (drift detection)
        op.execute(
            """
            CREATE INDEX ix_eval_history_state_changes
            ON detection_evaluation_history (detection_id, recorded_at DESC)
            WHERE state_changed = TRUE;
        """
        )

        # Partial index for non-compliant/alarm states (compliance reporting)
        op.execute(
            """
            CREATE INDEX ix_eval_history_unhealthy
            ON detection_evaluation_history (cloud_account_id, recorded_at DESC)
            WHERE current_state IN ('NON_COMPLIANT', 'ALARM', 'DISABLED');
        """
        )

    # 2. Create detection_evaluation_daily_summary table
    if "detection_evaluation_daily_summary" not in existing_tables:
        op.create_table(
            "detection_evaluation_daily_summary",
            sa.Column("id", UUID(as_uuid=True), primary_key=True),
            sa.Column(
                "cloud_account_id",
                UUID(as_uuid=True),
                sa.ForeignKey("cloud_accounts.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column("summary_date", sa.Date(), nullable=False),
            sa.Column("detection_type", sa.String(64), nullable=False),
            # Aggregate counts
            sa.Column(
                "total_detections",
                sa.Integer(),
                nullable=False,
                server_default="0",
            ),
            sa.Column(
                "compliant_count",
                sa.Integer(),
                nullable=False,
                server_default="0",
            ),
            sa.Column(
                "non_compliant_count",
                sa.Integer(),
                nullable=False,
                server_default="0",
            ),
            sa.Column(
                "alarm_count",
                sa.Integer(),
                nullable=False,
                server_default="0",
            ),
            sa.Column(
                "ok_count",
                sa.Integer(),
                nullable=False,
                server_default="0",
            ),
            sa.Column(
                "insufficient_data_count",
                sa.Integer(),
                nullable=False,
                server_default="0",
            ),
            sa.Column(
                "enabled_count",
                sa.Integer(),
                nullable=False,
                server_default="0",
            ),
            sa.Column(
                "disabled_count",
                sa.Integer(),
                nullable=False,
                server_default="0",
            ),
            sa.Column(
                "unknown_count",
                sa.Integer(),
                nullable=False,
                server_default="0",
            ),
            sa.Column(
                "state_changes_count",
                sa.Integer(),
                nullable=False,
                server_default="0",
            ),
            # Derived compliance rate
            sa.Column("compliance_rate", sa.Float(), nullable=True),
            # Metadata
            sa.Column(
                "calculated_at",
                sa.DateTime(timezone=True),
                nullable=False,
                server_default=sa.func.now(),
            ),
        )

        # Unique constraint for daily summary
        op.create_unique_constraint(
            "uq_eval_daily_summary_account_date_type",
            "detection_evaluation_daily_summary",
            ["cloud_account_id", "summary_date", "detection_type"],
        )

        # Index for dashboard queries
        op.create_index(
            "ix_eval_daily_summary_account_date",
            "detection_evaluation_daily_summary",
            ["cloud_account_id", sa.text("summary_date DESC")],
        )

    # 3. Create detection_evaluation_alerts table
    if "detection_evaluation_alerts" not in existing_tables:
        op.create_table(
            "detection_evaluation_alerts",
            sa.Column("id", UUID(as_uuid=True), primary_key=True),
            # References
            sa.Column(
                "organization_id",
                UUID(as_uuid=True),
                sa.ForeignKey("organizations.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column(
                "cloud_account_id",
                UUID(as_uuid=True),
                sa.ForeignKey("cloud_accounts.id", ondelete="CASCADE"),
                nullable=True,
            ),
            sa.Column(
                "detection_id",
                UUID(as_uuid=True),
                sa.ForeignKey("detections.id", ondelete="CASCADE"),
                nullable=True,
            ),
            # Reference to history record (no FK due to potential partitioning)
            sa.Column("evaluation_history_id", UUID(as_uuid=True), nullable=True),
            # Alert details
            sa.Column("alert_type", sa.String(64), nullable=False),
            sa.Column(
                "severity",
                sa.Enum(
                    "info",
                    "warning",
                    "critical",
                    name="evaluationalertseverity",
                    create_type=False,
                ),
                nullable=False,
            ),
            # State change details
            sa.Column("previous_state", sa.String(32), nullable=True),
            sa.Column("current_state", sa.String(32), nullable=False),
            # Human-readable message
            sa.Column("title", sa.String(255), nullable=False),
            sa.Column("message", sa.Text(), nullable=False),
            # Additional context
            sa.Column("details", JSONB, nullable=False, server_default="{}"),
            # Acknowledgement workflow
            sa.Column(
                "is_acknowledged",
                sa.Boolean(),
                nullable=False,
                server_default="false",
            ),
            sa.Column(
                "acknowledged_at",
                sa.DateTime(timezone=True),
                nullable=True,
            ),
            sa.Column(
                "acknowledged_by",
                UUID(as_uuid=True),
                sa.ForeignKey("users.id", ondelete="SET NULL"),
                nullable=True,
            ),
            # Timestamps
            sa.Column(
                "created_at",
                sa.DateTime(timezone=True),
                nullable=False,
                server_default=sa.func.now(),
            ),
        )

        # Indexes for detection_evaluation_alerts
        op.create_index(
            "ix_eval_alerts_org_created",
            "detection_evaluation_alerts",
            ["organization_id", sa.text("created_at DESC")],
        )

        op.create_index(
            "ix_eval_alerts_account_created",
            "detection_evaluation_alerts",
            ["cloud_account_id", sa.text("created_at DESC")],
        )

        # Partial index for unacknowledged alerts
        op.execute(
            """
            CREATE INDEX ix_eval_alerts_unacknowledged
            ON detection_evaluation_alerts (organization_id, created_at DESC)
            WHERE is_acknowledged = FALSE;
        """
        )

    # 4. Create views for common queries

    # View: Recent state changes (last 7 days)
    op.execute(
        """
        CREATE OR REPLACE VIEW v_recent_evaluation_changes AS
        SELECT
            h.id,
            h.detection_id,
            d.name as detection_name,
            h.cloud_account_id,
            ca.name as account_name,
            h.detection_type,
            h.evaluation_type,
            h.previous_state,
            h.current_state,
            h.recorded_at,
            h.evaluation_summary
        FROM detection_evaluation_history h
        JOIN detections d ON h.detection_id = d.id
        LEFT JOIN cloud_accounts ca ON h.cloud_account_id = ca.id
        WHERE h.state_changed = TRUE
          AND h.recorded_at > NOW() - INTERVAL '7 days'
        ORDER BY h.recorded_at DESC;
    """
    )

    # View: Daily compliance trend
    op.execute(
        """
        CREATE OR REPLACE VIEW v_daily_compliance_trend AS
        SELECT
            cloud_account_id,
            summary_date,
            SUM(total_detections) as total_detections,
            SUM(compliant_count + ok_count + enabled_count) as healthy_count,
            SUM(non_compliant_count + alarm_count + disabled_count) as unhealthy_count,
            SUM(state_changes_count) as state_changes,
            ROUND(
                CASE
                    WHEN SUM(total_detections) > 0 THEN
                        (SUM(compliant_count + ok_count + enabled_count)::DECIMAL /
                         SUM(total_detections) * 100)
                    ELSE 0
                END,
                2
            ) as health_percentage
        FROM detection_evaluation_daily_summary
        GROUP BY cloud_account_id, summary_date
        ORDER BY cloud_account_id, summary_date DESC;
    """
    )


def downgrade() -> None:
    # Drop views first
    op.execute("DROP VIEW IF EXISTS v_daily_compliance_trend")
    op.execute("DROP VIEW IF EXISTS v_recent_evaluation_changes")

    # Drop tables
    op.execute("DROP TABLE IF EXISTS detection_evaluation_alerts CASCADE")
    op.execute("DROP TABLE IF EXISTS detection_evaluation_daily_summary CASCADE")
    op.execute("DROP TABLE IF EXISTS detection_evaluation_history CASCADE")

    # Drop enums
    op.execute("DROP TYPE IF EXISTS evaluationalertseverity")
    op.execute("DROP TYPE IF EXISTS evaluationtype")
