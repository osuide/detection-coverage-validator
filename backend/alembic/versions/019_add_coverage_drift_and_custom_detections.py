"""Add coverage drift detection and custom detection tables.

Revision ID: 019_add_coverage_drift
Revises: 20251220_fix_admin_audit_nullable
Create Date: 2025-12-20 09:20:00.000000
"""

from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "019_add_coverage_drift"
down_revision: Union[str, None] = "fix_audit_nullable"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Create drift_severity enum
    drift_severity_enum = postgresql.ENUM(
        "none",
        "info",
        "warning",
        "critical",
        name="driftseverity",
        create_type=False,
    )
    drift_severity_enum.create(op.get_bind(), checkfirst=True)

    # Create custom_detection_format enum
    custom_detection_format_enum = postgresql.ENUM(
        "sigma",
        "yara",
        "snort",
        "suricata",
        "spl",
        "kql",
        "elasticsearch",
        "cloudwatch",
        "custom",
        name="customdetectionformat",
        create_type=False,
    )
    custom_detection_format_enum.create(op.get_bind(), checkfirst=True)

    # Create custom_detection_status enum
    custom_detection_status_enum = postgresql.ENUM(
        "pending",
        "processing",
        "mapped",
        "failed",
        "needs_review",
        name="customdetectionstatus",
        create_type=False,
    )
    custom_detection_status_enum.create(op.get_bind(), checkfirst=True)

    # Create coverage_history table
    op.create_table(
        "coverage_history",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "cloud_account_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("cloud_accounts.id", ondelete="CASCADE"),
            nullable=False,
            index=True,
        ),
        sa.Column(
            "scan_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("scans.id", ondelete="SET NULL"),
            nullable=True,
            index=True,
        ),
        sa.Column("total_techniques", sa.Integer(), nullable=False, default=0),
        sa.Column("covered_techniques", sa.Integer(), nullable=False, default=0),
        sa.Column("coverage_percent", sa.Float(), nullable=False, default=0.0),
        sa.Column("coverage_delta", sa.Float(), nullable=False, default=0.0),
        sa.Column(
            "techniques_added", postgresql.JSONB(), nullable=False, server_default="[]"
        ),
        sa.Column(
            "techniques_removed",
            postgresql.JSONB(),
            nullable=False,
            server_default="[]",
        ),
        sa.Column(
            "drift_severity",
            sa.Enum("none", "info", "warning", "critical", name="driftseverity"),
            nullable=False,
            server_default="none",
        ),
        sa.Column("coverage_by_tactic", postgresql.JSONB(), nullable=True),
        sa.Column(
            "recorded_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
            index=True,
        ),
    )

    # Create coverage_alerts table
    op.create_table(
        "coverage_alerts",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "organization_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
            index=True,
        ),
        sa.Column(
            "cloud_account_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("cloud_accounts.id", ondelete="CASCADE"),
            nullable=True,
            index=True,
        ),
        sa.Column(
            "coverage_history_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("coverage_history.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("alert_type", sa.String(64), nullable=False),
        sa.Column(
            "severity",
            sa.Enum("none", "info", "warning", "critical", name="driftseverity"),
            nullable=False,
        ),
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column("message", sa.String(1024), nullable=False),
        sa.Column("details", postgresql.JSONB(), nullable=False, server_default="{}"),
        sa.Column(
            "is_acknowledged", sa.Boolean(), nullable=False, server_default="false"
        ),
        sa.Column("acknowledged_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("acknowledged_by", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
            index=True,
        ),
    )

    # Create custom_detections table
    op.create_table(
        "custom_detections",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "organization_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
            index=True,
        ),
        sa.Column(
            "cloud_account_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("cloud_accounts.id", ondelete="CASCADE"),
            nullable=True,
            index=True,
        ),
        sa.Column(
            "created_by",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id"),
            nullable=False,
            index=True,
        ),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column(
            "format",
            sa.Enum(
                "sigma",
                "yara",
                "snort",
                "suricata",
                "spl",
                "kql",
                "elasticsearch",
                "cloudwatch",
                "custom",
                name="customdetectionformat",
            ),
            nullable=False,
        ),
        sa.Column(
            "status",
            sa.Enum(
                "pending",
                "processing",
                "mapped",
                "failed",
                "needs_review",
                name="customdetectionstatus",
            ),
            nullable=False,
            server_default="pending",
        ),
        sa.Column("rule_content", sa.Text(), nullable=False),
        sa.Column("rule_metadata", postgresql.JSONB(), nullable=True),
        sa.Column("mapped_techniques", postgresql.ARRAY(sa.String()), nullable=True),
        sa.Column("mapping_confidence", sa.Float(), nullable=True),
        sa.Column("mapping_notes", sa.Text(), nullable=True),
        sa.Column("processing_error", sa.Text(), nullable=True),
        sa.Column("processed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("tags", postgresql.ARRAY(sa.String()), nullable=True),
        sa.Column("severity", sa.String(50), nullable=True),
        sa.Column("data_sources", postgresql.ARRAY(sa.String()), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )

    # Create custom_detection_batches table
    op.create_table(
        "custom_detection_batches",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "organization_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
            index=True,
        ),
        sa.Column(
            "created_by",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id"),
            nullable=False,
            index=True,
        ),
        sa.Column("filename", sa.String(255), nullable=False),
        sa.Column(
            "format",
            sa.Enum(
                "sigma",
                "yara",
                "snort",
                "suricata",
                "spl",
                "kql",
                "elasticsearch",
                "cloudwatch",
                "custom",
                name="customdetectionformat",
            ),
            nullable=False,
        ),
        sa.Column("total_rules", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("processed_rules", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("successful_rules", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("failed_rules", sa.Integer(), nullable=False, server_default="0"),
        sa.Column(
            "status",
            sa.Enum(
                "pending",
                "processing",
                "mapped",
                "failed",
                "needs_review",
                name="customdetectionstatus",
            ),
            nullable=False,
            server_default="pending",
        ),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )


def downgrade() -> None:
    op.drop_table("custom_detection_batches")
    op.drop_table("custom_detections")
    op.drop_table("coverage_alerts")
    op.drop_table("coverage_history")

    # Drop enums
    op.execute("DROP TYPE IF EXISTS customdetectionstatus")
    op.execute("DROP TYPE IF EXISTS customdetectionformat")
    op.execute("DROP TYPE IF EXISTS driftseverity")
