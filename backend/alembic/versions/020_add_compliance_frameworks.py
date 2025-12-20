"""Add compliance framework tables.

Maps MITRE ATT&CK techniques to compliance framework controls (NIST 800-53, CIS, etc.).

Revision ID: 020_add_compliance
Revises: 019_add_coverage_drift
Create Date: 2025-12-20 12:00:00.000000
"""

from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "020_add_compliance"
down_revision: Union[str, None] = "019_add_coverage_drift"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Check existing tables for idempotency
    conn = op.get_bind()
    inspector = sa.inspect(conn)
    existing_tables = inspector.get_table_names()

    # Create compliance_frameworks table
    if "compliance_frameworks" not in existing_tables:
        op.create_table(
            "compliance_frameworks",
            sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
            sa.Column(
                "framework_id",
                sa.String(64),
                nullable=False,
                unique=True,
                index=True,
            ),
            sa.Column("name", sa.String(128), nullable=False),
            sa.Column("version", sa.String(32), nullable=False),
            sa.Column("description", sa.Text(), nullable=True),
            sa.Column("source_url", sa.String(512), nullable=True),
            sa.Column("is_active", sa.Boolean(), nullable=False, server_default="true"),
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

    # Create compliance_controls table
    if "compliance_controls" not in existing_tables:
        op.create_table(
            "compliance_controls",
            sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
            sa.Column(
                "framework_id",
                postgresql.UUID(as_uuid=True),
                sa.ForeignKey("compliance_frameworks.id", ondelete="CASCADE"),
                nullable=False,
                index=True,
            ),
            sa.Column("control_id", sa.String(32), nullable=False, index=True),
            sa.Column("control_family", sa.String(128), nullable=False),
            sa.Column("name", sa.String(256), nullable=False),
            sa.Column("description", sa.Text(), nullable=True),
            sa.Column("priority", sa.String(8), nullable=True),
            sa.Column(
                "parent_control_id",
                postgresql.UUID(as_uuid=True),
                sa.ForeignKey("compliance_controls.id", ondelete="SET NULL"),
                nullable=True,
            ),
            sa.Column(
                "is_enhancement", sa.Boolean(), nullable=False, server_default="false"
            ),
            sa.Column(
                "display_order", sa.Integer(), nullable=False, server_default="0"
            ),
            sa.Column(
                "created_at",
                sa.DateTime(timezone=True),
                nullable=False,
                server_default=sa.func.now(),
            ),
        )

        # Create unique constraint on (framework_id, control_id)
        op.create_unique_constraint(
            "uq_compliance_controls_framework_control",
            "compliance_controls",
            ["framework_id", "control_id"],
        )

    # Create control_technique_mappings table (many-to-many junction)
    if "control_technique_mappings" not in existing_tables:
        op.create_table(
            "control_technique_mappings",
            sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
            sa.Column(
                "control_id",
                postgresql.UUID(as_uuid=True),
                sa.ForeignKey("compliance_controls.id", ondelete="CASCADE"),
                nullable=False,
                index=True,
            ),
            sa.Column(
                "technique_id",
                postgresql.UUID(as_uuid=True),
                sa.ForeignKey("techniques.id", ondelete="CASCADE"),
                nullable=False,
                index=True,
            ),
            sa.Column("mapping_source", sa.String(32), nullable=False),
            sa.Column("mapping_type", sa.String(32), nullable=False),
            sa.Column("source_url", sa.String(512), nullable=True),
            sa.Column("notes", sa.Text(), nullable=True),
            sa.Column(
                "created_at",
                sa.DateTime(timezone=True),
                nullable=False,
                server_default=sa.func.now(),
            ),
        )

        # Create unique constraint to prevent duplicate mappings
        op.create_unique_constraint(
            "uq_control_technique_mapping",
            "control_technique_mappings",
            ["control_id", "technique_id"],
        )

    # Create compliance_coverage_snapshots table
    if "compliance_coverage_snapshots" not in existing_tables:
        op.create_table(
            "compliance_coverage_snapshots",
            sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
            sa.Column(
                "cloud_account_id",
                postgresql.UUID(as_uuid=True),
                sa.ForeignKey("cloud_accounts.id", ondelete="CASCADE"),
                nullable=False,
                index=True,
            ),
            sa.Column(
                "framework_id",
                postgresql.UUID(as_uuid=True),
                sa.ForeignKey("compliance_frameworks.id", ondelete="CASCADE"),
                nullable=False,
                index=True,
            ),
            sa.Column(
                "coverage_snapshot_id",
                postgresql.UUID(as_uuid=True),
                sa.ForeignKey("coverage_snapshots.id", ondelete="CASCADE"),
                nullable=False,
                index=True,
            ),
            sa.Column(
                "total_controls", sa.Integer(), nullable=False, server_default="0"
            ),
            sa.Column(
                "covered_controls", sa.Integer(), nullable=False, server_default="0"
            ),
            sa.Column(
                "partial_controls", sa.Integer(), nullable=False, server_default="0"
            ),
            sa.Column(
                "uncovered_controls", sa.Integer(), nullable=False, server_default="0"
            ),
            sa.Column(
                "coverage_percent", sa.Float(), nullable=False, server_default="0.0"
            ),
            sa.Column(
                "family_coverage",
                postgresql.JSONB(),
                nullable=False,
                server_default="{}",
            ),
            sa.Column(
                "top_gaps",
                postgresql.JSONB(),
                nullable=False,
                server_default="[]",
            ),
            sa.Column(
                "created_at",
                sa.DateTime(timezone=True),
                nullable=False,
                server_default=sa.func.now(),
                index=True,
            ),
        )

        # Create index for faster queries
        op.create_index(
            "ix_compliance_coverage_account_framework",
            "compliance_coverage_snapshots",
            ["cloud_account_id", "framework_id", "created_at"],
        )


def downgrade() -> None:
    # Drop tables in reverse dependency order
    op.execute("DROP TABLE IF EXISTS compliance_coverage_snapshots CASCADE")
    op.execute("DROP TABLE IF EXISTS control_technique_mappings CASCADE")
    op.execute("DROP TABLE IF EXISTS compliance_controls CASCADE")
    op.execute("DROP TABLE IF EXISTS compliance_frameworks CASCADE")
