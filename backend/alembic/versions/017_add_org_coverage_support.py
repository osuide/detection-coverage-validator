"""Add organisation-level coverage support.

Revision ID: 017
Revises: 016
Create Date: 2024-12-20

Adds:
- Organisation contribution fields to coverage_snapshots table
- New org_coverage_snapshots table for aggregate org coverage
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID, JSONB


# revision identifiers, used by Alembic.
revision = "017"
down_revision = "016"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Add organisation contribution fields to coverage_snapshots
    op.add_column(
        "coverage_snapshots",
        sa.Column(
            "org_detection_count", sa.Integer(), nullable=False, server_default="0"
        ),
    )
    op.add_column(
        "coverage_snapshots",
        sa.Column(
            "org_covered_techniques", sa.Integer(), nullable=False, server_default="0"
        ),
    )
    op.add_column(
        "coverage_snapshots",
        sa.Column(
            "account_only_techniques", sa.Integer(), nullable=False, server_default="0"
        ),
    )
    op.add_column(
        "coverage_snapshots",
        sa.Column(
            "org_only_techniques", sa.Integer(), nullable=False, server_default="0"
        ),
    )
    op.add_column(
        "coverage_snapshots",
        sa.Column(
            "overlap_techniques", sa.Integer(), nullable=False, server_default="0"
        ),
    )
    op.add_column(
        "coverage_snapshots",
        sa.Column("coverage_breakdown", JSONB(), nullable=False, server_default="{}"),
    )

    # Create org_coverage_snapshots table
    op.create_table(
        "org_coverage_snapshots",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "cloud_organization_id",
            UUID(as_uuid=True),
            sa.ForeignKey("cloud_organizations.id"),
            nullable=False,
            index=True,
        ),
        # Account counts
        sa.Column("total_member_accounts", sa.Integer(), nullable=False, default=0),
        sa.Column("connected_accounts", sa.Integer(), nullable=False, default=0),
        # Aggregate coverage metrics
        sa.Column("total_techniques", sa.Integer(), nullable=False, default=0),
        sa.Column("union_covered_techniques", sa.Integer(), nullable=False, default=0),
        sa.Column(
            "minimum_covered_techniques", sa.Integer(), nullable=False, default=0
        ),
        sa.Column("average_coverage_percent", sa.Float(), nullable=False, default=0.0),
        # Coverage percentages
        sa.Column("union_coverage_percent", sa.Float(), nullable=False, default=0.0),
        sa.Column("minimum_coverage_percent", sa.Float(), nullable=False, default=0.0),
        # Org-level detection summary
        sa.Column("org_detection_count", sa.Integer(), nullable=False, default=0),
        sa.Column("org_covered_techniques", sa.Integer(), nullable=False, default=0),
        # Per-account breakdown stored as JSONB
        sa.Column("per_account_coverage", JSONB(), nullable=False, server_default="{}"),
        # Per-tactic aggregate coverage stored as JSONB
        sa.Column("tactic_coverage", JSONB(), nullable=False, server_default="{}"),
        # MITRE version
        sa.Column("mitre_version", sa.String(16), nullable=False, default="14.1"),
        # Metadata
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
            index=True,
        ),
    )


def downgrade() -> None:
    # Drop org_coverage_snapshots table
    op.drop_table("org_coverage_snapshots")

    # Remove organisation contribution fields from coverage_snapshots
    op.drop_column("coverage_snapshots", "coverage_breakdown")
    op.drop_column("coverage_snapshots", "overlap_techniques")
    op.drop_column("coverage_snapshots", "org_only_techniques")
    op.drop_column("coverage_snapshots", "account_only_techniques")
    op.drop_column("coverage_snapshots", "org_covered_techniques")
    op.drop_column("coverage_snapshots", "org_detection_count")
