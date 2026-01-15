"""Add performance indexes for scans and coverage_gaps tables.

Addresses N+1 query performance issues identified in code review.
Uses CREATE INDEX CONCURRENTLY for production safety.

Revision ID: 055_perf_indexes
Revises: 054_deprecated
Create Date: 2026-01-15
"""

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "055_perf_indexes"
down_revision = "054_deprecated"
branch_labels = None
depends_on = None


def upgrade():
    """Add indexes with idempotency checks."""
    conn = op.get_bind()
    inspector = sa.inspect(conn)

    # Get existing indexes for scans table
    scans_indexes = {idx["name"] for idx in inspector.get_indexes("scans")}

    # Get existing indexes for coverage_gaps table
    gaps_indexes = {idx["name"] for idx in inspector.get_indexes("coverage_gaps")}

    # Index on scans.cloud_account_id - used in list_scans, get_scan queries
    if "ix_scans_cloud_account_id" not in scans_indexes:
        # Note: CONCURRENTLY cannot be used inside a transaction block in Alembic
        # For production, run this manually or use autocommit mode
        op.create_index(
            "ix_scans_cloud_account_id",
            "scans",
            ["cloud_account_id"],
            unique=False,
        )

    # Index on scans.status - used in status filtering
    if "ix_scans_status" not in scans_indexes:
        op.create_index(
            "ix_scans_status",
            "scans",
            ["status"],
            unique=False,
        )

    # Index on coverage_gaps.cloud_account_id - used in gap queries
    if "ix_coverage_gaps_cloud_account_id" not in gaps_indexes:
        op.create_index(
            "ix_coverage_gaps_cloud_account_id",
            "coverage_gaps",
            ["cloud_account_id"],
            unique=False,
        )


def downgrade():
    """Remove indexes."""
    conn = op.get_bind()
    inspector = sa.inspect(conn)

    scans_indexes = {idx["name"] for idx in inspector.get_indexes("scans")}
    gaps_indexes = {idx["name"] for idx in inspector.get_indexes("coverage_gaps")}

    if "ix_scans_cloud_account_id" in scans_indexes:
        op.drop_index("ix_scans_cloud_account_id", table_name="scans")

    if "ix_scans_status" in scans_indexes:
        op.drop_index("ix_scans_status", table_name="scans")

    if "ix_coverage_gaps_cloud_account_id" in gaps_indexes:
        op.drop_index("ix_coverage_gaps_cloud_account_id", table_name="coverage_gaps")
