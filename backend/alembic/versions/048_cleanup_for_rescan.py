"""Cleanup detections for fresh scan.

Revision ID: 048_cleanup_rescan
Revises: 047_add_webauthn
Create Date: 2025-12-29

This migration clears detection data so a fresh scan can be run.
The OTHER category and CIS mapping issues require a fresh scan after code fix.
"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = "048_cleanup_rescan"
down_revision = "047_add_webauthn"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Delete all detection data to allow fresh scan."""
    conn = op.get_bind()

    # Get list of existing tables to avoid errors for non-existent tables
    inspector = sa.inspect(conn)
    existing_tables = set(inspector.get_table_names())

    def safe_delete(table_name: str, description: str) -> None:
        """Delete from table only if it exists."""
        if table_name in existing_tables:
            result = conn.execute(sa.text(f"DELETE FROM {table_name}"))
            print(f"Deleted {result.rowcount} {description}")
        else:
            print(f"Table '{table_name}' does not exist, skipping")

    # Delete scan-related data first (FK constraints point TO scans table)
    # These must be deleted/nullified before scans can be deleted
    safe_delete("coverage_snapshots", "coverage snapshots")
    safe_delete("coverage_gaps", "coverage gaps")
    safe_delete("coverage_history", "coverage history records")

    # Delete detection-related data (order matters due to FK constraints)
    safe_delete("detection_evaluation_alerts", "detection evaluation alerts")
    safe_delete("detection_evaluation_history", "detection evaluation history records")
    safe_delete("detection_mappings", "detection mappings")
    safe_delete("detections", "detections")

    # Delete scans (now safe - all FK references cleared)
    safe_delete("scans", "scans")

    print("\nCleanup complete! Run a fresh scan to populate data.")


def downgrade() -> None:
    """No downgrade - data cleanup is one-way."""
    pass
