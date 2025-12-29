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

    # Delete scan-related data first (FK constraints point TO scans table)
    # These must be deleted/nullified before scans can be deleted

    # 1. Delete coverage snapshots (FK to scans)
    result = conn.execute(sa.text("DELETE FROM coverage_snapshots"))
    print(f"Deleted {result.rowcount} coverage snapshots")

    # 2. Delete gaps (FK to scans)
    result = conn.execute(sa.text("DELETE FROM gaps"))
    print(f"Deleted {result.rowcount} gaps")

    # 3. Delete coverage history (FK to scans with SET NULL, but clean anyway)
    result = conn.execute(sa.text("DELETE FROM coverage_history"))
    print(f"Deleted {result.rowcount} coverage history records")

    # Now delete detection-related data (order matters due to FK constraints)
    # 4. Delete detection evaluation alerts
    result = conn.execute(sa.text("DELETE FROM detection_evaluation_alerts"))
    print(f"Deleted {result.rowcount} detection evaluation alerts")

    # 5. Delete detection evaluation history (FK to scans with SET NULL)
    result = conn.execute(sa.text("DELETE FROM detection_evaluation_history"))
    print(f"Deleted {result.rowcount} detection evaluation history records")

    # 6. Delete detection mappings (FK to detections)
    result = conn.execute(sa.text("DELETE FROM detection_mappings"))
    print(f"Deleted {result.rowcount} detection mappings")

    # 7. Delete detections
    result = conn.execute(sa.text("DELETE FROM detections"))
    print(f"Deleted {result.rowcount} detections")

    # 8. Delete scans (now safe - all FK references cleared)
    result = conn.execute(sa.text("DELETE FROM scans"))
    print(f"Deleted {result.rowcount} scans")

    # 9. Delete scan usage records to reset limits
    result = conn.execute(sa.text("DELETE FROM scan_usage"))
    print(f"Deleted {result.rowcount} scan usage records")

    print("\nCleanup complete! Run a fresh scan to populate data.")


def downgrade() -> None:
    """No downgrade - data cleanup is one-way."""
    pass
