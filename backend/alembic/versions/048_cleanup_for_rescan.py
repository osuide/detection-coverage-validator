"""Cleanup detections for fresh scan.

Revision ID: 048_cleanup_rescan
Revises: 047_add_user_webauthn
Create Date: 2025-12-29

This migration clears detection data so a fresh scan can be run.
The OTHER category and CIS mapping issues require a fresh scan after code fix.
"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = "048_cleanup_rescan"
down_revision = "047_add_user_webauthn"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Delete all detection data to allow fresh scan."""
    conn = op.get_bind()

    # Delete detection-related data (order matters due to FK constraints)
    # 1. Delete detection evaluation alerts
    result = conn.execute(sa.text("DELETE FROM detection_evaluation_alerts"))
    print(f"Deleted {result.rowcount} detection evaluation alerts")

    # 2. Delete detection evaluation history
    result = conn.execute(sa.text("DELETE FROM detection_evaluation_history"))
    print(f"Deleted {result.rowcount} detection evaluation history records")

    # 3. Delete detection mappings
    result = conn.execute(sa.text("DELETE FROM detection_mappings"))
    print(f"Deleted {result.rowcount} detection mappings")

    # 4. Delete detections
    result = conn.execute(sa.text("DELETE FROM detections"))
    print(f"Deleted {result.rowcount} detections")

    # 5. Delete scans
    result = conn.execute(sa.text("DELETE FROM scans"))
    print(f"Deleted {result.rowcount} scans")

    # 6. Delete scan usage records to reset limits
    result = conn.execute(sa.text("DELETE FROM scan_usage"))
    print(f"Deleted {result.rowcount} scan usage records")

    print("\nCleanup complete! Run a fresh scan to populate data.")


def downgrade() -> None:
    """No downgrade - data cleanup is one-way."""
    pass
