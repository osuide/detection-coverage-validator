"""Add REMOVED status to detection_status enum.

Revision ID: 041_add_removed_stat
Revises: 040_cleanup_alarms
Create Date: 2025-12-27

Adds 'removed' status for detections that are no longer found in the
cloud account (e.g., deleted alarms, rules, etc.).
"""

from alembic import op


# revision identifiers, used by Alembic.
revision = "041_add_removed_stat"
down_revision = "040_cleanup_alarms"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Add 'removed' value to detection_status enum."""
    # PostgreSQL requires ALTER TYPE to add enum values
    op.execute("ALTER TYPE detectionstatus ADD VALUE IF NOT EXISTS 'removed'")


def downgrade() -> None:
    """Cannot remove enum values in PostgreSQL - no-op."""
    # PostgreSQL doesn't support removing enum values
    # Detections with 'removed' status would need to be updated first
    pass
