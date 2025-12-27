"""Add REMOVED status to detection_status enum.

Revision ID: 041_add_removed_stat
Revises: 040_cleanup_alarms
Create Date: 2025-12-27

Adds 'removed' status for detections that are no longer found in the
cloud account (e.g., deleted alarms, rules, etc.).
"""

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "041_add_removed_stat"
down_revision = "040_cleanup_alarms"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Add 'removed' value to detection_status enum.

    PostgreSQL's ALTER TYPE ... ADD VALUE cannot run inside a transaction.
    We need to commit the current transaction first, then add the value.
    """
    # Get connection and commit current transaction
    conn = op.get_bind()

    # Check if the value already exists to make this idempotent
    result = conn.execute(
        sa.text(
            """
            SELECT 1 FROM pg_enum
            WHERE enumtypid = 'detectionstatus'::regtype
            AND enumlabel = 'removed'
            """
        )
    )
    if result.fetchone():
        # Value already exists, skip
        return

    # Commit current transaction so we can add enum value
    conn.execute(sa.text("COMMIT"))

    # Add the enum value (must be outside transaction)
    conn.execute(sa.text("ALTER TYPE detectionstatus ADD VALUE 'removed'"))

    # Start a new transaction for any subsequent operations
    conn.execute(sa.text("BEGIN"))


def downgrade() -> None:
    """Cannot remove enum values in PostgreSQL - no-op."""
    # PostgreSQL doesn't support removing enum values
    # Detections with 'removed' status would need to be updated first
    pass
