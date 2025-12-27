"""Add REMOVED status to detection_status enum.

Revision ID: 041_add_removed_stat
Revises: 040_cleanup_alarms
Create Date: 2025-12-27

Adds 'removed' status for detections that are no longer found in the
cloud account (e.g., deleted alarms, rules, etc.).

Uses the "recreate enum" approach because ALTER TYPE ... ADD VALUE
cannot run inside a transaction, and asyncpg has issues with autocommit.
See: https://blog.yo1.dog/updating-enum-values-in-postgresql-the-safe-and-easy-way/
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

    Uses the recreate enum approach:
    1. Rename existing type to _old
    2. Create new type with all values
    3. Update column to use new type
    4. Drop old type

    This works inside a transaction unlike ALTER TYPE ADD VALUE.
    """
    conn = op.get_bind()

    # Check if 'removed' already exists (idempotency)
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

    # Step 1: Rename existing type
    conn.execute(sa.text("ALTER TYPE detectionstatus RENAME TO detectionstatus_old"))

    # Step 2: Create new type with all values including 'removed'
    conn.execute(
        sa.text(
            """
            CREATE TYPE detectionstatus AS ENUM (
                'active', 'disabled', 'error', 'unknown', 'removed'
            )
            """
        )
    )

    # Step 3: Update column to use new type
    # Need to cast through text to convert between enum types
    conn.execute(
        sa.text(
            """
            ALTER TABLE detections
            ALTER COLUMN status TYPE detectionstatus
            USING status::text::detectionstatus
            """
        )
    )

    # Step 4: Drop old type
    conn.execute(sa.text("DROP TYPE detectionstatus_old"))


def downgrade() -> None:
    """Remove 'removed' value from detection_status enum.

    First updates any 'removed' rows to 'unknown', then recreates
    the enum without 'removed'.
    """
    conn = op.get_bind()

    # Update any 'removed' rows to 'unknown' first
    conn.execute(
        sa.text(
            """
            UPDATE detections SET status = 'unknown'
            WHERE status = 'removed'
            """
        )
    )

    # Recreate enum without 'removed'
    conn.execute(sa.text("ALTER TYPE detectionstatus RENAME TO detectionstatus_old"))

    conn.execute(
        sa.text(
            """
            CREATE TYPE detectionstatus AS ENUM (
                'active', 'disabled', 'error', 'unknown'
            )
            """
        )
    )

    conn.execute(
        sa.text(
            """
            ALTER TABLE detections
            ALTER COLUMN status TYPE detectionstatus
            USING status::text::detectionstatus
            """
        )
    )

    conn.execute(sa.text("DROP TYPE detectionstatus_old"))
