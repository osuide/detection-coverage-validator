"""Delete ALL Security Hub standard detections including OTHER.

Revision ID: 045_sh_cleanup_all
Revises: 044_sh_cleanup
Create Date: 2025-12-28

Previous migration (044) only deleted detections with api_version='cspm_aggregated'.
This migration deletes ALL SecurityHub-* detections to ensure "OTHER" and any
other old detections are removed before a clean re-scan.
"""

from alembic import op
import sqlalchemy as sa
import logging

logger = logging.getLogger("alembic.runtime.migration")

# revision identifiers, used by Alembic.
revision = "045_sh_cleanup_all"
down_revision = "044_sh_cleanup"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Delete ALL Security Hub standard detections."""
    conn = op.get_bind()

    # Count ALL Security Hub standard detections
    count_result = conn.execute(
        sa.text(
            """
            SELECT COUNT(*) FROM detections
            WHERE detection_type = 'security_hub'
            AND name LIKE 'SecurityHub-%'
            """
        )
    )
    count = count_result.scalar()
    logger.info(f"Found {count} Security Hub standard detections to delete")

    if count == 0:
        logger.info("No Security Hub standard detections to delete")
        return

    # Delete detection_mappings first (foreign key constraint)
    deleted_mappings = conn.execute(
        sa.text(
            """
            DELETE FROM detection_mappings
            WHERE detection_id IN (
                SELECT id FROM detections
                WHERE detection_type = 'security_hub'
                AND name LIKE 'SecurityHub-%'
            )
            """
        )
    )
    logger.info(f"Deleted {deleted_mappings.rowcount} detection_mappings")

    # Delete the detections
    deleted_detections = conn.execute(
        sa.text(
            """
            DELETE FROM detections
            WHERE detection_type = 'security_hub'
            AND name LIKE 'SecurityHub-%'
            """
        )
    )
    logger.info(f"Deleted {deleted_detections.rowcount} Security Hub detections")
    logger.info("Run a new scan to create clean detections with correct standards")


def downgrade() -> None:
    """Cannot restore - re-scan to recreate detections."""
    pass
