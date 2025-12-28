"""Delete all Security Hub aggregated detections to fix source_arn duplicates.

Revision ID: 044_sh_cleanup
Revises: 043_del_cspm_ctrl
Create Date: 2025-12-28

The source_arn format was changed from region-specific to account-specific.
Old format: {hub_arn}#{standard_id}
New format: arn:aws:securityhub:::account/{account_id}/standard/{standard_id}

This caused duplicate detections. This migration deletes all Security Hub
aggregated detections so a fresh scan creates clean data.
"""

from alembic import op
import sqlalchemy as sa
import logging

logger = logging.getLogger("alembic.runtime.migration")

# revision identifiers, used by Alembic.
revision = "044_sh_cleanup"
down_revision = "043_del_cspm_ctrl"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Delete all Security Hub aggregated detections."""
    conn = op.get_bind()

    # Count aggregated Security Hub detections
    count_result = conn.execute(
        sa.text(
            """
            SELECT COUNT(*) FROM detections
            WHERE detection_type = 'security_hub'
            AND raw_config->>'api_version' = 'cspm_aggregated'
            """
        )
    )
    count = count_result.scalar()
    logger.info(f"Found {count} Security Hub aggregated detections to delete")

    if count == 0:
        logger.info("No Security Hub aggregated detections to delete")
        return

    # Get IDs to delete
    result = conn.execute(
        sa.text(
            """
            SELECT id FROM detections
            WHERE detection_type = 'security_hub'
            AND raw_config->>'api_version' = 'cspm_aggregated'
            """
        )
    )
    detection_ids = [row[0] for row in result.fetchall()]

    # Delete related detection_mappings first (foreign key constraint)
    conn.execute(
        sa.text(
            """
            DELETE FROM detection_mappings
            WHERE detection_id = ANY(:ids)
            """
        ),
        {"ids": detection_ids},
    )
    logger.info(f"Deleted detection_mappings for {count} detections")

    # Now delete the detections
    conn.execute(
        sa.text(
            """
            DELETE FROM detections
            WHERE id = ANY(:ids)
            """
        ),
        {"ids": detection_ids},
    )

    logger.info(f"Deleted {count} Security Hub aggregated detections")
    logger.info("Run a new scan to create clean detections with correct source_arn")


def downgrade() -> None:
    """No downgrade - re-scan to restore detections."""
    pass
