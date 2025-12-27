"""Delete individual CSPM control detections before aggregation.

Revision ID: 043_del_cspm_ctrl
Revises: 042_cspm_dedup
Create Date: 2025-12-27

The Security Hub scanner now creates ONE detection per security standard
(FSBP, CIS, PCI-DSS) instead of 500+ individual control detections.

This migration deletes all old individual CSPM control detections.
New scans will create the aggregated standard-level detections.
"""

from alembic import op
import sqlalchemy as sa
import logging

logger = logging.getLogger("alembic.runtime.migration")

# revision identifiers, used by Alembic.
revision = "043_del_cspm_ctrl"
down_revision = "042_cspm_dedup"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Delete all individual CSPM control detections."""
    conn = op.get_bind()

    # Count individual CSPM control detections (api_version = 'cspm', not 'cspm_aggregated')
    count_result = conn.execute(
        sa.text(
            """
            SELECT COUNT(*) FROM detections
            WHERE detection_type = 'security_hub'
            AND raw_config->>'api_version' = 'cspm'
            """
        )
    )
    count = count_result.scalar()
    logger.info(f"Found {count} individual CSPM control detections to delete")

    if count == 0:
        logger.info("No individual CSPM control detections to delete")
        return

    # Get IDs to delete
    result = conn.execute(
        sa.text(
            """
            SELECT id FROM detections
            WHERE detection_type = 'security_hub'
            AND raw_config->>'api_version' = 'cspm'
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

    logger.info(f"Deleted {count} individual CSPM control detections")
    logger.info("New scans will create aggregated standard-level detections")


def downgrade() -> None:
    """No downgrade - re-scan to restore detections."""
    pass
