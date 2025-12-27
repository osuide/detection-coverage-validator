"""Remove duplicate CSPM Security Hub detections.

Revision ID: 042_cspm_dedup
Revises: 041_add_removed_status
Create Date: 2025-12-27

CSPM control definitions are GLOBAL - the same S3.1 control exists in
every region. We accidentally created duplicates by scanning all regions.

This migration keeps ONE detection per control_id (the first one by
discovered_at) and deletes the duplicates.
"""

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "042_cspm_dedup"
down_revision = "041_add_removed_status"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Delete duplicate CSPM Security Hub detections, keeping the oldest."""
    conn = op.get_bind()

    # Find duplicate CSPM detections (same control_id, different regions)
    # Keep the one with the earliest discovered_at
    result = conn.execute(
        sa.text(
            """
            WITH duplicates AS (
                SELECT id,
                       raw_config->>'control_id' as control_id,
                       cloud_account_id,
                       ROW_NUMBER() OVER (
                           PARTITION BY cloud_account_id, raw_config->>'control_id'
                           ORDER BY discovered_at ASC
                       ) as rn
                FROM detections
                WHERE detection_type = 'security_hub'
                AND raw_config->>'api_version' = 'cspm'
                AND raw_config->>'control_id' IS NOT NULL
            )
            SELECT id FROM duplicates WHERE rn > 1
            """
        )
    )
    duplicate_ids = [row[0] for row in result.fetchall()]
    count = len(duplicate_ids)
    print(f"Found {count} duplicate CSPM detections to delete")

    if count == 0:
        print("No duplicate CSPM detections to delete")
        return

    # Delete related detection_mappings first (foreign key constraint)
    conn.execute(
        sa.text(
            """
            DELETE FROM detection_mappings
            WHERE detection_id = ANY(:ids)
            """
        ),
        {"ids": duplicate_ids},
    )
    print(f"Deleted detection_mappings for {count} detections")

    # Now delete the duplicate detections
    conn.execute(
        sa.text(
            """
            DELETE FROM detections
            WHERE id = ANY(:ids)
            """
        ),
        {"ids": duplicate_ids},
    )

    print(f"Deleted {count} duplicate CSPM Security Hub detections")


def downgrade() -> None:
    """No downgrade - data migration only. Re-scan to restore if needed."""
    pass
