"""Remove operational CloudWatch alarms from detections.

Revision ID: 040_cleanup_alarms
Revises: 039_fix_gap_names
Create Date: 2025-12-27

This data migration removes CloudWatch alarms that are AWS-managed
operational alarms (auto-scaling, billing, etc.) rather than security
detections. These were ingested before filtering was added to the scanner.
"""

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "040_cleanup_alarms"
down_revision = "039_fix_gap_names"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Delete operational CloudWatch alarms that aren't security-relevant."""
    conn = op.get_bind()

    # First, get the IDs of detections to delete
    result = conn.execute(
        sa.text(
            """
            SELECT id FROM detections
            WHERE detection_type::text = 'cloudwatch_alarm'
            AND (
                description LIKE '%DO NOT EDIT OR DELETE%'
                OR description LIKE '%TargetTrackingScaling%'
                OR name LIKE '%TargetTracking%'
                OR raw_config::text LIKE '%AWS/Billing%'
                OR raw_config::text LIKE '%AWS/AutoScaling%'
                OR raw_config::text LIKE '%ApplicationAutoScaling%'
            )
            """
        )
    )
    detection_ids = [row[0] for row in result.fetchall()]
    count = len(detection_ids)
    print(f"Found {count} operational alarms to delete")

    if count == 0:
        print("No operational alarms to delete")
        return

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
    print(f"Deleted detection_mappings for {count} detections")

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

    print(f"Deleted {count} operational CloudWatch alarms")


def downgrade() -> None:
    """No downgrade - data migration only. Re-scan to restore if needed."""
    pass
