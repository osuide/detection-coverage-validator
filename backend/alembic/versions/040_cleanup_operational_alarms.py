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

    # Count before deletion for logging
    result = conn.execute(
        sa.text(
            """
            SELECT COUNT(*) FROM detections
            WHERE detection_type = 'cloudwatch_alarm'
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
    count = result.scalar()
    print(f"Found {count} operational alarms to delete")

    # Delete operational alarms
    conn.execute(
        sa.text(
            """
            DELETE FROM detections
            WHERE detection_type = 'cloudwatch_alarm'
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

    print(f"Deleted {count} operational CloudWatch alarms")


def downgrade() -> None:
    """No downgrade - data migration only. Re-scan to restore if needed."""
    pass
