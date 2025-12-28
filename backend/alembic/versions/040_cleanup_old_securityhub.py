"""Cleanup old Security Hub detections with incorrect grouping

This migration deletes old Security Hub standard detections that were created
with the inference-based grouping (which produced "OTHER" categories and
incorrect control counts). The new scan will recreate them correctly using
GetEnabledStandards and DescribeStandardsControls APIs.

Revision ID: 040_cleanup_securityhub
Revises: 039_add_eval_type
Create Date: 2025-12-28

"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = "040_cleanup_securityhub"
down_revision = "039_fix_gap_names"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Delete old Security Hub standard detections.

    These will be recreated correctly on the next scan with:
    - Proper standard names (CIS, NIST, FSBP) instead of "OTHER"
    - Correct per-standard control counts
    - Region-agnostic source_arns
    """
    conn = op.get_bind()

    # First, delete detection_mappings for Security Hub detections
    conn.execute(
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

    # Then delete the detections themselves
    result = conn.execute(
        sa.text(
            """
            DELETE FROM detections
            WHERE detection_type = 'security_hub'
            AND name LIKE 'SecurityHub-%'
            RETURNING id, name
            """
        )
    )

    deleted_count = result.rowcount
    print(f"Deleted {deleted_count} old Security Hub standard detections")


def downgrade() -> None:
    """Cannot restore deleted detections - they will be recreated on next scan."""
    pass
