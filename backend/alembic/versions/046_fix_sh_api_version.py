"""Fix Security Hub api_version in raw_config.

Revision ID: 046_fix_sh_api
Revises: 045_sh_cleanup_all
Create Date: 2025-12-28

Changes 'cspm_per_enabled_standard' to 'cspm_aggregated' in raw_config
so the frontend can recognize these detections as aggregated Security
Hub standards.
"""

from alembic import op
import sqlalchemy as sa
import logging

logger = logging.getLogger("alembic.runtime.migration")

# revision identifiers, used by Alembic.
revision = "046_fix_sh_api"
down_revision = "045_sh_cleanup_all"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Update api_version in Security Hub detection raw_config."""
    conn = op.get_bind()

    # Count detections with wrong api_version
    count_result = conn.execute(
        sa.text(
            """
            SELECT COUNT(*) FROM detections
            WHERE detection_type::text = 'security_hub'
            AND raw_config->>'api_version' = 'cspm_per_enabled_standard'
            """
        )
    )
    count = count_result.scalar()
    logger.info(f"Found {count} Security Hub detections with wrong api_version")

    if count == 0:
        logger.info("No detections need updating")
        return

    # Update the api_version in raw_config JSONB
    result = conn.execute(
        sa.text(
            """
            UPDATE detections
            SET raw_config = jsonb_set(
                raw_config,
                '{api_version}',
                '"cspm_aggregated"'
            )
            WHERE detection_type::text = 'security_hub'
            AND raw_config->>'api_version' = 'cspm_per_enabled_standard'
            """
        )
    )
    logger.info(
        f"Updated {result.rowcount} detection(s) api_version to cspm_aggregated"
    )


def downgrade() -> None:
    """Revert api_version change (optional - data migration)."""
    pass
