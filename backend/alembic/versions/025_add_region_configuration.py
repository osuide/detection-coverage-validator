"""Add region configuration to cloud accounts.

Revision ID: 025
Revises: 024
Create Date: 2025-12-21

This migration adds multi-region scanning support by adding a region_config
JSONB column to cloud_accounts that supports three modes:
- "all": Scan all available regions (optionally with exclusions)
- "selected": Scan only explicitly selected regions
- "auto": Auto-discover active regions and scan those
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

# revision identifiers, used by Alembic.
revision = "025_add_region_config"
down_revision = "024_add_key_rotation"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Add region_config column to cloud_accounts."""
    op.add_column(
        "cloud_accounts",
        sa.Column(
            "region_config",
            JSONB,
            nullable=True,
            server_default=None,
            comment="Region configuration: {mode, regions, excluded_regions, discovered_regions}",
        ),
    )

    # Migrate existing regions data to region_config
    # For accounts that have regions set, convert to selected mode
    op.execute(
        """
        UPDATE cloud_accounts
        SET region_config = jsonb_build_object(
            'mode', 'selected',
            'regions', COALESCE(regions, '[]'::jsonb),
            'excluded_regions', '[]'::jsonb
        )
        WHERE regions IS NOT NULL AND regions != '[]'::jsonb
        """
    )


def downgrade() -> None:
    """Remove region_config column."""
    op.drop_column("cloud_accounts", "region_config")
