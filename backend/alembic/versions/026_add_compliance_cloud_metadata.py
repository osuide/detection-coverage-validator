"""Add cloud applicability metadata to compliance controls.

Revision ID: 026
Revises: 025
Create Date: 2025-12-22

This migration adds cloud-specific metadata to compliance controls:
- cloud_applicability: Indicates how relevant the control is to cloud environments
- cloud_context: JSONB with AWS/GCP service mappings and shared responsibility info
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

# revision identifiers, used by Alembic.
revision = "026_add_compliance_cloud"
down_revision = "025_add_region_config"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Add cloud_applicability column
    op.add_column(
        "compliance_controls",
        sa.Column(
            "cloud_applicability",
            sa.String(32),
            nullable=True,
            server_default="highly_relevant",
        ),
    )

    # Add cloud_context JSONB column
    op.add_column(
        "compliance_controls",
        sa.Column("cloud_context", JSONB, nullable=True),
    )


def downgrade() -> None:
    op.drop_column("compliance_controls", "cloud_context")
    op.drop_column("compliance_controls", "cloud_applicability")
