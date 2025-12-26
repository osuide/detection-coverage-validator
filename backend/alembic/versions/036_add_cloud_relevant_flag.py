"""Add is_cloud_relevant flag to control_technique_mappings.

Revision ID: 036_add_cloud_relevant_flag
Revises: 035_fix_allowed_auth_methods
Create Date: 2025-12-26

This migration adds a boolean flag to indicate whether a technique mapping
is cloud-relevant (detectable via cloud-native logging sources like CloudTrail,
Cloud Audit Logs). Non-cloud techniques (e.g., T1574.002 DLL Side-Loading)
are filtered from coverage calculations by default.
"""

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "036_add_cloud_relevant_flag"
down_revision = "035_fix_allowed_auth_methods"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Add is_cloud_relevant column with default True
    op.add_column(
        "control_technique_mappings",
        sa.Column(
            "is_cloud_relevant",
            sa.Boolean(),
            server_default=sa.text("true"),
            nullable=False,
        ),
    )

    # Create index for efficient filtering
    op.create_index(
        "ix_control_technique_mappings_is_cloud_relevant",
        "control_technique_mappings",
        ["is_cloud_relevant"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(
        "ix_control_technique_mappings_is_cloud_relevant",
        table_name="control_technique_mappings",
    )
    op.drop_column("control_technique_mappings", "is_cloud_relevant")
