"""Add GCP WIF fields to cloud_credentials.

Adds additional columns needed for AWS-to-GCP Workload Identity Federation:
- gcp_wif_provider_id: The WIF provider ID (e.g., "aws")
- gcp_wif_pool_location: The WIF pool location (e.g., "global")

Revision ID: 050_add_gcp_wif
Revises: 049_create_test
Create Date: 2025-12-30
"""

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "050_add_gcp_wif"
down_revision = "049_create_test_users"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Add GCP WIF configuration columns."""
    # Check if columns already exist (idempotent)
    conn = op.get_bind()
    inspector = sa.inspect(conn)
    existing_columns = {
        col["name"] for col in inspector.get_columns("cloud_credentials")
    }

    # Add gcp_wif_provider_id if not exists
    if "gcp_wif_provider_id" not in existing_columns:
        op.add_column(
            "cloud_credentials",
            sa.Column(
                "gcp_wif_provider_id",
                sa.String(128),
                nullable=True,
                server_default="aws",
            ),
        )

    # Add gcp_wif_pool_location if not exists
    if "gcp_wif_pool_location" not in existing_columns:
        op.add_column(
            "cloud_credentials",
            sa.Column(
                "gcp_wif_pool_location",
                sa.String(64),
                nullable=True,
                server_default="global",
            ),
        )


def downgrade() -> None:
    """Remove GCP WIF configuration columns."""
    op.drop_column("cloud_credentials", "gcp_wif_pool_location")
    op.drop_column("cloud_credentials", "gcp_wif_provider_id")
