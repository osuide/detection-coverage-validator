"""Add Azure support - enum values and WIF config column.

Adds AZURE to CloudProvider enum, AZURE_DEFENDER and AZURE_POLICY to DetectionType enum,
and azure_workload_identity_config JSONB column to cloud_accounts table.

Revision ID: 059_azure_support
Revises: 058_add_detection_unique_index
Create Date: 2026-01-21
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

# revision identifiers, used by Alembic.
revision = "059_azure_support"
down_revision = "058_detection_unique"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Add Azure support."""
    conn = op.get_bind()
    inspector = sa.inspect(conn)

    # Add AZURE to cloudprovider enum
    op.execute("ALTER TYPE cloudprovider ADD VALUE IF NOT EXISTS 'azure'")

    # Add Azure detection types to detectiontype enum
    op.execute("ALTER TYPE detectiontype ADD VALUE IF NOT EXISTS 'azure_defender'")
    op.execute("ALTER TYPE detectiontype ADD VALUE IF NOT EXISTS 'azure_policy'")

    # Add azure_workload_identity_config column if it doesn't exist
    columns = {col["name"] for col in inspector.get_columns("cloud_accounts")}

    if "azure_workload_identity_config" not in columns:
        op.add_column(
            "cloud_accounts",
            sa.Column(
                "azure_workload_identity_config",
                JSONB,
                nullable=True,
                comment="Azure WIF config (tenant_id, client_id, subscription_id)",
            ),
        )

    # Add azure_enabled boolean feature flag if it doesn't exist
    if "azure_enabled" not in columns:
        op.add_column(
            "cloud_accounts",
            sa.Column(
                "azure_enabled",
                sa.Boolean(),
                nullable=False,
                server_default="false",
                comment="Feature flag for Azure scanning",
            ),
        )


def downgrade() -> None:
    """Remove Azure support.

    Note: PostgreSQL does not support removing enum values directly.
    Column removal is reversible.
    """
    conn = op.get_bind()
    inspector = sa.inspect(conn)

    columns = {col["name"] for col in inspector.get_columns("cloud_accounts")}

    # Remove columns if they exist
    if "azure_enabled" in columns:
        op.drop_column("cloud_accounts", "azure_enabled")

    if "azure_workload_identity_config" in columns:
        op.drop_column("cloud_accounts", "azure_workload_identity_config")

    # Enum values cannot be safely removed without recreating the entire type
    # Leave them in place - they won't cause issues
