"""Add service awareness fields for coverage calculation.

Revision ID: 029
Revises: 028
Create Date: 2025-12-23

Adds service-aware coverage tracking:
- target_services on detections: Which services each detection monitors
- discovered_services on cloud_accounts: Which services have resources in account
- discovered_services_at on cloud_accounts: When service discovery last ran

This enables more accurate coverage calculation by checking if detections
exist for all services where data resides, not just technique coverage.
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

# revision identifiers, used by Alembic.
revision = "029_add_service_awareness"
down_revision = "028_fix_governance_controls"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Add target_services to detections - which services this detection monitors
    op.add_column(
        "detections",
        sa.Column("target_services", JSONB, nullable=True, default=list),
    )

    # Add discovered_services to cloud_accounts - which services have resources
    op.add_column(
        "cloud_accounts",
        sa.Column("discovered_services", JSONB, nullable=True, default=list),
    )
    op.add_column(
        "cloud_accounts",
        sa.Column("discovered_services_at", sa.DateTime(timezone=True), nullable=True),
    )

    # Add GIN indexes for array containment queries
    op.create_index(
        "ix_detections_target_services_gin",
        "detections",
        ["target_services"],
        postgresql_using="gin",
    )
    op.create_index(
        "ix_cloud_accounts_discovered_services_gin",
        "cloud_accounts",
        ["discovered_services"],
        postgresql_using="gin",
    )


def downgrade() -> None:
    op.drop_index(
        "ix_cloud_accounts_discovered_services_gin", table_name="cloud_accounts"
    )
    op.drop_index("ix_detections_target_services_gin", table_name="detections")
    op.drop_column("cloud_accounts", "discovered_services_at")
    op.drop_column("cloud_accounts", "discovered_services")
    op.drop_column("detections", "target_services")
