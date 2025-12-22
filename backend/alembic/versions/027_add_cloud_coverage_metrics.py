"""Add cloud coverage metrics to compliance snapshots.

Revision ID: 027
Revises: 026
Create Date: 2025-12-22

Adds cloud_metrics JSONB column to store cloud-specific coverage analytics:
- cloud_detectable_total: Controls that are cloud-detectable
- cloud_detectable_covered: Covered cloud-detectable controls
- cloud_coverage_percent: Cloud detection coverage percentage
- customer_responsibility_total: Customer responsibility controls
- customer_responsibility_covered: Covered customer responsibility controls
- provider_managed_total: Provider-managed controls
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

# revision identifiers, used by Alembic.
revision = "027_add_cloud_metrics"
down_revision = "026_add_compliance_cloud"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "compliance_coverage_snapshots",
        sa.Column("cloud_metrics", JSONB, nullable=True),
    )


def downgrade() -> None:
    op.drop_column("compliance_coverage_snapshots", "cloud_metrics")
