"""Add evaluation_summary field to detections.

Revision ID: 037_add_evaluation_summary
Revises: 036_add_cloud_relevant_flag
Create Date: 2025-12-27

This migration adds evaluation_summary JSONB field to store type-specific
evaluation/compliance data for detections:
- Config Rules: compliance status (COMPLIANT/NON_COMPLIANT) and resource counts
- CloudWatch Alarms: alarm state (OK/ALARM/INSUFFICIENT_DATA)
- EventBridge Rules: rule state (ENABLED/DISABLED)

This allows users to see not just that a detection exists, but whether
resources are actually compliant or in a healthy state.
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB


# revision identifiers, used by Alembic.
revision = "037_add_evaluation_summary"
down_revision = "036_add_cloud_relevant_flag"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Add evaluation_summary JSONB field for type-specific evaluation data
    op.add_column(
        "detections",
        sa.Column("evaluation_summary", JSONB, nullable=True),
    )

    # Add evaluation_updated_at timestamp to track when evaluation was last fetched
    op.add_column(
        "detections",
        sa.Column(
            "evaluation_updated_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )

    # Create GIN index for efficient JSONB queries
    # Allows queries like: WHERE evaluation_summary->>'compliance_type' = 'NON_COMPLIANT'
    op.create_index(
        "ix_detections_evaluation_summary",
        "detections",
        ["evaluation_summary"],
        postgresql_using="gin",
    )


def downgrade() -> None:
    op.drop_index("ix_detections_evaluation_summary", table_name="detections")
    op.drop_column("detections", "evaluation_updated_at")
    op.drop_column("detections", "evaluation_summary")
