"""Add cloudwatch_alarm detection type.

Revision ID: 014_add_cloudwatch_alarm_type
Revises: 013_add_platform_settings
Create Date: 2025-12-19
"""
from alembic import op

# revision identifiers, used by Alembic.
revision = '014_add_cloudwatch_alarm_type'
down_revision = '013_add_platform_settings'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Add 'cloudwatch_alarm' to the detectiontype enum
    op.execute("ALTER TYPE detectiontype ADD VALUE IF NOT EXISTS 'cloudwatch_alarm'")


def downgrade() -> None:
    # Note: PostgreSQL doesn't support removing enum values directly
    # This would require recreating the enum type
    pass
