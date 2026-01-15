"""Add API_KEY_UPDATED to AuditLogAction enum.

Revision ID: 056_api_key_updated
Revises: 055_add_performance_idx
Create Date: 2026-01-15
"""

from alembic import op

# revision identifiers, used by Alembic.
revision = "056_api_key_updated"
down_revision = "055_add_performance_idx"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Add new enum value to auditlogaction type
    # PostgreSQL requires ALTER TYPE ... ADD VALUE
    op.execute("ALTER TYPE auditlogaction ADD VALUE IF NOT EXISTS 'api_key.updated'")


def downgrade() -> None:
    # PostgreSQL does not support removing enum values directly
    # Would require recreating the type, which is complex and risky
    # Leave the value in place - it won't cause issues
    pass
