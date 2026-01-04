"""Add welcome_email_sent_at to users table.

Revision ID: 052_add_welcome_email
Revises: 051_add_inspector_macie
Create Date: 2026-01-04

Tracks when welcome email was sent to new users.
"""

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic
revision = "052_add_welcome_email"
down_revision = "051_add_inspector_macie"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Add welcome_email_sent_at column to users table."""
    op.add_column(
        "users",
        sa.Column("welcome_email_sent_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    """Remove welcome_email_sent_at column."""
    op.drop_column("users", "welcome_email_sent_at")
