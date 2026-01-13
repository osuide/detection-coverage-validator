"""Add token_rotated_at to user_sessions for grace window.

Revision ID: 053_token_rotated_at
Revises: 052_add_welcome_email
Create Date: 2026-01-13

Adds timestamp tracking for token rotation to support a grace window
in refresh token theft detection. This prevents false positives when
users have multiple tabs open that may race to refresh tokens.
"""

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic
revision = "053_token_rotated_at"
down_revision = "052_add_welcome_email"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Add token_rotated_at column to user_sessions table."""
    op.add_column(
        "user_sessions",
        sa.Column("token_rotated_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    """Remove token_rotated_at column."""
    op.drop_column("user_sessions", "token_rotated_at")
