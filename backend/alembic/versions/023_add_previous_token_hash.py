"""Add previous_token_hash to user_sessions.

M2: Enables refresh token rotation detection to identify potential token theft.

Revision ID: 023_add_previous_token
Revises: 022_add_processed_webhook
Create Date: 2024-12-21

"""

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "023_add_previous_token"
down_revision = "022_add_processed_webhook"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        "user_sessions",
        sa.Column("previous_token_hash", sa.String(255), nullable=True),
    )
    op.create_index(
        "ix_user_sessions_previous_token_hash",
        "user_sessions",
        ["previous_token_hash"],
    )


def downgrade():
    op.drop_index("ix_user_sessions_previous_token_hash", table_name="user_sessions")
    op.drop_column("user_sessions", "previous_token_hash")
