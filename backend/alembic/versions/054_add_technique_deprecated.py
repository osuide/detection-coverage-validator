"""Add is_deprecated column to techniques table.

Revision ID: 054_deprecated
Revises: 053_token_rotated_at
Create Date: 2026-01-13
"""

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "054_deprecated"
down_revision = "053_token_rotated_at"
branch_labels = None
depends_on = None


def upgrade():
    # Add is_deprecated column with default False (idempotent)
    conn = op.get_bind()
    inspector = sa.inspect(conn)
    columns = [col["name"] for col in inspector.get_columns("techniques")]

    if "is_deprecated" not in columns:
        op.add_column(
            "techniques",
            sa.Column(
                "is_deprecated", sa.Boolean(), nullable=False, server_default="false"
            ),
        )


def downgrade():
    op.drop_column("techniques", "is_deprecated")
