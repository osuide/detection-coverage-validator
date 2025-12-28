"""Add WebAuthn credentials to users table.

Revision ID: 047_add_webauthn
Revises: 046_fix_sh_api
Create Date: 2025-12-28

Adds webauthn_credentials JSONB column to users table for storing
FIDO2/WebAuthn credential data (passkeys, hardware keys like YubiKey).
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

# revision identifiers, used by Alembic.
revision = "047_add_webauthn"
down_revision = "046_fix_sh_api"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Add webauthn_credentials column to users table."""
    # Check if column already exists (idempotency)
    conn = op.get_bind()
    inspector = sa.inspect(conn)
    columns = [c["name"] for c in inspector.get_columns("users")]

    if "webauthn_credentials" not in columns:
        op.add_column(
            "users",
            sa.Column(
                "webauthn_credentials",
                JSONB,
                nullable=True,
                server_default="[]",
                comment="FIDO2/WebAuthn credentials for passkeys and hardware keys",
            ),
        )


def downgrade() -> None:
    """Remove webauthn_credentials column."""
    op.drop_column("users", "webauthn_credentials")
