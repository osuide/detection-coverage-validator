"""Add organization security settings and verified domains

Revision ID: 007
Revises: 006
Create Date: 2025-12-18

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB


# revision identifiers, used by Alembic.
revision: str = "007"
down_revision: Union[str, None] = "006"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Create organization_security_settings table
    op.create_table(
        "organization_security_settings",
        sa.Column(
            "id", sa.UUID(), server_default=sa.text("gen_random_uuid()"), nullable=False
        ),
        sa.Column("organization_id", sa.UUID(), nullable=False),
        # MFA Settings
        sa.Column("require_mfa", sa.Boolean(), server_default="false", nullable=False),
        sa.Column(
            "mfa_grace_period_days", sa.Integer(), server_default="7", nullable=False
        ),
        # Session Settings
        sa.Column(
            "session_timeout_minutes",
            sa.Integer(),
            server_default="1440",
            nullable=False,
        ),  # 24 hours
        sa.Column(
            "idle_timeout_minutes", sa.Integer(), server_default="60", nullable=False
        ),
        # Auth Methods
        sa.Column(
            "allowed_auth_methods", JSONB, server_default='["password"]', nullable=False
        ),
        # Password Policy
        sa.Column(
            "password_min_length", sa.Integer(), server_default="12", nullable=False
        ),
        sa.Column(
            "password_require_uppercase",
            sa.Boolean(),
            server_default="true",
            nullable=False,
        ),
        sa.Column(
            "password_require_lowercase",
            sa.Boolean(),
            server_default="true",
            nullable=False,
        ),
        sa.Column(
            "password_require_number",
            sa.Boolean(),
            server_default="true",
            nullable=False,
        ),
        sa.Column(
            "password_require_special",
            sa.Boolean(),
            server_default="true",
            nullable=False,
        ),
        # Lockout Policy
        sa.Column(
            "max_failed_login_attempts",
            sa.Integer(),
            server_default="5",
            nullable=False,
        ),
        sa.Column(
            "lockout_duration_minutes",
            sa.Integer(),
            server_default="30",
            nullable=False,
        ),
        # IP Allowlist (null = allow all)
        sa.Column("ip_allowlist", JSONB, nullable=True),
        # Timestamps
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("NOW()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("NOW()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"], ["organizations.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("organization_id", name="uq_security_settings_org"),
    )

    op.create_index(
        "idx_security_settings_org",
        "organization_security_settings",
        ["organization_id"],
    )

    # Create verified_domains table
    op.create_table(
        "verified_domains",
        sa.Column(
            "id", sa.UUID(), server_default=sa.text("gen_random_uuid()"), nullable=False
        ),
        sa.Column("organization_id", sa.UUID(), nullable=False),
        sa.Column("domain", sa.String(255), nullable=False),
        sa.Column("verification_token", sa.String(255), nullable=True),
        sa.Column(
            "verification_method", sa.String(50), nullable=True
        ),  # dns_txt, dns_cname, meta_tag
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "auto_join_enabled", sa.Boolean(), server_default="false", nullable=False
        ),
        sa.Column("sso_required", sa.Boolean(), server_default="false", nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("NOW()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"], ["organizations.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("domain", name="uq_verified_domain"),
    )

    op.create_index("idx_verified_domains_org", "verified_domains", ["organization_id"])
    op.create_index("idx_verified_domains_domain", "verified_domains", ["domain"])


def downgrade() -> None:
    op.drop_index("idx_verified_domains_domain")
    op.drop_index("idx_verified_domains_org")
    op.drop_table("verified_domains")

    op.drop_index("idx_security_settings_org")
    op.drop_table("organization_security_settings")
