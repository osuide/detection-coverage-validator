"""Add platform settings table for encrypted secrets

Revision ID: 013
Revises: 012
Create Date: 2025-12-19

Stores platform-wide configuration including:
- Stripe API keys (encrypted)
- OAuth client secrets (encrypted)
- Feature flags
- Other platform settings
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '013'
down_revision = '012'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Create platform_settings table for encrypted secrets and config
    op.execute("""
        CREATE TABLE platform_settings (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            key VARCHAR(100) UNIQUE NOT NULL,
            value_encrypted BYTEA,
            value_text TEXT,
            is_secret BOOLEAN DEFAULT FALSE,
            description TEXT,
            category VARCHAR(50) NOT NULL DEFAULT 'general',
            created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
            updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
            updated_by_id UUID REFERENCES admin_users(id)
        )
    """)
    op.execute("CREATE INDEX ix_platform_settings_key ON platform_settings(key)")
    op.execute("CREATE INDEX ix_platform_settings_category ON platform_settings(category)")

    # Create settings audit log for tracking changes to sensitive settings
    op.execute("""
        CREATE TABLE platform_settings_audit (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            setting_id UUID NOT NULL REFERENCES platform_settings(id),
            setting_key VARCHAR(100) NOT NULL,
            action VARCHAR(20) NOT NULL,
            old_value_hash VARCHAR(64),
            new_value_hash VARCHAR(64),
            changed_by_id UUID NOT NULL REFERENCES admin_users(id),
            changed_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
            ip_address VARCHAR(45),
            reason TEXT
        )
    """)
    op.execute("CREATE INDEX ix_platform_settings_audit_setting ON platform_settings_audit(setting_id)")
    op.execute("CREATE INDEX ix_platform_settings_audit_changed_at ON platform_settings_audit(changed_at)")


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS platform_settings_audit CASCADE")
    op.execute("DROP TABLE IF EXISTS platform_settings CASCADE")
