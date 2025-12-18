"""Add auth tables (users, organizations, sessions, api_keys, audit_logs)

Revision ID: 004
Revises: 003
Create Date: 2024-12-18

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = '004'
down_revision: Union[str, None] = '003'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Create enums
    op.execute("""
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'userrole') THEN
                CREATE TYPE userrole AS ENUM ('owner', 'admin', 'member', 'viewer');
            END IF;
        END $$;
    """)

    op.execute("""
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'membershipstatus') THEN
                CREATE TYPE membershipstatus AS ENUM ('active', 'pending', 'suspended');
            END IF;
        END $$;
    """)

    op.execute("""
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'auditlogaction') THEN
                CREATE TYPE auditlogaction AS ENUM (
                    'user.login', 'user.logout', 'user.login_failed',
                    'user.mfa_enabled', 'user.mfa_disabled',
                    'user.password_changed', 'user.password_reset',
                    'user.invite', 'user.invite_accepted',
                    'user.role_changed', 'user.removed', 'user.suspended',
                    'org.created', 'org.settings_updated', 'org.sso_configured',
                    'api_key.created', 'api_key.revoked',
                    'account.created', 'account.updated', 'account.deleted',
                    'account.credentials_updated',
                    'scan.triggered', 'scan.completed',
                    'detection.mapping_updated'
                );
            END IF;
        END $$;
    """)

    # Users table
    op.create_table(
        'users',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('email', sa.String(255), unique=True, nullable=False),
        sa.Column('full_name', sa.String(255), nullable=False),
        sa.Column('password_hash', sa.String(255), nullable=True),

        # Email verification
        sa.Column('email_verified', sa.Boolean, default=False),
        sa.Column('email_verification_token', sa.String(255), nullable=True),
        sa.Column('email_verification_sent_at', sa.DateTime(timezone=True), nullable=True),

        # MFA
        sa.Column('mfa_enabled', sa.Boolean, default=False),
        sa.Column('mfa_secret', sa.String(255), nullable=True),
        sa.Column('mfa_backup_codes', postgresql.JSONB, nullable=True),

        # OAuth
        sa.Column('oauth_provider', sa.String(50), nullable=True),
        sa.Column('oauth_id', sa.String(255), nullable=True),

        # Profile
        sa.Column('avatar_url', sa.String(500), nullable=True),
        sa.Column('timezone', sa.String(50), default='UTC'),

        # Password reset
        sa.Column('password_reset_token', sa.String(255), nullable=True),
        sa.Column('password_reset_expires_at', sa.DateTime(timezone=True), nullable=True),

        # Account status
        sa.Column('is_active', sa.Boolean, default=True),
        sa.Column('is_superadmin', sa.Boolean, default=False),
        sa.Column('last_login_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('failed_login_attempts', sa.Integer, default=0),
        sa.Column('locked_until', sa.DateTime(timezone=True), nullable=True),

        # Timestamps
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index('ix_users_email', 'users', ['email'])
    op.create_index('ix_users_oauth', 'users', ['oauth_provider', 'oauth_id'])

    # Organizations table
    op.create_table(
        'organizations',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('name', sa.String(255), nullable=False),
        sa.Column('slug', sa.String(100), unique=True, nullable=False),

        # Settings
        sa.Column('logo_url', sa.String(500), nullable=True),
        sa.Column('primary_domain', sa.String(255), nullable=True),
        sa.Column('verified_domains', postgresql.JSONB, default=list),

        # Security policies
        sa.Column('require_mfa', sa.Boolean, default=False),
        sa.Column('allowed_auth_methods', postgresql.JSONB, default=['email_password']),
        sa.Column('session_timeout_minutes', sa.Integer, default=1440),

        # SSO Configuration
        sa.Column('sso_enabled', sa.Boolean, default=False),
        sa.Column('sso_provider', sa.String(50), nullable=True),
        sa.Column('sso_config', postgresql.JSONB, nullable=True),

        # Subscription
        sa.Column('plan', sa.String(50), default='free'),
        sa.Column('plan_seats', sa.Integer, default=5),
        sa.Column('trial_ends_at', sa.DateTime(timezone=True), nullable=True),

        # Status
        sa.Column('is_active', sa.Boolean, default=True),

        # Timestamps
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index('ix_organizations_slug', 'organizations', ['slug'])

    # Organization Members table
    op.create_table(
        'organization_members',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('organization_id', postgresql.UUID(as_uuid=True),
                  sa.ForeignKey('organizations.id', ondelete='CASCADE'), nullable=False),
        sa.Column('user_id', postgresql.UUID(as_uuid=True),
                  sa.ForeignKey('users.id', ondelete='CASCADE'), nullable=True),

        # For pending invitations
        sa.Column('invite_email', sa.String(255), nullable=True),
        sa.Column('invite_token', sa.String(255), nullable=True, unique=True),
        sa.Column('invite_expires_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('invited_by_id', postgresql.UUID(as_uuid=True),
                  sa.ForeignKey('users.id', ondelete='SET NULL'), nullable=True),

        # Role and status
        sa.Column('role', postgresql.ENUM('owner', 'admin', 'member', 'viewer',
                                          name='userrole', create_type=False), default='member'),
        sa.Column('status', postgresql.ENUM('active', 'pending', 'suspended',
                                            name='membershipstatus', create_type=False), default='pending'),

        # Cloud account access
        sa.Column('allowed_account_ids', postgresql.JSONB, nullable=True),

        # Timestamps
        sa.Column('joined_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index('ix_org_members_org_user', 'organization_members',
                    ['organization_id', 'user_id'], unique=True)
    op.create_index('ix_org_members_invite_token', 'organization_members', ['invite_token'])

    # User Sessions table
    op.create_table(
        'user_sessions',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('user_id', postgresql.UUID(as_uuid=True),
                  sa.ForeignKey('users.id', ondelete='CASCADE'), nullable=False),
        sa.Column('organization_id', postgresql.UUID(as_uuid=True),
                  sa.ForeignKey('organizations.id', ondelete='CASCADE'), nullable=True),

        # Token
        sa.Column('refresh_token_hash', sa.String(255), nullable=False, unique=True),

        # Session metadata
        sa.Column('user_agent', sa.String(500), nullable=True),
        sa.Column('ip_address', sa.String(45), nullable=True),
        sa.Column('device_info', postgresql.JSONB, nullable=True),
        sa.Column('location', sa.String(255), nullable=True),

        # Status
        sa.Column('is_active', sa.Boolean, default=True),
        sa.Column('last_activity_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),

        # Timestamps
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index('ix_sessions_user_active', 'user_sessions', ['user_id', 'is_active'])
    op.create_index('ix_sessions_expires', 'user_sessions', ['expires_at'])

    # API Keys table
    op.create_table(
        'api_keys',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('organization_id', postgresql.UUID(as_uuid=True),
                  sa.ForeignKey('organizations.id', ondelete='CASCADE'), nullable=False),
        sa.Column('created_by_id', postgresql.UUID(as_uuid=True),
                  sa.ForeignKey('users.id', ondelete='SET NULL'), nullable=True),

        # Key details
        sa.Column('name', sa.String(255), nullable=False),
        sa.Column('key_prefix', sa.String(12), nullable=False),
        sa.Column('key_hash', sa.String(255), nullable=False, unique=True),

        # Permissions
        sa.Column('scopes', postgresql.JSONB, default=list),

        # Restrictions
        sa.Column('ip_allowlist', postgresql.JSONB, nullable=True),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=True),

        # Usage tracking
        sa.Column('last_used_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_used_ip', sa.String(45), nullable=True),
        sa.Column('usage_count', sa.Integer, default=0),

        # Status
        sa.Column('is_active', sa.Boolean, default=True),
        sa.Column('revoked_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('revoked_by_id', postgresql.UUID(as_uuid=True),
                  sa.ForeignKey('users.id', ondelete='SET NULL'), nullable=True),

        # Timestamps
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index('ix_api_keys_org', 'api_keys', ['organization_id'])
    op.create_index('ix_api_keys_prefix', 'api_keys', ['key_prefix'])

    # Audit Logs table
    op.create_table(
        'audit_logs',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('organization_id', postgresql.UUID(as_uuid=True),
                  sa.ForeignKey('organizations.id', ondelete='SET NULL'), nullable=True),
        sa.Column('user_id', postgresql.UUID(as_uuid=True),
                  sa.ForeignKey('users.id', ondelete='SET NULL'), nullable=True),

        # Action details
        sa.Column('action', postgresql.ENUM(
            'user.login', 'user.logout', 'user.login_failed',
            'user.mfa_enabled', 'user.mfa_disabled',
            'user.password_changed', 'user.password_reset',
            'user.invite', 'user.invite_accepted',
            'user.role_changed', 'user.removed', 'user.suspended',
            'org.created', 'org.settings_updated', 'org.sso_configured',
            'api_key.created', 'api_key.revoked',
            'account.created', 'account.updated', 'account.deleted',
            'account.credentials_updated',
            'scan.triggered', 'scan.completed',
            'detection.mapping_updated',
            name='auditlogaction', create_type=False
        ), nullable=False),
        sa.Column('resource_type', sa.String(50), nullable=True),
        sa.Column('resource_id', sa.String(255), nullable=True),

        # Context
        sa.Column('details', postgresql.JSONB, nullable=True),
        sa.Column('ip_address', sa.String(45), nullable=True),
        sa.Column('user_agent', sa.String(500), nullable=True),
        sa.Column('location', sa.String(255), nullable=True),

        # Result
        sa.Column('success', sa.Boolean, default=True),
        sa.Column('error_message', sa.Text, nullable=True),

        # Timestamp
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index('ix_audit_logs_org_created', 'audit_logs', ['organization_id', 'created_at'])
    op.create_index('ix_audit_logs_user', 'audit_logs', ['user_id'])
    op.create_index('ix_audit_logs_action', 'audit_logs', ['action'])
    op.create_index('ix_audit_logs_created_at', 'audit_logs', ['created_at'])

    # Add organization_id to cloud_accounts
    op.add_column('cloud_accounts',
                  sa.Column('organization_id', postgresql.UUID(as_uuid=True),
                            sa.ForeignKey('organizations.id', ondelete='CASCADE'), nullable=True))
    op.create_index('ix_cloud_accounts_org', 'cloud_accounts', ['organization_id'])


def downgrade() -> None:
    # Remove organization_id from cloud_accounts
    op.drop_index('ix_cloud_accounts_org', table_name='cloud_accounts')
    op.drop_column('cloud_accounts', 'organization_id')

    # Drop tables in reverse order
    op.drop_table('audit_logs')
    op.drop_table('api_keys')
    op.drop_table('user_sessions')
    op.drop_table('organization_members')
    op.drop_table('organizations')
    op.drop_table('users')

    # Drop enums
    op.execute('DROP TYPE IF EXISTS auditlogaction')
    op.execute('DROP TYPE IF EXISTS membershipstatus')
    op.execute('DROP TYPE IF EXISTS userrole')
