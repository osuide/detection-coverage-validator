"""Add admin portal tables

Revision ID: 012
Revises: 011
Create Date: 2025-12-19

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '012'
down_revision = '011'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Create enum types
    op.execute("""
        DO $$ BEGIN
            CREATE TYPE admin_role AS ENUM (
                'super_admin', 'platform_admin', 'security_admin',
                'support_admin', 'billing_admin', 'readonly_admin'
            );
        EXCEPTION
            WHEN duplicate_object THEN null;
        END $$
    """)

    op.execute("""
        DO $$ BEGIN
            CREATE TYPE approval_status AS ENUM ('pending', 'approved', 'rejected', 'expired');
        EXCEPTION
            WHEN duplicate_object THEN null;
        END $$
    """)

    op.execute("""
        DO $$ BEGIN
            CREATE TYPE incident_severity AS ENUM ('critical', 'high', 'medium', 'low');
        EXCEPTION
            WHEN duplicate_object THEN null;
        END $$
    """)

    op.execute("""
        DO $$ BEGIN
            CREATE TYPE incident_status AS ENUM ('open', 'investigating', 'resolved', 'false_positive');
        EXCEPTION
            WHEN duplicate_object THEN null;
        END $$
    """)

    # Create admin_users table
    op.execute("""
        CREATE TABLE admin_users (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            email VARCHAR(255) UNIQUE NOT NULL,
            password_hash VARCHAR(255) NOT NULL,
            role admin_role NOT NULL,
            full_name VARCHAR(255),
            mfa_enabled BOOLEAN DEFAULT FALSE,
            mfa_secret_encrypted BYTEA,
            webauthn_credentials JSONB DEFAULT '[]',
            is_active BOOLEAN DEFAULT TRUE,
            locked_until TIMESTAMP WITH TIME ZONE,
            failed_login_attempts INTEGER DEFAULT 0,
            requires_password_change BOOLEAN DEFAULT TRUE,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
            created_by_id UUID REFERENCES admin_users(id),
            updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
            last_login_at TIMESTAMP WITH TIME ZONE,
            last_password_change TIMESTAMP WITH TIME ZONE
        )
    """)
    op.execute("CREATE INDEX ix_admin_users_email ON admin_users(email)")

    # Create admin_sessions table
    op.execute("""
        CREATE TABLE admin_sessions (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            admin_id UUID NOT NULL REFERENCES admin_users(id) ON DELETE CASCADE,
            ip_address VARCHAR(45) NOT NULL,
            user_agent TEXT,
            device_fingerprint VARCHAR(255),
            geo_location JSONB,
            refresh_token_hash VARCHAR(255) NOT NULL,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
            last_activity_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
            expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
            last_auth_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
            is_active BOOLEAN DEFAULT TRUE,
            terminated_reason VARCHAR(50)
        )
    """)
    op.execute("CREATE INDEX ix_admin_sessions_admin_id ON admin_sessions(admin_id)")
    op.execute("CREATE INDEX ix_admin_sessions_expires ON admin_sessions(expires_at) WHERE is_active = true")

    # Create admin_audit_logs table
    op.execute("""
        CREATE TABLE admin_audit_logs (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            admin_id UUID NOT NULL REFERENCES admin_users(id),
            admin_email VARCHAR(255) NOT NULL,
            admin_role admin_role NOT NULL,
            action VARCHAR(100) NOT NULL,
            resource_type VARCHAR(50),
            resource_id UUID,
            resource_name VARCHAR(255),
            ip_address VARCHAR(45) NOT NULL,
            user_agent TEXT,
            device_fingerprint VARCHAR(255),
            geo_location JSONB,
            session_id UUID,
            request_id UUID NOT NULL DEFAULT gen_random_uuid(),
            request_path VARCHAR(255),
            request_method VARCHAR(10),
            request_body_hash VARCHAR(64),
            response_status INTEGER,
            success BOOLEAN NOT NULL,
            error_message TEXT,
            reason TEXT,
            approval_id UUID,
            impersonating_user_id UUID,
            timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
            log_hash VARCHAR(64) NOT NULL,
            previous_log_hash VARCHAR(64)
        )
    """)
    op.execute("CREATE INDEX ix_admin_audit_logs_admin_id ON admin_audit_logs(admin_id)")
    op.execute("CREATE INDEX ix_admin_audit_logs_action ON admin_audit_logs(action)")
    op.execute("CREATE INDEX ix_admin_audit_logs_resource ON admin_audit_logs(resource_type, resource_id)")
    op.execute("CREATE INDEX ix_admin_audit_logs_timestamp ON admin_audit_logs(timestamp)")

    # Create admin_approval_requests table
    op.execute("""
        CREATE TABLE admin_approval_requests (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            requestor_id UUID NOT NULL REFERENCES admin_users(id),
            action VARCHAR(100) NOT NULL,
            resource_type VARCHAR(50),
            resource_id UUID,
            reason TEXT NOT NULL,
            status approval_status NOT NULL DEFAULT 'pending',
            approver_id UUID REFERENCES admin_users(id),
            approver_notes TEXT,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
            expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
            resolved_at TIMESTAMP WITH TIME ZONE,
            CONSTRAINT different_approver CHECK (approver_id IS NULL OR approver_id != requestor_id)
        )
    """)
    op.execute("CREATE INDEX ix_admin_approval_requests_requestor ON admin_approval_requests(requestor_id)")

    # Create admin_impersonation_sessions table
    op.execute("""
        CREATE TABLE admin_impersonation_sessions (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            admin_id UUID NOT NULL REFERENCES admin_users(id),
            admin_session_id UUID NOT NULL REFERENCES admin_sessions(id),
            target_user_id UUID NOT NULL REFERENCES users(id),
            target_org_id UUID NOT NULL REFERENCES organizations(id),
            reason TEXT NOT NULL,
            started_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
            ended_at TIMESTAMP WITH TIME ZONE,
            max_duration_minutes INTEGER DEFAULT 30,
            actions_log JSONB DEFAULT '[]',
            CONSTRAINT valid_duration CHECK (max_duration_minutes <= 60)
        )
    """)
    op.execute("CREATE INDEX ix_admin_impersonation_admin ON admin_impersonation_sessions(admin_id)")

    # Create security_incidents table
    op.execute("""
        CREATE TABLE security_incidents (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            severity incident_severity NOT NULL,
            incident_type VARCHAR(100) NOT NULL,
            organization_id UUID REFERENCES organizations(id),
            user_id UUID REFERENCES users(id),
            title VARCHAR(255) NOT NULL,
            description TEXT NOT NULL,
            evidence JSONB,
            auto_actions_taken JSONB DEFAULT '[]',
            status incident_status NOT NULL DEFAULT 'open',
            assigned_to_id UUID REFERENCES admin_users(id),
            resolved_by_id UUID REFERENCES admin_users(id),
            resolution_notes TEXT,
            detected_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
            acknowledged_at TIMESTAMP WITH TIME ZONE,
            resolved_at TIMESTAMP WITH TIME ZONE
        )
    """)
    op.execute("CREATE INDEX ix_security_incidents_status ON security_incidents(status, severity)")
    op.execute("CREATE INDEX ix_security_incidents_org ON security_incidents(organization_id)")

    # Create admin_ip_allowlist table
    op.execute("""
        CREATE TABLE admin_ip_allowlist (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            ip_address VARCHAR(43) UNIQUE NOT NULL,
            description VARCHAR(255),
            created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
            created_by_id UUID REFERENCES admin_users(id),
            expires_at TIMESTAMP WITH TIME ZONE,
            is_active BOOLEAN DEFAULT TRUE
        )
    """)


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS admin_ip_allowlist CASCADE")
    op.execute("DROP TABLE IF EXISTS security_incidents CASCADE")
    op.execute("DROP TABLE IF EXISTS admin_impersonation_sessions CASCADE")
    op.execute("DROP TABLE IF EXISTS admin_approval_requests CASCADE")
    op.execute("DROP TABLE IF EXISTS admin_audit_logs CASCADE")
    op.execute("DROP TABLE IF EXISTS admin_sessions CASCADE")
    op.execute("DROP TABLE IF EXISTS admin_users CASCADE")
    op.execute("DROP TYPE IF EXISTS incident_status")
    op.execute("DROP TYPE IF EXISTS incident_severity")
    op.execute("DROP TYPE IF EXISTS approval_status")
    op.execute("DROP TYPE IF EXISTS admin_role")
