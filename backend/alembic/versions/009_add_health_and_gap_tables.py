"""Add health monitoring and gap tracking tables.

Revision ID: 009
Revises: 008
Create Date: 2024-12-18

Adds:
- Health monitoring columns to detections table
- Coverage gaps table for remediation tracking
- Gap history table for audit trail
- New GCP detection types to enum
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID, JSONB


# revision identifiers, used by Alembic.
revision = '009'
down_revision = '008'
branch_labels = None
depends_on = None


def upgrade():
    # Add new GCP detection types to enum (one at a time for asyncpg compatibility)
    op.execute("ALTER TYPE detectiontype ADD VALUE IF NOT EXISTS 'gcp_cloud_logging'")
    op.execute("ALTER TYPE detectiontype ADD VALUE IF NOT EXISTS 'gcp_security_command_center'")
    op.execute("ALTER TYPE detectiontype ADD VALUE IF NOT EXISTS 'gcp_eventarc'")
    op.execute("ALTER TYPE detectiontype ADD VALUE IF NOT EXISTS 'gcp_cloud_monitoring'")
    op.execute("ALTER TYPE detectiontype ADD VALUE IF NOT EXISTS 'gcp_cloud_function'")

    # Create enums
    op.execute("CREATE TYPE healthstatus AS ENUM ('healthy', 'degraded', 'broken', 'unknown')")
    op.execute("CREATE TYPE gapstatus AS ENUM ('open', 'acknowledged', 'in_progress', 'remediated', 'risk_accepted')")
    op.execute("CREATE TYPE gappriority AS ENUM ('critical', 'high', 'medium', 'low')")

    # Add health columns to detections table
    op.execute("ALTER TABLE detections ADD COLUMN health_status healthstatus DEFAULT 'unknown'")
    op.execute("ALTER TABLE detections ADD COLUMN health_issues JSONB")
    op.execute("ALTER TABLE detections ADD COLUMN last_validated_at TIMESTAMP WITH TIME ZONE")

    # Create coverage_gaps table
    op.execute("""
        CREATE TABLE coverage_gaps (
            id UUID PRIMARY KEY,
            cloud_account_id UUID NOT NULL REFERENCES cloud_accounts(id),
            organization_id UUID NOT NULL REFERENCES organizations(id),
            technique_id VARCHAR(32) NOT NULL,
            technique_name VARCHAR(255) NOT NULL,
            tactic_id VARCHAR(32) NOT NULL,
            tactic_name VARCHAR(255) NOT NULL,
            status gapstatus DEFAULT 'open',
            priority gappriority DEFAULT 'medium',
            reason TEXT,
            data_sources JSONB,
            recommended_detections JSONB,
            assigned_to UUID REFERENCES users(id),
            remediation_notes TEXT,
            remediation_due_date TIMESTAMP WITH TIME ZONE,
            remediated_detection_id UUID REFERENCES detections(id),
            risk_acceptance_reason TEXT,
            risk_accepted_by UUID REFERENCES users(id),
            risk_accepted_at TIMESTAMP WITH TIME ZONE,
            first_identified_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
            status_changed_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
            created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
            updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
            scan_id UUID REFERENCES scans(id)
        )
    """)

    # Create gap_history table
    op.execute("""
        CREATE TABLE gap_history (
            id UUID PRIMARY KEY,
            gap_id UUID NOT NULL REFERENCES coverage_gaps(id),
            previous_status gapstatus,
            new_status gapstatus NOT NULL,
            changed_by UUID REFERENCES users(id),
            change_reason TEXT,
            changed_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
        )
    """)

    # Create indexes
    op.execute("CREATE INDEX ix_coverage_gaps_technique_id ON coverage_gaps(technique_id)")
    op.execute("CREATE INDEX ix_coverage_gaps_tactic_id ON coverage_gaps(tactic_id)")
    op.execute("CREATE INDEX ix_coverage_gaps_status ON coverage_gaps(status)")
    op.execute("CREATE INDEX ix_coverage_gaps_priority ON coverage_gaps(priority)")
    op.execute("CREATE INDEX ix_coverage_gaps_org_status ON coverage_gaps(organization_id, status)")
    op.execute("CREATE INDEX ix_coverage_gaps_account_technique ON coverage_gaps(cloud_account_id, technique_id)")
    op.execute("CREATE INDEX ix_gap_history_gap_id ON gap_history(gap_id)")


def downgrade():
    # Drop indexes
    op.execute("DROP INDEX IF EXISTS ix_gap_history_gap_id")
    op.execute("DROP INDEX IF EXISTS ix_coverage_gaps_account_technique")
    op.execute("DROP INDEX IF EXISTS ix_coverage_gaps_org_status")
    op.execute("DROP INDEX IF EXISTS ix_coverage_gaps_priority")
    op.execute("DROP INDEX IF EXISTS ix_coverage_gaps_status")
    op.execute("DROP INDEX IF EXISTS ix_coverage_gaps_tactic_id")
    op.execute("DROP INDEX IF EXISTS ix_coverage_gaps_technique_id")

    # Drop tables
    op.execute("DROP TABLE IF EXISTS gap_history")
    op.execute("DROP TABLE IF EXISTS coverage_gaps")

    # Remove columns from detections
    op.execute("ALTER TABLE detections DROP COLUMN IF EXISTS last_validated_at")
    op.execute("ALTER TABLE detections DROP COLUMN IF EXISTS health_issues")
    op.execute("ALTER TABLE detections DROP COLUMN IF EXISTS health_status")

    # Drop enums
    op.execute("DROP TYPE IF EXISTS gappriority")
    op.execute("DROP TYPE IF EXISTS gapstatus")
    op.execute("DROP TYPE IF EXISTS healthstatus")
