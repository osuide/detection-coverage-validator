"""Add scan schedules table

Revision ID: 002
Revises: 001
Create Date: 2024-12-18

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = '002'
down_revision: Union[str, None] = '001'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Create schedule frequency enum (if not exists)
    op.execute("""
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'schedulefrequency') THEN
                CREATE TYPE schedulefrequency AS ENUM ('hourly', 'daily', 'weekly', 'monthly', 'custom');
            END IF;
        END $$;
    """)

    # Scan Schedules
    op.create_table(
        'scan_schedules',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('cloud_account_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('cloud_accounts.id'), nullable=False),
        sa.Column('name', sa.String(255), nullable=False),
        sa.Column('description', sa.String(500), nullable=True),
        sa.Column('frequency', postgresql.ENUM('hourly', 'daily', 'weekly', 'monthly', 'custom', name='schedulefrequency', create_type=False), nullable=False),
        sa.Column('cron_expression', sa.String(100), nullable=True),
        sa.Column('day_of_week', sa.Integer, nullable=True),
        sa.Column('day_of_month', sa.Integer, nullable=True),
        sa.Column('hour', sa.Integer, default=0),
        sa.Column('minute', sa.Integer, default=0),
        sa.Column('timezone', sa.String(50), default='UTC'),
        sa.Column('regions', postgresql.JSONB, default=list),
        sa.Column('detection_types', postgresql.JSONB, default=list),
        sa.Column('is_active', sa.Boolean, default=True),
        sa.Column('last_run_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('next_run_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('run_count', sa.Integer, default=0),
        sa.Column('last_scan_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index('ix_scan_schedules_cloud_account_id', 'scan_schedules', ['cloud_account_id'])
    op.create_index('ix_scan_schedules_is_active', 'scan_schedules', ['is_active'])


def downgrade() -> None:
    op.drop_table('scan_schedules')
    op.execute('DROP TYPE IF EXISTS schedulefrequency')
