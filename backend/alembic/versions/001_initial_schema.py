"""Initial schema

Revision ID: 001
Revises:
Create Date: 2024-12-18

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = '001'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Cloud Accounts
    op.create_table(
        'cloud_accounts',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('name', sa.String(255), nullable=False),
        sa.Column('provider', sa.Enum('aws', 'gcp', name='cloudprovider'), nullable=False),
        sa.Column('account_id', sa.String(64), nullable=False, unique=True),
        sa.Column('regions', postgresql.JSONB, default=list),
        sa.Column('credentials_arn', sa.String(255), nullable=True),
        sa.Column('description', sa.Text, nullable=True),
        sa.Column('is_active', sa.Boolean, default=True),
        sa.Column('last_scan_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index('ix_cloud_accounts_account_id', 'cloud_accounts', ['account_id'])

    # Tactics
    op.create_table(
        'tactics',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('tactic_id', sa.String(16), nullable=False, unique=True),
        sa.Column('name', sa.String(128), nullable=False),
        sa.Column('description', sa.Text, nullable=True),
        sa.Column('short_name', sa.String(64), nullable=False),
        sa.Column('display_order', sa.Integer, default=0),
        sa.Column('mitre_version', sa.String(16), default='14.1'),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index('ix_tactics_tactic_id', 'tactics', ['tactic_id'])

    # Techniques
    op.create_table(
        'techniques',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('technique_id', sa.String(16), nullable=False, unique=True),
        sa.Column('name', sa.String(255), nullable=False),
        sa.Column('description', sa.Text, nullable=True),
        sa.Column('tactic_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('tactics.id'), nullable=False),
        sa.Column('parent_technique_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('techniques.id'), nullable=True),
        sa.Column('platforms', postgresql.JSONB, default=list),
        sa.Column('data_sources', postgresql.JSONB, default=list),
        sa.Column('detection_guidance', sa.Text, nullable=True),
        sa.Column('mitre_version', sa.String(16), default='14.1'),
        sa.Column('is_subtechnique', sa.Boolean, default=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index('ix_techniques_technique_id', 'techniques', ['technique_id'])

    # Detections
    op.create_table(
        'detections',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('cloud_account_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('cloud_accounts.id'), nullable=False),
        sa.Column('name', sa.String(255), nullable=False),
        sa.Column('detection_type', sa.Enum(
            'cloudwatch_logs_insights', 'eventbridge_rule', 'guardduty_finding',
            'config_rule', 'custom_lambda', 'security_hub',
            name='detectiontype'
        ), nullable=False),
        sa.Column('status', sa.Enum('active', 'disabled', 'error', 'unknown', name='detectionstatus'), default='unknown'),
        sa.Column('source_arn', sa.String(512), nullable=True),
        sa.Column('region', sa.String(64), nullable=False),
        sa.Column('raw_config', postgresql.JSONB, default=dict),
        sa.Column('query_pattern', sa.Text, nullable=True),
        sa.Column('event_pattern', postgresql.JSONB, nullable=True),
        sa.Column('log_groups', postgresql.JSONB, nullable=True),
        sa.Column('description', sa.Text, nullable=True),
        sa.Column('last_triggered_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('health_score', sa.Float, nullable=True),
        sa.Column('discovered_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column('is_managed', sa.Boolean, default=False),
    )
    op.create_index('ix_detections_detection_type', 'detections', ['detection_type'])

    # Detection Mappings
    op.create_table(
        'detection_mappings',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('detection_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('detections.id'), nullable=False),
        sa.Column('technique_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('techniques.id'), nullable=False),
        sa.Column('confidence', sa.Float, nullable=False),
        sa.Column('mapping_source', sa.Enum('pattern_match', 'nlp', 'manual', 'vendor', name='mappingsource'), nullable=False),
        sa.Column('rationale', sa.Text, nullable=True),
        sa.Column('matched_indicators', postgresql.JSONB, nullable=True),
        sa.Column('vendor_mapping_id', sa.String(64), nullable=True),
        sa.Column('is_stale', sa.Boolean, default=False),
        sa.Column('last_validated_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index('ix_detection_mappings_detection_id', 'detection_mappings', ['detection_id'])
    op.create_index('ix_detection_mappings_technique_id', 'detection_mappings', ['technique_id'])

    # Scans
    op.create_table(
        'scans',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('cloud_account_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('cloud_accounts.id'), nullable=False),
        sa.Column('status', sa.Enum('pending', 'running', 'completed', 'failed', 'cancelled', name='scanstatus'), default='pending'),
        sa.Column('regions', postgresql.JSONB, default=list),
        sa.Column('detection_types', postgresql.JSONB, default=list),
        sa.Column('progress_percent', sa.Integer, default=0),
        sa.Column('current_step', sa.String(255), nullable=True),
        sa.Column('detections_found', sa.Integer, default=0),
        sa.Column('detections_new', sa.Integer, default=0),
        sa.Column('detections_updated', sa.Integer, default=0),
        sa.Column('detections_removed', sa.Integer, default=0),
        sa.Column('errors', postgresql.JSONB, nullable=True),
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # Coverage Snapshots
    op.create_table(
        'coverage_snapshots',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('cloud_account_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('cloud_accounts.id'), nullable=False),
        sa.Column('total_techniques', sa.Integer, default=0),
        sa.Column('covered_techniques', sa.Integer, default=0),
        sa.Column('partial_techniques', sa.Integer, default=0),
        sa.Column('uncovered_techniques', sa.Integer, default=0),
        sa.Column('coverage_percent', sa.Float, default=0.0),
        sa.Column('average_confidence', sa.Float, default=0.0),
        sa.Column('tactic_coverage', postgresql.JSONB, default=dict),
        sa.Column('total_detections', sa.Integer, default=0),
        sa.Column('active_detections', sa.Integer, default=0),
        sa.Column('mapped_detections', sa.Integer, default=0),
        sa.Column('top_gaps', postgresql.JSONB, default=list),
        sa.Column('mitre_version', sa.String(16), default='14.1'),
        sa.Column('scan_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('scans.id'), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index('ix_coverage_snapshots_cloud_account_id', 'coverage_snapshots', ['cloud_account_id'])
    op.create_index('ix_coverage_snapshots_created_at', 'coverage_snapshots', ['created_at'])


def downgrade() -> None:
    op.drop_table('coverage_snapshots')
    op.drop_table('scans')
    op.drop_table('detection_mappings')
    op.drop_table('detections')
    op.drop_table('techniques')
    op.drop_table('tactics')
    op.drop_table('cloud_accounts')

    op.execute('DROP TYPE IF EXISTS cloudprovider')
    op.execute('DROP TYPE IF EXISTS detectiontype')
    op.execute('DROP TYPE IF EXISTS detectionstatus')
    op.execute('DROP TYPE IF EXISTS mappingsource')
    op.execute('DROP TYPE IF EXISTS scanstatus')
