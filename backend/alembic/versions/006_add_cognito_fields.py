"""Add Cognito SSO fields and federated identities

Revision ID: 006
Revises: 005
Create Date: 2025-12-18

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '006'
down_revision: Union[str, None] = '005'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Add Cognito fields to users table
    op.add_column('users', sa.Column('cognito_sub', sa.String(255), nullable=True))
    op.add_column('users', sa.Column('cognito_username', sa.String(255), nullable=True))
    op.add_column('users', sa.Column('identity_provider', sa.String(50), nullable=True))

    # Create unique index on cognito_sub
    op.create_index('idx_users_cognito_sub', 'users', ['cognito_sub'], unique=True)

    # Create federated_identities table
    op.create_table(
        'federated_identities',
        sa.Column('id', sa.UUID(), server_default=sa.text('gen_random_uuid()'), nullable=False),
        sa.Column('user_id', sa.UUID(), nullable=False),
        sa.Column('provider', sa.String(50), nullable=False),
        sa.Column('provider_user_id', sa.String(255), nullable=False),
        sa.Column('provider_email', sa.String(255), nullable=True),
        sa.Column('linked_at', sa.DateTime(timezone=True), server_default=sa.text('NOW()'), nullable=False),
        sa.Column('last_login_at', sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('provider', 'provider_user_id', name='uq_federated_provider_user')
    )

    op.create_index('idx_federated_identities_user', 'federated_identities', ['user_id'])
    op.create_index('idx_federated_identities_provider', 'federated_identities', ['provider', 'provider_user_id'])


def downgrade() -> None:
    op.drop_index('idx_federated_identities_provider')
    op.drop_index('idx_federated_identities_user')
    op.drop_table('federated_identities')

    op.drop_index('idx_users_cognito_sub')
    op.drop_column('users', 'identity_provider')
    op.drop_column('users', 'cognito_username')
    op.drop_column('users', 'cognito_sub')
