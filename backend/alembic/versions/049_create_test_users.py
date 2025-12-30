"""Create test users with different subscription tiers for staging.

Revision ID: 049_create_test_users
Revises: 048_cleanup_rescan
Create Date: 2025-12-30

This migration creates test users for staging environment testing:
- testuser-individual@a13e.com (Individual tier, 6 accounts)
- testuser-pro@a13e.com (Pro tier, 500 accounts)

Password for both: A13e-Staging-Xk9mPq-2025!

These users are idempotent - if they already exist, they are skipped.
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "049_create_test_users"
down_revision: Union[str, None] = "048_cleanup_rescan"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

# Pre-computed bcrypt hashes for password: A13e-Staging-Xk9mPq-2025!
# Generated with bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))
PASSWORD_HASH_INDIVIDUAL = (
    "$2b$12$4EfLu69CkmpGMT5mzbNNm.cmiXP4Xj76BSbfg.jfjA8VjBmum8NWi"
)
PASSWORD_HASH_PRO = "$2b$12$slPEDETbFB.h4qD0IoJT8u/RKWyypdT9/ARxz5PHi1T.kXj.aHuz6"


def upgrade() -> None:
    conn = op.get_bind()

    # Create INDIVIDUAL tier test user
    # Note: DO blocks don't support bind parameters, so hash is embedded directly
    conn.execute(
        sa.text(
            f"""
        DO $$
        DECLARE
            v_user_id UUID;
            v_org_id UUID;
        BEGIN
            -- Check if user already exists
            SELECT id INTO v_user_id FROM users WHERE email = 'testuser-individual@a13e.com';
            IF v_user_id IS NOT NULL THEN
                RAISE NOTICE 'User testuser-individual@a13e.com already exists';
                RETURN;
            END IF;

            -- Create user
            INSERT INTO users (id, email, full_name, password_hash, email_verified, is_active, created_at, updated_at)
            VALUES (gen_random_uuid(), 'testuser-individual@a13e.com', 'Test User (Individual)', '{PASSWORD_HASH_INDIVIDUAL}', true, true, NOW(), NOW())
            RETURNING id INTO v_user_id;

            -- Create organization
            INSERT INTO organizations (id, name, slug, is_active, created_at, updated_at)
            VALUES (gen_random_uuid(), 'Test Org - Individual', 'test-org-individual', true, NOW(), NOW())
            RETURNING id INTO v_org_id;

            -- Create membership
            INSERT INTO organization_members (id, user_id, organization_id, role, created_at, updated_at)
            VALUES (gen_random_uuid(), v_user_id, v_org_id, 'owner', NOW(), NOW());

            -- Create subscription (INDIVIDUAL tier: 6 accounts)
            INSERT INTO subscriptions (id, organization_id, tier, status, included_accounts, max_accounts, max_team_members, org_features_enabled, history_retention_days, created_at, updated_at)
            VALUES (gen_random_uuid(), v_org_id, 'individual', 'active', 6, 6, 3, false, 90, NOW(), NOW());

            RAISE NOTICE 'Created INDIVIDUAL tier user: testuser-individual@a13e.com';
        END $$;
    """
        )
    )

    # Create PRO tier test user
    conn.execute(
        sa.text(
            f"""
        DO $$
        DECLARE
            v_user_id UUID;
            v_org_id UUID;
        BEGIN
            -- Check if user already exists
            SELECT id INTO v_user_id FROM users WHERE email = 'testuser-pro@a13e.com';
            IF v_user_id IS NOT NULL THEN
                RAISE NOTICE 'User testuser-pro@a13e.com already exists';
                RETURN;
            END IF;

            -- Create user
            INSERT INTO users (id, email, full_name, password_hash, email_verified, is_active, created_at, updated_at)
            VALUES (gen_random_uuid(), 'testuser-pro@a13e.com', 'Test User (Pro)', '{PASSWORD_HASH_PRO}', true, true, NOW(), NOW())
            RETURNING id INTO v_user_id;

            -- Create organization
            INSERT INTO organizations (id, name, slug, is_active, created_at, updated_at)
            VALUES (gen_random_uuid(), 'Test Org - Pro', 'test-org-pro', true, NOW(), NOW())
            RETURNING id INTO v_org_id;

            -- Create membership
            INSERT INTO organization_members (id, user_id, organization_id, role, created_at, updated_at)
            VALUES (gen_random_uuid(), v_user_id, v_org_id, 'owner', NOW(), NOW());

            -- Create subscription (PRO tier: 500 accounts)
            INSERT INTO subscriptions (id, organization_id, tier, status, included_accounts, max_accounts, max_team_members, org_features_enabled, history_retention_days, created_at, updated_at)
            VALUES (gen_random_uuid(), v_org_id, 'pro', 'active', 500, 500, 10, true, 365, NOW(), NOW());

            RAISE NOTICE 'Created PRO tier user: testuser-pro@a13e.com';
        END $$;
    """
        )
    )

    print("\n" + "=" * 60)
    print("Test users created!")
    print("=" * 60)
    print("  - testuser-individual@a13e.com (Individual tier, 6 accounts)")
    print("  - testuser-pro@a13e.com (Pro tier, 500 accounts)")
    print("  - Password: A13e-Staging-Xk9mPq-2025!")
    print("=" * 60 + "\n")


def downgrade() -> None:
    conn = op.get_bind()

    # Delete in reverse order to respect FK constraints
    # 1. Delete subscriptions
    conn.execute(
        sa.text(
            """
        DELETE FROM subscriptions WHERE organization_id IN (
            SELECT id FROM organizations WHERE slug IN ('test-org-individual', 'test-org-pro')
        )
    """
        )
    )

    # 2. Delete organization members
    conn.execute(
        sa.text(
            """
        DELETE FROM organization_members WHERE organization_id IN (
            SELECT id FROM organizations WHERE slug IN ('test-org-individual', 'test-org-pro')
        )
    """
        )
    )

    # 3. Delete organizations
    conn.execute(
        sa.text(
            """
        DELETE FROM organizations WHERE slug IN ('test-org-individual', 'test-org-pro')
    """
        )
    )

    # 4. Delete users
    conn.execute(
        sa.text(
            """
        DELETE FROM users WHERE email IN ('testuser-individual@a13e.com', 'testuser-pro@a13e.com')
    """
        )
    )

    print("Test users removed.")
