"""Unit tests for security ACL and authorization helpers."""

from uuid import uuid4
from unittest.mock import MagicMock

from app.core.security import AuthContext, get_allowed_account_filter
from app.models.user import UserRole


def _create_mock_user():
    """Create a mock user with an ID."""
    user = MagicMock()
    user.id = uuid4()
    return user


def _create_mock_org():
    """Create a mock organization with an ID."""
    org = MagicMock()
    org.id = uuid4()
    return org


def _create_mock_membership(role: UserRole, allowed_account_ids=None):
    """Create a mock membership with role and optional allowed_account_ids."""
    membership = MagicMock()
    membership.role = role
    membership.allowed_account_ids = allowed_account_ids
    return membership


class TestGetAllowedAccountFilter:
    """Tests for get_allowed_account_filter helper."""

    def test_no_membership_returns_empty_list(self):
        """User with no membership should get empty list (no access)."""
        auth = AuthContext(
            user=_create_mock_user(),
            organization=None,
            membership=None,
        )
        result = get_allowed_account_filter(auth)
        assert result == []

    def test_owner_with_restrictions_returns_list(self):
        """Owner with allowed_account_ids should get that list (CWE-639 fix).

        Security: allowed_account_ids applies to ALL roles including OWNER.
        """
        account_id = uuid4()
        auth = AuthContext(
            user=_create_mock_user(),
            organization=_create_mock_org(),
            membership=_create_mock_membership(
                UserRole.OWNER,
                allowed_account_ids=[str(account_id)],
            ),
        )
        result = get_allowed_account_filter(auth)
        assert result is not None
        assert len(result) == 1
        assert account_id in result

    def test_owner_with_null_returns_none(self):
        """Owner with null allowed_account_ids has unrestricted access."""
        auth = AuthContext(
            user=_create_mock_user(),
            organization=_create_mock_org(),
            membership=_create_mock_membership(
                UserRole.OWNER, allowed_account_ids=None
            ),
        )
        result = get_allowed_account_filter(auth)
        assert result is None

    def test_admin_with_restrictions_returns_list(self):
        """Admin with allowed_account_ids should get that list (CWE-639 fix).

        Security: allowed_account_ids applies to ALL roles including ADMIN.
        """
        account_id = uuid4()
        auth = AuthContext(
            user=_create_mock_user(),
            organization=_create_mock_org(),
            membership=_create_mock_membership(
                UserRole.ADMIN,
                allowed_account_ids=[str(account_id)],
            ),
        )
        result = get_allowed_account_filter(auth)
        assert result is not None
        assert len(result) == 1
        assert account_id in result

    def test_admin_with_null_returns_none(self):
        """Admin with null allowed_account_ids has unrestricted access."""
        auth = AuthContext(
            user=_create_mock_user(),
            organization=_create_mock_org(),
            membership=_create_mock_membership(
                UserRole.ADMIN, allowed_account_ids=None
            ),
        )
        result = get_allowed_account_filter(auth)
        assert result is None

    def test_member_with_null_allowed_returns_none(self):
        """Member with null allowed_account_ids has full access."""
        auth = AuthContext(
            user=_create_mock_user(),
            organization=_create_mock_org(),
            membership=_create_mock_membership(
                UserRole.MEMBER, allowed_account_ids=None
            ),
        )
        result = get_allowed_account_filter(auth)
        assert result is None

    def test_member_with_restricted_access(self):
        """Member with allowed_account_ids should get that list as UUIDs."""
        account_id_1 = uuid4()
        account_id_2 = uuid4()
        auth = AuthContext(
            user=_create_mock_user(),
            organization=_create_mock_org(),
            membership=_create_mock_membership(
                UserRole.MEMBER,
                allowed_account_ids=[str(account_id_1), str(account_id_2)],
            ),
        )
        result = get_allowed_account_filter(auth)
        assert result is not None
        assert len(result) == 2
        assert account_id_1 in result
        assert account_id_2 in result

    def test_viewer_with_restricted_access(self):
        """Viewer with allowed_account_ids should get that list."""
        account_id = uuid4()
        auth = AuthContext(
            user=_create_mock_user(),
            organization=_create_mock_org(),
            membership=_create_mock_membership(
                UserRole.VIEWER,
                allowed_account_ids=[str(account_id)],
            ),
        )
        result = get_allowed_account_filter(auth)
        assert result is not None
        assert len(result) == 1
        assert account_id in result

    def test_member_with_empty_list_returns_empty(self):
        """Member with empty allowed_account_ids has no access."""
        auth = AuthContext(
            user=_create_mock_user(),
            organization=_create_mock_org(),
            membership=_create_mock_membership(UserRole.MEMBER, allowed_account_ids=[]),
        )
        result = get_allowed_account_filter(auth)
        assert result == []


class TestAuthContextCanAccessAccount:
    """Tests for AuthContext.can_access_account method."""

    def test_owner_with_restrictions_cannot_access_other_account(self):
        """Owner with allowed_account_ids cannot access unlisted accounts (CWE-639 fix).

        Security: allowed_account_ids applies to ALL roles including OWNER.
        """
        allowed_account = uuid4()
        auth = AuthContext(
            user=_create_mock_user(),
            organization=_create_mock_org(),
            membership=_create_mock_membership(
                UserRole.OWNER,
                allowed_account_ids=[str(allowed_account)],
            ),
        )

        # Can access the allowed account
        assert auth.can_access_account(allowed_account) is True
        # Cannot access a different account
        random_account = uuid4()
        assert auth.can_access_account(random_account) is False

    def test_owner_with_null_can_access_any(self):
        """Owner with null allowed_account_ids can access any account."""
        auth = AuthContext(
            user=_create_mock_user(),
            organization=_create_mock_org(),
            membership=_create_mock_membership(
                UserRole.OWNER, allowed_account_ids=None
            ),
        )

        assert auth.can_access_account(uuid4()) is True

    def test_admin_with_restrictions_cannot_access_other_account(self):
        """Admin with allowed_account_ids cannot access unlisted accounts (CWE-639 fix).

        Security: allowed_account_ids applies to ALL roles including ADMIN.
        """
        allowed_account = uuid4()
        auth = AuthContext(
            user=_create_mock_user(),
            organization=_create_mock_org(),
            membership=_create_mock_membership(
                UserRole.ADMIN,
                allowed_account_ids=[str(allowed_account)],
            ),
        )

        # Can access the allowed account
        assert auth.can_access_account(allowed_account) is True
        # Cannot access a different account
        assert auth.can_access_account(uuid4()) is False

    def test_admin_with_null_can_access_any(self):
        """Admin with null allowed_account_ids can access any account."""
        auth = AuthContext(
            user=_create_mock_user(),
            organization=_create_mock_org(),
            membership=_create_mock_membership(
                UserRole.ADMIN, allowed_account_ids=None
            ),
        )

        assert auth.can_access_account(uuid4()) is True

    def test_member_with_null_acl_can_access_any(self):
        """Member with null ACL can access any account."""
        auth = AuthContext(
            user=_create_mock_user(),
            organization=_create_mock_org(),
            membership=_create_mock_membership(
                UserRole.MEMBER, allowed_account_ids=None
            ),
        )

        assert auth.can_access_account(uuid4()) is True

    def test_member_can_access_allowed_account(self):
        """Member can access account in allowed list."""
        allowed_id = uuid4()
        auth = AuthContext(
            user=_create_mock_user(),
            organization=_create_mock_org(),
            membership=_create_mock_membership(
                UserRole.MEMBER,
                allowed_account_ids=[str(allowed_id)],
            ),
        )

        assert auth.can_access_account(allowed_id) is True

    def test_member_cannot_access_non_allowed_account(self):
        """Member cannot access account not in allowed list."""
        allowed_id = uuid4()
        other_id = uuid4()

        auth = AuthContext(
            user=_create_mock_user(),
            organization=_create_mock_org(),
            membership=_create_mock_membership(
                UserRole.MEMBER,
                allowed_account_ids=[str(allowed_id)],
            ),
        )

        assert auth.can_access_account(other_id) is False

    def test_no_membership_cannot_access(self):
        """User with no membership cannot access any account."""
        auth = AuthContext(
            user=_create_mock_user(),
            organization=None,
            membership=None,
        )

        assert auth.can_access_account(uuid4()) is False

    def test_uuid_case_insensitive(self):
        """UUID comparison should be case-insensitive."""
        allowed_id = uuid4()
        auth = AuthContext(
            user=_create_mock_user(),
            organization=_create_mock_org(),
            membership=_create_mock_membership(
                UserRole.MEMBER,
                # Store as uppercase string
                allowed_account_ids=[str(allowed_id).upper()],
            ),
        )

        # Query with lowercase - should still match
        assert auth.can_access_account(allowed_id) is True


class TestACLFilteringBehavior:
    """Tests for ACL filtering behavior in API layer (logic tests)."""

    def test_restricted_user_empty_list_returns_no_access(self):
        """User with empty allowed_account_ids should have no access."""
        auth = AuthContext(
            user=_create_mock_user(),
            organization=_create_mock_org(),
            membership=_create_mock_membership(UserRole.MEMBER, allowed_account_ids=[]),
        )

        allowed = get_allowed_account_filter(auth)
        # Should return empty list (no access)
        assert allowed is not None
        assert len(allowed) == 0

    def test_restricted_user_needs_specific_account_for_bulk(self):
        """Restricted user should require cloud_account_id for bulk operations.

        This tests the logic: if user has restricted access (allowed_accounts not None)
        and doesn't provide a cloud_account_id, bulk operations should fail.
        """
        account_id = uuid4()
        auth = AuthContext(
            user=_create_mock_user(),
            organization=_create_mock_org(),
            membership=_create_mock_membership(
                UserRole.MEMBER, allowed_account_ids=[str(account_id)]
            ),
        )

        allowed = get_allowed_account_filter(auth)
        # Should return list of allowed accounts
        assert allowed is not None
        assert len(allowed) == 1

        # API logic: when allowed_accounts is not None and cloud_account_id is None,
        # bulk endpoints should return 400 error
        cloud_account_id = None
        should_require_account = allowed is not None and cloud_account_id is None
        assert should_require_account is True

    def test_unrestricted_user_can_use_bulk_operations(self):
        """Owner/admin can use bulk operations without specifying account."""
        auth = AuthContext(
            user=_create_mock_user(),
            organization=_create_mock_org(),
            membership=_create_mock_membership(UserRole.OWNER),
        )

        allowed = get_allowed_account_filter(auth)
        # Should return None (unrestricted)
        assert allowed is None

        # API logic: when allowed_accounts is None, bulk operations work
        cloud_account_id = None
        should_require_account = allowed is not None and cloud_account_id is None
        assert should_require_account is False

    def test_member_null_acl_can_use_bulk_operations(self):
        """Member with null ACL can use bulk operations."""
        auth = AuthContext(
            user=_create_mock_user(),
            organization=_create_mock_org(),
            membership=_create_mock_membership(
                UserRole.MEMBER, allowed_account_ids=None
            ),
        )

        allowed = get_allowed_account_filter(auth)
        # Should return None (unrestricted)
        assert allowed is None

    def test_list_filtering_for_restricted_user(self):
        """Restricted user list queries should be filtered to allowed accounts."""
        account_a = uuid4()
        account_b = uuid4()
        auth = AuthContext(
            user=_create_mock_user(),
            organization=_create_mock_org(),
            membership=_create_mock_membership(
                UserRole.MEMBER, allowed_account_ids=[str(account_a), str(account_b)]
            ),
        )

        allowed = get_allowed_account_filter(auth)
        assert allowed is not None
        assert account_a in allowed
        assert account_b in allowed

        # Random account should not be in allowed
        account_c = uuid4()
        assert account_c not in allowed

    def test_can_access_account_integration_with_filter(self):
        """Verify can_access_account and get_allowed_account_filter are consistent."""
        account_a = uuid4()
        account_b = uuid4()
        account_c = uuid4()

        auth = AuthContext(
            user=_create_mock_user(),
            organization=_create_mock_org(),
            membership=_create_mock_membership(
                UserRole.MEMBER, allowed_account_ids=[str(account_a), str(account_b)]
            ),
        )

        allowed = get_allowed_account_filter(auth)

        # Both methods should agree
        assert auth.can_access_account(account_a) is True
        assert auth.can_access_account(account_b) is True
        assert auth.can_access_account(account_c) is False

        # And filter should contain the same accounts
        assert account_a in allowed
        assert account_b in allowed
        assert account_c not in allowed
