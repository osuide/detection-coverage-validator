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

    def test_owner_returns_none(self):
        """Owner should have unrestricted access (None)."""
        auth = AuthContext(
            user=_create_mock_user(),
            organization=_create_mock_org(),
            membership=_create_mock_membership(
                UserRole.OWNER,
                allowed_account_ids=[str(uuid4())],  # Even if set, should be ignored
            ),
        )
        result = get_allowed_account_filter(auth)
        assert result is None

    def test_admin_returns_none(self):
        """Admin should have unrestricted access (None)."""
        auth = AuthContext(
            user=_create_mock_user(),
            organization=_create_mock_org(),
            membership=_create_mock_membership(
                UserRole.ADMIN,
                allowed_account_ids=[str(uuid4())],
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

    def test_owner_can_access_any_account(self):
        """Owner should access any account regardless of ACL."""
        auth = AuthContext(
            user=_create_mock_user(),
            organization=_create_mock_org(),
            membership=_create_mock_membership(
                UserRole.OWNER,
                allowed_account_ids=[str(uuid4())],  # Different account
            ),
        )

        random_account = uuid4()
        assert auth.can_access_account(random_account) is True

    def test_admin_can_access_any_account(self):
        """Admin should access any account regardless of ACL."""
        auth = AuthContext(
            user=_create_mock_user(),
            organization=_create_mock_org(),
            membership=_create_mock_membership(
                UserRole.ADMIN,
                allowed_account_ids=[str(uuid4())],
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
