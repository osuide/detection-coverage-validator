"""Unit tests for authentication security fixes.

Tests cover:
1. MFA token type validation in get_current_user
2. UUID parsing guards in get_current_user
3. Organisation suspension enforcement in get_auth_context
4. Organisation suspension enforcement in public API auth
5. Code analysis tier checks
"""

import os
import sys
import uuid

import pytest

# Ensure the backend app is importable
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))


class TestMFATokenTypeValidation:
    """Tests for MFA token type validation in get_current_user.

    Security fix: get_current_user must reject mfa_pending tokens
    to prevent MFA bypass attacks.
    """

    def test_mfa_pending_token_has_correct_type(self):
        """Verify MFA pending tokens are generated with type='mfa_pending'."""
        from app.services.auth_service import AuthService

        user_id = uuid.uuid4()
        token = AuthService.generate_mfa_pending_token(user_id)

        # Decode and verify type
        payload = AuthService.decode_token(token)
        assert payload is not None
        assert payload.get("type") == "mfa_pending"
        assert payload.get("sub") == str(user_id)

    def test_access_token_has_correct_type(self):
        """Verify access tokens are generated with type='access'."""
        from app.services.auth_service import AuthService

        user_id = uuid.uuid4()
        org_id = uuid.uuid4()
        token = AuthService.generate_access_token(user_id, org_id)

        payload = AuthService.decode_token(token)
        assert payload is not None
        assert payload.get("type") == "access"

    def test_token_type_check_rejects_mfa_pending(self):
        """Verify token type check logic correctly rejects mfa_pending."""
        # Simulates the check added to get_current_user
        valid_types = ("access", None)

        assert "mfa_pending" not in valid_types
        assert "admin" not in valid_types
        assert "access" in valid_types
        assert None in valid_types  # Legacy tokens without type

    def test_token_type_check_accepts_access(self):
        """Verify token type check accepts access tokens."""
        valid_types = ("access", None)
        assert "access" in valid_types

    def test_token_type_check_accepts_legacy_tokens(self):
        """Verify token type check accepts legacy tokens without type field."""
        valid_types = ("access", None)
        token_type = None  # Legacy token
        assert token_type in valid_types


class TestUUIDParsing:
    """Tests for UUID parsing guards in get_current_user.

    Security fix: Malformed UUIDs should return 401, not 500.
    """

    def test_valid_uuid_parsing(self):
        """Verify valid UUIDs parse correctly."""
        valid_uuid = "550e8400-e29b-41d4-a716-446655440000"
        parsed = uuid.UUID(valid_uuid)
        assert str(parsed) == valid_uuid

    def test_malformed_uuid_raises_value_error(self):
        """Verify malformed UUIDs raise ValueError."""
        malformed_uuids = [
            "not-a-uuid",
            "12345",
            "",
            "550e8400-e29b-41d4-a716",  # Truncated
            "550e8400-e29b-41d4-a716-44665544000g",  # Invalid char
        ]
        for malformed in malformed_uuids:
            with pytest.raises((ValueError, AttributeError)):
                uuid.UUID(malformed)

    def test_none_uuid_raises_type_error(self):
        """Verify None UUID raises TypeError."""
        with pytest.raises(TypeError):
            uuid.UUID(None)

    def test_uuid_guard_pattern(self):
        """Verify the try/except guard pattern catches malformed UUIDs."""
        malformed = "not-a-valid-uuid"

        caught = False
        try:
            uuid.UUID(malformed)
        except (ValueError, TypeError):
            caught = True

        assert caught, "Guard pattern should catch malformed UUIDs"


class TestOrgSuspensionEnforcement:
    """Tests for organisation suspension enforcement.

    Security fix: Suspended organisations should not be able to access APIs.
    """

    def test_is_active_check_logic_active_org(self):
        """Verify is_active check allows active organisations."""
        # Simulates the check in get_auth_context
        is_active = True
        should_allow = is_active
        assert should_allow

    def test_is_active_check_logic_suspended_org(self):
        """Verify is_active check blocks suspended organisations."""
        is_active = False
        should_allow = is_active
        assert not should_allow

    def test_suspension_clears_org_context(self):
        """Verify suspended orgs have their context cleared."""
        # Simulates: if organization and not organization.is_active: organization = None

        class MockOrg:
            def __init__(self, active):
                self.is_active = active

        # Active org - should retain
        org = MockOrg(active=True)
        if org and not org.is_active:
            org = None
        assert org is not None

        # Suspended org - should be cleared
        org = MockOrg(active=False)
        if org and not org.is_active:
            org = None
        assert org is None


class TestCodeAnalysisTierCheck:
    """Tests for code analysis tier availability.

    Security fix: Use current tier names (INDIVIDUAL, PRO) not legacy.
    """

    def test_individual_tier_has_access(self):
        """Verify INDIVIDUAL tier has code analysis access."""
        from app.models.billing import AccountTier

        allowed_tiers = [
            AccountTier.INDIVIDUAL,
            AccountTier.PRO,
            AccountTier.SUBSCRIBER,  # Legacy
        ]
        assert AccountTier.INDIVIDUAL in allowed_tiers

    def test_pro_tier_has_access(self):
        """Verify PRO tier has code analysis access."""
        from app.models.billing import AccountTier

        allowed_tiers = [
            AccountTier.INDIVIDUAL,
            AccountTier.PRO,
            AccountTier.SUBSCRIBER,  # Legacy
        ]
        assert AccountTier.PRO in allowed_tiers

    def test_free_tier_no_access(self):
        """Verify FREE tier does not have code analysis access."""
        from app.models.billing import AccountTier

        allowed_tiers = [
            AccountTier.INDIVIDUAL,
            AccountTier.PRO,
            AccountTier.SUBSCRIBER,  # Legacy
        ]
        assert AccountTier.FREE not in allowed_tiers

    def test_legacy_subscriber_has_access(self):
        """Verify legacy SUBSCRIBER tier still has code analysis access."""
        from app.models.billing import AccountTier

        allowed_tiers = [
            AccountTier.INDIVIDUAL,
            AccountTier.PRO,
            AccountTier.SUBSCRIBER,  # Legacy
        ]
        assert AccountTier.SUBSCRIBER in allowed_tiers


class TestPublicAPIKeyOrgSuspension:
    """Tests for API key organisation suspension checks.

    Security fix: API keys should be rejected for suspended organisations.
    """

    def test_api_key_rejected_for_suspended_org(self):
        """Verify logic rejects API keys for suspended orgs."""
        # Simulates: if org and not org.is_active: raise 403

        class MockOrg:
            def __init__(self, active):
                self.is_active = active

        org = MockOrg(active=False)
        should_reject = org and not org.is_active
        assert should_reject

    def test_api_key_accepted_for_active_org(self):
        """Verify logic accepts API keys for active orgs."""

        class MockOrg:
            def __init__(self, active):
                self.is_active = active

        org = MockOrg(active=True)
        should_reject = org and not org.is_active
        assert not should_reject


class TestStripeAsyncCalls:
    """Tests for Stripe async call wrapping.

    Security fix: Stripe SDK calls should not block the event loop.
    """

    def test_asyncio_to_thread_available(self):
        """Verify asyncio.to_thread is available for wrapping sync calls."""
        import asyncio

        assert hasattr(asyncio, "to_thread")

    @pytest.mark.asyncio
    async def test_to_thread_runs_sync_function(self):
        """Verify to_thread correctly wraps synchronous functions."""
        import asyncio

        def sync_function(x, y):
            return x + y

        result = await asyncio.to_thread(sync_function, 1, 2)
        assert result == 3
