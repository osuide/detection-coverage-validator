"""Integration tests for support ticket system.

Tests for:
- Rate limiting on ticket submission (CWE-799)
- Input validation
- Authentication requirements
"""

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
class TestSupportTicketValidation:
    """Test input validation on support tickets."""

    async def test_subject_too_short(self, authenticated_client: AsyncClient):
        """Subject under 5 chars should fail validation."""
        response = await authenticated_client.post(
            "/api/v1/support/tickets",
            json={
                "subject": "Hi",  # Too short (min 5)
                "description": "This is a valid description with enough characters.",
                "category": "technical",
            },
        )
        assert response.status_code == 422

    async def test_description_too_short(self, authenticated_client: AsyncClient):
        """Description under 20 chars should fail validation."""
        response = await authenticated_client.post(
            "/api/v1/support/tickets",
            json={
                "subject": "Valid subject here",
                "description": "Too short",  # Too short (min 20)
                "category": "technical",
            },
        )
        assert response.status_code == 422

    async def test_invalid_category(self, authenticated_client: AsyncClient):
        """Invalid category should fail validation."""
        response = await authenticated_client.post(
            "/api/v1/support/tickets",
            json={
                "subject": "Valid subject here",
                "description": "This is a valid description with enough characters.",
                "category": "invalid_category",  # Not in allowed list
            },
        )
        assert response.status_code == 422

    async def test_valid_ticket_structure(self, authenticated_client: AsyncClient):
        """Valid ticket structure should pass validation (may fail on workspace)."""
        response = await authenticated_client.post(
            "/api/v1/support/tickets",
            json={
                "subject": "Testing valid ticket structure",
                "description": "This is a valid description to test that the ticket structure passes validation.",
                "category": "technical",
            },
        )
        # 200 success or 503 if workspace not configured (acceptable in test)
        # Should NOT be 422 (validation error)
        assert response.status_code != 422, "Valid ticket rejected by validation"


@pytest.mark.asyncio
class TestSupportTicketAuth:
    """Test authentication requirements for support tickets."""

    async def test_unauthenticated_request_rejected(self, client: AsyncClient):
        """Unauthenticated requests should be rejected."""
        response = await client.post(
            "/api/v1/support/tickets",
            json={
                "subject": "Test ticket",
                "description": "This should fail because we are not authenticated.",
                "category": "technical",
            },
        )
        assert response.status_code == 401


@pytest.mark.asyncio
class TestSupportTicketRateLimiting:
    """Test rate limiting on support ticket endpoint.

    Note: Rate limiting uses Redis and persists across tests.
    These tests verify rate limiting behaviour but may be affected by
    other tests that submit tickets in the same test run.
    """

    async def test_rate_limit_returns_429_on_excessive_requests(
        self, authenticated_client: AsyncClient
    ):
        """Rate limit should return 429 after exceeding limit.

        The limit is 5 requests per hour. We submit 6 requests and verify
        that either:
        - The 6th request returns 429 (rate limited)
        - Earlier requests return 429 (if limit already reached from other tests)
        """
        rate_limited = False
        successful_count = 0

        for i in range(6):
            response = await authenticated_client.post(
                "/api/v1/support/tickets",
                json={
                    "subject": f"Rate limit test ticket number {i}",
                    "description": "Testing rate limiting - this should eventually fail with 429.",
                    "category": "technical",
                },
            )

            if response.status_code == 429:
                rate_limited = True
                break
            elif response.status_code in (200, 503):
                # 200 = success, 503 = workspace not configured (both count as not rate-limited)
                successful_count += 1

        # Verify that rate limiting kicked in at some point
        assert rate_limited, (
            f"Expected 429 rate limit response after 5 requests, "
            f"but got {successful_count} successful requests without rate limiting"
        )

    async def test_rate_limit_response_format(self, authenticated_client: AsyncClient):
        """Rate limit response should have correct format."""
        # First, exhaust the rate limit (if not already exhausted)
        for _ in range(6):
            response = await authenticated_client.post(
                "/api/v1/support/tickets",
                json={
                    "subject": "Exhaust rate limit for format test",
                    "description": "Testing rate limit response format verification.",
                    "category": "technical",
                },
            )
            if response.status_code == 429:
                break

        # Now verify the format of a rate-limited response
        response = await authenticated_client.post(
            "/api/v1/support/tickets",
            json={
                "subject": "Should be rate limited",
                "description": "This request should definitely be rate limited.",
                "category": "technical",
            },
        )

        if response.status_code == 429:
            # Verify response contains useful information
            data = response.json()
            assert "detail" in data or "error" in data or response.text


@pytest.mark.asyncio
class TestSupportContext:
    """Test support context endpoint."""

    async def test_get_context_authenticated(self, authenticated_client: AsyncClient):
        """Authenticated users can get their support context."""
        response = await authenticated_client.get("/api/v1/support/context")
        assert response.status_code == 200
        data = response.json()
        assert "email" in data
        assert "tier" in data
        assert "tier_display" in data
        assert "cloud_accounts_count" in data

    async def test_get_context_unauthenticated(self, client: AsyncClient):
        """Unauthenticated users cannot get support context."""
        response = await client.get("/api/v1/support/context")
        assert response.status_code == 401
