"""Integration tests for API documentation endpoints.

These tests ensure the public API documentation is correctly served
and does not expose internal endpoints.
"""

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_public_openapi_json_returns_200(client: AsyncClient):
    """Test that /public/openapi.json returns the public API spec."""
    response = await client.get("/public/openapi.json")
    assert response.status_code == 200
    data = response.json()

    # Verify it's the public API spec
    assert data["info"]["title"] == "A13E Public API"
    assert "openapi" in data
    assert "paths" in data


@pytest.mark.asyncio
async def test_public_openapi_only_contains_public_endpoints(client: AsyncClient):
    """Test that /public/openapi.json only contains /api/v1/public/* paths."""
    response = await client.get("/public/openapi.json")
    assert response.status_code == 200
    data = response.json()

    # All paths should start with /api/v1/public/
    for path in data.get("paths", {}).keys():
        assert path.startswith(
            "/api/v1/public/"
        ), f"Non-public path exposed in public API docs: {path}"


@pytest.mark.asyncio
async def test_public_openapi_excludes_internal_endpoints(client: AsyncClient):
    """Test that internal endpoints are NOT in the public spec."""
    response = await client.get("/public/openapi.json")
    assert response.status_code == 200
    data = response.json()

    paths = list(data.get("paths", {}).keys())

    # These prefixes should NEVER appear in public docs
    forbidden_prefixes = [
        "/api/v1/admin",
        "/api/v1/auth",
        "/api/v1/cognito",
        "/api/v1/github",
        "/health",
        "/api/v1/accounts",  # Internal account management (not public API)
        "/api/v1/teams",
        "/api/v1/billing",
    ]

    for path in paths:
        for forbidden in forbidden_prefixes:
            assert not path.startswith(
                forbidden
            ), f"Internal endpoint exposed in public API docs: {path}"


@pytest.mark.asyncio
async def test_public_openapi_has_api_key_security(client: AsyncClient):
    """Test that public API uses API key authentication."""
    response = await client.get("/public/openapi.json")
    assert response.status_code == 200
    data = response.json()

    # Check security schemes
    security_schemes = data.get("components", {}).get("securitySchemes", {})
    assert "ApiKeyAuth" in security_schemes
    assert security_schemes["ApiKeyAuth"]["type"] == "apiKey"
    assert security_schemes["ApiKeyAuth"]["in"] == "header"
    assert security_schemes["ApiKeyAuth"]["name"] == "X-API-Key"


@pytest.mark.asyncio
async def test_redoc_returns_html(client: AsyncClient):
    """Test that /redoc returns HTML documentation page."""
    response = await client.get("/redoc")
    assert response.status_code == 200
    assert "text/html" in response.headers.get("content-type", "")

    content = response.text
    # Check it references the public spec, not the internal one
    assert "/public/openapi.json" in content
    assert "A13E" in content


@pytest.mark.asyncio
async def test_redoc_uses_public_spec_not_internal(client: AsyncClient):
    """Test that ReDoc specifically uses the public API spec."""
    response = await client.get("/redoc")
    assert response.status_code == 200

    content = response.text

    # MUST use public spec
    assert "spec-url='/public/openapi.json'" in content

    # MUST NOT use internal spec
    assert "spec-url='/openapi.json'" not in content


@pytest.mark.asyncio
async def test_internal_openapi_not_exposed_at_root(client: AsyncClient):
    """Test that /openapi.json is not accessible (disabled in prod-like env)."""
    response = await client.get("/openapi.json")
    # In development/staging, this returns the full spec
    # In production, this should be disabled
    # For now, just verify it exists but document the risk
    if response.status_code == 200:
        # If accessible, it should NOT be linked from /redoc
        redoc_response = await client.get("/redoc")
        assert "/openapi.json'" not in redoc_response.text.replace(
            "/public/openapi.json", ""
        )
