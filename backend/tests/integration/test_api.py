"""Integration tests for API endpoints."""

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_health_check(client: AsyncClient):
    """Test the health check endpoint."""
    response = await client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"


@pytest.mark.asyncio
async def test_root_endpoint(client: AsyncClient):
    """Test the root endpoint."""
    response = await client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert "name" in data
    assert "version" in data


@pytest.mark.asyncio
async def test_list_accounts_empty(authenticated_client: AsyncClient):
    """Test listing accounts when none exist."""
    response = await authenticated_client.get("/api/v1/accounts")
    assert response.status_code == 200
    data = response.json()
    assert data == []


@pytest.mark.asyncio
async def test_create_account(authenticated_client: AsyncClient):
    """Test creating a cloud account."""
    account_data = {
        "name": "Test AWS Account",
        "provider": "aws",
        "account_id": "123456789012",
        "regions": ["us-east-1", "us-west-2"],
    }

    response = await authenticated_client.post("/api/v1/accounts", json=account_data)
    assert response.status_code == 201
    data = response.json()
    assert data["name"] == account_data["name"]
    assert data["provider"] == account_data["provider"]
    assert data["account_id"] == account_data["account_id"]
    assert data["is_active"] is True


@pytest.mark.asyncio
async def test_create_duplicate_account(authenticated_client: AsyncClient):
    """Test that creating a duplicate account fails."""
    account_data = {
        "name": "Test AWS Account",
        "provider": "aws",
        "account_id": "999888777666",
        "regions": ["us-east-1"],
    }

    # Create first account
    response = await authenticated_client.post("/api/v1/accounts", json=account_data)
    assert response.status_code == 201

    # Try to create duplicate
    response = await authenticated_client.post("/api/v1/accounts", json=account_data)
    assert response.status_code == 400


@pytest.mark.asyncio
async def test_get_account_not_found(authenticated_client: AsyncClient):
    """Test getting a non-existent account."""
    response = await authenticated_client.get(
        "/api/v1/accounts/00000000-0000-0000-0000-000000000000"
    )
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_list_detections_empty(authenticated_client: AsyncClient):
    """Test listing detections when none exist."""
    response = await authenticated_client.get("/api/v1/detections")
    assert response.status_code == 200
    data = response.json()
    assert data["items"] == []
    assert data["total"] == 0


@pytest.mark.asyncio
async def test_unauthenticated_create_account_fails(client: AsyncClient):
    """Test that creating an account without auth fails."""
    account_data = {
        "name": "Test Account",
        "provider": "aws",
        "account_id": "111222333444",
        "regions": ["us-east-1"],
    }

    response = await client.post("/api/v1/accounts", json=account_data)
    # Should get 401 Unauthorized or 403 Forbidden
    assert response.status_code in [401, 403]


@pytest.mark.asyncio
async def test_forgot_password_endpoint(client: AsyncClient):
    """Test the forgot password endpoint (no auth required)."""
    response = await client.post(
        "/api/v1/auth/forgot-password", json={"email": "test@example.com"}
    )
    # Always returns 204 to prevent email enumeration
    assert response.status_code == 204
