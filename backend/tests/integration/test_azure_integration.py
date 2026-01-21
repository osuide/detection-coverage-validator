"""Integration tests for Azure WIF integration."""

import pytest
from httpx import AsyncClient
from app.mappers.azure_defender_mappings import (
    get_mitre_techniques_for_defender_assessment,
)
from app.mappers.azure_policy_mappings import get_mitre_techniques_for_policy


@pytest.mark.asyncio
async def test_create_azure_account(authenticated_client: AsyncClient):
    """Test creating an Azure cloud account with WIF configuration."""
    account_data = {
        "name": "Test Azure Subscription",
        "provider": "azure",
        "account_id": "12345678-1234-1234-1234-123456789012",  # Valid GUID
        "regions": ["global"],  # Azure scanning is subscription-level
        "azure_workload_identity_config": {
            "tenant_id": "87654321-4321-4321-4321-210987654321",
            "client_id": "abcd1234-1234-1234-1234-1234abcd1234",
            "subscription_id": "12345678-1234-1234-1234-123456789012",
        },
        "azure_enabled": True,
    }

    response = await authenticated_client.post("/api/v1/accounts", json=account_data)
    assert response.status_code == 201
    data = response.json()
    assert data["name"] == account_data["name"]
    assert data["provider"] == "azure"
    assert data["account_id"] == account_data["account_id"]
    assert data["is_active"] is True
    assert data["azure_enabled"] is True
    assert data["azure_workload_identity_config"] is not None
    assert (
        data["azure_workload_identity_config"]["tenant_id"]
        == account_data["azure_workload_identity_config"]["tenant_id"]
    )


@pytest.mark.asyncio
async def test_create_azure_account_invalid_subscription_id(
    authenticated_client: AsyncClient,
):
    """Test that invalid Azure subscription ID is rejected."""
    account_data = {
        "name": "Invalid Azure Account",
        "provider": "azure",
        "account_id": "not-a-valid-guid",  # Invalid GUID format
        "regions": ["global"],
        "azure_workload_identity_config": {
            "tenant_id": "87654321-4321-4321-4321-210987654321",
            "client_id": "abcd1234-1234-1234-1234-1234abcd1234",
            "subscription_id": "12345678-1234-1234-1234-123456789012",
        },
    }

    response = await authenticated_client.post("/api/v1/accounts", json=account_data)
    assert response.status_code == 422  # Validation error


@pytest.mark.asyncio
async def test_create_azure_account_missing_wif_config(
    authenticated_client: AsyncClient,
):
    """Test that Azure account creation fails without WIF config."""
    account_data = {
        "name": "Azure Without Config",
        "provider": "azure",
        "account_id": "12345678-1234-1234-1234-123456789012",
        "regions": ["global"],
        # Missing azure_workload_identity_config
    }

    response = await authenticated_client.post("/api/v1/accounts", json=account_data)
    assert response.status_code == 422  # Validation error


@pytest.mark.asyncio
async def test_update_azure_account(authenticated_client: AsyncClient):
    """Test updating Azure account WIF configuration."""
    # First create an Azure account
    create_data = {
        "name": "Test Azure Update",
        "provider": "azure",
        "account_id": "99999999-9999-9999-9999-999999999999",
        "regions": ["global"],
        "azure_workload_identity_config": {
            "tenant_id": "11111111-1111-1111-1111-111111111111",
            "client_id": "22222222-2222-2222-2222-222222222222",
            "subscription_id": "99999999-9999-9999-9999-999999999999",
        },
        "azure_enabled": False,
    }

    create_response = await authenticated_client.post(
        "/api/v1/accounts", json=create_data
    )
    assert create_response.status_code == 201
    account_id = create_response.json()["id"]

    # Update azure_enabled flag
    update_data = {"azure_enabled": True}

    update_response = await authenticated_client.patch(
        f"/api/v1/accounts/{account_id}", json=update_data
    )
    assert update_response.status_code == 200
    updated = update_response.json()
    assert updated["azure_enabled"] is True


def test_azure_defender_mitre_mappings():
    """Test Azure Defender MITRE ATT&CK mappings."""
    # Test common Defender assessment mappings
    mfa_techniques = get_mitre_techniques_for_defender_assessment(
        "MFA should be enabled on accounts with owner permissions"
    )
    assert len(mfa_techniques) > 0
    # Should map to Valid Accounts: Cloud Accounts (T1078.004)
    assert any(tid == "T1078.004" for tid, _ in mfa_techniques)

    # Test endpoint protection mapping
    endpoint_techniques = get_mitre_techniques_for_defender_assessment(
        "Endpoint protection should be installed"
    )
    assert len(endpoint_techniques) > 0
    # Should map to Impair Defenses (T1562.001)
    assert any(tid == "T1562.001" for tid, _ in endpoint_techniques)

    # Test network security group mapping
    nsg_techniques = get_mitre_techniques_for_defender_assessment(
        "Network Security Groups should be enabled"
    )
    assert len(nsg_techniques) > 0
    # Should map to Disable or Modify Cloud Firewall (T1562.007)
    assert any(tid == "T1562.007" for tid, _ in nsg_techniques)

    # Test unknown assessment (should return empty)
    unknown_techniques = get_mitre_techniques_for_defender_assessment(
        "This is not a real assessment"
    )
    assert len(unknown_techniques) == 0


def test_azure_policy_mitre_mappings():
    """Test Azure Policy MITRE ATT&CK mappings."""
    # Test MFA policy mapping
    mfa_techniques = get_mitre_techniques_for_policy("Multi-factor authentication")
    assert len(mfa_techniques) > 0
    # Should map to Valid Accounts and Brute Force
    technique_ids = [tid for tid, _ in mfa_techniques]
    assert "T1078.004" in technique_ids  # Valid Accounts: Cloud Accounts
    assert "T1110" in technique_ids  # Brute Force

    # Test encryption policy mapping
    encryption_techniques = get_mitre_techniques_for_policy(
        "Transparent Data Encryption"
    )
    assert len(encryption_techniques) > 0
    # Should map to Data from Cloud Storage
    technique_ids = [tid for tid, _ in encryption_techniques]
    assert "T1530" in technique_ids

    # Test container policy mapping
    container_techniques = get_mitre_techniques_for_policy("Container registry")
    assert len(container_techniques) > 0
    # Should map to Implant Internal Image
    technique_ids = [tid for tid, _ in container_techniques]
    assert "T1525" in technique_ids

    # Test multiple pattern matches (policy matches multiple patterns)
    network_techniques = get_mitre_techniques_for_policy(
        "Network security group should be configured"
    )
    assert len(network_techniques) > 0

    # Test unknown policy (should return empty)
    unknown_techniques = get_mitre_techniques_for_policy("Not a real policy pattern")
    assert len(unknown_techniques) == 0


def test_azure_mitre_coverage():
    """Test that Azure MITRE mappings provide good technique coverage."""
    from app.mappers.azure_defender_mappings import get_all_defender_techniques
    from app.mappers.azure_policy_mappings import get_all_policy_techniques

    # Get all unique techniques from both mappers
    defender_techniques = get_all_defender_techniques()
    policy_techniques = get_all_policy_techniques()

    # Verify we have substantial coverage
    assert len(defender_techniques) >= 30, "Defender should cover 30+ techniques"
    assert len(policy_techniques) >= 30, "Policy should cover 30+ techniques"

    # Verify combined coverage (some overlap is expected)
    combined = defender_techniques | policy_techniques
    assert len(combined) >= 50, "Combined should cover 50+ unique techniques"

    # Verify all techniques follow MITRE format (T#### or T####.###)
    import re

    mitre_pattern = re.compile(r"^T\d{4}(\.\d{3})?$")
    for technique_id in combined:
        assert mitre_pattern.match(
            technique_id
        ), f"Invalid technique ID format: {technique_id}"
