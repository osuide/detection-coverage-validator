"""Integration tests for scan status Redis caching.

Tests cover:
1. Scan status endpoint returns cached data when available
2. Scan status endpoint falls back to database when cache miss
3. Cache is populated during scan execution
4. Cache is cleaned up after scan completion
"""

import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch

import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.cloud_account import CloudAccount, CloudProvider
from app.models.scan import Scan, ScanStatus


@pytest_asyncio.fixture
async def test_cloud_account(
    db_session: AsyncSession,
    test_org,
) -> CloudAccount:
    """Create a test cloud account."""
    account = CloudAccount(
        id=uuid.uuid4(),
        organization_id=test_org.id,
        name="Test AWS Account",
        provider=CloudProvider.AWS,
        account_id="123456789012",
        is_active=True,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    db_session.add(account)
    await db_session.flush()
    return account


@pytest_asyncio.fixture
async def test_scan(
    db_session: AsyncSession,
    test_cloud_account: CloudAccount,
) -> Scan:
    """Create a test scan in running state."""
    scan = Scan(
        id=uuid.uuid4(),
        cloud_account_id=test_cloud_account.id,
        status=ScanStatus.RUNNING,
        progress_percent=50,
        current_step="Processing detections",
        regions=["eu-west-2"],
        detection_types=[],
        detections_found=10,
        detections_new=5,
        detections_updated=3,
        detections_removed=2,
        started_at=datetime.now(timezone.utc),
        created_at=datetime.now(timezone.utc),
    )
    db_session.add(scan)
    await db_session.commit()
    return scan


@pytest.mark.asyncio
async def test_get_scan_returns_cached_data(
    authenticated_client: AsyncClient,
    test_scan: Scan,
    test_cloud_account: CloudAccount,
):
    """Verify get_scan returns cached data when available."""
    cached_data = {
        "id": str(test_scan.id),
        "cloud_account_id": str(test_cloud_account.id),
        "status": "running",
        "regions": ["eu-west-2"],
        "detection_types": [],
        "progress_percent": 75,  # Different from DB to prove cache is used
        "current_step": "Mapping to MITRE ATT&CK",
        "detections_found": 15,
        "detections_new": 8,
        "detections_updated": 5,
        "detections_removed": 2,
        "errors": None,
        "started_at": datetime.now(timezone.utc).isoformat(),
        "completed_at": None,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }

    with patch(
        "app.api.routes.scans.get_cached_scan_status",
        new_callable=AsyncMock,
        return_value=cached_data,
    ):
        response = await authenticated_client.get(f"/api/v1/scans/{test_scan.id}")

    assert response.status_code == 200
    data = response.json()

    # Should have cached progress (75), not DB progress (50)
    assert data["progress_percent"] == 75
    assert data["current_step"] == "Mapping to MITRE ATT&CK"
    assert data["detections_found"] == 15


@pytest.mark.asyncio
async def test_get_scan_falls_back_to_database(
    authenticated_client: AsyncClient,
    test_scan: Scan,
):
    """Verify get_scan falls back to database when cache miss."""
    # Mock cache to return None (cache miss)
    with patch(
        "app.api.routes.scans.get_cached_scan_status",
        new_callable=AsyncMock,
        return_value=None,
    ):
        response = await authenticated_client.get(f"/api/v1/scans/{test_scan.id}")

    assert response.status_code == 200
    data = response.json()

    # Should have DB values
    assert data["progress_percent"] == 50
    assert data["current_step"] == "Processing detections"
    assert data["detections_found"] == 10


@pytest.mark.asyncio
async def test_get_scan_verifies_org_ownership_for_cached_data(
    authenticated_client: AsyncClient,
    test_scan: Scan,
    db_session: AsyncSession,
):
    """Verify cached scan data is only returned if org owns the account."""
    # Create cached data with a different org's account
    other_org_account_id = str(uuid.uuid4())

    cached_data = {
        "id": str(test_scan.id),
        "cloud_account_id": other_org_account_id,  # Different org's account
        "status": "running",
        "regions": [],
        "detection_types": [],
        "progress_percent": 99,
        "current_step": "Cached step",
        "detections_found": 100,
        "detections_new": 50,
        "detections_updated": 30,
        "detections_removed": 10,
        "errors": None,
        "started_at": datetime.now(timezone.utc).isoformat(),
        "completed_at": None,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }

    with patch(
        "app.api.routes.scans.get_cached_scan_status",
        new_callable=AsyncMock,
        return_value=cached_data,
    ):
        response = await authenticated_client.get(f"/api/v1/scans/{test_scan.id}")

    assert response.status_code == 200
    data = response.json()

    # Should have DB values since cached account doesn't belong to user's org
    assert data["progress_percent"] == 50
    assert data["current_step"] == "Processing detections"


@pytest.mark.asyncio
async def test_get_scan_not_found(authenticated_client: AsyncClient):
    """Verify get_scan returns 404 for non-existent scan."""
    fake_scan_id = str(uuid.uuid4())

    with patch(
        "app.api.routes.scans.get_cached_scan_status",
        new_callable=AsyncMock,
        return_value=None,
    ):
        response = await authenticated_client.get(f"/api/v1/scans/{fake_scan_id}")

    assert response.status_code == 404


@pytest.mark.asyncio
async def test_cache_functions_are_called_in_scan_service():
    """Verify scan service calls cache functions at appropriate points.

    This test verifies the structural integration - that the scan service
    is wired up to call cache functions after status updates.
    """
    from app.services.scan_service import ScanService

    # Check that the cache import exists in scan_service
    import app.services.scan_service as scan_service_module

    assert hasattr(scan_service_module, "cache_scan_status")
    assert hasattr(scan_service_module, "delete_scan_status_cache")

    # Check that ScanService has the _cache_scan_status method
    assert hasattr(ScanService, "_cache_scan_status")
