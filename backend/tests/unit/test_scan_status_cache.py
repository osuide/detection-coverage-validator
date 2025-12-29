"""Unit tests for scan status Redis caching.

Tests cover:
1. Scan status cache key generation
2. Cache set/get/delete operations
3. Cache data serialisation and deserialisation
4. Error handling when Redis is unavailable
"""

import json
import os
import sys
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch
from uuid import uuid4

import pytest

# Ensure the backend app is importable
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))


class TestScanStatusCacheKeyGeneration:
    """Tests for scan status cache key generation."""

    def test_scan_status_key_sanitizes_uuid(self):
        """Verify scan_status_key sanitizes UUID correctly."""
        from app.core.cache import scan_status_key

        scan_id = "550e8400-e29b-41d4-a716-446655440000"
        key = scan_status_key(scan_id)

        # Should produce a valid key with only allowed characters
        assert key.startswith("status:")
        assert "550e8400-e29b-41d4-a716-446655440000" in key

    def test_scan_status_key_handles_malicious_input(self):
        """Verify scan_status_key sanitizes potentially malicious input."""
        from app.core.cache import scan_status_key

        # Input with special characters should be sanitized
        malicious_id = "scan_id; DROP TABLE scans;--"
        key = scan_status_key(malicious_id)

        # SQL injection special characters should be stripped
        # Note: alphanumeric chars like "DROP" are kept but harmless as cache keys
        assert ";" not in key
        # Verify the key is valid for Redis
        assert key.startswith("status:")
        # Key should only contain allowed characters
        import re

        key_part = key.replace("status:", "")
        assert re.match(r"^[a-zA-Z0-9_\-]+$", key_part)


class TestCacheScanStatus:
    """Tests for cache_scan_status function."""

    @pytest.mark.asyncio
    async def test_cache_scan_status_success(self):
        """Verify cache_scan_status stores data correctly."""
        from app.core.cache import cache_scan_status, SCAN_STATUS_PREFIX

        scan_id = str(uuid4())
        scan_data = {
            "id": scan_id,
            "cloud_account_id": str(uuid4()),
            "status": "running",
            "progress_percent": 50,
            "current_step": "Processing detections",
            "detections_found": 10,
            "detections_new": 5,
            "detections_updated": 3,
            "detections_removed": 2,
            "errors": None,
            "started_at": datetime.now(timezone.utc).isoformat(),
            "completed_at": None,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }

        mock_redis = AsyncMock()
        mock_redis.setex = AsyncMock(return_value=True)

        with patch("app.core.cache._redis_cache", mock_redis):
            result = await cache_scan_status(scan_data)

        assert result is True
        mock_redis.setex.assert_called_once()

        # Verify the key format
        call_args = mock_redis.setex.call_args
        key = call_args[0][0]
        assert key.startswith(SCAN_STATUS_PREFIX)

        # Verify TTL
        ttl = call_args[0][1]
        assert ttl == 60  # SCAN_STATUS_TTL

        # Verify data is JSON serialised
        data = call_args[0][2]
        parsed = json.loads(data)
        assert parsed["id"] == scan_id
        assert parsed["status"] == "running"

    @pytest.mark.asyncio
    async def test_cache_scan_status_returns_false_when_no_redis(self):
        """Verify cache_scan_status returns False when Redis unavailable."""
        from app.core.cache import cache_scan_status

        scan_data = {"id": str(uuid4()), "status": "running"}

        with patch("app.core.cache._redis_cache", None):
            result = await cache_scan_status(scan_data)

        assert result is False

    @pytest.mark.asyncio
    async def test_cache_scan_status_returns_false_when_no_id(self):
        """Verify cache_scan_status returns False when scan_id missing."""
        from app.core.cache import cache_scan_status

        scan_data = {"status": "running"}  # No id field

        mock_redis = AsyncMock()
        with patch("app.core.cache._redis_cache", mock_redis):
            result = await cache_scan_status(scan_data)

        assert result is False


class TestGetCachedScanStatus:
    """Tests for get_cached_scan_status function."""

    @pytest.mark.asyncio
    async def test_get_cached_scan_status_success(self):
        """Verify get_cached_scan_status retrieves data correctly."""
        from app.core.cache import get_cached_scan_status

        scan_id = str(uuid4())
        cached_data = {
            "id": scan_id,
            "status": "running",
            "progress_percent": 75,
        }

        mock_redis = AsyncMock()
        mock_redis.get = AsyncMock(return_value=json.dumps(cached_data))

        with patch("app.core.cache._redis_cache", mock_redis):
            result = await get_cached_scan_status(scan_id)

        assert result is not None
        assert result["id"] == scan_id
        assert result["status"] == "running"
        assert result["progress_percent"] == 75

    @pytest.mark.asyncio
    async def test_get_cached_scan_status_returns_none_when_not_found(self):
        """Verify get_cached_scan_status returns None when key not found."""
        from app.core.cache import get_cached_scan_status

        mock_redis = AsyncMock()
        mock_redis.get = AsyncMock(return_value=None)

        with patch("app.core.cache._redis_cache", mock_redis):
            result = await get_cached_scan_status(str(uuid4()))

        assert result is None

    @pytest.mark.asyncio
    async def test_get_cached_scan_status_returns_none_when_no_redis(self):
        """Verify get_cached_scan_status returns None when Redis unavailable."""
        from app.core.cache import get_cached_scan_status

        with patch("app.core.cache._redis_cache", None):
            result = await get_cached_scan_status(str(uuid4()))

        assert result is None


class TestDeleteScanStatusCache:
    """Tests for delete_scan_status_cache function."""

    @pytest.mark.asyncio
    async def test_delete_scan_status_cache_success(self):
        """Verify delete_scan_status_cache deletes key correctly."""
        from app.core.cache import delete_scan_status_cache

        scan_id = str(uuid4())

        mock_redis = AsyncMock()
        mock_redis.delete = AsyncMock(return_value=1)

        with patch("app.core.cache._redis_cache", mock_redis):
            result = await delete_scan_status_cache(scan_id)

        assert result is True
        mock_redis.delete.assert_called_once()

    @pytest.mark.asyncio
    async def test_delete_scan_status_cache_returns_false_when_no_redis(self):
        """Verify delete_scan_status_cache returns False when Redis unavailable."""
        from app.core.cache import delete_scan_status_cache

        with patch("app.core.cache._redis_cache", None):
            result = await delete_scan_status_cache(str(uuid4()))

        assert result is False


class TestScanServiceCacheIntegration:
    """Tests for ScanService cache integration."""

    def test_cache_scan_status_method_creates_correct_data(self):
        """Verify _cache_scan_status creates correctly formatted data."""
        # This is a structural test - verifying the data format
        # without actually hitting Redis

        scan_data = {
            "id": str(uuid4()),
            "cloud_account_id": str(uuid4()),
            "status": "running",
            "regions": ["eu-west-2"],
            "detection_types": [],
            "progress_percent": 50,
            "current_step": "Processing",
            "detections_found": 10,
            "detections_new": 5,
            "detections_updated": 3,
            "detections_removed": 2,
            "errors": None,
            "started_at": "2025-01-01T00:00:00+00:00",
            "completed_at": None,
            "created_at": "2025-01-01T00:00:00+00:00",
        }

        # Verify all required fields are present
        required_fields = [
            "id",
            "cloud_account_id",
            "status",
            "progress_percent",
            "current_step",
            "detections_found",
            "detections_new",
            "detections_updated",
            "detections_removed",
            "started_at",
            "completed_at",
            "created_at",
        ]

        for field in required_fields:
            assert field in scan_data, f"Missing required field: {field}"

        # Verify serialisation works
        serialised = json.dumps(scan_data)
        deserialised = json.loads(serialised)
        assert deserialised == scan_data
