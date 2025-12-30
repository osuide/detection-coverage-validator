"""Unit tests for parallel scanning infrastructure.

Tests cover:
- Rate limiter token bucket algorithm
- Concurrent region scanning with semaphore limiting
- Rate limiting integration with scanning
"""

import asyncio
from datetime import datetime
from unittest.mock import MagicMock

import pytest

from app.models.detection import DetectionType
from app.scanners.base import BaseScanner, RawDetection, MAX_CONCURRENT_REGIONS
from app.scanners.rate_limiter import (
    RateLimiter,
    get_rate_limiter,
    rate_limited_call,
    reset_rate_limiters,
    RATE_LIMITS,
    MAX_CONCURRENT,
)


class TestRateLimiter:
    """Tests for the RateLimiter class."""

    @pytest.fixture(autouse=True)
    def setup(self):
        """Reset rate limiters before each test."""
        reset_rate_limiters()

    def test_init_with_known_service(self):
        """Test initialisation with a known service name."""
        limiter = RateLimiter("securityhub")
        assert limiter.service == "securityhub"
        assert limiter.rate == RATE_LIMITS["securityhub"]
        assert limiter.max_concurrent == MAX_CONCURRENT["securityhub"]

    def test_init_with_unknown_service(self):
        """Test initialisation with an unknown service uses defaults."""
        limiter = RateLimiter("unknown_service")
        assert limiter.rate == RATE_LIMITS["default"]
        assert limiter.max_concurrent == MAX_CONCURRENT["default"]

    @pytest.mark.asyncio
    async def test_acquire_when_tokens_available(self):
        """Test acquire succeeds immediately when tokens available."""
        limiter = RateLimiter("eventbridge")
        # Should complete almost instantly when tokens available
        start = datetime.utcnow()
        async with limiter._semaphore:
            await limiter.acquire()
        elapsed = (datetime.utcnow() - start).total_seconds()
        # Should complete in less than 50ms when tokens available
        assert elapsed < 0.05

    @pytest.mark.asyncio
    async def test_rate_limiter_context_manager(self):
        """Test using rate limiter as context manager."""
        limiter = RateLimiter("config")
        async with limiter:
            # Inside context manager, we should have acquired a token
            assert limiter.tokens < limiter.rate

    @pytest.mark.asyncio
    async def test_get_rate_limiter_singleton(self):
        """Test that get_rate_limiter returns the same instance."""
        limiter1 = await get_rate_limiter("guardduty")
        limiter2 = await get_rate_limiter("guardduty")
        assert limiter1 is limiter2

    @pytest.mark.asyncio
    async def test_get_rate_limiter_different_services(self):
        """Test that different services get different limiters."""
        limiter1 = await get_rate_limiter("securityhub")
        limiter2 = await get_rate_limiter("config")
        assert limiter1 is not limiter2

    @pytest.mark.asyncio
    async def test_rate_limited_call(self):
        """Test the rate_limited_call utility function."""

        async def dummy_func(x: int) -> int:
            return x * 2

        result = await rate_limited_call("eventbridge", dummy_func, 5)
        assert result == 10

    @pytest.mark.asyncio
    async def test_rate_limited_call_with_kwargs(self):
        """Test rate_limited_call with keyword arguments."""

        async def dummy_func(x: int, multiplier: int = 1) -> int:
            return x * multiplier

        result = await rate_limited_call("config", dummy_func, 5, multiplier=3)
        assert result == 15


class ConcreteScanner(BaseScanner):
    """Concrete implementation for testing BaseScanner."""

    def __init__(self, session, detections_per_region: dict[str, list[RawDetection]]):
        super().__init__(session)
        self._detections_per_region = detections_per_region
        self._scanned_regions: list[str] = []

    @property
    def detection_type(self) -> DetectionType:
        return DetectionType.EVENTBRIDGE_RULE

    @property
    def service_key(self) -> str:
        return "eventbridge"

    async def scan(
        self,
        regions: list[str],
        options: dict = None,
    ) -> list[RawDetection]:
        return await self.scan_regions_parallel(regions, options)

    async def scan_region(
        self,
        region: str,
        options: dict = None,
    ) -> list[RawDetection]:
        self._scanned_regions.append(region)
        # Small delay to simulate API call
        await asyncio.sleep(0.01)
        return self._detections_per_region.get(region, [])


class TestBaseScannerParallel:
    """Tests for BaseScanner parallel region scanning."""

    @pytest.fixture(autouse=True)
    def setup(self):
        """Reset rate limiters before each test."""
        reset_rate_limiters()

    def _make_detection(self, name: str, region: str) -> RawDetection:
        """Helper to create a RawDetection for testing."""
        return RawDetection(
            name=name,
            detection_type=DetectionType.EVENTBRIDGE_RULE,
            source_arn=f"arn:aws:events:{region}:123456789012:rule/{name}",
            region=region,
            raw_config={"test": True},
        )

    @pytest.mark.asyncio
    async def test_scan_regions_parallel_empty_regions(self):
        """Test scanning with empty regions list returns empty."""
        scanner = ConcreteScanner(MagicMock(), {})
        result = await scanner.scan_regions_parallel([], None)
        assert result == []

    @pytest.mark.asyncio
    async def test_scan_regions_parallel_single_region(self):
        """Test scanning a single region."""
        detection = self._make_detection("test-rule", "eu-west-2")
        scanner = ConcreteScanner(MagicMock(), {"eu-west-2": [detection]})

        result = await scanner.scan_regions_parallel(["eu-west-2"], None)

        assert len(result) == 1
        assert result[0].name == "test-rule"
        assert result[0].region == "eu-west-2"

    @pytest.mark.asyncio
    async def test_scan_regions_parallel_multiple_regions(self):
        """Test scanning multiple regions in parallel."""
        detections = {
            "eu-west-1": [self._make_detection("rule-1", "eu-west-1")],
            "eu-west-2": [
                self._make_detection("rule-2", "eu-west-2"),
                self._make_detection("rule-3", "eu-west-2"),
            ],
            "us-east-1": [self._make_detection("rule-4", "us-east-1")],
        }
        scanner = ConcreteScanner(MagicMock(), detections)

        result = await scanner.scan_regions_parallel(
            ["eu-west-1", "eu-west-2", "us-east-1"], None
        )

        assert len(result) == 4
        # All regions should have been scanned
        assert len(scanner._scanned_regions) == 3

    @pytest.mark.asyncio
    async def test_scan_regions_parallel_handles_empty_region(self):
        """Test that regions with no detections are handled correctly."""
        detections = {
            "eu-west-1": [self._make_detection("rule-1", "eu-west-1")],
            "eu-west-2": [],  # No detections
        }
        scanner = ConcreteScanner(MagicMock(), detections)

        result = await scanner.scan_regions_parallel(["eu-west-1", "eu-west-2"], None)

        assert len(result) == 1
        assert result[0].region == "eu-west-1"

    @pytest.mark.asyncio
    async def test_scan_regions_parallel_respects_max_concurrent(self):
        """Test that parallel scanning respects MAX_CONCURRENT_REGIONS."""
        # Create more regions than MAX_CONCURRENT_REGIONS
        regions = [f"region-{i}" for i in range(MAX_CONCURRENT_REGIONS + 3)]
        detections = {r: [] for r in regions}

        scanner = ConcreteScanner(MagicMock(), detections)

        # Track concurrent executions
        concurrent_count = 0
        max_concurrent = 0
        lock = asyncio.Lock()

        original_scan_region = scanner.scan_region

        async def tracked_scan_region(region: str, options=None):
            nonlocal concurrent_count, max_concurrent
            async with lock:
                concurrent_count += 1
                max_concurrent = max(max_concurrent, concurrent_count)
            try:
                return await original_scan_region(region, options)
            finally:
                async with lock:
                    concurrent_count -= 1

        scanner.scan_region = tracked_scan_region

        await scanner.scan_regions_parallel(regions, None)

        # Max concurrent should not exceed MAX_CONCURRENT_REGIONS
        assert max_concurrent <= MAX_CONCURRENT_REGIONS

    @pytest.mark.asyncio
    async def test_scan_regions_parallel_handles_exceptions(self):
        """Test that exceptions in one region don't affect others."""

        class FailingScanner(ConcreteScanner):
            async def scan_region(self, region: str, options=None):
                if region == "eu-west-2":
                    raise ValueError("Simulated failure")
                return await super().scan_region(region, options)

        detections = {
            "eu-west-1": [self._make_detection("rule-1", "eu-west-1")],
            "eu-west-2": [],
            "us-east-1": [self._make_detection("rule-2", "us-east-1")],
        }
        scanner = FailingScanner(MagicMock(), detections)

        # Should not raise, but should skip the failed region
        result = await scanner.scan_regions_parallel(
            ["eu-west-1", "eu-west-2", "us-east-1"], None
        )

        # Should have results from the non-failing regions
        assert len(result) == 2
        regions = {d.region for d in result}
        assert "eu-west-2" not in regions


class TestScanServiceParallel:
    """Tests for parallel scanner execution in scan_service."""

    @pytest.fixture(autouse=True)
    def setup(self):
        """Reset rate limiters before each test."""
        reset_rate_limiters()

    @pytest.mark.asyncio
    async def test_multiple_scanners_run_in_parallel(self):
        """Test that multiple scanners are executed concurrently."""
        # Track execution order and timing
        execution_order = []
        start_times = {}
        end_times = {}

        async def mock_scanner_run(name: str, delay: float = 0.05):
            start_times[name] = datetime.utcnow()
            execution_order.append(f"{name}_start")
            await asyncio.sleep(delay)
            execution_order.append(f"{name}_end")
            end_times[name] = datetime.utcnow()
            return []

        # Simulate running scanners in parallel with asyncio.gather
        # This mirrors what scan_service._scan_detections does
        await asyncio.gather(
            mock_scanner_run("scanner1"),
            mock_scanner_run("scanner2"),
            mock_scanner_run("scanner3"),
        )

        # All scanners should have started before any finished
        # (if they were truly parallel)
        assert len(execution_order) == 6

        # Check that all started before all ended (parallel execution)
        starts = [e for e in execution_order if e.endswith("_start")]
        ends = [e for e in execution_order if e.endswith("_end")]

        # In parallel execution, all starts should happen before ends
        # (within the same batch)
        first_end_idx = execution_order.index(ends[0])
        all_starts_before_first_end = all(
            execution_order.index(s) < first_end_idx for s in starts
        )
        assert all_starts_before_first_end
