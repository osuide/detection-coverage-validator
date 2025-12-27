"""In-memory metrics collection for admin dashboard.

Provides rolling window metrics for API latency, error rates, and cache performance.
Uses thread-safe collections for concurrent access.

Note: These metrics are ephemeral and reset on application restart.
For persistent metrics with historical trends, see CloudWatch EMF (backlog item).
"""

import time
from collections import deque
from dataclasses import dataclass, field
from threading import Lock
from typing import Optional

# Rolling window size (last N requests)
WINDOW_SIZE = 1000

# Time window for error rate calculation (seconds)
ERROR_WINDOW_SECONDS = 300  # 5 minutes


@dataclass
class RequestMetric:
    """Single request metric."""

    timestamp: float
    duration_ms: float
    status_code: int
    path: str


@dataclass
class CacheMetric:
    """Cache hit/miss tracking."""

    hits: int = 0
    misses: int = 0
    _lock: Lock = field(default_factory=Lock, repr=False)

    def record_hit(self) -> None:
        with self._lock:
            self.hits += 1

    def record_miss(self) -> None:
        with self._lock:
            self.misses += 1

    def hit_rate(self) -> float:
        with self._lock:
            total = self.hits + self.misses
            if total == 0:
                return 0.0
            return self.hits / total


class MetricsCollector:
    """Thread-safe in-memory metrics collector.

    Maintains rolling windows of request metrics for real-time dashboard display.
    """

    def __init__(self, window_size: int = WINDOW_SIZE):
        self._requests: deque[RequestMetric] = deque(maxlen=window_size)
        self._lock = Lock()
        self._cache_metrics = CacheMetric()

    def record_request(self, duration_ms: float, status_code: int, path: str) -> None:
        """Record a completed request.

        Args:
            duration_ms: Request duration in milliseconds
            status_code: HTTP status code
            path: Request path (for filtering)
        """
        metric = RequestMetric(
            timestamp=time.time(),
            duration_ms=duration_ms,
            status_code=status_code,
            path=path,
        )
        with self._lock:
            self._requests.append(metric)

    def record_cache_hit(self) -> None:
        """Record a cache hit."""
        self._cache_metrics.record_hit()

    def record_cache_miss(self) -> None:
        """Record a cache miss."""
        self._cache_metrics.record_miss()

    def get_latency_stats(self) -> dict:
        """Calculate latency statistics from recent requests.

        Returns:
            Dict with avg, p50, p95, p99 latency in milliseconds
        """
        with self._lock:
            if not self._requests:
                return {
                    "avg_ms": 0.0,
                    "p50_ms": 0.0,
                    "p95_ms": 0.0,
                    "p99_ms": 0.0,
                    "sample_size": 0,
                }

            durations = sorted([r.duration_ms for r in self._requests])
            n = len(durations)

            return {
                "avg_ms": round(sum(durations) / n, 2),
                "p50_ms": round(durations[n // 2], 2),
                "p95_ms": (
                    round(durations[int(n * 0.95)], 2)
                    if n >= 20
                    else round(durations[-1], 2)
                ),
                "p99_ms": (
                    round(durations[int(n * 0.99)], 2)
                    if n >= 100
                    else round(durations[-1], 2)
                ),
                "sample_size": n,
            }

    def get_error_rate(self, window_seconds: int = ERROR_WINDOW_SECONDS) -> float:
        """Calculate error rate over recent time window.

        Args:
            window_seconds: Time window to consider (default 5 minutes)

        Returns:
            Error rate as percentage (0-100)
        """
        cutoff = time.time() - window_seconds

        with self._lock:
            recent = [r for r in self._requests if r.timestamp >= cutoff]

            if not recent:
                return 0.0

            errors = sum(1 for r in recent if r.status_code >= 500)
            return round((errors / len(recent)) * 100, 2)

    def get_cache_hit_rate(self) -> float:
        """Get cache hit rate as percentage.

        Returns:
            Hit rate as percentage (0-100)
        """
        return round(self._cache_metrics.hit_rate() * 100, 2)

    def get_request_count(self, window_seconds: int = 60) -> int:
        """Get request count over recent time window.

        Args:
            window_seconds: Time window to consider (default 1 minute)

        Returns:
            Number of requests in window
        """
        cutoff = time.time() - window_seconds

        with self._lock:
            return sum(1 for r in self._requests if r.timestamp >= cutoff)

    def get_all_stats(self) -> dict:
        """Get all metrics for dashboard display.

        Returns:
            Dict with all current metrics
        """
        latency = self.get_latency_stats()
        return {
            "latency": latency,
            "error_rate_percent": self.get_error_rate(),
            "cache_hit_rate_percent": self.get_cache_hit_rate(),
            "requests_per_minute": self.get_request_count(60),
            "sample_size": latency["sample_size"],
        }


# Global metrics collector instance
_metrics_collector: Optional[MetricsCollector] = None


def get_metrics_collector() -> MetricsCollector:
    """Get or create the global metrics collector."""
    global _metrics_collector
    if _metrics_collector is None:
        _metrics_collector = MetricsCollector()
    return _metrics_collector


def record_request(duration_ms: float, status_code: int, path: str) -> None:
    """Convenience function to record a request metric."""
    get_metrics_collector().record_request(duration_ms, status_code, path)


def record_cache_hit() -> None:
    """Convenience function to record a cache hit."""
    get_metrics_collector().record_cache_hit()


def record_cache_miss() -> None:
    """Convenience function to record a cache miss."""
    get_metrics_collector().record_cache_miss()
