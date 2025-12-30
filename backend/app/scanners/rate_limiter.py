"""Rate limiting for AWS API calls.

Prevents AWS API throttling when running parallel requests across
multiple scanners and regions.

AWS rate limits vary by service:
- Security Hub: ~10 TPS
- Config: ~20 TPS
- GuardDuty: ~10 TPS
- EventBridge: ~50 TPS
- CloudWatch: ~50 TPS

This module implements a token bucket rate limiter per service.
"""

import asyncio
from datetime import datetime
from typing import Any, Callable, TypeVar

import structlog

logger = structlog.get_logger()

T = TypeVar("T")

# AWS service rate limits (requests per second) - conservative estimates
# These are per-account limits, not per-region
RATE_LIMITS: dict[str, int] = {
    "securityhub": 10,
    "config": 20,
    "guardduty": 10,
    "eventbridge": 50,
    "cloudwatch": 50,
    "logs": 50,
    "default": 10,
}

# Maximum concurrent requests per service (to prevent overwhelming AWS)
MAX_CONCURRENT: dict[str, int] = {
    "securityhub": 5,
    "config": 10,
    "guardduty": 5,
    "eventbridge": 10,
    "cloudwatch": 10,
    "logs": 10,
    "default": 5,
}


class RateLimiter:
    """Token bucket rate limiter for AWS API calls.

    Uses a simple token bucket algorithm with semaphore for concurrency control.
    Thread-safe for use with asyncio.
    """

    def __init__(self, service: str):
        """Initialise rate limiter for a specific AWS service.

        Args:
            service: AWS service name (e.g., 'securityhub', 'config')
        """
        self.service = service
        self.rate = RATE_LIMITS.get(service, RATE_LIMITS["default"])
        self.max_concurrent = MAX_CONCURRENT.get(service, MAX_CONCURRENT["default"])
        self.tokens = float(self.rate)
        self.last_update = datetime.utcnow()
        self._lock = asyncio.Lock()
        self._semaphore = asyncio.Semaphore(self.max_concurrent)
        self.logger = logger.bind(service=service, rate_limit=self.rate)

    async def acquire(self) -> None:
        """Wait until a token is available.

        This method blocks until both:
        1. A token is available (rate limiting)
        2. A semaphore slot is available (concurrency limiting)
        """
        async with self._semaphore:
            async with self._lock:
                now = datetime.utcnow()
                elapsed = (now - self.last_update).total_seconds()

                # Replenish tokens based on time elapsed
                self.tokens = min(
                    float(self.rate),
                    self.tokens + elapsed * self.rate,
                )
                self.last_update = now

                if self.tokens < 1.0:
                    # Wait for token to become available
                    wait_time = (1.0 - self.tokens) / self.rate
                    self.logger.debug(
                        "rate_limit_wait",
                        wait_seconds=round(wait_time, 3),
                    )
                    await asyncio.sleep(wait_time)
                    self.tokens = 1.0

                self.tokens -= 1.0

    async def __aenter__(self) -> "RateLimiter":
        """Context manager entry - acquire a token."""
        await self.acquire()
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Context manager exit - nothing to release."""
        pass


# Global rate limiters per service (singleton pattern)
_limiters: dict[str, RateLimiter] = {}
_limiters_lock = asyncio.Lock()


async def get_rate_limiter(service: str) -> RateLimiter:
    """Get or create a rate limiter for a service.

    Args:
        service: AWS service name

    Returns:
        RateLimiter instance for the service
    """
    # Fast path without lock
    if service in _limiters:
        return _limiters[service]

    # Slow path with lock for creation
    async with _limiters_lock:
        if service not in _limiters:
            _limiters[service] = RateLimiter(service)
        return _limiters[service]


async def rate_limited_call(
    service: str,
    func: Callable[..., T],
    *args: Any,
    **kwargs: Any,
) -> T:
    """Execute a function with rate limiting.

    Args:
        service: AWS service name for rate limiting
        func: Async function to call
        *args: Positional arguments for func
        **kwargs: Keyword arguments for func

    Returns:
        Result from func
    """
    limiter = await get_rate_limiter(service)
    async with limiter:
        return await func(*args, **kwargs)


def reset_rate_limiters() -> None:
    """Reset all rate limiters. Useful for testing."""
    global _limiters
    _limiters = {}
