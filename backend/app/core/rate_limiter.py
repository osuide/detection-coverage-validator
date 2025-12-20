"""Rate limiting for public API endpoints.

Implements tier-based rate limiting for API consumers.
"""

from datetime import datetime, timedelta
from typing import Optional
import hashlib

from fastapi import HTTPException, status


# Rate limits by tier (requests per hour)
RATE_LIMITS = {
    "free": 100,
    "individual": 1000,
    "pro": 10000,
    "enterprise": 100000,  # Effectively unlimited
}


class RateLimitExceeded(HTTPException):
    """Rate limit exceeded exception."""

    def __init__(self, limit: int, reset_at: datetime):
        super().__init__(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail={
                "error": "rate_limit_exceeded",
                "message": f"Rate limit of {limit} requests per hour exceeded",
                "limit": limit,
                "reset_at": reset_at.isoformat(),
            },
            headers={
                "X-RateLimit-Limit": str(limit),
                "X-RateLimit-Remaining": "0",
                "X-RateLimit-Reset": str(int(reset_at.timestamp())),
                "Retry-After": str(int((reset_at - datetime.utcnow()).total_seconds())),
            },
        )


class InMemoryRateLimiter:
    """Simple in-memory rate limiter.

    For production, use Redis-based rate limiting.
    """

    def __init__(self):
        self._requests: dict[str, list[datetime]] = {}

    def _get_key(self, api_key: str) -> str:
        """Hash the API key for privacy."""
        return hashlib.sha256(api_key.encode()).hexdigest()[:16]

    def _clean_old_requests(self, key: str, window: timedelta):
        """Remove requests outside the time window."""
        if key not in self._requests:
            return

        cutoff = datetime.utcnow() - window
        self._requests[key] = [ts for ts in self._requests[key] if ts > cutoff]

    def check_rate_limit(
        self,
        api_key: str,
        tier: str,
        window: timedelta = timedelta(hours=1),
    ) -> tuple[int, int, datetime]:
        """Check if request is within rate limit.

        Args:
            api_key: The API key making the request
            tier: Account tier for limit lookup
            window: Time window for rate limiting

        Returns:
            Tuple of (limit, remaining, reset_at)

        Raises:
            RateLimitExceeded: If rate limit is exceeded
        """
        limit = RATE_LIMITS.get(tier, RATE_LIMITS["free"])
        key = self._get_key(api_key)

        # Clean old requests
        self._clean_old_requests(key, window)

        # Get current count
        if key not in self._requests:
            self._requests[key] = []

        current_count = len(self._requests[key])

        # Calculate reset time
        if self._requests[key]:
            oldest = min(self._requests[key])
            reset_at = oldest + window
        else:
            reset_at = datetime.utcnow() + window

        # Check limit
        if current_count >= limit:
            raise RateLimitExceeded(limit, reset_at)

        # Record request
        self._requests[key].append(datetime.utcnow())
        remaining = limit - current_count - 1

        return limit, remaining, reset_at


# Global rate limiter instance
_rate_limiter: Optional[InMemoryRateLimiter] = None


def get_rate_limiter() -> InMemoryRateLimiter:
    """Get the global rate limiter instance."""
    global _rate_limiter
    if _rate_limiter is None:
        _rate_limiter = InMemoryRateLimiter()
    return _rate_limiter


async def check_api_rate_limit(
    api_key: str,
    tier: str,
) -> dict:
    """Check rate limit and return headers.

    Args:
        api_key: The API key
        tier: Account tier

    Returns:
        Dict with rate limit info for response headers

    Raises:
        RateLimitExceeded: If limit exceeded
    """
    limiter = get_rate_limiter()
    limit, remaining, reset_at = limiter.check_rate_limit(api_key, tier)

    return {
        "X-RateLimit-Limit": str(limit),
        "X-RateLimit-Remaining": str(remaining),
        "X-RateLimit-Reset": str(int(reset_at.timestamp())),
    }
