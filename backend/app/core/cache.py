"""Redis-backed caching for static reference data.

Provides caching for data that rarely changes (compliance frameworks,
MITRE mappings) to reduce database load and improve response times.

Security Considerations:
- Only cache public/non-sensitive data (framework definitions, MITRE mappings)
- NEVER cache: credentials, PII, session tokens, API keys
- All cache keys use a fixed prefix (dcv:cache:) - no user input in keys
- TTL enforced on all entries to limit exposure window
- Redis connection uses TLS in production (rediss:// URL scheme)
- Redis is network-isolated in private subnets
"""

import json
import re
from typing import Any, Optional

import structlog
from redis import asyncio as aioredis

from app.core.config import get_settings

logger = structlog.get_logger()

# Redis connection for caching
_redis_cache: Optional[aioredis.Redis] = None

# Cache key prefixes
CACHE_PREFIX = "dcv:cache:"

# Default TTL in seconds (1 hour)
DEFAULT_TTL = 3600

# Maximum TTL (24 hours) - prevents indefinite caching
MAX_TTL = 86400

# Maximum cached value size (1MB) - prevents memory exhaustion
MAX_VALUE_SIZE = 1024 * 1024

# Valid cache key pattern (alphanumeric, hyphens, underscores, colons, dots)
# Prevents injection attacks via malicious key names
VALID_KEY_PATTERN = re.compile(r"^[a-zA-Z0-9_\-:.]+$")


async def init_cache() -> None:
    """Initialise Redis cache connection.

    Should be called during application startup.
    """
    global _redis_cache

    settings = get_settings()

    try:
        _redis_cache = await aioredis.from_url(
            settings.redis_url,
            encoding="utf-8",
            decode_responses=True,
        )
        # Test connection
        await _redis_cache.ping()
        logger.info(
            "cache_initialised",
            redis_url=settings.redis_url.split("@")[-1],
        )
    except Exception as e:
        logger.warning(
            "cache_init_failed",
            error=str(e),
            message="Cache disabled - falling back to no caching",
        )
        _redis_cache = None


async def close_cache() -> None:
    """Close Redis cache connection.

    Should be called during application shutdown.
    """
    global _redis_cache

    if _redis_cache:
        try:
            await _redis_cache.close()
            logger.info("cache_closed")
        except Exception as e:
            logger.warning("cache_close_failed", error=str(e))
        finally:
            _redis_cache = None


async def get_cached(key: str) -> Optional[Any]:
    """Get value from cache.

    Args:
        key: Cache key (prefix will be added automatically)

    Returns:
        Cached value or None if not found/cache unavailable
    """
    if not _redis_cache:
        return None

    try:
        full_key = f"{CACHE_PREFIX}{key}"
        value = await _redis_cache.get(full_key)
        if value:
            return json.loads(value)
        return None
    except Exception as e:
        logger.warning("cache_get_failed", key=key, error=str(e))
        return None


def _validate_key(key: str) -> bool:
    """Validate cache key to prevent injection attacks.

    Args:
        key: Cache key to validate

    Returns:
        True if key is valid, False otherwise
    """
    if not key or len(key) > 256:
        return False
    return bool(VALID_KEY_PATTERN.match(key))


def _sanitize_identifier(identifier: str) -> str:
    """Sanitize an identifier for use in cache keys.

    Removes any characters that aren't alphanumeric, hyphens, or underscores.

    Args:
        identifier: Raw identifier (e.g., framework_id)

    Returns:
        Sanitized identifier safe for cache keys
    """
    # Replace spaces with hyphens, remove other special chars
    sanitized = re.sub(r"[^a-zA-Z0-9_\-]", "", identifier.replace(" ", "-"))
    # Truncate to reasonable length
    return sanitized[:64]


async def set_cached(key: str, value: Any, ttl: int = DEFAULT_TTL) -> bool:
    """Set value in cache.

    Args:
        key: Cache key (prefix will be added automatically)
        value: Value to cache (must be JSON serializable)
        ttl: Time to live in seconds (default 1 hour, max 24 hours)

    Returns:
        True if cached successfully, False otherwise

    Security:
        - Validates key format to prevent injection
        - Enforces max TTL to prevent indefinite caching
        - Enforces max value size to prevent memory exhaustion
    """
    if not _redis_cache:
        return False

    # Security: Validate key format
    if not _validate_key(key):
        logger.warning("cache_invalid_key", key=key[:50])
        return False

    # Security: Enforce TTL limits
    ttl = min(max(1, ttl), MAX_TTL)

    try:
        full_key = f"{CACHE_PREFIX}{key}"
        serialized = json.dumps(value)

        # Security: Enforce value size limit
        if len(serialized) > MAX_VALUE_SIZE:
            logger.warning(
                "cache_value_too_large",
                key=key,
                size=len(serialized),
                max_size=MAX_VALUE_SIZE,
            )
            return False

        await _redis_cache.setex(full_key, ttl, serialized)
        return True
    except Exception as e:
        logger.warning("cache_set_failed", key=key, error=str(e))
        return False


async def delete_cached(key: str) -> bool:
    """Delete value from cache.

    Args:
        key: Cache key (prefix will be added automatically)

    Returns:
        True if deleted successfully, False otherwise
    """
    if not _redis_cache:
        return False

    try:
        full_key = f"{CACHE_PREFIX}{key}"
        await _redis_cache.delete(full_key)
        return True
    except Exception as e:
        logger.warning("cache_delete_failed", key=key, error=str(e))
        return False


async def clear_cache_pattern(pattern: str) -> int:
    """Clear all cache keys matching a pattern.

    Args:
        pattern: Pattern to match (e.g., "frameworks:*")

    Returns:
        Number of keys deleted
    """
    if not _redis_cache:
        return 0

    try:
        full_pattern = f"{CACHE_PREFIX}{pattern}"
        keys = []
        async for key in _redis_cache.scan_iter(match=full_pattern):
            keys.append(key)
        if keys:
            return await _redis_cache.delete(*keys)
        return 0
    except Exception as e:
        logger.warning("cache_clear_failed", pattern=pattern, error=str(e))
        return 0


# Cache key generators for common data
# All generators use sanitization to prevent injection attacks
def frameworks_key() -> str:
    """Cache key for all active frameworks."""
    return "frameworks:active"


def framework_key(framework_id: str) -> str:
    """Cache key for a specific framework.

    Args:
        framework_id: Framework identifier (will be sanitized)
    """
    return f"frameworks:{_sanitize_identifier(framework_id)}"


def framework_controls_key(framework_id: str) -> str:
    """Cache key for framework controls.

    Args:
        framework_id: Framework identifier (will be sanitized)
    """
    return f"controls:{_sanitize_identifier(framework_id)}"


def mitre_techniques_key() -> str:
    """Cache key for MITRE techniques."""
    return "mitre:techniques"


def mitre_tactics_key() -> str:
    """Cache key for MITRE tactics."""
    return "mitre:tactics"
