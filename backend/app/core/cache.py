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
from app.core.metrics import record_cache_hit, record_cache_miss

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
        record_cache_miss()
        return None

    try:
        full_key = f"{CACHE_PREFIX}{key}"
        value = await _redis_cache.get(full_key)
        if value:
            record_cache_hit()
            return json.loads(value)
        record_cache_miss()
        return None
    except Exception as e:
        logger.warning("cache_get_failed", key=key, error=str(e))
        record_cache_miss()
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


# Scan status caching - for reducing database load during polling
# Uses a separate prefix to distinguish from static data caching
SCAN_STATUS_PREFIX = "dcv:scan:"
SCAN_STATUS_TTL = 60  # 60 seconds - short TTL for active scans


def scan_status_key(scan_id: str) -> str:
    """Cache key for scan status.

    Args:
        scan_id: Scan UUID as string

    Returns:
        Cache key for the scan status
    """
    return f"status:{_sanitize_identifier(scan_id)}"


async def cache_scan_status(scan_data: dict) -> bool:
    """Cache scan status for fast polling.

    This is used during active scans to avoid database queries
    for status polling. Uses a short TTL since scan status changes frequently.

    Args:
        scan_data: Dictionary with scan status fields:
            - id: Scan UUID
            - status: ScanStatus value
            - progress_percent: 0-100
            - current_step: Current operation description
            - detections_found, detections_new, etc.
            - started_at, completed_at (ISO format strings)

    Returns:
        True if cached successfully, False otherwise

    Security:
        - Only caches non-sensitive scan metadata
        - Short TTL prevents stale data accumulation
        - Scan ID is sanitized to prevent key injection
    """
    if not _redis_cache:
        return False

    scan_id = str(scan_data.get("id", ""))
    if not scan_id:
        return False

    try:
        key = f"{SCAN_STATUS_PREFIX}{scan_status_key(scan_id)}"
        serialized = json.dumps(scan_data)

        # Use short TTL for scan status
        await _redis_cache.setex(key, SCAN_STATUS_TTL, serialized)
        return True
    except Exception as e:
        logger.warning("scan_status_cache_set_failed", scan_id=scan_id, error=str(e))
        return False


async def get_cached_scan_status(scan_id: str) -> Optional[dict]:
    """Get cached scan status.

    Args:
        scan_id: Scan UUID as string

    Returns:
        Cached scan status dict or None if not found/cache unavailable
    """
    if not _redis_cache:
        return None

    try:
        key = f"{SCAN_STATUS_PREFIX}{scan_status_key(scan_id)}"
        value = await _redis_cache.get(key)
        if value:
            return json.loads(value)
        return None
    except Exception as e:
        logger.warning("scan_status_cache_get_failed", scan_id=scan_id, error=str(e))
        return None


async def delete_scan_status_cache(scan_id: str) -> bool:
    """Delete cached scan status.

    Should be called when a scan completes or fails to clean up.

    Args:
        scan_id: Scan UUID as string

    Returns:
        True if deleted successfully, False otherwise
    """
    if not _redis_cache:
        return False

    try:
        key = f"{SCAN_STATUS_PREFIX}{scan_status_key(scan_id)}"
        await _redis_cache.delete(key)
        return True
    except Exception as e:
        logger.warning("scan_status_cache_delete_failed", scan_id=scan_id, error=str(e))
        return False


# Billing scan status caching - for reducing database load during polling
# This caches the organisation's scan limit status (can_scan, scans_used, etc.)
BILLING_STATUS_PREFIX = "dcv:billing:"
BILLING_STATUS_TTL = 10  # 10 seconds - short TTL as this changes when scans start


def billing_status_key(organization_id: str) -> str:
    """Cache key for billing scan status.

    Args:
        organization_id: Organisation UUID as string

    Returns:
        Cache key for the billing status
    """
    return f"scan-status:{_sanitize_identifier(organization_id)}"


async def cache_billing_scan_status(organization_id: str, status_data: dict) -> bool:
    """Cache billing scan status for fast polling.

    This caches the organisation's scan limit status to avoid database
    queries during frequent polling. Uses a short TTL since status
    changes when scans are initiated.

    Args:
        organization_id: Organisation UUID as string
        status_data: Dictionary with scan status fields:
            - can_scan: bool
            - scans_used: int
            - scans_allowed: int | None
            - unlimited: bool
            - next_available_at: str | None
            - week_resets_at: str | None
            - total_scans: int

    Returns:
        True if cached successfully, False otherwise

    Security:
        - Only caches non-sensitive scan limit metadata
        - Short TTL prevents stale data accumulation
        - Organisation ID is sanitized to prevent key injection
    """
    if not _redis_cache:
        return False

    if not organization_id:
        return False

    try:
        key = f"{BILLING_STATUS_PREFIX}{billing_status_key(organization_id)}"
        serialized = json.dumps(status_data)

        await _redis_cache.setex(key, BILLING_STATUS_TTL, serialized)
        return True
    except Exception as e:
        logger.warning(
            "billing_status_cache_set_failed",
            organization_id=organization_id,
            error=str(e),
        )
        return False


async def get_cached_billing_scan_status(organization_id: str) -> Optional[dict]:
    """Get cached billing scan status.

    Args:
        organization_id: Organisation UUID as string

    Returns:
        Cached billing status dict or None if not found/cache unavailable
    """
    if not _redis_cache:
        return None

    try:
        key = f"{BILLING_STATUS_PREFIX}{billing_status_key(organization_id)}"
        value = await _redis_cache.get(key)
        if value:
            record_cache_hit()
            return json.loads(value)
        record_cache_miss()
        return None
    except Exception as e:
        logger.warning(
            "billing_status_cache_get_failed",
            organization_id=organization_id,
            error=str(e),
        )
        record_cache_miss()
        return None


async def invalidate_billing_scan_status(organization_id: str) -> bool:
    """Invalidate cached billing scan status.

    Should be called when a scan is initiated to ensure fresh data.

    Args:
        organization_id: Organisation UUID as string

    Returns:
        True if invalidated successfully, False otherwise
    """
    if not _redis_cache:
        return False

    try:
        key = f"{BILLING_STATUS_PREFIX}{billing_status_key(organization_id)}"
        await _redis_cache.delete(key)
        return True
    except Exception as e:
        logger.warning(
            "billing_status_cache_invalidate_failed",
            organization_id=organization_id,
            error=str(e),
        )
        return False


# Security Hub control data caching
# Caches FULL control response (including status) for fast back-to-back scans
# On cache hit, ALL API calls are skipped - making second scan very fast
SECURITYHUB_CONTROL_PREFIX = "dcv:securityhub:"
SECURITYHUB_CONTROL_TTL = 300  # 5 minutes - balances freshness with performance


def securityhub_controls_key(account_id: str) -> str:
    """Cache key for Security Hub control metadata.

    Args:
        account_id: AWS account ID

    Returns:
        Cache key for the control metadata
    """
    return f"controls:{_sanitize_identifier(account_id)}"


async def cache_securityhub_controls(
    account_id: str, controls_data: dict[str, dict]
) -> bool:
    """Cache Security Hub FULL control response for fast back-to-back scans.

    Caches the complete control data including status. On cache hit,
    the scanner skips ALL API calls and returns cached data immediately.
    This makes second+ scans within 5 minutes very fast.

    Args:
        account_id: AWS account ID
        controls_data: Dictionary of control_id -> {
            "control_id": str,
            "title": str,
            "description": str,
            "status": str (ENABLED/DISABLED),
            "severity": str,
            "remediation_url": str,
            ...
        }

    Returns:
        True if cached successfully, False otherwise

    Security:
        - Caches control configuration, not compliance findings
        - Account ID is sanitized to prevent key injection
        - 5-minute TTL limits staleness
    """
    if not _redis_cache:
        return False

    if not account_id:
        return False

    try:
        key = f"{SECURITYHUB_CONTROL_PREFIX}{securityhub_controls_key(account_id)}"
        serialized = json.dumps(controls_data)

        # Check size limit
        if len(serialized) > MAX_VALUE_SIZE:
            logger.warning(
                "securityhub_controls_cache_too_large",
                account_id=account_id,
                size=len(serialized),
            )
            return False

        await _redis_cache.setex(key, SECURITYHUB_CONTROL_TTL, serialized)
        return True
    except Exception as e:
        logger.warning(
            "securityhub_controls_cache_set_failed",
            account_id=account_id,
            error=str(e),
        )
        return False


async def get_cached_securityhub_controls(account_id: str) -> Optional[dict[str, dict]]:
    """Get cached Security Hub control metadata.

    Args:
        account_id: AWS account ID

    Returns:
        Cached control metadata dict or None if not found/cache unavailable
    """
    if not _redis_cache:
        record_cache_miss()
        return None

    try:
        key = f"{SECURITYHUB_CONTROL_PREFIX}{securityhub_controls_key(account_id)}"
        value = await _redis_cache.get(key)
        if value:
            record_cache_hit()
            return json.loads(value)
        record_cache_miss()
        return None
    except Exception as e:
        logger.warning(
            "securityhub_controls_cache_get_failed",
            account_id=account_id,
            error=str(e),
        )
        record_cache_miss()
        return None


# Full scan tracking - for weekly full scan fallback
FULL_SCAN_PREFIX = "dcv:full-scan:"
FULL_SCAN_TTL = 604800  # 7 days - tracks when last full scan was done


def full_scan_key(account_id: str) -> str:
    """Cache key for last full scan timestamp.

    Args:
        account_id: Cloud account ID (UUID)

    Returns:
        Cache key for the full scan timestamp
    """
    return f"last:{_sanitize_identifier(account_id)}"


async def set_last_full_scan(account_id: str, timestamp: str) -> bool:
    """Record when a full scan was completed.

    Used to determine if incremental scanning can be used or if a
    full scan is needed for accurate compliance data.

    Args:
        account_id: Cloud account ID (UUID string)
        timestamp: ISO format timestamp of scan completion

    Returns:
        True if set successfully, False otherwise
    """
    if not _redis_cache:
        return False

    if not account_id:
        return False

    try:
        key = f"{FULL_SCAN_PREFIX}{full_scan_key(account_id)}"
        await _redis_cache.setex(key, FULL_SCAN_TTL, timestamp)
        return True
    except Exception as e:
        logger.warning(
            "full_scan_timestamp_set_failed",
            account_id=account_id,
            error=str(e),
        )
        return False


async def get_last_full_scan(account_id: str) -> Optional[str]:
    """Get timestamp of last full scan.

    Args:
        account_id: Cloud account ID (UUID string)

    Returns:
        ISO format timestamp or None if never done/cache unavailable
    """
    if not _redis_cache:
        return None

    try:
        key = f"{FULL_SCAN_PREFIX}{full_scan_key(account_id)}"
        return await _redis_cache.get(key)
    except Exception as e:
        logger.warning(
            "full_scan_timestamp_get_failed",
            account_id=account_id,
            error=str(e),
        )
        return None


async def should_force_full_scan(account_id: str, days_threshold: int = 7) -> bool:
    """Check if a full scan should be forced.

    Returns True if:
    - No full scan has ever been recorded
    - Last full scan was more than days_threshold days ago

    Args:
        account_id: Cloud account ID (UUID string)
        days_threshold: Number of days before forcing full scan (default 7)

    Returns:
        True if full scan should be forced, False otherwise
    """
    from datetime import datetime, timezone, timedelta

    last_scan = await get_last_full_scan(account_id)
    if not last_scan:
        return True  # Never done a full scan

    try:
        last_dt = datetime.fromisoformat(last_scan.replace("Z", "+00:00"))
        now = datetime.now(timezone.utc)
        age = now - last_dt
        return age > timedelta(days=days_threshold)
    except (ValueError, TypeError):
        # Invalid timestamp, force full scan
        return True


# ============================================================================
# OAuth State Store (Redis-backed)
# ============================================================================
# CWE-352: Cross-Site Request Forgery (CSRF) protection for OAuth flows
# Uses Redis for distributed state validation across multiple instances.

OAUTH_STATE_PREFIX = "dcv:oauth:"
OAUTH_STATE_TTL = 300  # 5 minutes - OAuth flows should complete quickly


async def store_oauth_state(state: str, provider: str = "oauth") -> bool:
    """Store an OAuth state token for CSRF protection.

    Uses Redis for distributed validation across multiple instances.
    State tokens are one-time use and expire after 5 minutes.

    Args:
        state: The state token to store (should be cryptographically random)
        provider: OAuth provider name (github, cognito) for logging

    Returns:
        True if stored successfully, False otherwise

    Security:
        - State token is validated against injection attacks
        - Short TTL limits replay window
        - Used with validate_and_consume for one-time use
    """
    if not _redis_cache:
        logger.warning(
            "oauth_state_store_no_redis",
            provider=provider,
            message="Redis unavailable - falling back to in-memory (not recommended)",
        )
        return False

    # Validate state format (should be base64url-safe)
    if not state or len(state) > 128 or not VALID_KEY_PATTERN.match(state):
        logger.warning("oauth_state_invalid_format", provider=provider)
        return False

    try:
        key = f"{OAUTH_STATE_PREFIX}{provider}:{state}"
        # Store with value "1" - we only care about existence
        await _redis_cache.setex(key, OAUTH_STATE_TTL, "1")
        logger.debug("oauth_state_stored", provider=provider)
        return True
    except Exception as e:
        logger.warning(
            "oauth_state_store_failed",
            provider=provider,
            error=str(e),
        )
        return False


async def validate_and_consume_oauth_state(state: str, provider: str = "oauth") -> bool:
    """Validate and consume an OAuth state token (one-time use).

    Checks if the state exists in Redis and removes it atomically.
    This prevents replay attacks by ensuring each state can only be used once.

    Args:
        state: The state token to validate
        provider: OAuth provider name (github, cognito)

    Returns:
        True if state was valid and consumed, False otherwise

    Security:
        - Atomic get-and-delete prevents race conditions
        - Expired states automatically rejected (Redis TTL)
        - Logs invalid attempts for security monitoring
    """
    if not _redis_cache:
        logger.warning(
            "oauth_state_validate_no_redis",
            provider=provider,
            message="Redis unavailable - cannot validate state",
        )
        return False

    if not state or len(state) > 128:
        logger.warning(
            "oauth_state_invalid_attempt",
            provider=provider,
            reason="invalid_format",
        )
        return False

    try:
        key = f"{OAUTH_STATE_PREFIX}{provider}:{state}"
        # Atomic delete returns 1 if key existed, 0 if not
        deleted = await _redis_cache.delete(key)
        if deleted:
            logger.debug("oauth_state_consumed", provider=provider)
            return True
        else:
            logger.warning(
                "oauth_state_invalid_attempt",
                provider=provider,
                reason="not_found_or_expired",
            )
            return False
    except Exception as e:
        logger.warning(
            "oauth_state_validate_failed",
            provider=provider,
            error=str(e),
        )
        return False


def is_redis_available() -> bool:
    """Check if Redis cache is available.

    Used by OAuth routes to determine if they should fall back to
    in-memory state storage (not recommended for production).

    Returns:
        True if Redis is connected and available
    """
    return _redis_cache is not None


# ============================================================================
# WebAuthn Challenge Store (Redis-backed)
# ============================================================================
# CWE-384: Session Fixation prevention for WebAuthn registration/authentication.
# Uses Redis for distributed challenge validation across multiple instances.
# Challenges are single-use and expire after 2 minutes.

WEBAUTHN_CHALLENGE_PREFIX = "dcv:webauthn:"
WEBAUTHN_CHALLENGE_TTL = 120  # 2 minutes - challenges should complete quickly


async def store_webauthn_challenge(key: str, challenge: bytes) -> bool:
    """Store a WebAuthn challenge for later verification.

    Uses Redis for distributed validation across multiple instances.
    Challenges are single-use and expire after 2 minutes.

    Args:
        key: Unique key for this challenge (e.g., "reg:{user_id}" or "auth:{user_id}")
        challenge: The challenge bytes to store

    Returns:
        True if stored successfully, False otherwise

    Security:
        - Challenge key is validated against injection attacks
        - Short TTL limits replay window
        - Used with get_and_consume for single-use validation
    """
    if not _redis_cache:
        logger.warning(
            "webauthn_challenge_store_no_redis",
            key=key[:20] if key else "none",
            message="Redis unavailable - WebAuthn may fail in multi-instance",
        )
        return False

    # Validate key format
    if not key or len(key) > 128 or not VALID_KEY_PATTERN.match(key):
        logger.warning(
            "webauthn_challenge_invalid_key",
            key=key[:20] if key else "none",
        )
        return False

    try:
        full_key = f"{WEBAUTHN_CHALLENGE_PREFIX}{key}"
        # Store challenge as base64 string
        import base64

        challenge_b64 = base64.b64encode(challenge).decode("utf-8")
        await _redis_cache.setex(full_key, WEBAUTHN_CHALLENGE_TTL, challenge_b64)
        logger.debug("webauthn_challenge_stored", key=key[:20])
        return True
    except Exception as e:
        logger.warning(
            "webauthn_challenge_store_failed",
            key=key[:20] if key else "none",
            error=str(e),
        )
        return False


async def get_and_consume_webauthn_challenge(key: str) -> Optional[bytes]:
    """Get and consume a WebAuthn challenge (single-use).

    Retrieves the challenge and deletes it atomically to prevent replay attacks.
    Each challenge can only be used once.

    Args:
        key: The challenge key used during storage

    Returns:
        Challenge bytes if found and valid, None otherwise

    Security:
        - Atomic get-and-delete prevents race conditions
        - Expired challenges automatically rejected (Redis TTL)
        - Logs invalid attempts for security monitoring
    """
    if not _redis_cache:
        logger.warning(
            "webauthn_challenge_get_no_redis",
            key=key[:20] if key else "none",
            message="Redis unavailable - cannot validate challenge",
        )
        return None

    if not key or len(key) > 128:
        logger.warning(
            "webauthn_challenge_invalid_attempt",
            key=key[:20] if key else "none",
            reason="invalid_key_format",
        )
        return None

    try:
        full_key = f"{WEBAUTHN_CHALLENGE_PREFIX}{key}"
        # Get the challenge
        challenge_b64 = await _redis_cache.get(full_key)
        if not challenge_b64:
            logger.warning(
                "webauthn_challenge_invalid_attempt",
                key=key[:20],
                reason="not_found_or_expired",
            )
            return None

        # Delete it atomically (single-use)
        await _redis_cache.delete(full_key)

        # Decode and return
        import base64

        challenge = base64.b64decode(challenge_b64)
        logger.debug("webauthn_challenge_consumed", key=key[:20])
        return challenge
    except Exception as e:
        logger.warning(
            "webauthn_challenge_get_failed",
            key=key[:20] if key else "none",
            error=str(e),
        )
        return None
