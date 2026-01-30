"""Redis-backed rate limiting for authentication endpoints.

This module provides distributed rate limiting using Redis, suitable for
multi-instance deployments where in-memory rate limiting would be ineffective.
"""

import structlog
from redis import asyncio as aioredis
from fastapi_limiter import FastAPILimiter
from fastapi_limiter.depends import RateLimiter

from app.core.config import get_settings

logger = structlog.get_logger()

# Redis connection for rate limiting
_redis_connection = None


async def init_rate_limiter() -> None:
    """Initialise Redis-backed rate limiter.

    Should be called during application startup.
    """
    global _redis_connection

    settings = get_settings()

    try:
        _redis_connection = await aioredis.from_url(
            settings.redis_url,
            encoding="utf-8",
            decode_responses=True,
        )
        await FastAPILimiter.init(_redis_connection)
        logger.info(
            "rate_limiter_initialised",
            redis_url=settings.redis_url.split("@")[-1],  # Log host only, not creds
        )
    except Exception as e:
        logger.error(
            "rate_limiter_init_failed",
            error=str(e),
            message="Falling back to no rate limiting - this is a security risk",
        )
        raise


async def close_rate_limiter() -> None:
    """Close Redis connection for rate limiter.

    Should be called during application shutdown.
    """
    global _redis_connection

    if _redis_connection:
        try:
            await FastAPILimiter.close()
            await _redis_connection.close()
            logger.info("rate_limiter_closed")
        except Exception as e:
            logger.warning("rate_limiter_close_failed", error=str(e))
        finally:
            _redis_connection = None


# Pre-configured rate limiters for common use cases
# These are FastAPI dependencies that can be used with Depends()


def auth_rate_limit() -> dict:
    """Rate limit for login endpoint: 10 requests per minute per IP."""
    return RateLimiter(times=10, seconds=60)


def signup_rate_limit() -> dict:
    """Rate limit for signup endpoint: 5 requests per 5 minutes per IP."""
    return RateLimiter(times=5, seconds=300)


def password_reset_rate_limit() -> dict:
    """Rate limit for password reset: 3 requests per hour per IP."""
    return RateLimiter(times=3, seconds=3600)


def mfa_rate_limit() -> dict:
    """Rate limit for MFA verification: 5 attempts per minute per IP."""
    return RateLimiter(times=5, seconds=60)


def api_key_rate_limit() -> dict:
    """Rate limit for API key authentication: 100 requests per minute per IP.

    M1: Add rate limiting for API key authentication to prevent brute force attacks.
    This is a generous limit for legitimate API usage while still preventing abuse.
    """
    return RateLimiter(times=100, seconds=60)


def support_ticket_rate_limit() -> dict:
    """Rate limit for support tickets: 5 requests per hour per IP.

    Prevents support inbox flooding and Google Workspace API abuse.
    CWE-799: Improper Control of Interaction Frequency
    """
    return RateLimiter(times=5, seconds=3600)


def quick_scan_rate_limit() -> dict:
    """Rate limit for quick scan: 5 requests per 5 minutes per IP.

    Public endpoint accepting untrusted input — strict limit to prevent
    abuse whilst allowing legitimate experimentation.
    """
    return RateLimiter(times=5, seconds=300)
