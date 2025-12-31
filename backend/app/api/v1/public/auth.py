"""API key authentication for public API endpoints."""

from datetime import datetime, timezone
from typing import Optional
from uuid import UUID

from fastapi import HTTPException, Security, status
from fastapi.security import APIKeyHeader
from sqlalchemy import select

from app.core.database import get_db_session
from app.core.rate_limiter import check_api_rate_limit
from app.models.user import APIKey, Organization
from app.models.billing import Subscription
from app.services.auth_service import AuthService


api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


class APIKeyContext:
    """Context for API key authenticated requests."""

    def __init__(
        self,
        api_key_id: UUID,
        organization_id: UUID,
        tier: str,
        rate_limit_headers: dict,
    ):
        self.api_key_id = api_key_id
        self.organization_id = organization_id
        self.tier = tier
        self.rate_limit_headers = rate_limit_headers


async def get_api_key_context(
    api_key: Optional[str] = Security(api_key_header),
) -> APIKeyContext:
    """Validate API key and return context.

    Args:
        api_key: API key from X-API-Key header

    Returns:
        APIKeyContext with organization and tier info

    Raises:
        HTTPException: If key is invalid or rate limit exceeded
    """
    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API key required. Set X-API-Key header.",
        )

    async with get_db_session() as db:
        # Security: Look up API key by hash, not raw key
        # API keys are stored as SHA-256 hashes for security
        key_hash = AuthService.hash_token(api_key)
        result = await db.execute(
            select(APIKey).where(
                APIKey.key_hash == key_hash,
                APIKey.is_active.is_(True),
            )
        )
        api_key_record = result.scalar_one_or_none()

        if not api_key_record:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or inactive API key.",
            )

        # Check expiration
        if api_key_record.expires_at:
            if api_key_record.expires_at < datetime.now(timezone.utc):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="API key has expired.",
                )

        # Get organization tier for rate limiting
        org_result = await db.execute(
            select(Organization).where(
                Organization.id == api_key_record.organization_id
            )
        )
        org = org_result.scalar_one_or_none()

        tier = "free"
        if org:
            # Get subscription tier
            sub_result = await db.execute(
                select(Subscription)
                .where(Subscription.organization_id == org.id)
                .order_by(Subscription.created_at.desc())
                .limit(1)
            )
            subscription = sub_result.scalar_one_or_none()
            if subscription:
                tier = subscription.tier.value

        # API access requires a paid subscription
        if tier == "free":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="API access requires a paid subscription. "
                "Please upgrade to Individual, Pro, or Enterprise.",
            )

        # Check rate limit
        try:
            rate_limit_headers = await check_api_rate_limit(api_key, tier)
        except Exception as e:
            # Re-raise rate limit exceptions
            raise e

        # Update last used timestamp
        api_key_record.last_used_at = datetime.now(timezone.utc)
        await db.commit()

        return APIKeyContext(
            api_key_id=api_key_record.id,
            organization_id=api_key_record.organization_id,
            tier=tier,
            rate_limit_headers=rate_limit_headers,
        )
