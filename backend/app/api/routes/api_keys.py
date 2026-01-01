"""API Key management endpoints."""

from datetime import datetime, timezone
from typing import Optional
from uuid import UUID

import structlog
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, Field, ConfigDict
from sqlalchemy import select, and_
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.config import get_settings
from app.core.database import get_db
from app.core.security import AuthContext, get_auth_context, get_client_ip, require_role
from app.models.user import (
    APIKey,
    UserRole,
    AuditLog,
    AuditLogAction,
)
from app.services.auth_service import AuthService

logger = structlog.get_logger()
settings = get_settings()
router = APIRouter()


# Request/Response schemas
class APIKeyCreateRequest(BaseModel):
    """Create API key request."""

    name: str = Field(..., min_length=1, max_length=255)
    scopes: list[str] = Field(default_factory=list)
    expires_days: Optional[int] = Field(None, ge=1, le=365)
    ip_allowlist: Optional[list[str]] = None


class APIKeyResponse(BaseModel):
    """API key response (without secret)."""

    id: UUID
    name: str
    key_prefix: str
    scopes: list[str]
    ip_allowlist: Optional[list[str]]
    expires_at: Optional[datetime]
    last_used_at: Optional[datetime]
    last_used_ip: Optional[str]
    usage_count: int
    is_active: bool
    created_at: datetime
    created_by_name: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class APIKeyCreatedResponse(APIKeyResponse):
    """API key response with secret (only shown once)."""

    key: str  # Full API key, only returned on creation


class APIKeyUpdateRequest(BaseModel):
    """Update API key request."""

    name: Optional[str] = Field(None, min_length=1, max_length=255)
    scopes: Optional[list[str]] = None
    ip_allowlist: Optional[list[str]] = None
    is_active: Optional[bool] = None


# Available scopes
AVAILABLE_SCOPES = [
    "read:accounts",
    "write:accounts",
    "read:scans",
    "write:scans",
    "read:detections",
    "write:detections",
    "read:coverage",
    "read:mappings",
    "write:mappings",
    "read:reports",
    "write:reports",
]


async def log_api_key_action(
    db: AsyncSession,
    user_id: UUID,
    org_id: UUID,
    action: AuditLogAction,
    details: dict,
    ip_address: Optional[str] = None,
) -> None:
    """Log an API key management action."""
    log = AuditLog(
        user_id=user_id,
        organization_id=org_id,
        action=action,
        resource_type="api_key",
        details=details,
        ip_address=ip_address,
    )
    db.add(log)


@router.get("/scopes")
async def list_available_scopes(
    auth: AuthContext = Depends(get_auth_context),
) -> dict:
    """List all available API key scopes."""
    return {
        "scopes": AVAILABLE_SCOPES,
        "descriptions": {
            "read:accounts": "View cloud accounts",
            "write:accounts": "Create, update, delete cloud accounts",
            "read:scans": "View scan results",
            "write:scans": "Trigger scans",
            "read:detections": "View detection rules",
            "write:detections": "Update detection mappings",
            "read:coverage": "View coverage analysis",
            "read:mappings": "View MITRE ATT&CK mappings",
            "write:mappings": "Update custom mappings",
            "read:reports": "View and download reports",
            "write:reports": "Generate reports",
        },
    }


@router.get("", response_model=list[APIKeyResponse])
async def list_api_keys(
    auth: AuthContext = Depends(require_role(UserRole.OWNER, UserRole.ADMIN)),
    db: AsyncSession = Depends(get_db),
) -> list[APIKeyResponse]:
    """List all API keys for the organization."""
    if not auth.organization_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No organization context",
        )

    result = await db.execute(
        select(APIKey)
        .options(selectinload(APIKey.created_by))
        .where(APIKey.organization_id == auth.organization_id)
        .order_by(APIKey.created_at.desc())
    )
    keys = result.scalars().all()

    return [
        APIKeyResponse(
            id=key.id,
            name=key.name,
            key_prefix=key.key_prefix,
            scopes=key.scopes,
            ip_allowlist=key.ip_allowlist,
            expires_at=key.expires_at,
            last_used_at=key.last_used_at,
            last_used_ip=key.last_used_ip,
            usage_count=key.usage_count,
            is_active=key.is_active,
            created_at=key.created_at,
            created_by_name=key.created_by.full_name if key.created_by else None,
        )
        for key in keys
    ]


@router.post(
    "", response_model=APIKeyCreatedResponse, status_code=status.HTTP_201_CREATED
)
async def create_api_key(
    request: Request,
    body: APIKeyCreateRequest,
    auth: AuthContext = Depends(require_role(UserRole.OWNER, UserRole.ADMIN)),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """
    Create a new API key.

    The full key is only returned once on creation - store it securely!
    """
    if not auth.organization_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No organization context",
        )

    # Validate scopes
    invalid_scopes = set(body.scopes) - set(AVAILABLE_SCOPES)
    if invalid_scopes:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid scopes: {', '.join(invalid_scopes)}",
        )

    # Generate key
    full_key, prefix = APIKey.generate_key()
    auth_service = AuthService(db)

    # Calculate expiration
    expires_at = None
    if body.expires_days:
        from datetime import timedelta

        expires_at = datetime.now(timezone.utc) + timedelta(days=body.expires_days)

    # Create API key
    # Security: Use SHA-256 hash (hash_token) for API keys, not bcrypt (hash_password)
    # API keys have high entropy (secrets.token_hex) so SHA-256 is secure and allows
    # fast lookup during authentication
    api_key = APIKey(
        organization_id=auth.organization_id,
        created_by_id=auth.user.id,
        name=body.name,
        key_prefix=prefix,
        key_hash=auth_service.hash_token(full_key),
        scopes=body.scopes or [],
        ip_allowlist=body.ip_allowlist,
        expires_at=expires_at,
    )
    db.add(api_key)

    # Log the action
    await log_api_key_action(
        db=db,
        user_id=auth.user.id,
        org_id=auth.organization_id,
        action=AuditLogAction.API_KEY_CREATED,
        details={
            "key_name": body.name,
            "key_prefix": prefix,
            "scopes": body.scopes,
            "expires_days": body.expires_days,
        },
        ip_address=get_client_ip(request),
    )

    await db.commit()
    await db.refresh(api_key)

    logger.info(
        "API key created",
        key_name=body.name,
        key_prefix=prefix,
        org_id=str(auth.organization_id),
    )

    return APIKeyCreatedResponse(
        id=api_key.id,
        name=api_key.name,
        key_prefix=api_key.key_prefix,
        key=full_key,  # Only time the full key is returned
        scopes=api_key.scopes,
        ip_allowlist=api_key.ip_allowlist,
        expires_at=api_key.expires_at,
        last_used_at=api_key.last_used_at,
        last_used_ip=api_key.last_used_ip,
        usage_count=api_key.usage_count,
        is_active=api_key.is_active,
        created_at=api_key.created_at,
        created_by_name=auth.user.full_name,
    )


@router.get("/{key_id}", response_model=APIKeyResponse)
async def get_api_key(
    key_id: UUID,
    auth: AuthContext = Depends(require_role(UserRole.OWNER, UserRole.ADMIN)),
    db: AsyncSession = Depends(get_db),
) -> APIKeyResponse:
    """Get a specific API key's details."""
    if not auth.organization_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No organization context",
        )

    result = await db.execute(
        select(APIKey)
        .options(selectinload(APIKey.created_by))
        .where(
            and_(
                APIKey.id == key_id,
                APIKey.organization_id == auth.organization_id,
            )
        )
    )
    key = result.scalar_one_or_none()

    if not key:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="API key not found",
        )

    return APIKeyResponse(
        id=key.id,
        name=key.name,
        key_prefix=key.key_prefix,
        scopes=key.scopes,
        ip_allowlist=key.ip_allowlist,
        expires_at=key.expires_at,
        last_used_at=key.last_used_at,
        last_used_ip=key.last_used_ip,
        usage_count=key.usage_count,
        is_active=key.is_active,
        created_at=key.created_at,
        created_by_name=key.created_by.full_name if key.created_by else None,
    )


@router.patch("/{key_id}", response_model=APIKeyResponse)
async def update_api_key(
    request: Request,
    key_id: UUID,
    body: APIKeyUpdateRequest,
    auth: AuthContext = Depends(require_role(UserRole.OWNER, UserRole.ADMIN)),
    db: AsyncSession = Depends(get_db),
) -> APIKeyResponse:
    """Update an API key's properties."""
    if not auth.organization_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No organization context",
        )

    result = await db.execute(
        select(APIKey)
        .options(selectinload(APIKey.created_by))
        .where(
            and_(
                APIKey.id == key_id,
                APIKey.organization_id == auth.organization_id,
            )
        )
    )
    key = result.scalar_one_or_none()

    if not key:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="API key not found",
        )

    # Validate scopes if provided
    if body.scopes is not None:
        invalid_scopes = set(body.scopes) - set(AVAILABLE_SCOPES)
        if invalid_scopes:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid scopes: {', '.join(invalid_scopes)}",
            )

    # Update fields
    if body.name is not None:
        key.name = body.name
    if body.scopes is not None:
        key.scopes = body.scopes
    if body.ip_allowlist is not None:
        key.ip_allowlist = body.ip_allowlist
    if body.is_active is not None:
        key.is_active = body.is_active

    await db.commit()

    return APIKeyResponse(
        id=key.id,
        name=key.name,
        key_prefix=key.key_prefix,
        scopes=key.scopes,
        ip_allowlist=key.ip_allowlist,
        expires_at=key.expires_at,
        last_used_at=key.last_used_at,
        last_used_ip=key.last_used_ip,
        usage_count=key.usage_count,
        is_active=key.is_active,
        created_at=key.created_at,
        created_by_name=key.created_by.full_name if key.created_by else None,
    )


@router.delete("/{key_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_api_key(
    request: Request,
    key_id: UUID,
    auth: AuthContext = Depends(require_role(UserRole.OWNER, UserRole.ADMIN)),
    db: AsyncSession = Depends(get_db),
) -> None:
    """Revoke an API key."""
    if not auth.organization_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No organization context",
        )

    result = await db.execute(
        select(APIKey).where(
            and_(
                APIKey.id == key_id,
                APIKey.organization_id == auth.organization_id,
            )
        )
    )
    key = result.scalar_one_or_none()

    if not key:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="API key not found",
        )

    # Revoke the key
    key.is_active = False
    key.revoked_at = datetime.now(timezone.utc)
    key.revoked_by_id = auth.user.id

    # Log the action
    await log_api_key_action(
        db=db,
        user_id=auth.user.id,
        org_id=auth.organization_id,
        action=AuditLogAction.API_KEY_REVOKED,
        details={
            "key_name": key.name,
            "key_prefix": key.key_prefix,
        },
        ip_address=get_client_ip(request),
    )

    await db.commit()

    logger.info(
        "API key revoked",
        key_name=key.name,
        key_prefix=key.key_prefix,
        org_id=str(auth.organization_id),
    )

    return Response(status_code=status.HTTP_204_NO_CONTENT)
