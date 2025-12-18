"""Cognito SSO authentication routes."""

import secrets
from datetime import datetime, timezone, timedelta
from typing import Optional
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import RedirectResponse
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
import structlog

from app.core.config import get_settings
from app.core.database import get_db
from app.models.user import User, Organization, OrganizationMember, UserRole, MembershipStatus, FederatedIdentity, AuditLog, AuditLogAction
from app.models.billing import Subscription, AccountTier
from app.services.cognito_service import cognito_service, generate_pkce
from app.services.auth_service import AuthService
from app.api.routes.auth import get_current_user, get_client_ip

logger = structlog.get_logger()
router = APIRouter()
settings = get_settings()


class CognitoConfigResponse(BaseModel):
    """Cognito configuration for frontend."""
    configured: bool
    region: Optional[str] = None
    user_pool_id: Optional[str] = None
    client_id: Optional[str] = None
    domain: Optional[str] = None
    authorization_url: Optional[str] = None
    providers: list[str] = []


class CognitoTokenRequest(BaseModel):
    """Request to exchange Cognito tokens with PKCE."""
    code: str
    redirect_uri: str
    code_verifier: str  # PKCE - required
    state: Optional[str] = None


class CognitoTokenResponse(BaseModel):
    """Response with app tokens after Cognito auth."""
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int
    user: dict


class SSOInitiateResponse(BaseModel):
    """Response for SSO initiation."""
    authorization_url: str
    state: str
    code_verifier: str  # PKCE - client must store and send back


@router.get("/config", response_model=CognitoConfigResponse)
async def get_cognito_config():
    """Get Cognito configuration for frontend."""
    if not cognito_service.is_configured():
        return CognitoConfigResponse(configured=False)

    providers = ["COGNITO"]
    if settings.google_client_id:
        providers.append("Google")

    return CognitoConfigResponse(
        configured=True,
        region=cognito_service.region,
        user_pool_id=cognito_service.user_pool_id,
        client_id=cognito_service.client_id,
        domain=cognito_service.domain,
        authorization_url=cognito_service.authorization_url,
        providers=providers,
    )


@router.get("/authorize/{provider}")
async def initiate_sso(
    provider: str,
    redirect_uri: str,
) -> SSOInitiateResponse:
    """Initiate SSO flow for a provider with PKCE."""
    if not cognito_service.is_configured():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="SSO is not configured"
        )

    # Validate provider
    valid_providers = ["google", "cognito"]
    if provider.lower() not in valid_providers:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid provider. Must be one of: {valid_providers}"
        )

    # Generate state for CSRF protection
    state = secrets.token_urlsafe(32)

    # Generate PKCE code verifier and challenge
    code_verifier, code_challenge = generate_pkce()

    # Build authorization URL with PKCE
    identity_provider = None
    if provider.lower() == "google":
        identity_provider = "Google"

    auth_url = cognito_service.build_authorization_url(
        redirect_uri=redirect_uri,
        state=state,
        code_challenge=code_challenge,
        identity_provider=identity_provider,
    )

    return SSOInitiateResponse(
        authorization_url=auth_url,
        state=state,
        code_verifier=code_verifier,  # Client stores this securely
    )


@router.post("/token", response_model=CognitoTokenResponse)
async def exchange_cognito_token(
    request: Request,
    body: CognitoTokenRequest,
    db: AsyncSession = Depends(get_db),
):
    """Exchange Cognito authorization code for app tokens."""
    if not cognito_service.is_configured():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="SSO is not configured"
        )

    # Exchange code for Cognito tokens with PKCE
    tokens = await cognito_service.exchange_code_for_tokens(
        code=body.code,
        redirect_uri=body.redirect_uri,
        code_verifier=body.code_verifier,
    )

    if not tokens:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Failed to exchange authorization code"
        )

    # Verify the ID token
    id_token = tokens.get("id_token")
    if not id_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="No ID token received"
        )

    claims = await cognito_service.verify_token(id_token)
    if not claims:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid ID token"
        )

    # Extract user info from claims
    cognito_sub = claims.get("sub")
    email = claims.get("email")
    name = claims.get("name") or claims.get("cognito:username") or email.split("@")[0]
    email_verified = claims.get("email_verified", False)

    # Determine identity provider from claims
    identity_provider = "cognito"
    if "identities" in claims:
        identities = claims.get("identities", [])
        if identities and len(identities) > 0:
            identity_provider = identities[0].get("providerName", "cognito").lower()

    if not email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email not provided by identity provider"
        )

    # Find or create user
    result = await db.execute(
        select(User).where(
            (User.cognito_sub == cognito_sub) | (User.email == email)
        )
    )
    user = result.scalar_one_or_none()

    if user:
        # Update existing user with Cognito info if not set
        if not user.cognito_sub:
            user.cognito_sub = cognito_sub
        user.identity_provider = identity_provider
        user.last_login_at = datetime.now(timezone.utc)
        if not user.email_verified and email_verified:
            user.email_verified = True
    else:
        # Create new user
        user = User(
            id=uuid4(),
            email=email,
            full_name=name,
            cognito_sub=cognito_sub,
            identity_provider=identity_provider,
            email_verified=email_verified,
            is_active=True,
        )
        db.add(user)
        await db.flush()

        # Create organization for new user
        org_name = f"{name}'s Organization"
        org_slug = f"{email.split('@')[0]}-{secrets.token_hex(4)}"

        organization = Organization(
            id=uuid4(),
            name=org_name,
            slug=org_slug,
        )
        db.add(organization)
        await db.flush()

        # Add user as owner
        membership = OrganizationMember(
            id=uuid4(),
            organization_id=organization.id,
            user_id=user.id,
            role=UserRole.OWNER,
            status=MembershipStatus.ACTIVE,
            joined_at=datetime.now(timezone.utc),
        )
        db.add(membership)

        # Create free subscription
        subscription = Subscription(
            organization_id=organization.id,
            tier=AccountTier.FREE_SCAN,
        )
        db.add(subscription)

        logger.info("user_created_via_sso", user_id=str(user.id), provider=identity_provider)

    # Track/update federated identity
    result = await db.execute(
        select(FederatedIdentity).where(
            FederatedIdentity.provider == identity_provider,
            FederatedIdentity.provider_user_id == cognito_sub,
        )
    )
    federated = result.scalar_one_or_none()

    if not federated:
        federated = FederatedIdentity(
            user_id=user.id,
            provider=identity_provider,
            provider_user_id=cognito_sub,
            provider_email=email,
        )
        db.add(federated)
    else:
        federated.last_login_at = datetime.now(timezone.utc)

    # Get user's organization
    result = await db.execute(
        select(OrganizationMember).where(
            OrganizationMember.user_id == user.id,
            OrganizationMember.status == MembershipStatus.ACTIVE,
        )
    )
    membership = result.scalar_one_or_none()

    if not membership:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User has no active organization membership"
        )

    # Get organization
    result = await db.execute(
        select(Organization).where(Organization.id == membership.organization_id)
    )
    organization = result.scalar_one()

    # Create audit log
    audit_log = AuditLog(
        organization_id=organization.id,
        user_id=user.id,
        action=AuditLogAction.USER_LOGIN,
        details={"method": "sso", "provider": identity_provider},
        ip_address=get_client_ip(request),
        success=True,
    )
    db.add(audit_log)

    await db.commit()

    # Create app tokens using AuthService
    auth_service = AuthService(db)
    ip_address = get_client_ip(request)
    user_agent = request.headers.get("User-Agent")

    access_token, refresh_token = await auth_service.create_session(
        user=user,
        organization_id=organization.id,
        ip_address=ip_address,
        user_agent=user_agent,
    )

    return CognitoTokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=settings.access_token_expire_minutes * 60,
        user={
            "id": str(user.id),
            "email": user.email,
            "full_name": user.full_name,
            "role": membership.role.value,
            "mfa_enabled": user.mfa_enabled,
            "identity_provider": user.identity_provider,
        },
    )


@router.get("/identities")
async def list_linked_identities(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List linked federated identities for current user."""
    result = await db.execute(
        select(FederatedIdentity).where(FederatedIdentity.user_id == user.id)
    )
    identities = result.scalars().all()

    return {
        "identities": [
            {
                "id": str(identity.id),
                "provider": identity.provider,
                "provider_email": identity.provider_email,
                "linked_at": identity.linked_at.isoformat(),
                "last_login_at": identity.last_login_at.isoformat() if identity.last_login_at else None,
            }
            for identity in identities
        ]
    }


@router.delete("/identities/{provider}")
async def unlink_identity(
    provider: str,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Unlink a federated identity."""
    # Check if user has a password set (can't unlink last auth method)
    if not user.password_hash:
        # Count remaining identities
        result = await db.execute(
            select(FederatedIdentity).where(FederatedIdentity.user_id == user.id)
        )
        identities = result.scalars().all()

        if len(identities) <= 1:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot unlink last authentication method. Set a password first."
            )

    # Find and delete the identity
    result = await db.execute(
        select(FederatedIdentity).where(
            FederatedIdentity.user_id == user.id,
            FederatedIdentity.provider == provider.lower(),
        )
    )
    identity = result.scalar_one_or_none()

    if not identity:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No linked identity found for provider: {provider}"
        )

    await db.delete(identity)
    await db.commit()

    return {"message": f"Successfully unlinked {provider}"}
