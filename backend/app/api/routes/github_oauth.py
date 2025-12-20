"""GitHub OAuth routes for direct authentication."""

import secrets
from datetime import datetime, timezone
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

import structlog

from app.core.config import get_settings
from app.core.database import get_db
from app.models.user import (
    User,
    Organization,
    OrganizationMember,
    UserRole,
    MembershipStatus,
    FederatedIdentity,
    AuditLog,
    AuditLogAction,
)
from app.models.billing import Subscription, AccountTier
from app.services.github_oauth_service import github_oauth_service
from app.services.auth_service import AuthService
from app.api.routes.cognito import get_client_ip

logger = structlog.get_logger()
settings = get_settings()
router = APIRouter(prefix="/github", tags=["GitHub OAuth"])


class GitHubAuthorizeResponse(BaseModel):
    """Response for GitHub authorize endpoint."""

    authorization_url: str
    state: str


class GitHubTokenRequest(BaseModel):
    """Request for GitHub token exchange."""

    code: str
    redirect_uri: str
    state: str


class GitHubTokenResponse(BaseModel):
    """Response for GitHub token exchange."""

    access_token: str
    refresh_token: str
    expires_in: int
    user: dict


@router.get("/config")
async def get_github_config():
    """Get GitHub OAuth configuration."""
    return {
        "enabled": github_oauth_service.is_configured(),
        "client_id": (
            settings.github_client_id if github_oauth_service.is_configured() else None
        ),
    }


@router.get("/authorize")
async def get_authorization_url(redirect_uri: str) -> GitHubAuthorizeResponse:
    """Get GitHub authorization URL."""
    if not github_oauth_service.is_configured():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="GitHub OAuth is not configured",
        )

    state = github_oauth_service.generate_state()
    authorization_url = github_oauth_service.build_authorization_url(
        redirect_uri=redirect_uri,
        state=state,
    )

    return GitHubAuthorizeResponse(
        authorization_url=authorization_url,
        state=state,
    )


@router.post("/token", response_model=GitHubTokenResponse)
async def exchange_github_token(
    body: GitHubTokenRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Exchange GitHub authorization code for tokens."""
    if not github_oauth_service.is_configured():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="GitHub OAuth is not configured",
        )

    # Exchange code for GitHub access token
    token_response = await github_oauth_service.exchange_code_for_token(
        code=body.code,
        redirect_uri=body.redirect_uri,
    )

    if not token_response:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Failed to exchange authorization code",
        )

    github_access_token = token_response.get("access_token")
    if not github_access_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="No access token received from GitHub",
        )

    # Get user info from GitHub
    user_info = await github_oauth_service.get_user_info(github_access_token)
    if not user_info:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Failed to get user info from GitHub",
        )

    github_id = str(user_info.get("id"))
    github_login = user_info.get("login")
    name = user_info.get("name") or github_login

    # Get user's email (may require separate API call if not public)
    email = user_info.get("email")
    if not email:
        email = await github_oauth_service.get_primary_email(github_access_token)

    if not email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Could not retrieve email from GitHub. Please ensure your email is verified on GitHub.",
        )

    logger.info(
        "github_oauth_user",
        github_id=github_id,
        github_login=github_login,
        email=email,
    )

    # Find or create user
    result = await db.execute(
        select(User).where((User.oauth_id == github_id) | (User.email == email))
    )
    user = result.scalar_one_or_none()

    if user:
        # Update existing user
        if not user.oauth_id:
            user.oauth_id = github_id
            user.oauth_provider = "github"
        user.identity_provider = "github"
        user.last_login_at = datetime.now(timezone.utc)
        if not user.email_verified:
            user.email_verified = True
    else:
        # Create new user
        user = User(
            id=uuid4(),
            email=email,
            full_name=name,
            oauth_id=github_id,
            oauth_provider="github",
            identity_provider="github",
            email_verified=True,
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

        logger.info("user_created_via_github", user_id=str(user.id))

    # Track/update federated identity
    result = await db.execute(
        select(FederatedIdentity).where(
            FederatedIdentity.provider == "github",
            FederatedIdentity.provider_user_id == github_id,
        )
    )
    federated = result.scalar_one_or_none()

    if not federated:
        federated = FederatedIdentity(
            user_id=user.id,
            provider="github",
            provider_user_id=github_id,
            provider_email=email,
            linked_at=datetime.now(timezone.utc),
            last_login_at=datetime.now(timezone.utc),
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
            detail="User has no active organization membership",
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
        details={"method": "oauth", "provider": "github"},
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

    return GitHubTokenResponse(
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
