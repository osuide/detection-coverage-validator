"""Security middleware and dependencies for RBAC."""

from datetime import datetime, timedelta, timezone
from typing import Optional, Callable
from uuid import UUID

import jwt
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy import select, and_
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.database import get_db
from app.models.user import (
    User,
    Organization,
    OrganizationMember,
    UserRole,
    MembershipStatus,
    APIKey,
)
from app.services.auth_service import AuthService

settings = get_settings()
security = HTTPBearer(auto_error=False)


def create_access_token(
    data: dict,
    expires_delta: Optional[timedelta] = None,
) -> str:
    """Create a JWT access token.

    Used by admin auth service for admin tokens.
    """
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (
        expires_delta or timedelta(minutes=settings.access_token_expire_minutes)
    )
    to_encode.update({"exp": expire, "iat": datetime.now(timezone.utc)})
    return jwt.encode(to_encode, settings.secret_key, algorithm="HS256")


def decode_token(token: str) -> Optional[dict]:
    """Decode and validate a JWT token."""
    try:
        payload = jwt.decode(token, settings.secret_key, algorithms=["HS256"])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


class AuthContext:
    """Authentication context with user, organization, and permissions."""

    def __init__(
        self,
        user: Optional[User] = None,
        organization: Optional[Organization] = None,
        membership: Optional[OrganizationMember] = None,
        api_key: Optional[APIKey] = None,
    ):
        self.user = user
        self.organization = organization
        self.membership = membership
        self.api_key = api_key

    @property
    def user_id(self) -> Optional[UUID]:
        return self.user.id if self.user else None

    @property
    def organization_id(self) -> Optional[UUID]:
        return self.organization.id if self.organization else None

    @property
    def role(self) -> Optional[UserRole]:
        return self.membership.role if self.membership else None

    def has_role(self, *roles: UserRole) -> bool:
        """Check if user has one of the specified roles."""
        if not self.membership:
            return False
        return self.membership.role in roles

    def is_owner(self) -> bool:
        return self.has_role(UserRole.OWNER)

    def is_admin(self) -> bool:
        return self.has_role(UserRole.OWNER, UserRole.ADMIN)

    def is_member(self) -> bool:
        return self.has_role(UserRole.OWNER, UserRole.ADMIN, UserRole.MEMBER)

    def can_access_account(self, account_id: UUID) -> bool:
        """Check if user can access a specific cloud account."""
        if not self.membership:
            return False

        # Owners and admins can access all accounts
        if self.is_admin():
            return True

        # Members and viewers with null allowed_account_ids can access all
        if self.membership.allowed_account_ids is None:
            return True

        # Check if account is in allowed list
        return str(account_id) in self.membership.allowed_account_ids


def get_client_ip(request: Request) -> Optional[str]:
    """Get client IP address from request."""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else None


async def get_auth_context(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    db: AsyncSession = Depends(get_db),
) -> AuthContext:
    """
    Get authentication context from JWT token or API key.

    Returns AuthContext with user, organization, and membership info.
    Raises HTTPException 401 if not authenticated.
    """
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = credentials.credentials

    # Check if it's an API key
    if token.startswith("dcv_"):
        return await _authenticate_api_key(token, db, request)

    # Otherwise, treat as JWT
    return await _authenticate_jwt(token, db, request)


async def get_auth_context_optional(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    db: AsyncSession = Depends(get_db),
) -> Optional[AuthContext]:
    """Get authentication context if authenticated, None otherwise."""
    if not credentials:
        return None
    try:
        return await get_auth_context(request, credentials, db)
    except HTTPException:
        return None


async def _authenticate_jwt(
    token: str,
    db: AsyncSession,
    request: Request,
) -> AuthContext:
    """Authenticate using JWT token."""
    auth_service = AuthService(db)
    payload = auth_service.decode_token(token)

    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user_id = UUID(payload.get("sub"))
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()

    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Get organization context if present
    organization = None
    membership = None
    org_id_str = payload.get("org")

    if org_id_str:
        org_id = UUID(org_id_str)
        result = await db.execute(select(Organization).where(Organization.id == org_id))
        organization = result.scalar_one_or_none()

        if organization:
            result = await db.execute(
                select(OrganizationMember).where(
                    and_(
                        OrganizationMember.user_id == user_id,
                        OrganizationMember.organization_id == org_id,
                        OrganizationMember.status == MembershipStatus.ACTIVE,
                    )
                )
            )
            membership = result.scalar_one_or_none()

    # Store context in request state
    request.state.auth_context = AuthContext(
        user=user,
        organization=organization,
        membership=membership,
    )

    return request.state.auth_context


async def _authenticate_api_key(
    key: str,
    db: AsyncSession,
    request: Request,
) -> AuthContext:
    """Authenticate using API key."""
    auth_service = AuthService(db)
    key_hash = auth_service.hash_token(key)

    result = await db.execute(
        select(APIKey).where(
            and_(
                APIKey.key_hash == key_hash,
                APIKey.is_active == True,
            )
        )
    )
    api_key = result.scalar_one_or_none()

    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Check expiration
    from datetime import datetime, timezone
    if api_key.expires_at and api_key.expires_at < datetime.now(timezone.utc):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API key has expired",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Check IP allowlist
    client_ip = get_client_ip(request)
    if api_key.ip_allowlist and client_ip:
        # Simple IP check (could be enhanced with CIDR support)
        if client_ip not in api_key.ip_allowlist:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="IP address not in allowlist",
            )

    # Update usage stats
    api_key.last_used_at = datetime.now(timezone.utc)
    api_key.last_used_ip = client_ip
    api_key.usage_count += 1

    # Get organization
    result = await db.execute(
        select(Organization).where(Organization.id == api_key.organization_id)
    )
    organization = result.scalar_one_or_none()

    # Store context in request state
    request.state.auth_context = AuthContext(
        organization=organization,
        api_key=api_key,
    )

    return request.state.auth_context


# Permission dependency factories

def require_auth(
    require_org: bool = True,
) -> Callable:
    """
    Dependency that requires authentication.

    Args:
        require_org: Whether organization context is required
    """
    async def dependency(
        auth: AuthContext = Depends(get_auth_context),
    ) -> AuthContext:
        if require_org and not auth.organization:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Organization context required",
            )
        return auth

    return dependency


def require_role(*roles: UserRole) -> Callable:
    """
    Dependency that requires specific role(s).

    Example: require_role(UserRole.OWNER, UserRole.ADMIN)
    """
    async def dependency(
        auth: AuthContext = Depends(get_auth_context),
    ) -> AuthContext:
        if not auth.organization:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Organization context required",
            )

        if not auth.has_role(*roles):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Requires role: {', '.join(r.value for r in roles)}",
            )

        return auth

    return dependency


def require_scope(*scopes: str) -> Callable:
    """
    Dependency that requires specific API key scope(s).
    For JWT tokens, allows all scopes.

    Example: require_scope("read:accounts", "write:accounts")
    """
    async def dependency(
        auth: AuthContext = Depends(get_auth_context),
    ) -> AuthContext:
        # JWT tokens have all scopes
        if not auth.api_key:
            return auth

        # Check API key scopes
        for scope in scopes:
            if scope not in auth.api_key.scopes:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Missing required scope: {scope}",
                )

        return auth

    return dependency


def require_account_access(account_id_param: str = "cloud_account_id") -> Callable:
    """
    Dependency that checks access to a specific cloud account.

    Args:
        account_id_param: Name of the path/query parameter containing the account ID
    """
    async def dependency(
        request: Request,
        auth: AuthContext = Depends(get_auth_context),
    ) -> AuthContext:
        # Get account ID from path parameters or query parameters
        account_id_str = request.path_params.get(account_id_param) or request.query_params.get(account_id_param)

        if not account_id_str:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Missing {account_id_param}",
            )

        try:
            account_id = UUID(account_id_str)
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid {account_id_param}",
            )

        if not auth.can_access_account(account_id):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied to this cloud account",
            )

        return auth

    return dependency


# Commonly used dependencies
RequireAuth = Depends(require_auth())
RequireAdmin = Depends(require_role(UserRole.OWNER, UserRole.ADMIN))
RequireOwner = Depends(require_role(UserRole.OWNER))
RequireMember = Depends(require_role(UserRole.OWNER, UserRole.ADMIN, UserRole.MEMBER))
