"""Security middleware and dependencies for RBAC."""

from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Optional
from uuid import UUID

import jwt
import structlog
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
logger = structlog.get_logger()
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
    return jwt.encode(
        to_encode, settings.secret_key.get_secret_value(), algorithm="HS256"
    )


def decode_token(token: str) -> Optional[dict]:
    """Decode and validate a JWT token."""
    try:
        payload = jwt.decode(
            token, settings.secret_key.get_secret_value(), algorithms=["HS256"]
        )
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
        """Check if user can access a specific cloud account.

        M3: Uses consistent string comparison with normalised UUID format.

        Security: The allowed_account_ids restriction applies to ALL roles,
        including ADMIN and OWNER. This enables fine-grained account-level
        access control even for privileged users.
        """
        # API keys have org-level access (can access all accounts in their org)
        if self.api_key:
            return True

        if not self.membership:
            return False

        # All roles with null allowed_account_ids can access all accounts
        # (None means unrestricted, different from empty list which means no access)
        if self.membership.allowed_account_ids is None:
            return True

        # M3: Normalise account_id to lowercase string for consistent comparison
        # UUIDs should be compared case-insensitively
        account_id_str = str(account_id).lower()

        # Check if account is in allowed list (normalise each entry)
        # This applies to ALL roles including ADMIN and OWNER
        return any(
            str(allowed_id).lower() == account_id_str
            for allowed_id in self.membership.allowed_account_ids
        )


def get_allowed_account_filter(auth: AuthContext) -> Optional[list[UUID]]:
    """Get list of allowed account IDs for filtering, or None if unrestricted.

    Security: Used to filter list queries by allowed_account_ids ACL.
    The allowed_account_ids restriction applies to ALL roles including ADMIN/OWNER.

    Returns:
        - None if allowed_account_ids is not set (full access - applies to all roles)
        - None if API key (org-level access)
        - Empty list if no membership (no access)
        - List of UUIDs if user has restricted access (applies to all roles)
    """
    # API keys have org-level access (can access all accounts in their org)
    if auth.api_key:
        return None

    if not auth.membership:
        return []  # No membership = no access

    # If allowed_account_ids is not set, user has access to all accounts
    # This applies to ALL roles including ADMIN/OWNER
    if auth.membership.allowed_account_ids is None:
        return None

    # Convert string UUIDs to UUID objects
    # Account restrictions apply to ALL roles including ADMIN/OWNER
    return [UUID(str(aid)) for aid in auth.membership.allowed_account_ids]


def _validate_ip(ip_str: str) -> Optional[str]:
    """Validate and return IP address, or None if invalid."""
    import ipaddress

    try:
        # Handle IPv6 with port (e.g., [::1]:8080)
        if ip_str.startswith("["):
            ip_str = ip_str.split("]")[0][1:]
        # Handle IPv4 with port (e.g., 1.2.3.4:8080)
        elif "." in ip_str and ":" in ip_str:
            ip_str = ip_str.rsplit(":", 1)[0]
        ipaddress.ip_address(ip_str)
        return ip_str
    except ValueError:
        return None


def _is_trusted_proxy(peer_ip: str) -> bool:
    """Check if the immediate peer IP is a trusted proxy.

    Security: Used to determine if X-Forwarded-For headers should be trusted.
    Only returns True if trust_proxy_headers is enabled AND the peer is in
    the trusted_proxy_cidrs list.
    """
    import ipaddress

    if not settings.trust_proxy_headers:
        return False

    if not settings.trusted_proxy_cidrs:
        # Security: No CIDRs configured - don't trust any proxy headers
        # This is fail-closed behaviour to prevent XFF spoofing
        logger.warning(
            "trust_proxy_headers_without_cidrs",
            message=(
                "trust_proxy_headers is True but no trusted_proxy_cidrs "
                "configured - ignoring proxy headers"
            ),
        )
        return False

    try:
        peer = ipaddress.ip_address(peer_ip)
    except ValueError:
        return False

    # Parse trusted CIDRs
    trusted_cidrs = [
        cidr.strip() for cidr in settings.trusted_proxy_cidrs.split(",") if cidr.strip()
    ]

    for cidr in trusted_cidrs:
        try:
            network = ipaddress.ip_network(cidr, strict=False)
            if peer in network:
                return True
        except ValueError:
            continue

    return False


def _parse_forwarded_header(forwarded: str) -> Optional[str]:
    """Parse RFC 7239 Forwarded header and extract client IP.

    Format: Forwarded: for=client_ip;by=proxy;host=example.com
    Multiple proxies: Forwarded: for=client1, for=client2
    """
    import re

    # Match the 'for=' directive (case-insensitive)
    # Handles both quoted and unquoted values, IPv4 and IPv6
    pattern = r'for\s*=\s*"?([^\s,;"\]]+|\[[^\]]+\])"?'
    matches = re.findall(pattern, forwarded, re.IGNORECASE)

    if matches:
        # First 'for' value is the original client
        client_ip = matches[0]
        # Handle IPv6 in brackets [::1]
        if client_ip.startswith("[") and "]" in client_ip:
            client_ip = client_ip[1:].split("]")[0]
        return _validate_ip(client_ip)

    return None


def get_client_ip(request: Request) -> Optional[str]:
    """Get client IP address from request with trusted proxy handling.

    Security Design:
    1. Only trusts forwarded headers if trust_proxy_headers is enabled
    2. Verifies the immediate peer is in trusted_proxy_cidrs before trusting
    3. Validates all IP addresses to prevent injection attacks
    4. Falls back to request.client.host when headers can't be trusted

    Header priority (when trusted):
    1. CloudFront-Viewer-Address (AWS CloudFront specific, most reliable)
    2. Forwarded header (RFC 7239 standard)
    3. X-Forwarded-For (de facto standard)
    4. request.client.host (direct connection)
    """
    # Get the immediate peer IP (direct connection)
    peer_ip = request.client.host if request.client else None

    # Check if we should trust proxy headers
    if peer_ip and _is_trusted_proxy(peer_ip):
        # CloudFront-Viewer-Address is most reliable when behind CloudFront
        cf_viewer = request.headers.get("CloudFront-Viewer-Address")
        if cf_viewer:
            # Format is IP:port, extract and validate
            validated = _validate_ip(cf_viewer.split(":")[0].strip())
            if validated:
                return validated

        # Try RFC 7239 Forwarded header first
        forwarded = request.headers.get("Forwarded")
        if forwarded:
            validated = _parse_forwarded_header(forwarded)
            if validated:
                return validated

        # X-Forwarded-For: client, proxy1, proxy2, ...
        xff = request.headers.get("X-Forwarded-For")
        if xff:
            first_ip = xff.split(",")[0].strip()
            validated = _validate_ip(first_ip)
            if validated:
                return validated

    # Not behind trusted proxy or no valid forwarded headers - use direct peer
    return peer_ip


def _check_ip_in_allowlist(client_ip: str, allowlist: list) -> bool:
    """Check if client IP is in the allowlist, supporting IPv4, IPv6, and CIDR notation.

    M15: Fully supports IPv6 addresses and CIDR ranges.

    Args:
        client_ip: The client's IP address (IPv4 or IPv6)
        allowlist: List of allowed IPs or CIDR ranges
            - IPv4: "192.168.1.1", "10.0.0.0/8"
            - IPv6: "2001:db8::1", "2001:db8::/32"

    Returns:
        True if the IP is allowed, False otherwise

    Note:
        IPv4 and IPv6 are compared separately - an IPv4 client won't match
        an IPv6 allowlist entry and vice versa.
    """
    import ipaddress

    try:
        client = ipaddress.ip_address(client_ip)
    except ValueError:
        # Invalid client IP - reject
        return False

    for entry in allowlist:
        try:
            # Try parsing as a network (CIDR notation)
            if "/" in entry:
                network = ipaddress.ip_network(entry, strict=False)
                # M15: Only compare matching IP versions (IPv4 vs IPv6)
                if isinstance(client, type(network.network_address)):
                    if client in network:
                        return True
            else:
                # Try parsing as a single IP address
                allowed_ip = ipaddress.ip_address(entry)
                # M15: Only compare matching IP versions (IPv4 vs IPv6)
                if isinstance(client, type(allowed_ip)):
                    if client == allowed_ip:
                        return True
        except ValueError:
            # Invalid allowlist entry - skip it
            continue

    return False


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

    # H1: Validate token type - only accept access tokens
    token_type = payload.get("type")
    if token_type not in ("access", None):
        # Only accept "access" tokens (or legacy tokens without type)
        # Reject:
        # - "admin" tokens (must use admin-specific endpoints)
        # - "mfa_pending" tokens (can only be used at /login/mfa endpoint)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token type for this endpoint",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Security: Log legacy tokens without type field (CWE-287 monitoring)
    # These will be deprecated in future releases
    if token_type is None:
        logger.warning(
            "legacy_token_without_type",
            user_id=payload.get("sub"),
            message="Token missing 'type' field - legacy format detected",
        )

    # SECURITY: Guard UUID parsing to return 401 instead of 500 on malformed tokens
    try:
        user_id = UUID(payload.get("sub"))
    except (ValueError, TypeError):
        logger.warning(
            "jwt_malformed_user_id",
            sub=payload.get("sub"),
            message="Token contains malformed user identifier",
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token: malformed user identifier",
            headers={"WWW-Authenticate": "Bearer"},
        )

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
        # SECURITY: Guard UUID parsing to return 401 instead of 500 on malformed tokens
        try:
            org_id = UUID(org_id_str)
        except (ValueError, TypeError):
            logger.warning(
                "jwt_malformed_org_id",
                org=org_id_str,
                user_id=str(user_id),
                message="Token contains malformed organisation identifier",
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token: malformed organisation identifier",
                headers={"WWW-Authenticate": "Bearer"},
            )

        result = await db.execute(select(Organization).where(Organization.id == org_id))
        organization = result.scalar_one_or_none()

        # SECURITY: Check if organisation is suspended
        if organization and not organization.is_active:
            logger.warning(
                "jwt_org_suspended",
                user_id=str(user_id),
                org_id=str(org_id),
                reason="organisation_suspended",
            )
            organization = None  # Clear org context for suspended organisations

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

            # SECURITY: If membership is not ACTIVE, don't grant org access
            if not membership:
                logger.warning(
                    "jwt_org_access_denied",
                    user_id=str(user_id),
                    org_id=str(org_id),
                    reason="membership_not_active",
                )
                organization = None  # Clear org context if no active membership

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
                APIKey.is_active.is_(True),
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

    # Check IP allowlist with CIDR support
    client_ip = get_client_ip(request)
    if api_key.ip_allowlist and client_ip:
        if not _check_ip_in_allowlist(client_ip, api_key.ip_allowlist):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="IP address not in allowlist",
            )

    # M8: Update usage stats with atomic increment for transaction isolation
    # This prevents lost updates when concurrent requests use the same API key
    from sqlalchemy import update

    await db.execute(
        update(APIKey)
        .where(APIKey.id == api_key.id)
        .values(
            last_used_at=datetime.now(timezone.utc),
            last_used_ip=client_ip,
            usage_count=APIKey.usage_count + 1,
        )
    )
    # Update local object for response (approximate, may differ from DB)
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
        account_id_str = request.path_params.get(
            account_id_param
        ) or request.query_params.get(account_id_param)

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


def require_feature(feature: str) -> Callable:
    """
    Dependency that requires a specific subscription feature to be enabled.

    Example: require_feature("org_features")

    Returns 403 if the organisation's subscription doesn't have the feature.
    """
    from app.models.billing import Subscription

    async def dependency(
        auth: AuthContext = Depends(get_auth_context),
        db: AsyncSession = Depends(get_db),
    ) -> AuthContext:
        if not auth.organization:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Organisation context required",
            )

        # Get subscription for the organisation
        result = await db.execute(
            select(Subscription).where(
                Subscription.organization_id == auth.organization.id
            )
        )
        subscription = result.scalar_one_or_none()

        if not subscription:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=(
                    "No subscription found. " "Please subscribe to access this feature."
                ),
            )

        # Check subscription status - must be active to access features
        from app.models.billing import SubscriptionStatus

        if subscription.status != SubscriptionStatus.ACTIVE:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=(
                    "Your subscription is not active. "
                    "Please update your payment method."
                ),
            )

        if not subscription.has_feature(feature):
            # Provide feature-specific upgrade messages
            feature_messages = {
                "scheduled_scans": (
                    "Scheduled scans require Individual tier (£29/mo) or higher. "
                    "Automate your security coverage analysis with recurring scans."
                ),
                "org_features": (
                    "Organisation features require Pro tier (£250/mo) or higher. "
                    "Manage teams, delegate scanning, and get org-wide dashboards."
                ),
                "api_access": (
                    "API access requires Individual tier (£29/mo) or higher. "
                    "Integrate detection coverage into your CI/CD pipeline."
                ),
                "team_invites": (
                    "Team member invitations require Individual tier (£29/mo) "
                    "or higher. Collaborate with your team by upgrading."
                ),
            }
            detail = feature_messages.get(
                feature,
                (
                    "This feature requires a paid subscription. "
                    "Upgrade to Individual (£29/mo) to unlock more capabilities."
                ),
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=detail,
            )

        return auth

    return dependency


def require_org_features() -> Callable:
    """
    Dependency that requires organisation features to be enabled.

    Pro and Enterprise tiers have organisation features.
    Returns 403 if on Free or Individual tier.

    Usage:
        @router.get("/cloud-organizations")
        async def list_orgs(auth: AuthContext = Depends(require_org_features())):
            ...
    """
    return require_feature("org_features")


def require_tier(*tiers: Any) -> Callable:
    """
    Dependency that requires a specific subscription tier.

    Example: require_tier(AccountTier.PRO, AccountTier.ENTERPRISE)

    Returns 403 if the organisation's subscription is not in the allowed tiers.
    """
    from app.models.billing import Subscription

    async def dependency(
        auth: AuthContext = Depends(get_auth_context),
        db: AsyncSession = Depends(get_db),
    ) -> AuthContext:
        if not auth.organization:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Organisation context required",
            )

        # Get subscription for the organisation
        result = await db.execute(
            select(Subscription).where(
                Subscription.organization_id == auth.organization.id
            )
        )
        subscription = result.scalar_one_or_none()

        if not subscription:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=(
                    "No subscription found. " "Please subscribe to access this feature."
                ),
            )

        # Check subscription status - must be active
        from app.models.billing import SubscriptionStatus

        if subscription.status != SubscriptionStatus.ACTIVE:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=(
                    "Your subscription is not active. "
                    "Please update your payment method."
                ),
            )

        if subscription.tier not in tiers:
            tier_names = ", ".join(t.value.title() for t in tiers)
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=(
                    f"This feature requires {tier_names} tier. "
                    "Please upgrade your subscription."
                ),
            )

        return auth

    return dependency


# Support API authentication
# Module-level bearer scheme instance for support API
_support_api_bearer = HTTPBearer(scheme_name="Support-API-Key", auto_error=True)


async def verify_support_api_key(
    credentials: HTTPAuthorizationCredentials = Depends(_support_api_bearer),
) -> str:
    """Verify the support API key for support system integration.

    This provides a dedicated authentication mechanism for the Google Workspace
    support integration, separate from regular user authentication.

    The support API key is configured via the SUPPORT_API_KEY environment variable.

    Raises:
        HTTPException 503: If support API is not configured
        HTTPException 401: If the API key is invalid
    """
    import secrets

    if not settings.support_api_key:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Support API not configured",
        )

    # Extract the token from HTTPAuthorizationCredentials
    token = credentials.credentials

    if not secrets.compare_digest(token, settings.support_api_key):
        logger.warning(
            "invalid_support_api_key",
            message="Invalid support API key provided",
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid support API key",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return token


# Commonly used dependencies
RequireAuth = Depends(require_auth())
RequireAdmin = Depends(require_role(UserRole.OWNER, UserRole.ADMIN))
RequireOwner = Depends(require_role(UserRole.OWNER))
RequireMember = Depends(require_role(UserRole.OWNER, UserRole.ADMIN, UserRole.MEMBER))
RequireOrgFeatures = Depends(require_org_features())
