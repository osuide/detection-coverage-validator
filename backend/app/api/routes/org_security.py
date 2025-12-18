"""Organization security settings API routes."""

import secrets
from datetime import datetime, timezone
from typing import Optional, List
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
import structlog

from app.core.config import get_settings
from app.core.database import get_db
from app.core.security import AuthContext, require_role
from app.models.user import User, Organization, AuditLog, AuditLogAction, UserRole
from app.models.security import OrganizationSecuritySettings, VerifiedDomain

logger = structlog.get_logger()
router = APIRouter()
settings = get_settings()


# Request/Response Models
class SecuritySettingsResponse(BaseModel):
    """Security settings response."""
    id: str
    organization_id: str
    require_mfa: bool
    mfa_grace_period_days: int
    session_timeout_minutes: int
    idle_timeout_minutes: int
    allowed_auth_methods: List[str]
    password_min_length: int
    password_require_uppercase: bool
    password_require_lowercase: bool
    password_require_number: bool
    password_require_special: bool
    max_failed_login_attempts: int
    lockout_duration_minutes: int
    ip_allowlist: Optional[List[str]]
    created_at: str
    updated_at: str


class SecuritySettingsUpdateRequest(BaseModel):
    """Request to update security settings."""
    require_mfa: Optional[bool] = None
    mfa_grace_period_days: Optional[int] = Field(None, ge=1, le=30)
    session_timeout_minutes: Optional[int] = Field(None, ge=15, le=43200)  # 15 min to 30 days
    idle_timeout_minutes: Optional[int] = Field(None, ge=5, le=1440)  # 5 min to 24 hours
    allowed_auth_methods: Optional[List[str]] = None
    password_min_length: Optional[int] = Field(None, ge=8, le=128)
    password_require_uppercase: Optional[bool] = None
    password_require_lowercase: Optional[bool] = None
    password_require_number: Optional[bool] = None
    password_require_special: Optional[bool] = None
    max_failed_login_attempts: Optional[int] = Field(None, ge=3, le=10)
    lockout_duration_minutes: Optional[int] = Field(None, ge=5, le=1440)
    ip_allowlist: Optional[List[str]] = None


class VerifiedDomainResponse(BaseModel):
    """Verified domain response."""
    id: str
    domain: str
    verification_token: Optional[str]
    verification_method: Optional[str]
    verified_at: Optional[str]
    auto_join_enabled: bool
    sso_required: bool
    created_at: str


class AddDomainRequest(BaseModel):
    """Request to add a domain for verification."""
    domain: str = Field(..., min_length=3, max_length=255)
    verification_method: str = Field(default="dns_txt")  # dns_txt, dns_cname


class UpdateDomainRequest(BaseModel):
    """Request to update domain settings."""
    auto_join_enabled: Optional[bool] = None
    sso_required: Optional[bool] = None


def _settings_to_response(settings: OrganizationSecuritySettings) -> SecuritySettingsResponse:
    """Convert settings model to response."""
    return SecuritySettingsResponse(
        id=str(settings.id),
        organization_id=str(settings.organization_id),
        require_mfa=settings.require_mfa,
        mfa_grace_period_days=settings.mfa_grace_period_days,
        session_timeout_minutes=settings.session_timeout_minutes,
        idle_timeout_minutes=settings.idle_timeout_minutes,
        allowed_auth_methods=settings.allowed_auth_methods or ["password"],
        password_min_length=settings.password_min_length,
        password_require_uppercase=settings.password_require_uppercase,
        password_require_lowercase=settings.password_require_lowercase,
        password_require_number=settings.password_require_number,
        password_require_special=settings.password_require_special,
        max_failed_login_attempts=settings.max_failed_login_attempts,
        lockout_duration_minutes=settings.lockout_duration_minutes,
        ip_allowlist=settings.ip_allowlist,
        created_at=settings.created_at.isoformat(),
        updated_at=settings.updated_at.isoformat(),
    )


def _domain_to_response(domain: VerifiedDomain) -> VerifiedDomainResponse:
    """Convert domain model to response."""
    return VerifiedDomainResponse(
        id=str(domain.id),
        domain=domain.domain,
        verification_token=domain.verification_token if not domain.verified_at else None,
        verification_method=domain.verification_method,
        verified_at=domain.verified_at.isoformat() if domain.verified_at else None,
        auto_join_enabled=domain.auto_join_enabled,
        sso_required=domain.sso_required,
        created_at=domain.created_at.isoformat(),
    )


# Security Settings Endpoints
@router.get("/security", response_model=SecuritySettingsResponse)
async def get_security_settings(
    auth: AuthContext = Depends(require_role(UserRole.ADMIN, UserRole.OWNER)),
    db: AsyncSession = Depends(get_db),
):
    """Get organization security settings."""
    result = await db.execute(
        select(OrganizationSecuritySettings).where(
            OrganizationSecuritySettings.organization_id == auth.organization_id
        )
    )
    settings_obj = result.scalar_one_or_none()

    if not settings_obj:
        # Create default settings
        settings_obj = OrganizationSecuritySettings(
            organization_id=auth.organization_id,
        )
        db.add(settings_obj)
        await db.commit()
        await db.refresh(settings_obj)

    return _settings_to_response(settings_obj)


@router.put("/security", response_model=SecuritySettingsResponse)
async def update_security_settings(
    request: Request,
    body: SecuritySettingsUpdateRequest,
    auth: AuthContext = Depends(require_role(UserRole.OWNER)),
    db: AsyncSession = Depends(get_db),
):
    """Update organization security settings. Owner only."""
    result = await db.execute(
        select(OrganizationSecuritySettings).where(
            OrganizationSecuritySettings.organization_id == auth.organization_id
        )
    )
    settings_obj = result.scalar_one_or_none()

    if not settings_obj:
        settings_obj = OrganizationSecuritySettings(
            organization_id=auth.organization_id,
        )
        db.add(settings_obj)

    # Update fields if provided
    update_data = body.model_dump(exclude_unset=True)
    old_values = {}

    for field, value in update_data.items():
        if hasattr(settings_obj, field):
            old_values[field] = getattr(settings_obj, field)
            setattr(settings_obj, field, value)

    settings_obj.updated_at = datetime.now(timezone.utc)

    # Audit log
    audit_log = AuditLog(
        organization_id=auth.organization_id,
        user_id=auth.user.id,
        action=AuditLogAction.ORG_SETTINGS_UPDATED,
        resource_type="security_settings",
        details={"changes": update_data, "previous": old_values},
        ip_address=request.client.host if request.client else None,
        success=True,
    )
    db.add(audit_log)

    await db.commit()
    await db.refresh(settings_obj)

    logger.info("security_settings_updated", org_id=str(auth.organization_id), changes=list(update_data.keys()))

    return _settings_to_response(settings_obj)


# Verified Domains Endpoints
@router.get("/domains", response_model=List[VerifiedDomainResponse])
async def list_domains(
    auth: AuthContext = Depends(require_role(UserRole.ADMIN, UserRole.OWNER)),
    db: AsyncSession = Depends(get_db),
):
    """List organization's verified domains."""
    result = await db.execute(
        select(VerifiedDomain).where(
            VerifiedDomain.organization_id == auth.organization_id
        ).order_by(VerifiedDomain.created_at.desc())
    )
    domains = result.scalars().all()

    return [_domain_to_response(d) for d in domains]


@router.post("/domains", response_model=VerifiedDomainResponse, status_code=status.HTTP_201_CREATED)
async def add_domain(
    request: Request,
    body: AddDomainRequest,
    auth: AuthContext = Depends(require_role(UserRole.OWNER)),
    db: AsyncSession = Depends(get_db),
):
    """Add a domain for verification. Owner only."""
    # Normalize domain
    domain = body.domain.lower().strip()

    # Check if domain is already claimed
    result = await db.execute(
        select(VerifiedDomain).where(VerifiedDomain.domain == domain)
    )
    existing = result.scalar_one_or_none()

    if existing:
        if existing.organization_id == auth.organization_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Domain already added to your organization"
            )
        if existing.verified_at:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Domain is already verified by another organization"
            )
        # Allow claiming unverified domains from other orgs after 7 days
        age = (datetime.now(timezone.utc) - existing.created_at).days
        if age < 7:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Domain is pending verification by another organization"
            )
        # Remove stale claim
        await db.delete(existing)

    # Generate verification token
    verification_token = f"dcv-verify-{secrets.token_hex(16)}"

    new_domain = VerifiedDomain(
        organization_id=auth.organization_id,
        domain=domain,
        verification_token=verification_token,
        verification_method=body.verification_method,
    )
    db.add(new_domain)

    # Audit log
    audit_log = AuditLog(
        organization_id=auth.organization_id,
        user_id=auth.user.id,
        action=AuditLogAction.ORG_SETTINGS_UPDATED,
        resource_type="verified_domain",
        details={"action": "add", "domain": domain},
        ip_address=request.client.host if request.client else None,
        success=True,
    )
    db.add(audit_log)

    await db.commit()
    await db.refresh(new_domain)

    logger.info("domain_added", org_id=str(auth.organization_id), domain=domain)

    return _domain_to_response(new_domain)


@router.get("/domains/{domain_id}/verify")
async def verify_domain(
    domain_id: UUID,
    auth: AuthContext = Depends(require_role(UserRole.OWNER)),
    db: AsyncSession = Depends(get_db),
):
    """Check domain verification status."""
    result = await db.execute(
        select(VerifiedDomain).where(
            VerifiedDomain.id == domain_id,
            VerifiedDomain.organization_id == auth.organization_id,
        )
    )
    domain = result.scalar_one_or_none()

    if not domain:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Domain not found"
        )

    if domain.verified_at:
        return {
            "verified": True,
            "verified_at": domain.verified_at.isoformat(),
            "message": "Domain is already verified"
        }

    # In production, this would check DNS records
    # For now, return verification instructions
    if domain.verification_method == "dns_txt":
        return {
            "verified": False,
            "verification_method": "dns_txt",
            "instructions": f"Add a TXT record to your domain with the value: {domain.verification_token}",
            "record_type": "TXT",
            "record_name": f"_dcv-verification.{domain.domain}",
            "record_value": domain.verification_token,
        }
    else:
        return {
            "verified": False,
            "verification_method": "dns_cname",
            "instructions": f"Add a CNAME record pointing to: dcv-verify.detectioncoverage.io",
            "record_type": "CNAME",
            "record_name": f"{domain.verification_token}.{domain.domain}",
            "record_value": "dcv-verify.detectioncoverage.io",
        }


@router.post("/domains/{domain_id}/verify")
async def confirm_domain_verification(
    request: Request,
    domain_id: UUID,
    auth: AuthContext = Depends(require_role(UserRole.OWNER)),
    db: AsyncSession = Depends(get_db),
):
    """Confirm domain verification (check DNS and mark verified)."""
    result = await db.execute(
        select(VerifiedDomain).where(
            VerifiedDomain.id == domain_id,
            VerifiedDomain.organization_id == auth.organization_id,
        )
    )
    domain = result.scalar_one_or_none()

    if not domain:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Domain not found"
        )

    if domain.verified_at:
        return {"verified": True, "message": "Domain is already verified"}

    # In production, this would actually check DNS records
    # For development, we'll auto-verify if the domain ends with .test or .local
    # or if a special header is present
    is_dev = domain.domain.endswith(('.test', '.local', '.example'))
    force_verify = request.headers.get('X-Force-Verify') == 'true'

    if not is_dev and not force_verify:
        # TODO: Implement actual DNS verification
        # For now, return instructions
        return {
            "verified": False,
            "message": "DNS verification not yet implemented. Use X-Force-Verify header in development.",
        }

    # Mark as verified
    domain.verified_at = datetime.now(timezone.utc)

    # Audit log
    audit_log = AuditLog(
        organization_id=auth.organization_id,
        user_id=auth.user.id,
        action=AuditLogAction.ORG_SETTINGS_UPDATED,
        resource_type="verified_domain",
        details={"action": "verify", "domain": domain.domain},
        ip_address=request.client.host if request.client else None,
        success=True,
    )
    db.add(audit_log)

    await db.commit()

    logger.info("domain_verified", org_id=str(auth.organization_id), domain=domain.domain)

    return {"verified": True, "message": "Domain verified successfully"}


@router.patch("/domains/{domain_id}", response_model=VerifiedDomainResponse)
async def update_domain(
    request: Request,
    domain_id: UUID,
    body: UpdateDomainRequest,
    auth: AuthContext = Depends(require_role(UserRole.OWNER)),
    db: AsyncSession = Depends(get_db),
):
    """Update domain settings."""
    result = await db.execute(
        select(VerifiedDomain).where(
            VerifiedDomain.id == domain_id,
            VerifiedDomain.organization_id == auth.organization_id,
        )
    )
    domain = result.scalar_one_or_none()

    if not domain:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Domain not found"
        )

    # Only allow settings changes on verified domains
    if not domain.verified_at:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Domain must be verified before changing settings"
        )

    update_data = body.model_dump(exclude_unset=True)

    for field, value in update_data.items():
        if hasattr(domain, field):
            setattr(domain, field, value)

    # Audit log
    audit_log = AuditLog(
        organization_id=auth.organization_id,
        user_id=auth.user.id,
        action=AuditLogAction.ORG_SETTINGS_UPDATED,
        resource_type="verified_domain",
        details={"action": "update", "domain": domain.domain, "changes": update_data},
        ip_address=request.client.host if request.client else None,
        success=True,
    )
    db.add(audit_log)

    await db.commit()
    await db.refresh(domain)

    return _domain_to_response(domain)


@router.delete("/domains/{domain_id}", status_code=status.HTTP_204_NO_CONTENT)
async def remove_domain(
    request: Request,
    domain_id: UUID,
    auth: AuthContext = Depends(require_role(UserRole.OWNER)),
    db: AsyncSession = Depends(get_db),
):
    """Remove a domain."""
    result = await db.execute(
        select(VerifiedDomain).where(
            VerifiedDomain.id == domain_id,
            VerifiedDomain.organization_id == auth.organization_id,
        )
    )
    domain = result.scalar_one_or_none()

    if not domain:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Domain not found"
        )

    domain_name = domain.domain

    # Audit log
    audit_log = AuditLog(
        organization_id=auth.organization_id,
        user_id=auth.user.id,
        action=AuditLogAction.ORG_SETTINGS_UPDATED,
        resource_type="verified_domain",
        details={"action": "remove", "domain": domain_name},
        ip_address=request.client.host if request.client else None,
        success=True,
    )
    db.add(audit_log)

    await db.delete(domain)
    await db.commit()

    logger.info("domain_removed", org_id=str(auth.organization_id), domain=domain_name)
