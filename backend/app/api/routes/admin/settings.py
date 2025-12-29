"""Admin platform settings routes."""

from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.security import get_client_ip
from app.models.admin import AdminUser, AdminRole
from app.models.platform_settings import SettingCategory, SettingKeys
from app.services.platform_settings_service import get_platform_settings_service
from app.api.deps import require_permission

router = APIRouter(prefix="/settings", tags=["Admin Settings"])


# Request/Response schemas
class SettingResponse(BaseModel):
    """Setting response (secrets are masked)."""

    key: str
    value: Optional[str]  # Masked for secrets
    is_secret: bool
    category: str
    description: Optional[str]
    updated_at: str
    is_configured: bool  # True if value is set


class SettingListResponse(BaseModel):
    """List of settings."""

    items: list[SettingResponse]
    total: int


class UpdateSettingRequest(BaseModel):
    """Update setting request."""

    value: str
    reason: Optional[str] = None


class CreateSettingRequest(BaseModel):
    """Create setting request."""

    key: str
    value: str
    is_secret: bool = False
    category: str = "general"
    description: Optional[str] = None
    reason: Optional[str] = None


class StripeConfigResponse(BaseModel):
    """Stripe configuration response."""

    publishable_key: Optional[str]
    secret_key_configured: bool
    webhook_secret_configured: bool


class StripeConfigRequest(BaseModel):
    """Stripe configuration request."""

    publishable_key: Optional[str] = None
    secret_key: Optional[str] = None
    webhook_secret: Optional[str] = None
    reason: Optional[str] = None


class SettingAuditResponse(BaseModel):
    """Setting audit log entry."""

    id: str
    setting_key: str
    action: str
    changed_by_id: str
    changed_at: str
    ip_address: Optional[str]
    reason: Optional[str]


def _setting_to_response(setting) -> SettingResponse:
    """Convert setting model to response."""
    if setting.is_secret:
        value = setting.masked_value
        is_configured = setting.value_encrypted is not None
    else:
        value = setting.value_text
        is_configured = setting.value_text is not None

    return SettingResponse(
        key=setting.key,
        value=value,
        is_secret=setting.is_secret,
        category=setting.category,
        description=setting.description,
        updated_at=setting.updated_at.isoformat() if setting.updated_at else "",
        is_configured=is_configured,
    )


@router.get("", response_model=SettingListResponse)
async def list_settings(
    category: Optional[str] = None,
    admin: AdminUser = Depends(require_permission("settings:read")),
    db: AsyncSession = Depends(get_db),
) -> SettingListResponse:
    """List all platform settings.

    Secrets are masked - only shows if configured, not the actual value.
    """
    service = get_platform_settings_service(db)

    if category:
        try:
            cat = SettingCategory(category)
            settings_list = await service.get_settings_by_category(cat)
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid category: {category}",
            )
    else:
        settings_list = await service.get_all_settings()

    items = [_setting_to_response(s) for s in settings_list]

    return SettingListResponse(items=items, total=len(items))


@router.get("/{key}", response_model=SettingResponse)
async def get_setting(
    key: str,
    admin: AdminUser = Depends(require_permission("settings:read")),
    db: AsyncSession = Depends(get_db),
) -> SettingResponse:
    """Get a single setting by key."""
    service = get_platform_settings_service(db)
    setting = await service.get_setting(key)

    if not setting:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=f"Setting not found: {key}"
        )

    return _setting_to_response(setting)


@router.put("/{key}")
async def update_setting(
    key: str,
    body: UpdateSettingRequest,
    request: Request,
    admin: AdminUser = Depends(require_permission("settings:write")),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Update a setting value.

    For secrets in billing/auth categories, requires super_admin role.
    """
    service = get_platform_settings_service(db)
    setting = await service.get_setting(key)

    if not setting:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=f"Setting not found: {key}"
        )

    # Check if setting is restricted to super_admin
    if setting.is_secret and setting.category in [
        SettingCategory.BILLING.value,
        SettingCategory.AUTH.value,
    ]:
        if admin.role != AdminRole.SUPER_ADMIN:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Only super_admin can modify billing/auth secrets",
            )

    ip_address = get_client_ip(request) or "unknown"

    updated = await service.set_setting(
        key=key,
        value=body.value,
        admin=admin,
        ip_address=ip_address,
        reason=body.reason,
        is_secret=setting.is_secret,
        category=setting.category,
        description=setting.description,
    )

    return _setting_to_response(updated)


@router.post("")
async def create_setting(
    body: CreateSettingRequest,
    request: Request,
    admin: AdminUser = Depends(require_permission("settings:write")),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Create a new setting.

    Requires super_admin for secrets in billing/auth categories.
    """
    service = get_platform_settings_service(db)

    # Check if already exists
    existing = await service.get_setting(body.key)
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Setting already exists: {body.key}",
        )

    # Check if restricted category
    if body.is_secret and body.category in [
        SettingCategory.BILLING.value,
        SettingCategory.AUTH.value,
    ]:
        if admin.role != AdminRole.SUPER_ADMIN:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Only super_admin can create billing/auth secrets",
            )

    ip_address = get_client_ip(request) or "unknown"

    setting = await service.set_setting(
        key=body.key,
        value=body.value,
        admin=admin,
        ip_address=ip_address,
        reason=body.reason,
        is_secret=body.is_secret,
        category=body.category,
        description=body.description,
    )

    return _setting_to_response(setting)


@router.delete("/{key}")
async def delete_setting(
    key: str,
    request: Request,
    reason: Optional[str] = None,
    admin: AdminUser = Depends(require_permission("settings:delete")),
    db: AsyncSession = Depends(get_db),
) -> None:
    """Delete a setting.

    Requires super_admin role.
    """
    if admin.role != AdminRole.SUPER_ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only super_admin can delete settings",
        )

    service = get_platform_settings_service(db)
    ip_address = get_client_ip(request) or "unknown"

    deleted = await service.delete_setting(
        key=key,
        admin=admin,
        ip_address=ip_address,
        reason=reason,
    )

    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=f"Setting not found: {key}"
        )

    return {"message": f"Setting deleted: {key}"}


# Stripe-specific endpoints
@router.get("/billing/stripe", response_model=StripeConfigResponse)
async def get_stripe_config(
    admin: AdminUser = Depends(require_permission("settings:read")),
    db: AsyncSession = Depends(get_db),
) -> StripeConfigResponse:
    """Get Stripe configuration status."""
    service = get_platform_settings_service(db)

    publishable = await service.get_setting(SettingKeys.STRIPE_PUBLISHABLE_KEY)
    secret = await service.get_setting(SettingKeys.STRIPE_SECRET_KEY)
    webhook = await service.get_setting(SettingKeys.STRIPE_WEBHOOK_SECRET)

    return StripeConfigResponse(
        publishable_key=publishable.value_text if publishable else None,
        secret_key_configured=secret is not None and secret.value_encrypted is not None,
        webhook_secret_configured=webhook is not None
        and webhook.value_encrypted is not None,
    )


@router.put("/billing/stripe")
async def update_stripe_config(
    body: StripeConfigRequest,
    request: Request,
    admin: AdminUser = Depends(require_permission("settings:write")),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Update Stripe configuration.

    Requires super_admin role.
    """
    if admin.role != AdminRole.SUPER_ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only super_admin can modify Stripe configuration",
        )

    service = get_platform_settings_service(db)
    ip_address = get_client_ip(request) or "unknown"
    updated = {}

    if body.publishable_key is not None:
        await service.set_setting(
            key=SettingKeys.STRIPE_PUBLISHABLE_KEY,
            value=body.publishable_key,
            admin=admin,
            ip_address=ip_address,
            reason=body.reason,
            is_secret=False,
            category=SettingCategory.BILLING.value,
            description="Stripe Publishable Key",
        )
        updated["publishable_key"] = True

    if body.secret_key is not None:
        await service.set_setting(
            key=SettingKeys.STRIPE_SECRET_KEY,
            value=body.secret_key,
            admin=admin,
            ip_address=ip_address,
            reason=body.reason,
            is_secret=True,
            category=SettingCategory.BILLING.value,
            description="Stripe Secret Key",
        )
        updated["secret_key"] = True

    if body.webhook_secret is not None:
        await service.set_setting(
            key=SettingKeys.STRIPE_WEBHOOK_SECRET,
            value=body.webhook_secret,
            admin=admin,
            ip_address=ip_address,
            reason=body.reason,
            is_secret=True,
            category=SettingCategory.BILLING.value,
            description="Stripe Webhook Secret",
        )
        updated["webhook_secret"] = True

    return {"message": "Stripe configuration updated", "updated": updated}


@router.get("/audit", response_model=list[SettingAuditResponse])
async def get_settings_audit(
    key: Optional[str] = None,
    limit: int = 100,
    admin: AdminUser = Depends(require_permission("settings:audit")),
    db: AsyncSession = Depends(get_db),
) -> list[SettingAuditResponse]:
    """Get audit history for settings changes."""
    service = get_platform_settings_service(db)
    audits = await service.get_audit_history(key=key, limit=limit)

    return [
        SettingAuditResponse(
            id=str(a.id),
            setting_key=a.setting_key,
            action=a.action,
            changed_by_id=str(a.changed_by_id),
            changed_at=a.changed_at.isoformat() if a.changed_at else "",
            ip_address=a.ip_address,
            reason=a.reason,
        )
        for a in audits
    ]


@router.post("/seed")
async def seed_default_settings(
    admin: AdminUser = Depends(require_permission("settings:write")),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Seed default platform settings.

    Creates default settings entries if they don't exist.
    Requires super_admin role.
    """
    if admin.role != AdminRole.SUPER_ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only super_admin can seed settings",
        )

    service = get_platform_settings_service(db)
    count = await service.seed_default_settings(admin)

    return {"message": f"Seeded {count} default settings"}


@router.post("/seed-mitre")
async def seed_mitre_data(
    admin: AdminUser = Depends(require_permission("settings:write")),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Seed MITRE ATT&CK tactics and techniques.

    Populates the database with MITRE ATT&CK framework data.
    Requires super_admin role.
    """
    if admin.role != AdminRole.SUPER_ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only super_admin can seed MITRE data",
        )

    from app.scripts.seed_mitre import TACTICS, TECHNIQUES
    from app.models.mitre import Tactic, Technique
    from sqlalchemy import select
    from uuid import uuid4
    from datetime import datetime, timezone

    now = datetime.now(timezone.utc)

    # Get existing tactics
    existing_tactics_result = await db.execute(select(Tactic))
    existing_tactics = {t.tactic_id: t for t in existing_tactics_result.scalars().all()}

    # Insert missing tactics
    tactics_added = 0
    for tactic_id, name, short_name, display_order in TACTICS:
        if tactic_id not in existing_tactics:
            tactic = Tactic(
                id=uuid4(),
                tactic_id=tactic_id,
                name=name,
                short_name=short_name,
                display_order=display_order,
                mitre_version="14.1",
                created_at=now,
            )
            db.add(tactic)
            existing_tactics[tactic_id] = tactic
            tactics_added += 1

    await db.flush()

    # Get existing techniques
    existing_techniques_result = await db.execute(select(Technique))
    existing_techniques = {
        t.technique_id: t for t in existing_techniques_result.scalars().all()
    }

    # Insert missing techniques
    techniques_added = 0
    for technique_id, name, tactic_id, description in TECHNIQUES:
        if technique_id not in existing_techniques:
            tactic = existing_tactics.get(tactic_id)
            if not tactic:
                continue

            is_subtechnique = "." in technique_id
            parent_id = None
            if is_subtechnique:
                parent_tech_id = technique_id.split(".")[0]
                parent = existing_techniques.get(parent_tech_id)
                if parent:
                    parent_id = parent.id

            technique = Technique(
                id=uuid4(),
                technique_id=technique_id,
                name=name,
                description=description,
                tactic_id=tactic.id,
                parent_technique_id=parent_id,
                platforms=["AWS", "Azure", "GCP", "IaaS"],
                mitre_version="14.1",
                is_subtechnique=is_subtechnique,
                created_at=now,
                updated_at=now,
            )
            db.add(technique)
            existing_techniques[technique_id] = technique
            techniques_added += 1

    await db.commit()

    return {
        "message": "Seeded MITRE data",
        "tactics_added": tactics_added,
        "techniques_added": techniques_added,
        "total_tactics": len(existing_tactics),
        "total_techniques": len(existing_techniques),
    }


@router.post("/seed-compliance")
async def seed_compliance_data(
    force_reload: bool = False,
    admin: AdminUser = Depends(require_permission("settings:write")),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Seed or reload compliance framework data.

    Loads NIST 800-53 and CIS Controls v8 from JSON files.
    Use force_reload=true to clear and reload existing data.
    Requires super_admin role.
    """
    if admin.role != AdminRole.SUPER_ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only super_admin can seed compliance data",
        )

    from sqlalchemy import func

    from app.data.compliance_mappings.loader import ComplianceMappingLoader
    from app.models.compliance import ComplianceCoverageSnapshot
    from app.models.mitre import Technique

    # Check if MITRE techniques exist - required for technique mappings
    technique_count_result = await db.execute(select(func.count(Technique.id)))
    technique_count = technique_count_result.scalar() or 0

    if technique_count == 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="MITRE data must be seeded first. Please seed MITRE data before loading compliance frameworks.",
        )

    loader = ComplianceMappingLoader(db)

    if force_reload:
        # Clear existing data first, including orphaned compliance snapshots
        await db.execute(ComplianceCoverageSnapshot.__table__.delete())
        await loader.clear_all()
        await db.commit()

    # Load all frameworks
    results = await loader.load_all()
    await db.commit()

    return {
        "message": "Compliance data seeded",
        "force_reload": force_reload,
        "frameworks_loaded": results["frameworks_loaded"],
        "frameworks_skipped": results["frameworks_skipped"],
        "total_controls": results["total_controls"],
        "total_mappings": results["total_mappings"],
        "mitre_techniques_available": technique_count,
    }
