"""Admin metrics and monitoring routes."""

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.models.admin import AdminUser
from app.models.user import Organization, User
from app.models.billing import Subscription, AccountTier
from app.models.cloud_account import CloudAccount
from app.models.scan import Scan, ScanStatus
from app.models.detection import Detection
from app.api.deps import require_permission

router = APIRouter(prefix="/metrics", tags=["Admin Metrics"])


class SystemHealthResponse(BaseModel):
    """System health metrics."""
    status: str
    api_latency_ms: float
    error_rate_percent: float
    active_scans: int
    queue_depth: int
    database_connections: int
    cache_hit_rate: float


class BusinessMetricsResponse(BaseModel):
    """Business metrics."""
    total_organizations: int
    active_organizations: int
    trial_organizations: int
    churned_30d: int

    total_users: int
    active_users_7d: int

    mrr_cents: int
    arr_cents: int

    tier_breakdown: dict


class UsageMetricsResponse(BaseModel):
    """Platform usage metrics."""
    scans_24h: int
    scans_7d: int
    scans_30d: int

    detections_discovered: int
    techniques_mapped: int

    cloud_accounts_total: int
    cloud_accounts_aws: int
    cloud_accounts_gcp: int


class SecurityMetricsResponse(BaseModel):
    """Security metrics."""
    failed_logins_24h: int
    locked_accounts: int
    mfa_enabled_percent: float
    suspicious_activity_count: int


@router.get("/system", response_model=SystemHealthResponse)
async def get_system_health(
    admin: AdminUser = Depends(require_permission("system:health")),
    db: AsyncSession = Depends(get_db),
):
    """Get system health metrics."""
    # Get active scans
    active_scans_result = await db.execute(
        select(func.count()).where(Scan.status == ScanStatus.RUNNING)
    )
    active_scans = active_scans_result.scalar() or 0

    # Get pending scans (queue)
    pending_scans_result = await db.execute(
        select(func.count()).where(Scan.status == ScanStatus.PENDING)
    )
    queue_depth = pending_scans_result.scalar() or 0

    # TODO: Get real metrics from monitoring system
    return SystemHealthResponse(
        status="healthy",
        api_latency_ms=45.0,  # TODO: Get from metrics
        error_rate_percent=0.02,  # TODO: Get from metrics
        active_scans=active_scans,
        queue_depth=queue_depth,
        database_connections=10,  # TODO: Get from pool
        cache_hit_rate=0.95,  # TODO: Get from Redis
    )


@router.get("/business", response_model=BusinessMetricsResponse)
async def get_business_metrics(
    admin: AdminUser = Depends(require_permission("metrics:read")),
    db: AsyncSession = Depends(get_db),
):
    """Get business metrics."""
    now = datetime.now(timezone.utc)
    seven_days_ago = now - timedelta(days=7)
    # Note: thirty_days_ago would be used for churn calculation when implemented

    # Total organizations
    total_orgs_result = await db.execute(select(func.count()).select_from(Organization))
    total_organizations = total_orgs_result.scalar() or 0

    # Active organizations
    active_orgs_result = await db.execute(
        select(func.count()).where(Organization.is_active.is_(True))
    )
    active_organizations = active_orgs_result.scalar() or 0

    # Total users
    total_users_result = await db.execute(select(func.count()).select_from(User))
    total_users = total_users_result.scalar() or 0

    # Active users (logged in within 7 days)
    active_users_result = await db.execute(
        select(func.count()).where(User.last_login_at >= seven_days_ago)
    )
    active_users_7d = active_users_result.scalar() or 0

    # Tier breakdown
    tier_breakdown = {}
    for tier in AccountTier:
        tier_count_result = await db.execute(
            select(func.count()).where(Subscription.tier == tier)
        )
        tier_breakdown[tier.value] = tier_count_result.scalar() or 0

    # Calculate MRR (simplified)
    # Free: $0, Subscriber: $29, Enterprise: $499
    subscriber_count = tier_breakdown.get("subscriber", 0)
    enterprise_count = tier_breakdown.get("enterprise", 0)
    mrr_cents = (subscriber_count * 2900) + (enterprise_count * 49900)

    return BusinessMetricsResponse(
        total_organizations=total_organizations,
        active_organizations=active_organizations,
        trial_organizations=tier_breakdown.get("free_scan", 0),
        churned_30d=0,  # TODO: Calculate from subscription history
        total_users=total_users,
        active_users_7d=active_users_7d,
        mrr_cents=mrr_cents,
        arr_cents=mrr_cents * 12,
        tier_breakdown=tier_breakdown,
    )


@router.get("/usage", response_model=UsageMetricsResponse)
async def get_usage_metrics(
    admin: AdminUser = Depends(require_permission("metrics:read")),
    db: AsyncSession = Depends(get_db),
):
    """Get platform usage metrics."""
    now = datetime.now(timezone.utc)
    one_day_ago = now - timedelta(days=1)
    seven_days_ago = now - timedelta(days=7)
    thirty_days_ago = now - timedelta(days=30)

    # Scans
    scans_24h_result = await db.execute(
        select(func.count()).where(Scan.created_at >= one_day_ago)
    )
    scans_24h = scans_24h_result.scalar() or 0

    scans_7d_result = await db.execute(
        select(func.count()).where(Scan.created_at >= seven_days_ago)
    )
    scans_7d = scans_7d_result.scalar() or 0

    scans_30d_result = await db.execute(
        select(func.count()).where(Scan.created_at >= thirty_days_ago)
    )
    scans_30d = scans_30d_result.scalar() or 0

    # Detections
    detections_result = await db.execute(select(func.count()).select_from(Detection))
    detections_discovered = detections_result.scalar() or 0

    # Cloud accounts
    accounts_result = await db.execute(select(func.count()).select_from(CloudAccount))
    cloud_accounts_total = accounts_result.scalar() or 0

    aws_accounts_result = await db.execute(
        select(func.count()).where(CloudAccount.provider == "aws")
    )
    cloud_accounts_aws = aws_accounts_result.scalar() or 0

    gcp_accounts_result = await db.execute(
        select(func.count()).where(CloudAccount.provider == "gcp")
    )
    cloud_accounts_gcp = gcp_accounts_result.scalar() or 0

    # Techniques mapped
    from app.models.mapping import DetectionMapping
    techniques_result = await db.execute(
        select(func.count(func.distinct(DetectionMapping.technique_id)))
    )
    techniques_mapped = techniques_result.scalar() or 0

    return UsageMetricsResponse(
        scans_24h=scans_24h,
        scans_7d=scans_7d,
        scans_30d=scans_30d,
        detections_discovered=detections_discovered,
        techniques_mapped=techniques_mapped,
        cloud_accounts_total=cloud_accounts_total,
        cloud_accounts_aws=cloud_accounts_aws,
        cloud_accounts_gcp=cloud_accounts_gcp,
    )


@router.get("/security", response_model=SecurityMetricsResponse)
async def get_security_metrics(
    admin: AdminUser = Depends(require_permission("metrics:security")),
    db: AsyncSession = Depends(get_db),
):
    """Get security metrics."""
    now = datetime.now(timezone.utc)
    one_day_ago = now - timedelta(days=1)

    # Failed logins (from audit log)
    from app.models.user import AuditLog, AuditLogAction
    failed_logins_result = await db.execute(
        select(func.count()).where(
            AuditLog.action == AuditLogAction.USER_LOGIN,
            AuditLog.success.is_(False),
            AuditLog.created_at >= one_day_ago,
        )
    )
    failed_logins_24h = failed_logins_result.scalar() or 0

    # Locked accounts
    locked_accounts_result = await db.execute(
        select(func.count()).where(User.locked_until > now)
    )
    locked_accounts = locked_accounts_result.scalar() or 0

    # MFA enabled percentage
    total_users_result = await db.execute(select(func.count()).select_from(User))
    total_users = total_users_result.scalar() or 1

    mfa_users_result = await db.execute(
        select(func.count()).where(User.mfa_enabled.is_(True))
    )
    mfa_users = mfa_users_result.scalar() or 0

    mfa_percent = (mfa_users / total_users) * 100 if total_users > 0 else 0

    # Suspicious activity (from security incidents)
    from app.models.admin import SecurityIncident, IncidentStatus
    suspicious_result = await db.execute(
        select(func.count()).where(
            SecurityIncident.status.in_([
                IncidentStatus.OPEN,
                IncidentStatus.INVESTIGATING,
            ])
        )
    )
    suspicious_activity_count = suspicious_result.scalar() or 0

    return SecurityMetricsResponse(
        failed_logins_24h=failed_logins_24h,
        locked_accounts=locked_accounts,
        mfa_enabled_percent=round(mfa_percent, 1),
        suspicious_activity_count=suspicious_activity_count,
    )
