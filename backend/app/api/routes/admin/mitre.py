"""Admin MITRE ATT&CK threat intelligence routes."""

from typing import Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.models.admin import AdminUser
from app.api.deps import require_permission
from app.schemas.mitre_admin import (
    MitreStatusResponse,
    MitreSyncResponse,
    MitreSyncHistoryResponse,
    MitreScheduleResponse,
    UpdateScheduleRequest,
    ThreatGroupSummary,
    CampaignSummary,
    MitreStatisticsResponse,
    PaginatedResponse,
)
from app.services.mitre_sync_service import MitreSyncService
from app.services.mitre_threat_service import MitreThreatService
from app.services.platform_settings_service import PlatformSettingsService
from app.services.scheduler_service import scheduler_service
from app.models.mitre_threat import SyncStatus, SyncTriggerType
from app.models.platform_settings import SettingKeys

router = APIRouter(prefix="/mitre", tags=["Admin MITRE"])


@router.get("/status", response_model=MitreStatusResponse)
async def get_mitre_status(
    admin: AdminUser = Depends(require_permission("settings:read")),
    db: AsyncSession = Depends(get_db),
) -> MitreStatusResponse:
    """
    Get MITRE data sync status and version information.

    Returns current sync state, version info, and statistics.
    """
    threat_service = MitreThreatService(db)
    stats = await threat_service.get_statistics()

    # Get last sync info
    sync_service = MitreSyncService(db)
    history = await sync_service.get_sync_history(limit=1)
    last_sync = history[0] if history else None

    return MitreStatusResponse(
        is_synced=stats.get("is_synced", False),
        mitre_version=stats.get("mitre_version"),
        stix_version=stats.get("stix_version"),
        last_sync_at=stats.get("last_sync_at"),
        last_sync_status=last_sync.status if last_sync else None,
        total_groups=stats.get("total_groups", 0),
        total_campaigns=stats.get("total_campaigns", 0),
        total_software=stats.get("total_software", 0),
        total_relationships=stats.get("total_relationships", 0),
        next_scheduled_sync=None,  # TODO: Implement scheduler integration
        schedule_enabled=False,  # TODO: Implement scheduler integration
    )


@router.post("/sync", response_model=MitreSyncResponse)
async def trigger_sync(
    background_tasks: BackgroundTasks,
    admin: AdminUser = Depends(require_permission("settings:write")),
    db: AsyncSession = Depends(get_db),
) -> MitreSyncResponse:
    """
    Trigger a manual MITRE data sync.

    Downloads latest MITRE ATT&CK STIX data and updates the database.
    This operation runs in the background and may take 1-2 minutes.

    Requires settings:write permission (SUPER_ADMIN or PLATFORM_ADMIN).
    """
    sync_service = MitreSyncService(db)

    # Check if a sync is already running
    history = await sync_service.get_sync_history(limit=1)
    if history and history[0].status == SyncStatus.RUNNING.value:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="A sync operation is already in progress",
        )

    # Create sync record and start background task
    try:
        sync_history = await sync_service.sync_all(
            admin_id=admin.id,
            trigger_type=SyncTriggerType.MANUAL.value,
        )

        return MitreSyncResponse(
            sync_id=str(sync_history.id),
            status=(
                "completed"
                if sync_history.status == SyncStatus.COMPLETED.value
                else sync_history.status
            ),
            message=(
                "MITRE data sync completed successfully"
                if sync_history.status == SyncStatus.COMPLETED.value
                else "MITRE data sync is running"
            ),
            estimated_duration_seconds=60,
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Sync failed: {str(e)}",
        )


@router.get("/sync/history", response_model=list[MitreSyncHistoryResponse])
async def get_sync_history(
    limit: int = Query(20, le=100, description="Maximum number of results"),
    admin: AdminUser = Depends(require_permission("settings:read")),
    db: AsyncSession = Depends(get_db),
) -> list[MitreSyncHistoryResponse]:
    """
    Get MITRE sync history.

    Returns recent sync operations with their status and statistics.
    """
    sync_service = MitreSyncService(db)
    history = await sync_service.get_sync_history(limit=limit)

    return [
        MitreSyncHistoryResponse(
            id=str(h.id),
            started_at=h.started_at,
            completed_at=h.completed_at,
            status=h.status,
            mitre_version=h.mitre_version,
            stix_version=h.stix_version,
            trigger_type=h.trigger_type,
            triggered_by_email=h.triggered_by.email if h.triggered_by else None,
            stats=h.stats or {},
            error_message=h.error_message,
            duration_seconds=h.duration_seconds,
        )
        for h in history
    ]


@router.get("/schedule", response_model=MitreScheduleResponse)
async def get_sync_schedule(
    admin: AdminUser = Depends(require_permission("settings:read")),
    db: AsyncSession = Depends(get_db),
) -> MitreScheduleResponse:
    """
    Get current MITRE sync schedule configuration.
    """
    settings_service = PlatformSettingsService(db)

    # Read schedule settings with error handling
    try:
        enabled_str = await settings_service.get_setting_value(
            SettingKeys.MITRE_SYNC_ENABLED
        )
        cron_expression = await settings_service.get_setting_value(
            SettingKeys.MITRE_SYNC_CRON
        )
    except Exception:
        # Settings don't exist yet, return defaults
        enabled_str = None
        cron_expression = None

    enabled = enabled_str is not None and enabled_str.lower() in ("true", "1", "yes")

    # Get next run time from scheduler if enabled
    next_run_at = None
    if enabled:
        try:
            job_status = scheduler_service.get_mitre_sync_job_status()
            if job_status and job_status.get("next_run_time"):
                next_run_at = job_status["next_run_time"]
        except Exception:
            # Scheduler might not be running, ignore
            pass

    return MitreScheduleResponse(
        enabled=enabled,
        cron_expression=cron_expression,
        next_run_at=next_run_at,
        timezone="UTC",
    )


@router.put("/schedule", response_model=MitreScheduleResponse)
async def update_sync_schedule(
    body: UpdateScheduleRequest,
    admin: AdminUser = Depends(require_permission("settings:write")),
    db: AsyncSession = Depends(get_db),
) -> MitreScheduleResponse:
    """
    Update MITRE sync schedule.

    Set a cron expression to schedule automatic syncs.
    Recommended: Weekly on Sundays at midnight UTC ("0 0 * * 0").

    Requires settings:write permission (SUPER_ADMIN or PLATFORM_ADMIN).
    """
    if body.enabled and not body.cron_expression:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="cron_expression is required when enabling schedule",
        )

    # Validate cron expression format
    if body.cron_expression:
        parts = body.cron_expression.split()
        if len(parts) != 5:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid cron expression. Expected 5 parts: minute hour day month day_of_week",
            )

    settings_service = PlatformSettingsService(db)

    # Save schedule settings
    await settings_service.set_setting(
        key=SettingKeys.MITRE_SYNC_ENABLED,
        value="true" if body.enabled else "false",
        admin=admin,
        category="general",
        description="Enable automatic MITRE ATT&CK data sync",
    )

    if body.cron_expression:
        await settings_service.set_setting(
            key=SettingKeys.MITRE_SYNC_CRON,
            value=body.cron_expression,
            admin=admin,
            category="general",
            description="Cron expression for MITRE sync schedule",
        )

    # Update scheduler job (best effort - scheduler might not be running)
    next_run_at = None
    try:
        if body.enabled and body.cron_expression:
            next_run_at = await scheduler_service.update_mitre_sync_schedule(
                body.cron_expression
            )
        else:
            await scheduler_service.remove_mitre_sync_schedule()
    except Exception:
        # Scheduler might not be running in all environments
        pass

    return MitreScheduleResponse(
        enabled=body.enabled,
        cron_expression=body.cron_expression,
        next_run_at=next_run_at,
        timezone="UTC",
    )


@router.get("/groups", response_model=PaginatedResponse)
async def list_threat_groups(
    search: Optional[str] = Query(None, description="Search by name or alias"),
    skip: int = Query(0, ge=0, description="Number of items to skip"),
    limit: int = Query(50, le=100, description="Maximum number of items"),
    admin: AdminUser = Depends(require_permission("settings:read")),
    db: AsyncSession = Depends(get_db),
) -> PaginatedResponse:
    """
    Browse MITRE threat groups.

    Lists all threat actor groups with optional search filtering.
    """
    threat_service = MitreThreatService(db)

    if search:
        groups = await threat_service.search_groups(search, limit=limit)
        total = len(groups)
    else:
        groups, total = await threat_service.get_all_groups(skip=skip, limit=limit)

    items = [
        ThreatGroupSummary(
            id=g.id,
            external_id=g.external_id,
            name=g.name,
            aliases=g.aliases,
            first_seen=g.first_seen,
            last_seen=g.last_seen,
            techniques_count=0,  # TODO: Count from relationships
            mitre_url=g.mitre_url,
        )
        for g in groups
    ]

    return PaginatedResponse(
        items=items,
        total=total,
        skip=skip,
        limit=limit,
        has_more=(skip + len(items)) < total,
    )


@router.get("/campaigns", response_model=PaginatedResponse)
async def list_campaigns(
    search: Optional[str] = Query(None, description="Search by name or external ID"),
    sort_by: str = Query("last_seen", description="Field to sort by"),
    sort_order: str = Query("desc", regex="^(asc|desc)$", description="Sort order"),
    skip: int = Query(0, ge=0, description="Number of items to skip"),
    limit: int = Query(50, le=100, description="Maximum number of items"),
    admin: AdminUser = Depends(require_permission("settings:read")),
    db: AsyncSession = Depends(get_db),
) -> PaginatedResponse:
    """
    Browse MITRE campaigns.

    Lists all attack campaigns with search and sorting support.

    Sort fields: name, external_id, first_seen, last_seen (default)
    """
    threat_service = MitreThreatService(db)
    campaigns, total = await threat_service.get_all_campaigns(
        skip=skip,
        limit=limit,
        search=search,
        sort_by=sort_by,
        sort_order=sort_order,
    )

    items = [
        CampaignSummary(
            id=c.id,
            external_id=c.external_id,
            name=c.name,
            first_seen=c.first_seen,
            last_seen=c.last_seen,
            techniques_count=0,  # TODO: Count from relationships
            mitre_url=c.mitre_url,
        )
        for c in campaigns
    ]

    return PaginatedResponse(
        items=items,
        total=total,
        skip=skip,
        limit=limit,
        has_more=(skip + len(items)) < total,
    )


@router.get("/statistics", response_model=MitreStatisticsResponse)
async def get_mitre_statistics(
    admin: AdminUser = Depends(require_permission("settings:read")),
    db: AsyncSession = Depends(get_db),
) -> MitreStatisticsResponse:
    """
    Get MITRE data statistics.

    Returns counts and breakdowns of threat intelligence data.
    """
    threat_service = MitreThreatService(db)
    stats = await threat_service.get_statistics()

    return MitreStatisticsResponse(
        is_synced=stats.get("is_synced", False),
        mitre_version=stats.get("mitre_version"),
        stix_version=stats.get("stix_version"),
        last_sync_at=stats.get("last_sync_at"),
        total_groups=stats.get("total_groups", 0),
        total_campaigns=stats.get("total_campaigns", 0),
        total_software=stats.get("total_software", 0),
        total_relationships=stats.get("total_relationships", 0),
        groups_by_activity={},  # TODO: Implement grouping
        software_by_type={},  # TODO: Implement grouping
    )
