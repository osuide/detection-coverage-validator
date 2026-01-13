"""Schedule management endpoints."""

from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.core.database import get_db
from app.core.security import (
    AuthContext,
    get_auth_context,
    require_scope,
    require_feature,
    require_role,
    get_allowed_account_filter,
)
from app.models.user import UserRole
from app.models.schedule import ScanSchedule
from app.models.cloud_account import CloudAccount
from app.schemas.schedule import (
    ScheduleCreate,
    ScheduleUpdate,
    ScheduleResponse,
    ScheduleListResponse,
    ScheduleStatusResponse,
)
from app.services.scheduler_service import scheduler_service

router = APIRouter()


@router.get(
    "",
    response_model=ScheduleListResponse,
    dependencies=[Depends(require_scope("read:schedules"))],
)
async def list_schedules(
    cloud_account_id: Optional[UUID] = None,
    is_active: Optional[bool] = None,
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
    auth: AuthContext = Depends(get_auth_context),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """List scan schedules.

    API keys require 'read:schedules' scope.
    """
    # Filter by organization through cloud_account
    query = (
        select(ScanSchedule)
        .join(CloudAccount, ScanSchedule.cloud_account_id == CloudAccount.id)
        .where(CloudAccount.organization_id == auth.organization_id)
    )
    count_query = (
        select(ScanSchedule)
        .join(CloudAccount, ScanSchedule.cloud_account_id == CloudAccount.id)
        .where(CloudAccount.organization_id == auth.organization_id)
    )

    # SECURITY: Apply allowed_account_ids ACL filter
    # This ensures restricted users only see schedules for accounts they can access
    allowed_accounts = get_allowed_account_filter(auth)
    if allowed_accounts is not None:  # None = unrestricted access
        if not allowed_accounts:  # Empty list = no access
            return ScheduleListResponse(items=[], total=0, page=1, page_size=limit)
        query = query.where(ScanSchedule.cloud_account_id.in_(allowed_accounts))
        count_query = count_query.where(
            ScanSchedule.cloud_account_id.in_(allowed_accounts)
        )

    if cloud_account_id:
        # SECURITY: Check allowed_account_ids ACL for specific account
        if not auth.can_access_account(cloud_account_id):
            raise HTTPException(
                status_code=403, detail="Access denied to this cloud account"
            )
        query = query.where(ScanSchedule.cloud_account_id == cloud_account_id)
        count_query = count_query.where(
            ScanSchedule.cloud_account_id == cloud_account_id
        )

    if is_active is not None:
        query = query.where(ScanSchedule.is_active == is_active)
        count_query = count_query.where(ScanSchedule.is_active == is_active)

    # Get total count
    total_result = await db.execute(count_query)
    total = len(total_result.scalars().all())

    # Get paginated results
    query = query.offset(skip).limit(limit).order_by(ScanSchedule.created_at.desc())
    result = await db.execute(query)
    schedules = result.scalars().all()

    return ScheduleListResponse(
        items=schedules,
        total=total,
        page=skip // limit + 1,
        page_size=limit,
    )


@router.post(
    "",
    response_model=ScheduleResponse,
    status_code=201,
    dependencies=[
        Depends(require_scope("write:schedules")),
        Depends(require_feature("scheduled_scans")),
        Depends(require_role(UserRole.MEMBER, UserRole.ADMIN, UserRole.OWNER)),
    ],
)
async def create_schedule(
    schedule_in: ScheduleCreate,
    auth: AuthContext = Depends(get_auth_context),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Create a new scan schedule.

    API keys require 'write:schedules' scope.
    Requires 'scheduled_scans' feature (INDIVIDUAL tier or higher).
    """
    # Verify cloud account exists and belongs to user's organization
    result = await db.execute(
        select(CloudAccount).where(
            CloudAccount.id == schedule_in.cloud_account_id,
            CloudAccount.organization_id == auth.organization_id,
        )
    )
    account = result.scalar_one_or_none()
    if not account:
        raise HTTPException(status_code=404, detail="Cloud account not found")

    # SECURITY: Check allowed_account_ids ACL
    if not auth.can_access_account(schedule_in.cloud_account_id):
        raise HTTPException(
            status_code=403, detail="Access denied to this cloud account"
        )

    # Create schedule
    schedule = ScanSchedule(
        cloud_account_id=schedule_in.cloud_account_id,
        name=schedule_in.name,
        description=schedule_in.description,
        frequency=schedule_in.frequency,
        cron_expression=schedule_in.cron_expression,
        day_of_week=schedule_in.day_of_week,
        day_of_month=schedule_in.day_of_month,
        hour=schedule_in.hour,
        minute=schedule_in.minute,
        timezone=schedule_in.timezone,
        regions=schedule_in.regions or account.regions or ["eu-west-2"],
        detection_types=schedule_in.detection_types,
        is_active=True,
    )
    db.add(schedule)
    await db.flush()
    await db.refresh(schedule)

    # Add to scheduler
    await scheduler_service.add_schedule(schedule)
    await db.commit()

    return schedule


@router.get(
    "/{schedule_id}",
    response_model=ScheduleResponse,
    dependencies=[Depends(require_scope("read:schedules"))],
)
async def get_schedule(
    schedule_id: UUID,
    auth: AuthContext = Depends(get_auth_context),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Get a specific schedule.

    API keys require 'read:schedules' scope.
    """
    result = await db.execute(
        select(ScanSchedule)
        .join(CloudAccount, ScanSchedule.cloud_account_id == CloudAccount.id)
        .where(
            ScanSchedule.id == schedule_id,
            CloudAccount.organization_id == auth.organization_id,
        )
    )
    schedule = result.scalar_one_or_none()
    if not schedule:
        raise HTTPException(status_code=404, detail="Schedule not found")

    # SECURITY: Check allowed_account_ids ACL
    if not auth.can_access_account(schedule.cloud_account_id):
        raise HTTPException(
            status_code=403, detail="Access denied to this cloud account"
        )

    return schedule


@router.get(
    "/{schedule_id}/status",
    response_model=ScheduleStatusResponse,
    dependencies=[Depends(require_scope("read:schedules"))],
)
async def get_schedule_status(
    schedule_id: UUID,
    auth: AuthContext = Depends(get_auth_context),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Get schedule status including job information.

    API keys require 'read:schedules' scope.
    """
    result = await db.execute(
        select(ScanSchedule)
        .join(CloudAccount, ScanSchedule.cloud_account_id == CloudAccount.id)
        .where(
            ScanSchedule.id == schedule_id,
            CloudAccount.organization_id == auth.organization_id,
        )
    )
    schedule = result.scalar_one_or_none()
    if not schedule:
        raise HTTPException(status_code=404, detail="Schedule not found")

    # SECURITY: Check allowed_account_ids ACL
    if not auth.can_access_account(schedule.cloud_account_id):
        raise HTTPException(
            status_code=403, detail="Access denied to this cloud account"
        )

    job_status = scheduler_service.get_job_status(schedule_id)

    return ScheduleStatusResponse(
        schedule=schedule,
        job_status=job_status,
    )


@router.put(
    "/{schedule_id}",
    response_model=ScheduleResponse,
    dependencies=[
        Depends(require_scope("write:schedules")),
        Depends(require_role(UserRole.MEMBER, UserRole.ADMIN, UserRole.OWNER)),
    ],
)
async def update_schedule(
    schedule_id: UUID,
    schedule_in: ScheduleUpdate,
    auth: AuthContext = Depends(get_auth_context),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Update a schedule.

    API keys require 'write:schedules' scope.
    """
    result = await db.execute(
        select(ScanSchedule)
        .join(CloudAccount, ScanSchedule.cloud_account_id == CloudAccount.id)
        .where(
            ScanSchedule.id == schedule_id,
            CloudAccount.organization_id == auth.organization_id,
        )
    )
    schedule = result.scalar_one_or_none()
    if not schedule:
        raise HTTPException(status_code=404, detail="Schedule not found")

    # SECURITY: Check allowed_account_ids ACL
    if not auth.can_access_account(schedule.cloud_account_id):
        raise HTTPException(
            status_code=403, detail="Access denied to this cloud account"
        )

    # Update fields
    update_data = schedule_in.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(schedule, field, value)

    await db.flush()

    # Update scheduler
    await scheduler_service.update_schedule(schedule)
    await db.commit()
    await db.refresh(schedule)

    return schedule


@router.delete(
    "/{schedule_id}",
    status_code=204,
    dependencies=[
        Depends(require_scope("write:schedules")),
        Depends(require_role(UserRole.MEMBER, UserRole.ADMIN, UserRole.OWNER)),
    ],
)
async def delete_schedule(
    schedule_id: UUID,
    auth: AuthContext = Depends(get_auth_context),
    db: AsyncSession = Depends(get_db),
) -> None:
    """Delete a schedule.

    API keys require 'write:schedules' scope.
    """
    result = await db.execute(
        select(ScanSchedule)
        .join(CloudAccount, ScanSchedule.cloud_account_id == CloudAccount.id)
        .where(
            ScanSchedule.id == schedule_id,
            CloudAccount.organization_id == auth.organization_id,
        )
    )
    schedule = result.scalar_one_or_none()
    if not schedule:
        raise HTTPException(status_code=404, detail="Schedule not found")

    # SECURITY: Check allowed_account_ids ACL
    if not auth.can_access_account(schedule.cloud_account_id):
        raise HTTPException(
            status_code=403, detail="Access denied to this cloud account"
        )

    # Remove from scheduler
    await scheduler_service.remove_schedule(schedule_id)

    # Delete from database
    await db.delete(schedule)
    await db.commit()


@router.post(
    "/{schedule_id}/activate",
    response_model=ScheduleResponse,
    dependencies=[
        Depends(require_scope("write:schedules")),
        Depends(require_role(UserRole.OWNER, UserRole.ADMIN)),
    ],
)
async def activate_schedule(
    schedule_id: UUID,
    auth: AuthContext = Depends(get_auth_context),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Activate a schedule.

    API keys require 'write:schedules' scope.
    Requires Owner or Admin role.
    """
    result = await db.execute(
        select(ScanSchedule)
        .join(CloudAccount, ScanSchedule.cloud_account_id == CloudAccount.id)
        .where(
            ScanSchedule.id == schedule_id,
            CloudAccount.organization_id == auth.organization_id,
        )
    )
    schedule = result.scalar_one_or_none()
    if not schedule:
        raise HTTPException(status_code=404, detail="Schedule not found")

    # SECURITY: Check allowed_account_ids ACL
    if not auth.can_access_account(schedule.cloud_account_id):
        raise HTTPException(
            status_code=403, detail="Access denied to this cloud account"
        )

    schedule.is_active = True
    await db.flush()

    # Add to scheduler
    await scheduler_service.add_schedule(schedule)
    await db.commit()
    await db.refresh(schedule)

    return schedule


@router.post(
    "/{schedule_id}/deactivate",
    response_model=ScheduleResponse,
    dependencies=[
        Depends(require_scope("write:schedules")),
        Depends(require_role(UserRole.OWNER, UserRole.ADMIN)),
    ],
)
async def deactivate_schedule(
    schedule_id: UUID,
    auth: AuthContext = Depends(get_auth_context),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Deactivate a schedule.

    API keys require 'write:schedules' scope.
    Requires Owner or Admin role.
    """
    result = await db.execute(
        select(ScanSchedule)
        .join(CloudAccount, ScanSchedule.cloud_account_id == CloudAccount.id)
        .where(
            ScanSchedule.id == schedule_id,
            CloudAccount.organization_id == auth.organization_id,
        )
    )
    schedule = result.scalar_one_or_none()
    if not schedule:
        raise HTTPException(status_code=404, detail="Schedule not found")

    # SECURITY: Check allowed_account_ids ACL
    if not auth.can_access_account(schedule.cloud_account_id):
        raise HTTPException(
            status_code=403, detail="Access denied to this cloud account"
        )

    schedule.is_active = False
    schedule.next_run_at = None
    await db.flush()

    # Remove from scheduler
    await scheduler_service.remove_schedule(schedule_id)
    await db.commit()
    await db.refresh(schedule)

    return schedule


@router.post(
    "/{schedule_id}/run-now",
    response_model=ScheduleResponse,
    dependencies=[
        Depends(require_scope("write:schedules")),
        Depends(require_role(UserRole.OWNER, UserRole.ADMIN)),
    ],
)
async def run_schedule_now(
    schedule_id: UUID,
    auth: AuthContext = Depends(get_auth_context),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Trigger an immediate run of a schedule.

    API keys require 'write:schedules' scope.
    Requires Owner or Admin role.
    """
    result = await db.execute(
        select(ScanSchedule)
        .join(CloudAccount, ScanSchedule.cloud_account_id == CloudAccount.id)
        .where(
            ScanSchedule.id == schedule_id,
            CloudAccount.organization_id == auth.organization_id,
        )
    )
    schedule = result.scalar_one_or_none()
    if not schedule:
        raise HTTPException(status_code=404, detail="Schedule not found")

    # SECURITY: Check allowed_account_ids ACL
    if not auth.can_access_account(schedule.cloud_account_id):
        raise HTTPException(
            status_code=403, detail="Access denied to this cloud account"
        )

    # Execute immediately
    await scheduler_service._execute_scheduled_scan(schedule_id)

    # Refresh schedule
    await db.refresh(schedule)
    return schedule
