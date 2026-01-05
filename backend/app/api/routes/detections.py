"""Detection endpoints."""

from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from sqlalchemy.orm import selectinload

from app.core.database import get_db
from app.core.security import (
    AuthContext,
    get_auth_context,
    require_scope,
    get_allowed_account_filter,
)
from app.core.service_registry import get_all_regions
from app.models.cloud_account import CloudAccount
from app.models.detection import Detection, DetectionType, DetectionStatus
from app.models.mapping import DetectionMapping
from app.models.mitre import Technique
from app.schemas.detection import DetectionResponse, DetectionListResponse
from app.services.detection_health_service import DetectionHealthService

router = APIRouter()


# Health response models
class HealthCheckResponse(BaseModel):
    """Health check result."""

    check_type: str
    passed: bool
    message: str
    severity: str
    details: dict = {}


class DetectionHealthResponse(BaseModel):
    """Detection health response."""

    detection_id: str
    detection_name: str
    health_status: str
    health_score: Optional[float]
    health_issues: list = []
    last_validated_at: Optional[str]
    last_triggered_at: Optional[str]


class ValidationResponse(BaseModel):
    """Validation result response."""

    detection_id: str
    detection_name: str
    health_status: str
    health_score: float
    checks: list[dict]
    issues: list[dict]
    validated_at: str


class HealthSummaryResponse(BaseModel):
    """Health summary response."""

    total_detections: int
    by_status: dict
    stale_count: int
    never_validated: int
    average_health_score: float
    overall_health: str


class BulkValidationResponse(BaseModel):
    """Bulk validation result response."""

    total: int
    validated: int
    healthy: int
    degraded: int
    broken: int
    unknown: int
    errors: list[dict]


@router.get(
    "",
    response_model=DetectionListResponse,
    dependencies=[Depends(require_scope("read:detections"))],
)
async def list_detections(
    cloud_account_id: Optional[UUID] = None,
    detection_type: Optional[DetectionType] = None,
    status: Optional[DetectionStatus] = None,
    region: Optional[str] = None,
    search: Optional[str] = None,
    include_region_coverage: bool = Query(
        False,
        description="Include effective regions for regional coverage analysis",
    ),
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=500),
    auth: AuthContext = Depends(get_auth_context),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """List detections with optional filters.

    API keys require 'read:detections' scope.

    When include_region_coverage=true and cloud_account_id is specified,
    the response includes effective_regions and provider for regional
    coverage gap analysis.
    """
    # Security: Get allowed accounts for ACL filtering
    allowed_accounts = get_allowed_account_filter(auth)

    # If user has restricted access with empty list, return empty result
    if allowed_accounts is not None and len(allowed_accounts) == 0:
        return DetectionListResponse(
            items=[], total=0, page=1, page_size=limit, pages=0
        )

    # Security: Check account-level ACL if filtering by specific account
    if cloud_account_id and not auth.can_access_account(cloud_account_id):
        raise HTTPException(
            status_code=403, detail="Access denied to this cloud account"
        )

    # Filter detections by organization through cloud_account
    query = (
        select(Detection)
        .join(CloudAccount, Detection.cloud_account_id == CloudAccount.id)
        .options(selectinload(Detection.mappings))
        .where(CloudAccount.organization_id == auth.organization_id)
    )

    # Security: Apply ACL filter when no specific account requested
    if cloud_account_id:
        query = query.where(Detection.cloud_account_id == cloud_account_id)
    elif allowed_accounts is not None:
        # Restricted user without specific account - filter to allowed accounts
        query = query.where(Detection.cloud_account_id.in_(allowed_accounts))

    if detection_type:
        query = query.where(Detection.detection_type == detection_type)
    if status:
        query = query.where(Detection.status == status)
    if region:
        query = query.where(Detection.region == region)
    if search:
        query = query.where(Detection.name.ilike(f"%{search}%"))

    # Get total count
    count_query = (
        select(func.count(Detection.id))
        .join(CloudAccount, Detection.cloud_account_id == CloudAccount.id)
        .where(CloudAccount.organization_id == auth.organization_id)
    )

    # Security: Apply same ACL filter to count query
    if cloud_account_id:
        count_query = count_query.where(Detection.cloud_account_id == cloud_account_id)
    elif allowed_accounts is not None:
        count_query = count_query.where(
            Detection.cloud_account_id.in_(allowed_accounts)
        )

    if detection_type:
        count_query = count_query.where(Detection.detection_type == detection_type)
    if status:
        count_query = count_query.where(Detection.status == status)
    if region:
        count_query = count_query.where(Detection.region == region)
    if search:
        count_query = count_query.where(Detection.name.ilike(f"%{search}%"))

    total_result = await db.execute(count_query)
    total = total_result.scalar()

    query = query.offset(skip).limit(limit).order_by(Detection.discovered_at.desc())
    result = await db.execute(query)
    detections = result.scalars().unique().all()

    # Enrich with mapping info
    items = []
    for det in detections:
        det_dict = {
            "id": det.id,
            "cloud_account_id": det.cloud_account_id,
            "name": det.name,
            "detection_type": det.detection_type,
            "status": det.status,
            "source_arn": det.source_arn,
            "region": det.region,
            "query_pattern": det.query_pattern,
            "event_pattern": det.event_pattern,
            "log_groups": det.log_groups,
            "description": det.description,
            "last_triggered_at": det.last_triggered_at,
            "health_score": det.health_score,
            "is_managed": det.is_managed,
            "discovered_at": det.discovered_at,
            "updated_at": det.updated_at,
            "mapping_count": len({m.technique_id for m in det.mappings}),
            "top_techniques": [],
            "evaluation_summary": det.evaluation_summary,
            "evaluation_updated_at": det.evaluation_updated_at,
            "raw_config": det.raw_config,
        }
        items.append(DetectionResponse(**det_dict))

    pages = (total + limit - 1) // limit if total else 0

    # Build response with optional region coverage data
    response_data = {
        "items": items,
        "total": total,
        "page": skip // limit + 1,
        "page_size": limit,
        "pages": pages,
    }

    # Include effective regions for regional coverage analysis
    if include_region_coverage and cloud_account_id:
        # Fetch the cloud account to get its region configuration
        account_result = await db.execute(
            select(CloudAccount).where(
                CloudAccount.id == cloud_account_id,
                CloudAccount.organization_id == auth.organization_id,
            )
        )
        account = account_result.scalar_one_or_none()
        if account:
            all_regions = get_all_regions(account.provider.value)
            effective_regions = account.get_effective_regions(all_regions)
            response_data["effective_regions"] = effective_regions
            response_data["provider"] = account.provider.value

    return DetectionListResponse(**response_data)


class DetectionSourceCount(BaseModel):
    """Count of detections by source type."""

    detection_type: str
    count: int


class DetectionSourceCountsResponse(BaseModel):
    """Response containing detection counts by source."""

    counts: list[DetectionSourceCount]
    total: int


@router.get(
    "/sources/counts",
    response_model=DetectionSourceCountsResponse,
    dependencies=[Depends(require_scope("read:detections"))],
)
async def get_detection_source_counts(
    cloud_account_id: Optional[UUID] = None,
    auth: AuthContext = Depends(get_auth_context),
    db: AsyncSession = Depends(get_db),
) -> DetectionSourceCountsResponse:
    """Get detection counts grouped by source type.

    This is more efficient than fetching all detections for dashboard display.
    Only counts active detections (excludes REMOVED status).
    """
    # Security: Get allowed accounts for ACL filtering
    allowed_accounts = get_allowed_account_filter(auth)

    # If user has restricted access with empty list, return empty result
    if allowed_accounts is not None and len(allowed_accounts) == 0:
        return DetectionSourceCountsResponse(counts=[], total=0)

    # Security: Check account-level ACL if filtering by specific account
    if cloud_account_id and not auth.can_access_account(cloud_account_id):
        raise HTTPException(
            status_code=403, detail="Access denied to this cloud account"
        )

    # Build the aggregation query
    query = (
        select(Detection.detection_type, func.count(Detection.id).label("count"))
        .join(CloudAccount, Detection.cloud_account_id == CloudAccount.id)
        .where(
            CloudAccount.organization_id == auth.organization_id,
            Detection.status != DetectionStatus.REMOVED,
        )
        .group_by(Detection.detection_type)
    )

    # Apply account filter
    if cloud_account_id:
        query = query.where(Detection.cloud_account_id == cloud_account_id)
    elif allowed_accounts is not None:
        query = query.where(Detection.cloud_account_id.in_(allowed_accounts))

    result = await db.execute(query)
    rows = result.all()

    counts = [
        DetectionSourceCount(detection_type=row.detection_type.value, count=row.count)
        for row in rows
    ]
    total = sum(c.count for c in counts)

    return DetectionSourceCountsResponse(counts=counts, total=total)


@router.get("/{detection_id}", response_model=DetectionResponse)
async def get_detection(
    detection_id: UUID,
    auth: AuthContext = Depends(get_auth_context),
    db: AsyncSession = Depends(get_db),
) -> DetectionResponse:
    """Get a specific detection."""
    result = await db.execute(
        select(Detection)
        .join(CloudAccount, Detection.cloud_account_id == CloudAccount.id)
        .options(selectinload(Detection.mappings))
        .where(
            Detection.id == detection_id,
            CloudAccount.organization_id == auth.organization_id,
        )
    )
    detection = result.scalar_one_or_none()
    if not detection:
        raise HTTPException(status_code=404, detail="Detection not found")

    # Security: Check account-level ACL
    if not auth.can_access_account(detection.cloud_account_id):
        raise HTTPException(
            status_code=403, detail="Access denied to this cloud account"
        )

    return DetectionResponse(
        id=detection.id,
        cloud_account_id=detection.cloud_account_id,
        name=detection.name,
        detection_type=detection.detection_type,
        status=detection.status,
        source_arn=detection.source_arn,
        region=detection.region,
        query_pattern=detection.query_pattern,
        event_pattern=detection.event_pattern,
        log_groups=detection.log_groups,
        description=detection.description,
        last_triggered_at=detection.last_triggered_at,
        health_score=detection.health_score,
        is_managed=detection.is_managed,
        discovered_at=detection.discovered_at,
        updated_at=detection.updated_at,
        mapping_count=len({m.technique_id for m in detection.mappings}),
        top_techniques=[],
        evaluation_summary=detection.evaluation_summary,
        evaluation_updated_at=detection.evaluation_updated_at,
        raw_config=detection.raw_config,
    )


@router.get(
    "/{detection_id}/mappings",
    dependencies=[Depends(require_scope("read:detections"))],
)
async def get_detection_mappings(
    detection_id: UUID,
    auth: AuthContext = Depends(get_auth_context),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Get technique mappings for a detection.

    API keys require 'read:detections' scope.
    """
    # Verify detection exists and belongs to user's organization
    result = await db.execute(
        select(Detection)
        .join(CloudAccount, Detection.cloud_account_id == CloudAccount.id)
        .where(
            Detection.id == detection_id,
            CloudAccount.organization_id == auth.organization_id,
        )
    )
    detection = result.scalar_one_or_none()
    if not detection:
        raise HTTPException(status_code=404, detail="Detection not found")

    # Security: Check account-level ACL
    if not auth.can_access_account(detection.cloud_account_id):
        raise HTTPException(
            status_code=403, detail="Access denied to this cloud account"
        )

    # Get mappings with technique details
    mappings_result = await db.execute(
        select(DetectionMapping, Technique)
        .join(Technique, DetectionMapping.technique_id == Technique.id)
        .where(DetectionMapping.detection_id == detection_id)
        .order_by(DetectionMapping.confidence.desc())
    )
    mappings = mappings_result.all()

    # Deduplicate by technique_id, keeping highest confidence (already sorted)
    seen_techniques: set[str] = set()
    unique_mappings = []
    for m, t in mappings:
        if t.technique_id not in seen_techniques:
            seen_techniques.add(t.technique_id)
            unique_mappings.append(
                {
                    "id": str(m.id),
                    "technique_id": t.technique_id,
                    "technique_name": t.name,
                    "confidence": round(m.confidence, 2),
                    "mapping_source": (
                        m.mapping_source.value if m.mapping_source else "unknown"
                    ),
                    "rationale": m.rationale,
                    "matched_indicators": m.matched_indicators,
                    "created_at": m.created_at.isoformat() if m.created_at else None,
                }
            )

    return {
        "detection_id": str(detection_id),
        "detection_name": detection.name,
        "mappings": unique_mappings,
    }


@router.delete("/{detection_id}", status_code=204)
async def delete_detection(
    detection_id: UUID,
    auth: AuthContext = Depends(get_auth_context),
    db: AsyncSession = Depends(get_db),
) -> None:
    """Delete a detection."""
    result = await db.execute(
        select(Detection)
        .join(CloudAccount, Detection.cloud_account_id == CloudAccount.id)
        .where(
            Detection.id == detection_id,
            CloudAccount.organization_id == auth.organization_id,
        )
    )
    detection = result.scalar_one_or_none()
    if not detection:
        raise HTTPException(status_code=404, detail="Detection not found")

    # Security: Check account-level ACL
    if not auth.can_access_account(detection.cloud_account_id):
        raise HTTPException(
            status_code=403, detail="Access denied to this cloud account"
        )

    await db.delete(detection)
    await db.commit()


# Health validation endpoints
@router.post("/{detection_id}/validate", response_model=ValidationResponse)
async def validate_detection(
    detection_id: UUID,
    auth: AuthContext = Depends(get_auth_context),
    db: AsyncSession = Depends(get_db),
) -> ValidationResponse:
    """Validate a detection and update its health status."""
    # Security: Fetch detection and verify ACL access
    result = await db.execute(
        select(Detection)
        .join(CloudAccount, Detection.cloud_account_id == CloudAccount.id)
        .where(
            Detection.id == detection_id,
            CloudAccount.organization_id == auth.organization_id,
        )
    )
    detection = result.scalar_one_or_none()
    if not detection:
        raise HTTPException(status_code=404, detail="Detection not found")

    # Security: Check account-level ACL
    if not auth.can_access_account(detection.cloud_account_id):
        raise HTTPException(
            status_code=403, detail="Access denied to this cloud account"
        )

    service = DetectionHealthService(db)
    validation_result = await service.validate_detection(
        detection_id, auth.organization_id
    )

    if "error" in validation_result:
        raise HTTPException(status_code=404, detail=validation_result["error"])

    return ValidationResponse(**validation_result)


@router.get("/{detection_id}/health", response_model=DetectionHealthResponse)
async def get_detection_health(
    detection_id: UUID,
    auth: AuthContext = Depends(get_auth_context),
    db: AsyncSession = Depends(get_db),
) -> DetectionHealthResponse:
    """Get current health status for a detection."""
    # Security: Fetch detection and verify ACL access
    result = await db.execute(
        select(Detection)
        .join(CloudAccount, Detection.cloud_account_id == CloudAccount.id)
        .where(
            Detection.id == detection_id,
            CloudAccount.organization_id == auth.organization_id,
        )
    )
    detection = result.scalar_one_or_none()
    if not detection:
        raise HTTPException(status_code=404, detail="Detection not found")

    # Security: Check account-level ACL
    if not auth.can_access_account(detection.cloud_account_id):
        raise HTTPException(
            status_code=403, detail="Access denied to this cloud account"
        )

    service = DetectionHealthService(db)
    health_result = await service.get_detection_health(
        detection_id, auth.organization_id
    )

    if not health_result:
        raise HTTPException(status_code=404, detail="Detection not found")

    return DetectionHealthResponse(**health_result)


@router.post("/validate-all", response_model=BulkValidationResponse)
async def validate_all_detections(
    cloud_account_id: Optional[UUID] = None,
    auth: AuthContext = Depends(get_auth_context),
    db: AsyncSession = Depends(get_db),
) -> BulkValidationResponse:
    """Validate all detections for the organization.

    This is a synchronous operation that may take time for large numbers
    of detections. Consider using background tasks for production use.
    """
    # Security: Get allowed accounts for ACL filtering
    allowed_accounts = get_allowed_account_filter(auth)

    # If user has restricted access with empty list, return empty result
    if allowed_accounts is not None and len(allowed_accounts) == 0:
        return BulkValidationResponse(
            total=0, validated=0, healthy=0, degraded=0, broken=0, unknown=0, errors=[]
        )

    # Security: Restricted users must specify a cloud_account_id
    if allowed_accounts is not None and cloud_account_id is None:
        raise HTTPException(
            status_code=400,
            detail="cloud_account_id is required for users with restricted account access",
        )

    # Security: Check account-level ACL if filtering by specific account
    if cloud_account_id and not auth.can_access_account(cloud_account_id):
        raise HTTPException(
            status_code=403, detail="Access denied to this cloud account"
        )

    service = DetectionHealthService(db)
    result = await service.validate_all_detections(
        auth.organization_id,
        cloud_account_id,
    )

    return BulkValidationResponse(**result)


@router.get("/health/summary", response_model=HealthSummaryResponse)
async def get_health_summary(
    cloud_account_id: Optional[UUID] = None,
    auth: AuthContext = Depends(get_auth_context),
    db: AsyncSession = Depends(get_db),
) -> HealthSummaryResponse:
    """Get health summary for all detections."""
    # Security: Get allowed accounts for ACL filtering
    allowed_accounts = get_allowed_account_filter(auth)

    # If user has restricted access with empty list, return empty result
    if allowed_accounts is not None and len(allowed_accounts) == 0:
        return HealthSummaryResponse(
            total_detections=0,
            by_status={},
            stale_count=0,
            never_validated=0,
            average_health_score=0.0,
            overall_health="unknown",
        )

    # Security: Restricted users must specify a cloud_account_id
    if allowed_accounts is not None and cloud_account_id is None:
        raise HTTPException(
            status_code=400,
            detail="cloud_account_id is required for users with restricted account access",
        )

    # Security: Check account-level ACL if filtering by specific account
    if cloud_account_id and not auth.can_access_account(cloud_account_id):
        raise HTTPException(
            status_code=403, detail="Access denied to this cloud account"
        )

    service = DetectionHealthService(db)
    result = await service.get_health_summary(
        auth.organization_id,
        cloud_account_id,
    )

    return HealthSummaryResponse(**result)
