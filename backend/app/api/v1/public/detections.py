"""Public API detection endpoints."""

from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

from app.core.database import get_db
from app.models.cloud_account import CloudAccount
from app.models.detection import Detection, DetectionType, DetectionStatus
from app.models.mapping import DetectionMapping
from app.api.v1.public.auth import APIKeyContext, get_api_key_context

router = APIRouter(tags=["Public API - Detections"])


class DetectionItem(BaseModel):
    """Detection item in list response."""

    id: str
    name: str
    detection_type: str
    status: str
    region: str
    is_managed: bool
    mapping_count: int
    discovered_at: str


class DetectionDetailResponse(BaseModel):
    """Full detection detail response."""

    id: str
    name: str
    detection_type: str
    status: str
    source_arn: Optional[str]
    region: str
    description: Optional[str]
    is_managed: bool
    mapping_count: int
    mapped_techniques: list[str]
    discovered_at: str
    updated_at: str


class DetectionsListResponse(BaseModel):
    """Detections list response."""

    cloud_account_id: str
    detections: list[DetectionItem]
    total: int
    page: int
    page_size: int


@router.get(
    "/accounts/{cloud_account_id}/detections", response_model=DetectionsListResponse
)
async def list_account_detections(
    cloud_account_id: UUID,
    response: Response,
    detection_type: Optional[str] = Query(None, description="Filter by detection type"),
    status: Optional[str] = Query(None, description="Filter by status"),
    region: Optional[str] = Query(None, description="Filter by region"),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    ctx: APIKeyContext = Depends(get_api_key_context),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """List detections for a cloud account.

    Returns paginated list of discovered security detections
    with optional filtering by type, status, or region.
    """
    # Add rate limit headers
    for key, value in ctx.rate_limit_headers.items():
        response.headers[key] = value

    # Verify account belongs to organization
    account_result = await db.execute(
        select(CloudAccount).where(
            CloudAccount.id == cloud_account_id,
            CloudAccount.organization_id == ctx.organization_id,
        )
    )
    if not account_result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Cloud account not found")

    # Build query
    query = select(Detection).where(Detection.cloud_account_id == cloud_account_id)
    count_query = select(func.count(Detection.id)).where(
        Detection.cloud_account_id == cloud_account_id
    )

    if detection_type:
        try:
            dt = DetectionType(detection_type)
            query = query.where(Detection.detection_type == dt)
            count_query = count_query.where(Detection.detection_type == dt)
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid detection_type. Valid values: {[t.value for t in DetectionType]}",
            )

    if status:
        try:
            ds = DetectionStatus(status)
            query = query.where(Detection.status == ds)
            count_query = count_query.where(Detection.status == ds)
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid status. Valid values: {[s.value for s in DetectionStatus]}",
            )

    if region:
        query = query.where(Detection.region == region)
        count_query = count_query.where(Detection.region == region)

    # Get total count
    total_result = await db.execute(count_query)
    total = total_result.scalar() or 0

    # Apply pagination
    offset = (page - 1) * page_size
    query = (
        query.offset(offset).limit(page_size).order_by(Detection.discovered_at.desc())
    )

    result = await db.execute(query)
    detections = result.scalars().all()

    # Get mapping counts
    items = []
    for det in detections:
        mapping_count_result = await db.execute(
            select(func.count(DetectionMapping.id)).where(
                DetectionMapping.detection_id == det.id
            )
        )
        mapping_count = mapping_count_result.scalar() or 0

        items.append(
            DetectionItem(
                id=str(det.id),
                name=det.name,
                detection_type=det.detection_type.value,
                status=det.status.value,
                region=det.region,
                is_managed=det.is_managed,
                mapping_count=mapping_count,
                discovered_at=det.discovered_at.isoformat(),
            )
        )

    return DetectionsListResponse(
        cloud_account_id=str(cloud_account_id),
        detections=items,
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get("/detections/{detection_id}", response_model=DetectionDetailResponse)
async def get_detection(
    detection_id: UUID,
    response: Response,
    ctx: APIKeyContext = Depends(get_api_key_context),
    db: AsyncSession = Depends(get_db),
) -> DetectionDetailResponse:
    """Get detection details.

    Returns full details of a specific detection including
    mapped MITRE ATT&CK techniques.
    """
    # Add rate limit headers
    for key, value in ctx.rate_limit_headers.items():
        response.headers[key] = value

    # Get detection with organization check via account
    result = await db.execute(
        select(Detection)
        .join(CloudAccount, Detection.cloud_account_id == CloudAccount.id)
        .where(
            Detection.id == detection_id,
            CloudAccount.organization_id == ctx.organization_id,
        )
    )
    detection = result.scalar_one_or_none()

    if not detection:
        raise HTTPException(status_code=404, detail="Detection not found")

    # Get mapped techniques
    from app.models.mitre import Technique

    mappings_result = await db.execute(
        select(Technique.technique_id)
        .join(DetectionMapping, DetectionMapping.technique_id == Technique.id)
        .where(DetectionMapping.detection_id == detection_id)
    )
    technique_ids = [row[0] for row in mappings_result.all()]

    return DetectionDetailResponse(
        id=str(detection.id),
        name=detection.name,
        detection_type=detection.detection_type.value,
        status=detection.status.value,
        source_arn=detection.source_arn,
        region=detection.region,
        description=detection.description,
        is_managed=detection.is_managed,
        mapping_count=len(technique_ids),
        mapped_techniques=technique_ids,
        discovered_at=detection.discovered_at.isoformat(),
        updated_at=detection.updated_at.isoformat(),
    )
