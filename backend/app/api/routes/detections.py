"""Detection endpoints."""

from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from sqlalchemy.orm import selectinload

from app.core.database import get_db
from app.models.detection import Detection, DetectionType, DetectionStatus
from app.models.mapping import DetectionMapping
from app.models.mitre import Technique
from app.schemas.detection import DetectionResponse, DetectionListResponse

router = APIRouter()


@router.get("", response_model=DetectionListResponse)
async def list_detections(
    cloud_account_id: Optional[UUID] = None,
    detection_type: Optional[DetectionType] = None,
    status: Optional[DetectionStatus] = None,
    region: Optional[str] = None,
    search: Optional[str] = None,
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
):
    """List detections with optional filters."""
    query = select(Detection).options(selectinload(Detection.mappings))

    if cloud_account_id:
        query = query.where(Detection.cloud_account_id == cloud_account_id)
    if detection_type:
        query = query.where(Detection.detection_type == detection_type)
    if status:
        query = query.where(Detection.status == status)
    if region:
        query = query.where(Detection.region == region)
    if search:
        query = query.where(Detection.name.ilike(f"%{search}%"))

    # Get total count
    count_query = select(func.count(Detection.id))
    if cloud_account_id:
        count_query = count_query.where(Detection.cloud_account_id == cloud_account_id)
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
            "mapping_count": len(det.mappings),
            "top_techniques": [],
        }
        items.append(DetectionResponse(**det_dict))

    pages = (total + limit - 1) // limit if total else 0

    return DetectionListResponse(
        items=items,
        total=total,
        page=skip // limit + 1,
        page_size=limit,
        pages=pages,
    )


@router.get("/{detection_id}", response_model=DetectionResponse)
async def get_detection(
    detection_id: UUID,
    db: AsyncSession = Depends(get_db),
):
    """Get a specific detection."""
    result = await db.execute(
        select(Detection)
        .options(selectinload(Detection.mappings))
        .where(Detection.id == detection_id)
    )
    detection = result.scalar_one_or_none()
    if not detection:
        raise HTTPException(status_code=404, detail="Detection not found")

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
        mapping_count=len(detection.mappings),
        top_techniques=[],
    )


@router.get("/{detection_id}/mappings")
async def get_detection_mappings(
    detection_id: UUID,
    db: AsyncSession = Depends(get_db),
):
    """Get technique mappings for a detection."""
    # Verify detection exists
    result = await db.execute(
        select(Detection).where(Detection.id == detection_id)
    )
    detection = result.scalar_one_or_none()
    if not detection:
        raise HTTPException(status_code=404, detail="Detection not found")

    # Get mappings with technique details
    mappings_result = await db.execute(
        select(DetectionMapping, Technique)
        .join(Technique, DetectionMapping.technique_id == Technique.id)
        .where(DetectionMapping.detection_id == detection_id)
        .order_by(DetectionMapping.confidence.desc())
    )
    mappings = mappings_result.all()

    return {
        "detection_id": str(detection_id),
        "detection_name": detection.name,
        "mappings": [
            {
                "id": str(m.id),
                "technique_id": t.technique_id,
                "technique_name": t.name,
                "confidence": round(m.confidence, 2),
                "mapping_source": m.mapping_source.value if m.mapping_source else "unknown",
                "rationale": m.rationale,
                "matched_indicators": m.matched_indicators,
                "created_at": m.created_at.isoformat() if m.created_at else None,
            }
            for m, t in mappings
        ]
    }


@router.delete("/{detection_id}", status_code=204)
async def delete_detection(
    detection_id: UUID,
    db: AsyncSession = Depends(get_db),
):
    """Delete a detection."""
    result = await db.execute(
        select(Detection).where(Detection.id == detection_id)
    )
    detection = result.scalar_one_or_none()
    if not detection:
        raise HTTPException(status_code=404, detail="Detection not found")

    await db.delete(detection)
