"""Mapping endpoints."""

from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from sqlalchemy.orm import selectinload

from app.core.database import get_db
from app.models.mapping import DetectionMapping, MappingSource
from app.models.detection import Detection
from app.models.mitre import Technique, Tactic
from app.schemas.mapping import (
    MappingResponse,
    MappingListResponse,
    TechniqueResponse,
    TacticResponse,
)

router = APIRouter()


@router.get("", response_model=MappingListResponse)
async def list_mappings(
    detection_id: Optional[UUID] = None,
    technique_id: Optional[str] = None,
    min_confidence: Optional[float] = Query(None, ge=0.0, le=1.0),
    source: Optional[MappingSource] = None,
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
):
    """List detection mappings with optional filters."""
    query = (
        select(DetectionMapping)
        .options(
            selectinload(DetectionMapping.detection),
            selectinload(DetectionMapping.technique).selectinload(Technique.tactic),
        )
    )

    if detection_id:
        query = query.where(DetectionMapping.detection_id == detection_id)
    if technique_id:
        query = query.join(Technique).where(Technique.technique_id == technique_id)
    if min_confidence is not None:
        query = query.where(DetectionMapping.confidence >= min_confidence)
    if source:
        query = query.where(DetectionMapping.mapping_source == source)

    # Get total count
    count_query = select(func.count(DetectionMapping.id))
    if detection_id:
        count_query = count_query.where(DetectionMapping.detection_id == detection_id)
    if min_confidence is not None:
        count_query = count_query.where(DetectionMapping.confidence >= min_confidence)
    if source:
        count_query = count_query.where(DetectionMapping.mapping_source == source)

    total_result = await db.execute(count_query)
    total = total_result.scalar()

    query = query.offset(skip).limit(limit).order_by(DetectionMapping.confidence.desc())
    result = await db.execute(query)
    mappings = result.scalars().unique().all()

    items = []
    for m in mappings:
        items.append(
            MappingResponse(
                id=m.id,
                detection_id=m.detection_id,
                detection_name=m.detection.name if m.detection else "",
                technique_id=m.technique.technique_id if m.technique else "",
                technique_name=m.technique.name if m.technique else "",
                tactic_id=m.technique.tactic.tactic_id if m.technique and m.technique.tactic else "",
                tactic_name=m.technique.tactic.name if m.technique and m.technique.tactic else "",
                confidence=m.confidence,
                mapping_source=m.mapping_source,
                rationale=m.rationale,
                matched_indicators=m.matched_indicators,
                is_stale=m.is_stale,
                last_validated_at=m.last_validated_at,
                created_at=m.created_at,
            )
        )

    return MappingListResponse(
        items=items,
        total=total,
        page=skip // limit + 1,
        page_size=limit,
    )


@router.get("/techniques", response_model=list[TechniqueResponse])
async def list_techniques(
    tactic_id: Optional[str] = None,
    platform: Optional[str] = Query(None, description="Filter by platform (AWS, GCP)"),
    search: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
):
    """List MITRE ATT&CK techniques."""
    query = select(Technique).options(selectinload(Technique.tactic))

    if tactic_id:
        query = query.join(Tactic).where(Tactic.tactic_id == tactic_id)
    if platform:
        query = query.where(Technique.platforms.contains([platform]))
    if search:
        query = query.where(
            (Technique.name.ilike(f"%{search}%"))
            | (Technique.technique_id.ilike(f"%{search}%"))
        )

    query = query.order_by(Technique.technique_id)
    result = await db.execute(query)
    techniques = result.scalars().unique().all()

    return [
        TechniqueResponse(
            id=t.id,
            technique_id=t.technique_id,
            name=t.name,
            description=t.description,
            tactic_id=t.tactic.tactic_id if t.tactic else "",
            tactic_name=t.tactic.name if t.tactic else "",
            platforms=t.platforms or [],
            data_sources=t.data_sources or [],
            is_subtechnique=t.is_subtechnique,
            parent_technique_id=None,  # Would need to join parent
        )
        for t in techniques
    ]


@router.get("/tactics", response_model=list[TacticResponse])
async def list_tactics(
    db: AsyncSession = Depends(get_db),
):
    """List MITRE ATT&CK tactics."""
    result = await db.execute(
        select(Tactic).order_by(Tactic.display_order)
    )
    tactics = result.scalars().all()

    return [
        TacticResponse(
            id=t.id,
            tactic_id=t.tactic_id,
            name=t.name,
            short_name=t.short_name,
            description=t.description,
            display_order=t.display_order,
        )
        for t in tactics
    ]


@router.delete("/{mapping_id}", status_code=204)
async def delete_mapping(
    mapping_id: UUID,
    db: AsyncSession = Depends(get_db),
):
    """Delete a detection mapping."""
    result = await db.execute(
        select(DetectionMapping).where(DetectionMapping.id == mapping_id)
    )
    mapping = result.scalar_one_or_none()
    if not mapping:
        raise HTTPException(status_code=404, detail="Mapping not found")

    await db.delete(mapping)
