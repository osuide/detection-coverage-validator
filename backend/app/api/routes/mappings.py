"""Mapping endpoints."""

from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from sqlalchemy.orm import selectinload

from app.core.database import get_db
from app.core.sql_utils import escape_like_pattern
from app.core.security import AuthContext, get_auth_context, require_scope, require_role
from app.models.user import UserRole
from app.models.cloud_account import CloudAccount
from app.models.mapping import DetectionMapping, MappingSource
from app.models.mitre import Technique, Tactic
from app.schemas.mapping import (
    MappingResponse,
    MappingListResponse,
    TechniqueResponse,
    TacticResponse,
)

router = APIRouter()


@router.get(
    "",
    response_model=MappingListResponse,
    dependencies=[Depends(require_scope("read:mappings"))],
)
async def list_mappings(
    detection_id: Optional[UUID] = None,
    technique_id: Optional[str] = None,
    min_confidence: Optional[float] = Query(None, ge=0.0, le=1.0),
    source: Optional[MappingSource] = None,
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    auth: AuthContext = Depends(get_auth_context),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """List detection mappings with optional filters."""
    from app.models.detection import Detection

    # Filter by organization through detection->cloud_account
    query = (
        select(DetectionMapping)
        .join(Detection, DetectionMapping.detection_id == Detection.id)
        .join(CloudAccount, Detection.cloud_account_id == CloudAccount.id)
        .options(
            selectinload(DetectionMapping.detection),
            selectinload(DetectionMapping.technique).selectinload(Technique.tactic),
        )
        .where(CloudAccount.organization_id == auth.organization_id)
    )

    if detection_id:
        query = query.where(DetectionMapping.detection_id == detection_id)
    if technique_id:
        query = query.join(Technique).where(Technique.technique_id == technique_id)
    if min_confidence is not None:
        query = query.where(DetectionMapping.confidence >= min_confidence)
    if source:
        query = query.where(DetectionMapping.mapping_source == source)

    # Get total count (also filtered by organization)
    count_query = (
        select(func.count(DetectionMapping.id))
        .join(Detection, DetectionMapping.detection_id == Detection.id)
        .join(CloudAccount, Detection.cloud_account_id == CloudAccount.id)
        .where(CloudAccount.organization_id == auth.organization_id)
    )
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
                tactic_id=(
                    m.technique.tactic.tactic_id
                    if m.technique and m.technique.tactic
                    else ""
                ),
                tactic_name=(
                    m.technique.tactic.name
                    if m.technique and m.technique.tactic
                    else ""
                ),
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


@router.get(
    "/techniques",
    response_model=list[TechniqueResponse],
    dependencies=[Depends(require_scope("read:mappings"))],
)
async def list_techniques(
    tactic_id: Optional[str] = None,
    platform: Optional[str] = Query(None, description="Filter by platform (AWS, GCP)"),
    search: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
) -> dict:
    """List MITRE ATT&CK techniques."""
    query = select(Technique).options(selectinload(Technique.tactic))

    if tactic_id:
        query = query.join(Tactic).where(Tactic.tactic_id == tactic_id)
    if platform:
        query = query.where(Technique.platforms.contains([platform]))
    if search:
        # CWE-89: Escape LIKE wildcards to prevent pattern injection
        escaped_search = escape_like_pattern(search)
        query = query.where(
            (Technique.name.ilike(f"%{escaped_search}%", escape="\\"))
            | (Technique.technique_id.ilike(f"%{escaped_search}%", escape="\\"))
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


@router.get(
    "/tactics",
    response_model=list[TacticResponse],
    dependencies=[Depends(require_scope("read:mappings"))],
)
async def list_tactics(
    db: AsyncSession = Depends(get_db),
) -> dict:
    """List MITRE ATT&CK tactics."""
    result = await db.execute(select(Tactic).order_by(Tactic.display_order))
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


@router.delete(
    "/{mapping_id}",
    status_code=204,
    dependencies=[
        Depends(require_role(UserRole.MEMBER, UserRole.ADMIN, UserRole.OWNER)),
    ],
)
async def delete_mapping(
    mapping_id: UUID,
    auth: AuthContext = Depends(get_auth_context),
    db: AsyncSession = Depends(get_db),
) -> None:
    """Delete a detection mapping.

    SECURITY: Requires MEMBER role or higher. VIEWERs are read-only.
    """
    from app.models.detection import Detection

    # Verify mapping exists and belongs to user's organization
    result = await db.execute(
        select(DetectionMapping)
        .join(Detection, DetectionMapping.detection_id == Detection.id)
        .join(CloudAccount, Detection.cloud_account_id == CloudAccount.id)
        .where(
            DetectionMapping.id == mapping_id,
            CloudAccount.organization_id == auth.organization_id,
        )
    )
    mapping = result.scalar_one_or_none()
    if not mapping:
        raise HTTPException(status_code=404, detail="Mapping not found")

    await db.delete(mapping)


@router.post(
    "/remap-all",
    dependencies=[
        Depends(require_scope("write:mappings")),
        Depends(require_role(UserRole.MEMBER, UserRole.ADMIN, UserRole.OWNER)),
    ],
)
async def remap_all_detections(
    cloud_account_id: Optional[UUID] = None,
    auth: AuthContext = Depends(get_auth_context),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Re-map all detections to MITRE techniques.

    Use this after seeding MITRE data or to refresh mappings.
    """
    from app.models.detection import Detection, DetectionStatus
    from app.scanners.base import RawDetection
    from app.mappers.pattern_mapper import PatternMapper

    mapper = PatternMapper()

    # Get detections (filtered by organization)
    query = (
        select(Detection)
        .join(CloudAccount, Detection.cloud_account_id == CloudAccount.id)
        .where(
            Detection.status == DetectionStatus.ACTIVE,
            CloudAccount.organization_id == auth.organization_id,
        )
    )
    if cloud_account_id:
        # Also verify the specific account belongs to user's organization
        query = query.where(Detection.cloud_account_id == cloud_account_id)

    result = await db.execute(query)
    detections = result.scalars().all()

    stats = {"total": len(detections), "mapped": 0, "mappings_created": 0}

    for detection in detections:
        # Delete existing mappings for this detection
        await db.execute(
            select(DetectionMapping).where(
                DetectionMapping.detection_id == detection.id
            )
        )
        existing = await db.execute(
            select(DetectionMapping).where(
                DetectionMapping.detection_id == detection.id
            )
        )
        for old_mapping in existing.scalars().all():
            await db.delete(old_mapping)

        # Create RawDetection for mapper
        raw = RawDetection(
            name=detection.name,
            detection_type=detection.detection_type,
            source_arn=detection.source_arn or "",
            region=detection.region,
            raw_config=detection.raw_config,
            query_pattern=detection.query_pattern,
            event_pattern=detection.event_pattern,
            log_groups=detection.log_groups,
            description=detection.description,
        )

        # Get mappings from pattern mapper
        mappings = mapper.map_detection(raw, min_confidence=0.4)

        if mappings:
            stats["mapped"] += 1

        # Create mapping records
        for mapping in mappings:
            # Look up technique in DB
            tech_result = await db.execute(
                select(Technique).where(Technique.technique_id == mapping.technique_id)
            )
            technique = tech_result.scalar_one_or_none()

            if technique:
                dm = DetectionMapping(
                    detection_id=detection.id,
                    technique_id=technique.id,
                    confidence=mapping.confidence,
                    mapping_source=MappingSource.PATTERN_MATCH,
                    rationale=mapping.rationale,
                    matched_indicators=mapping.matched_indicators,
                )
                db.add(dm)
                stats["mappings_created"] += 1

    await db.commit()

    return {
        "message": "Re-mapping complete",
        "detections_processed": stats["total"],
        "detections_with_mappings": stats["mapped"],
        "total_mappings_created": stats["mappings_created"],
    }
