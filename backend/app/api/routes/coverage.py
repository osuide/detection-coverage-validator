"""Coverage endpoints."""

from uuid import UUID
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc

from app.core.database import get_db
from app.models.coverage import CoverageSnapshot
from app.models.cloud_account import CloudAccount
from app.schemas.coverage import (
    CoverageResponse,
    TacticCoverage,
    GapItem,
    RecommendedStrategyItem,
    CoverageHistoryResponse,
    CoverageHistoryItem,
)
from app.services.coverage_service import CoverageService
from app.models.mitre import Technique, Tactic
from app.models.mapping import DetectionMapping
from app.models.detection import Detection, DetectionStatus

router = APIRouter()


@router.get("/{cloud_account_id}", response_model=CoverageResponse)
async def get_coverage(
    cloud_account_id: UUID,
    db: AsyncSession = Depends(get_db),
):
    """Get the latest coverage snapshot for a cloud account."""
    # Verify account exists
    account_result = await db.execute(
        select(CloudAccount).where(CloudAccount.id == cloud_account_id)
    )
    if not account_result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Cloud account not found")

    # Get latest snapshot
    result = await db.execute(
        select(CoverageSnapshot)
        .where(CoverageSnapshot.cloud_account_id == cloud_account_id)
        .order_by(desc(CoverageSnapshot.created_at))
        .limit(1)
    )
    snapshot = result.scalar_one_or_none()

    if not snapshot:
        raise HTTPException(
            status_code=404,
            detail="No coverage data found. Run a scan first.",
        )

    # Transform tactic_coverage dict to list
    tactic_list = []
    for tactic_id, data in snapshot.tactic_coverage.items():
        tactic_list.append(
            TacticCoverage(
                tactic_id=tactic_id,
                tactic_name=data.get("name", tactic_id),
                covered=data.get("covered", 0),
                partial=data.get("partial", 0),
                uncovered=data.get("uncovered", 0),
                total=data.get("total", 0),
                percent=data.get("percent", 0.0),
            )
        )

    # Transform top_gaps with enhanced remediation data
    gap_list = []
    for gap in snapshot.top_gaps:
        # Build recommended strategies list
        strategies = []
        for s in gap.get("recommended_strategies", []):
            strategies.append(
                RecommendedStrategyItem(
                    strategy_id=s.get("strategy_id", ""),
                    name=s.get("name", ""),
                    detection_type=s.get("detection_type", ""),
                    aws_service=s.get("aws_service", ""),
                    implementation_effort=s.get("implementation_effort", ""),
                    estimated_time=s.get("estimated_time", ""),
                    detection_coverage=s.get("detection_coverage", ""),
                    has_query=s.get("has_query", False),
                    has_cloudformation=s.get("has_cloudformation", False),
                    has_terraform=s.get("has_terraform", False),
                    # GCP support
                    gcp_service=s.get("gcp_service"),
                    cloud_provider=s.get("cloud_provider"),
                    has_gcp_query=s.get("has_gcp_query", False),
                    has_gcp_terraform=s.get("has_gcp_terraform", False),
                )
            )

        gap_list.append(
            GapItem(
                technique_id=gap.get("technique_id", ""),
                technique_name=gap.get("name", ""),
                tactic_id=gap.get("tactic_id", ""),
                tactic_name=gap.get("tactic_name", ""),
                priority=gap.get("priority", "medium"),
                reason=gap.get("reason", ""),
                data_sources=gap.get("data_sources", []),
                recommended_detections=gap.get("recommended_detections", []),
                # Enhanced template data
                has_template=gap.get("has_template", False),
                severity_score=gap.get("severity_score"),
                threat_actors=gap.get("threat_actors", []),
                business_impact=gap.get("business_impact", []),
                quick_win_strategy=gap.get("quick_win_strategy"),
                total_effort_hours=gap.get("total_effort_hours"),
                mitre_url=gap.get("mitre_url"),
                recommended_strategies=strategies,
            )
        )

    return CoverageResponse(
        id=snapshot.id,
        cloud_account_id=snapshot.cloud_account_id,
        total_techniques=snapshot.total_techniques,
        covered_techniques=snapshot.covered_techniques,
        partial_techniques=snapshot.partial_techniques,
        uncovered_techniques=snapshot.uncovered_techniques,
        coverage_percent=snapshot.coverage_percent,
        average_confidence=snapshot.average_confidence,
        tactic_coverage=tactic_list,
        total_detections=snapshot.total_detections,
        active_detections=snapshot.active_detections,
        mapped_detections=snapshot.mapped_detections,
        top_gaps=gap_list,
        mitre_version=snapshot.mitre_version,
        created_at=snapshot.created_at,
    )


@router.get("/{cloud_account_id}/history", response_model=CoverageHistoryResponse)
async def get_coverage_history(
    cloud_account_id: UUID,
    days: int = Query(30, ge=1, le=365),
    db: AsyncSession = Depends(get_db),
):
    """Get coverage history for trend analysis."""
    # Verify account exists
    account_result = await db.execute(
        select(CloudAccount).where(CloudAccount.id == cloud_account_id)
    )
    if not account_result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Cloud account not found")

    since = datetime.utcnow() - timedelta(days=days)

    result = await db.execute(
        select(CoverageSnapshot)
        .where(CoverageSnapshot.cloud_account_id == cloud_account_id)
        .where(CoverageSnapshot.created_at >= since)
        .order_by(CoverageSnapshot.created_at)
    )
    snapshots = result.scalars().all()

    history = [
        CoverageHistoryItem(
            date=s.created_at,
            coverage_percent=s.coverage_percent,
            covered_techniques=s.covered_techniques,
            total_techniques=s.total_techniques,
        )
        for s in snapshots
    ]

    # Calculate trend
    if len(history) >= 2:
        first = history[0].coverage_percent
        last = history[-1].coverage_percent
        change = last - first
        if change > 1:
            trend = "improving"
        elif change < -1:
            trend = "declining"
        else:
            trend = "stable"
    else:
        trend = "stable"
        change = 0.0

    return CoverageHistoryResponse(
        cloud_account_id=cloud_account_id,
        history=history,
        trend=trend,
        change_percent=change if len(history) >= 2 else 0.0,
    )


@router.get("/{cloud_account_id}/techniques")
async def get_technique_coverage(
    cloud_account_id: UUID,
    db: AsyncSession = Depends(get_db),
):
    """Get per-technique coverage details for heatmap visualization."""
    # Verify account exists
    account_result = await db.execute(
        select(CloudAccount).where(CloudAccount.id == cloud_account_id)
    )
    if not account_result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Cloud account not found")

    # Get all techniques with their tactics
    techniques_result = await db.execute(
        select(Technique, Tactic).join(Tactic, Technique.tactic_id == Tactic.id)
    )
    techniques_with_tactics = techniques_result.all()

    # Get detections for this account
    detections_result = await db.execute(
        select(Detection.id)
        .where(Detection.cloud_account_id == cloud_account_id)
        .where(Detection.status == DetectionStatus.ACTIVE)
    )
    detection_ids = [d[0] for d in detections_result.all()]

    # Get mappings for these detections grouped by technique
    technique_coverage = []

    for technique, tactic in techniques_with_tactics:
        # Get mappings with detection names for this technique
        detection_names = []
        detection_count = 0
        max_confidence = 0.0

        if detection_ids:
            # Get mappings with detection info
            mappings_result = await db.execute(
                select(DetectionMapping, Detection.name)
                .join(Detection, DetectionMapping.detection_id == Detection.id)
                .where(DetectionMapping.technique_id == technique.id)
                .where(DetectionMapping.detection_id.in_(detection_ids))
                .order_by(DetectionMapping.confidence.desc())
            )
            mappings = mappings_result.all()

            detection_count = len(mappings)
            if mappings:
                max_confidence = mappings[0][
                    0
                ].confidence  # First one has highest confidence
                detection_names = [m[1] for m in mappings]  # Detection names

        # Determine status based on confidence threshold
        if max_confidence >= 0.6:
            status = "covered"
        elif max_confidence >= 0.4:
            status = "partial"
        else:
            status = "uncovered"

        technique_coverage.append(
            {
                "technique_id": technique.technique_id,
                "technique_name": technique.name,
                "tactic_id": tactic.tactic_id,
                "tactic_name": tactic.name,
                "detection_count": detection_count,
                "max_confidence": round(max_confidence, 2) if max_confidence else 0.0,
                "status": status,
                "detection_names": detection_names,
            }
        )

    return {"techniques": technique_coverage}


@router.post("/{cloud_account_id}/calculate", response_model=CoverageResponse)
async def calculate_coverage(
    cloud_account_id: UUID,
    db: AsyncSession = Depends(get_db),
):
    """Manually trigger coverage calculation."""
    # Verify account exists
    account_result = await db.execute(
        select(CloudAccount).where(CloudAccount.id == cloud_account_id)
    )
    if not account_result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Cloud account not found")

    coverage_service = CoverageService(db)
    snapshot = await coverage_service.calculate_coverage(cloud_account_id)

    # Transform for response (same as get_coverage)
    tactic_list = []
    for tactic_id, data in snapshot.tactic_coverage.items():
        tactic_list.append(
            TacticCoverage(
                tactic_id=tactic_id,
                tactic_name=data.get("name", tactic_id),
                covered=data.get("covered", 0),
                partial=data.get("partial", 0),
                uncovered=data.get("uncovered", 0),
                total=data.get("total", 0),
                percent=data.get("percent", 0.0),
            )
        )

    # Transform gaps with enhanced remediation data
    gap_list = []
    for gap in snapshot.top_gaps:
        # Build recommended strategies list
        strategies = []
        for s in gap.get("recommended_strategies", []):
            strategies.append(
                RecommendedStrategyItem(
                    strategy_id=s.get("strategy_id", ""),
                    name=s.get("name", ""),
                    detection_type=s.get("detection_type", ""),
                    aws_service=s.get("aws_service", ""),
                    implementation_effort=s.get("implementation_effort", ""),
                    estimated_time=s.get("estimated_time", ""),
                    detection_coverage=s.get("detection_coverage", ""),
                    has_query=s.get("has_query", False),
                    has_cloudformation=s.get("has_cloudformation", False),
                    has_terraform=s.get("has_terraform", False),
                    # GCP support
                    gcp_service=s.get("gcp_service"),
                    cloud_provider=s.get("cloud_provider"),
                    has_gcp_query=s.get("has_gcp_query", False),
                    has_gcp_terraform=s.get("has_gcp_terraform", False),
                )
            )

        gap_list.append(
            GapItem(
                technique_id=gap.get("technique_id", ""),
                technique_name=gap.get("name", ""),
                tactic_id=gap.get("tactic_id", ""),
                tactic_name=gap.get("tactic_name", ""),
                priority=gap.get("priority", "medium"),
                reason=gap.get("reason", ""),
                data_sources=gap.get("data_sources", []),
                recommended_detections=gap.get("recommended_detections", []),
                # Enhanced template data
                has_template=gap.get("has_template", False),
                severity_score=gap.get("severity_score"),
                threat_actors=gap.get("threat_actors", []),
                business_impact=gap.get("business_impact", []),
                quick_win_strategy=gap.get("quick_win_strategy"),
                total_effort_hours=gap.get("total_effort_hours"),
                mitre_url=gap.get("mitre_url"),
                recommended_strategies=strategies,
            )
        )

    return CoverageResponse(
        id=snapshot.id,
        cloud_account_id=snapshot.cloud_account_id,
        total_techniques=snapshot.total_techniques,
        covered_techniques=snapshot.covered_techniques,
        partial_techniques=snapshot.partial_techniques,
        uncovered_techniques=snapshot.uncovered_techniques,
        coverage_percent=snapshot.coverage_percent,
        average_confidence=snapshot.average_confidence,
        tactic_coverage=tactic_list,
        total_detections=snapshot.total_detections,
        active_detections=snapshot.active_detections,
        mapped_detections=snapshot.mapped_detections,
        top_gaps=gap_list,
        mitre_version=snapshot.mitre_version,
        created_at=snapshot.created_at,
    )
