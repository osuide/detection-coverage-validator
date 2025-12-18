"""Coverage endpoints."""

from typing import Optional
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
    CoverageHistoryResponse,
    CoverageHistoryItem,
)
from app.services.coverage_service import CoverageService

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

    # Transform top_gaps
    gap_list = []
    for gap in snapshot.top_gaps:
        gap_list.append(
            GapItem(
                technique_id=gap.get("technique_id", ""),
                technique_name=gap.get("name", ""),
                tactic_id=gap.get("tactic_id", ""),
                tactic_name=gap.get("tactic_name", ""),
                priority=gap.get("priority", "medium"),
                reason=gap.get("reason", ""),
                data_sources=gap.get("data_sources", []),
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

    gap_list = []
    for gap in snapshot.top_gaps:
        gap_list.append(
            GapItem(
                technique_id=gap.get("technique_id", ""),
                technique_name=gap.get("name", ""),
                tactic_id=gap.get("tactic_id", ""),
                tactic_name=gap.get("tactic_name", ""),
                priority=gap.get("priority", "medium"),
                reason=gap.get("reason", ""),
                data_sources=gap.get("data_sources", []),
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
