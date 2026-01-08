"""Advanced analytics endpoints."""

from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.security import (
    AuthContext,
    get_auth_context,
    require_scope,
    require_feature,
)
from app.services.analytics_service import AnalyticsService


router = APIRouter()


# Response Models


class TrendDataPoint(BaseModel):
    """Single trend data point."""

    date: str
    coverage_percent: float
    covered_techniques: int
    total_techniques: int
    average_confidence: float


class TrendStatistics(BaseModel):
    """Trend statistics."""

    start_coverage: float
    end_coverage: float
    change_percent: float
    average_coverage: float
    max_coverage: float
    min_coverage: float
    trend_direction: str
    data_points: int


class TrendsResponse(BaseModel):
    """Coverage trends response."""

    trend_data: list[TrendDataPoint]
    statistics: Optional[TrendStatistics]
    period_days: int


class GapPriorityItem(BaseModel):
    """Prioritised gap item."""

    technique_id: str
    technique_name: str
    tactic_id: str
    tactic_name: str
    impact_score: int
    priority: str
    description: Optional[str]


class GapPrioritizationResponse(BaseModel):
    """Gap prioritisation response."""

    gaps: list[GapPriorityItem]
    total: int


class DetectionTypeEffectiveness(BaseModel):
    """Effectiveness by detection type."""

    detection_type: str
    total_detections: int
    active_detections: int
    techniques_covered: int
    effectiveness_rate: float


class EffectivenessSummary(BaseModel):
    """Effectiveness summary."""

    total_detections: int
    active_detections: int
    total_techniques_covered: int
    overall_effectiveness: float


class EffectivenessResponse(BaseModel):
    """Detection effectiveness response."""

    by_type: list[DetectionTypeEffectiveness]
    summary: EffectivenessSummary


class RecommendationItem(BaseModel):
    """Recommendation item."""

    type: str
    priority: str
    title: str
    message: str
    action: str


class RecommendationsResponse(BaseModel):
    """Recommendations response."""

    recommendations: list[RecommendationItem]


class TacticBreakdownItem(BaseModel):
    """Tactic breakdown item."""

    tactic_id: str
    tactic_name: str
    total_techniques: int
    covered_techniques: int
    coverage_percent: float
    priority_score: int


class TacticBreakdownResponse(BaseModel):
    """Tactic breakdown response."""

    tactics: list[TacticBreakdownItem]


# Endpoints


@router.get(
    "/trends",
    response_model=TrendsResponse,
    dependencies=[
        Depends(require_feature("historical_trends")),
        Depends(require_scope("read:analytics")),
    ],
)
async def get_coverage_trends(
    cloud_account_id: Optional[UUID] = None,
    days: int = Query(30, ge=1, le=365),
    auth: AuthContext = Depends(get_auth_context),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Get coverage trend analysis over time.

    Provides historical coverage data with statistics including
    trend direction, average, and change percentage.
    """
    if not auth.organization_id:
        raise HTTPException(status_code=401, detail="Organisation context required")

    service = AnalyticsService(db)
    result = await service.get_coverage_trends(
        auth.organization_id, cloud_account_id, days
    )

    # Transform statistics if present
    stats = None
    if result.get("statistics"):
        stats = TrendStatistics(**result["statistics"])

    # Transform trend data
    trend_data = [TrendDataPoint(**d) for d in result.get("trend_data", [])]

    return TrendsResponse(
        trend_data=trend_data,
        statistics=stats,
        period_days=result.get("period_days", days),
    )


@router.get(
    "/gaps",
    response_model=GapPrioritizationResponse,
    dependencies=[
        Depends(require_feature("historical_trends")),
        Depends(require_scope("read:analytics")),
    ],
)
async def get_gap_prioritization(
    cloud_account_id: Optional[UUID] = None,
    limit: int = Query(20, ge=1, le=100),
    auth: AuthContext = Depends(get_auth_context),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Get prioritised gap analysis with impact scores.

    Returns uncovered techniques sorted by impact score,
    considering tactic position in the kill chain.
    """
    if not auth.organization_id:
        raise HTTPException(status_code=401, detail="Organisation context required")

    service = AnalyticsService(db)
    gaps = await service.get_gap_prioritization(
        auth.organization_id, cloud_account_id, limit
    )

    return GapPrioritizationResponse(
        gaps=[GapPriorityItem(**g) for g in gaps],
        total=len(gaps),
    )


@router.get(
    "/effectiveness",
    response_model=EffectivenessResponse,
    dependencies=[
        Depends(require_feature("historical_trends")),
        Depends(require_scope("read:analytics")),
    ],
)
async def get_detection_effectiveness(
    cloud_account_id: Optional[UUID] = None,
    auth: AuthContext = Depends(get_auth_context),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Analyse detection effectiveness by type and coverage.

    Provides breakdown of detection effectiveness by type
    (CloudWatch, GuardDuty, etc.) with active/total ratios.
    """
    if not auth.organization_id:
        raise HTTPException(status_code=401, detail="Organisation context required")

    service = AnalyticsService(db)
    result = await service.get_detection_effectiveness(
        auth.organization_id, cloud_account_id
    )

    by_type = [DetectionTypeEffectiveness(**d) for d in result.get("by_type", [])]
    summary = EffectivenessSummary(**result.get("summary", {}))

    return EffectivenessResponse(by_type=by_type, summary=summary)


@router.get(
    "/recommendations",
    response_model=RecommendationsResponse,
    dependencies=[
        Depends(require_feature("historical_trends")),
        Depends(require_scope("read:analytics")),
    ],
)
async def get_recommendations(
    cloud_account_id: Optional[UUID] = None,
    limit: int = Query(10, ge=1, le=50),
    auth: AuthContext = Depends(get_auth_context),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Generate actionable security recommendations.

    Analyses coverage trends, effectiveness, and gaps to provide
    prioritised recommendations for improving detection coverage.
    """
    if not auth.organization_id:
        raise HTTPException(status_code=401, detail="Organisation context required")

    service = AnalyticsService(db)
    recommendations = await service.get_recommendations(
        auth.organization_id, cloud_account_id, limit
    )

    return RecommendationsResponse(
        recommendations=[RecommendationItem(**r) for r in recommendations]
    )


@router.get(
    "/tactics",
    response_model=TacticBreakdownResponse,
    dependencies=[
        Depends(require_feature("historical_trends")),
        Depends(require_scope("read:analytics")),
    ],
)
async def get_tactic_breakdown(
    cloud_account_id: Optional[UUID] = None,
    auth: AuthContext = Depends(get_auth_context),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Get coverage breakdown by MITRE ATT&CK tactic.

    Returns per-tactic coverage with priority scores based on
    position in the kill chain.
    """
    if not auth.organization_id:
        raise HTTPException(status_code=401, detail="Organisation context required")

    service = AnalyticsService(db)
    breakdown = await service.get_tactic_breakdown(
        auth.organization_id, cloud_account_id
    )

    return TacticBreakdownResponse(
        tactics=[TacticBreakdownItem(**t) for t in breakdown]
    )


@router.get(
    "/summary",
    dependencies=[
        Depends(require_feature("historical_trends")),
        Depends(require_scope("read:analytics")),
    ],
)
async def get_analytics_summary(
    cloud_account_id: Optional[UUID] = None,
    auth: AuthContext = Depends(get_auth_context),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Get a comprehensive analytics summary.

    Combines trends, effectiveness, and top recommendations
    into a single dashboard view.
    """
    if not auth.organization_id:
        raise HTTPException(status_code=401, detail="Organisation context required")

    service = AnalyticsService(db)

    # Get multiple analytics in parallel
    trends = await service.get_coverage_trends(
        auth.organization_id, cloud_account_id, days=7
    )
    effectiveness = await service.get_detection_effectiveness(
        auth.organization_id, cloud_account_id
    )
    gaps = await service.get_gap_prioritization(
        auth.organization_id, cloud_account_id, limit=5
    )
    recommendations = await service.get_recommendations(
        auth.organization_id, cloud_account_id, limit=3
    )

    return {
        "trends_7d": {
            "direction": trends.get("statistics", {}).get("trend_direction", "stable"),
            "change_percent": trends.get("statistics", {}).get("change_percent", 0),
            "current_coverage": trends.get("statistics", {}).get("end_coverage", 0),
        },
        "effectiveness": effectiveness.get("summary", {}),
        "top_gaps": [
            {
                "technique_id": g["technique_id"],
                "technique_name": g["technique_name"],
                "priority": g["priority"],
            }
            for g in gaps[:3]
        ],
        "top_recommendations": [
            {
                "title": r["title"],
                "priority": r["priority"],
            }
            for r in recommendations[:3]
        ],
    }
