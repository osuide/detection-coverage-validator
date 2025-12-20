"""Coverage endpoints."""

from typing import Optional
from uuid import UUID
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc

from app.core.database import get_db
from app.core.security import AuthContext, get_auth_context
from app.models.coverage import CoverageSnapshot, OrgCoverageSnapshot
from app.models.cloud_account import CloudAccount
from app.models.cloud_organization import CloudOrganization
from app.schemas.coverage import (
    CoverageResponse,
    TacticCoverage,
    CoverageBreakdown,
    GapItem,
    RecommendedStrategyItem,
    CoverageHistoryResponse,
    CoverageHistoryItem,
    OrgCoverageResponse,
    OrgTacticCoverage,
    AccountCoverageSummary,
)
from app.services.coverage_service import CoverageService
from app.services.drift_detection_service import DriftDetectionService
from app.models.mitre import Technique, Tactic
from app.models.mapping import DetectionMapping
from app.models.detection import Detection, DetectionStatus

router = APIRouter()


# Drift detection response models
class DriftHistoryItem(BaseModel):
    """Single drift history entry."""

    id: str
    recorded_at: str
    coverage_percent: float
    covered_techniques: int
    total_techniques: int
    coverage_delta: float
    drift_severity: str
    techniques_added_count: int
    techniques_removed_count: int


class DriftHistoryResponse(BaseModel):
    """Drift history response."""

    cloud_account_id: str
    history: list[DriftHistoryItem]


class DriftAlertItem(BaseModel):
    """Drift alert item."""

    id: str
    cloud_account_id: Optional[str]
    alert_type: str
    severity: str
    title: str
    message: str
    details: dict
    is_acknowledged: bool
    acknowledged_at: Optional[str]
    created_at: str


class DriftAlertsResponse(BaseModel):
    """Drift alerts response."""

    alerts: list[DriftAlertItem]
    total: int


class DriftSummaryResponse(BaseModel):
    """Drift summary response."""

    unacknowledged_alerts: dict
    total_unacknowledged: int
    coverage_trend_7d: float
    snapshots_last_7d: int


@router.get("/{cloud_account_id}", response_model=CoverageResponse)
async def get_coverage(
    cloud_account_id: UUID,
    auth: AuthContext = Depends(get_auth_context),
    db: AsyncSession = Depends(get_db),
):
    """Get the latest coverage snapshot for a cloud account."""
    # Verify account exists and belongs to user's organization
    account_result = await db.execute(
        select(CloudAccount).where(
            CloudAccount.id == cloud_account_id,
            CloudAccount.organization_id == auth.organization_id,
        )
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

    # Build coverage breakdown if available
    coverage_breakdown = None
    if snapshot.coverage_breakdown:
        coverage_breakdown = CoverageBreakdown(
            account_only=snapshot.coverage_breakdown.get("account_only", 0),
            org_only=snapshot.coverage_breakdown.get("org_only", 0),
            both=snapshot.coverage_breakdown.get("both", 0),
            total_covered=snapshot.coverage_breakdown.get("total_covered", 0),
            cloud_organization_id=snapshot.coverage_breakdown.get(
                "cloud_organization_id"
            ),
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
        # Org contribution fields
        org_detection_count=snapshot.org_detection_count or 0,
        org_covered_techniques=snapshot.org_covered_techniques or 0,
        account_only_techniques=snapshot.account_only_techniques or 0,
        org_only_techniques=snapshot.org_only_techniques or 0,
        overlap_techniques=snapshot.overlap_techniques or 0,
        coverage_breakdown=coverage_breakdown,
    )


@router.get("/{cloud_account_id}/history", response_model=CoverageHistoryResponse)
async def get_coverage_history(
    cloud_account_id: UUID,
    days: int = Query(30, ge=1, le=365),
    auth: AuthContext = Depends(get_auth_context),
    db: AsyncSession = Depends(get_db),
):
    """Get coverage history for trend analysis."""
    # Verify account exists and belongs to user's organization
    account_result = await db.execute(
        select(CloudAccount).where(
            CloudAccount.id == cloud_account_id,
            CloudAccount.organization_id == auth.organization_id,
        )
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
    auth: AuthContext = Depends(get_auth_context),
    db: AsyncSession = Depends(get_db),
):
    """Get per-technique coverage details for heatmap visualization."""
    # Verify account exists and belongs to user's organization
    account_result = await db.execute(
        select(CloudAccount).where(
            CloudAccount.id == cloud_account_id,
            CloudAccount.organization_id == auth.organization_id,
        )
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
    auth: AuthContext = Depends(get_auth_context),
    db: AsyncSession = Depends(get_db),
):
    """Manually trigger coverage calculation."""
    # Verify account exists and belongs to user's organization
    account_result = await db.execute(
        select(CloudAccount).where(
            CloudAccount.id == cloud_account_id,
            CloudAccount.organization_id == auth.organization_id,
        )
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

    # Build coverage breakdown if available
    calc_coverage_breakdown = None
    if snapshot.coverage_breakdown:
        calc_coverage_breakdown = CoverageBreakdown(
            account_only=snapshot.coverage_breakdown.get("account_only", 0),
            org_only=snapshot.coverage_breakdown.get("org_only", 0),
            both=snapshot.coverage_breakdown.get("both", 0),
            total_covered=snapshot.coverage_breakdown.get("total_covered", 0),
            cloud_organization_id=snapshot.coverage_breakdown.get(
                "cloud_organization_id"
            ),
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
        # Org contribution fields
        org_detection_count=snapshot.org_detection_count or 0,
        org_covered_techniques=snapshot.org_covered_techniques or 0,
        account_only_techniques=snapshot.account_only_techniques or 0,
        org_only_techniques=snapshot.org_only_techniques or 0,
        overlap_techniques=snapshot.overlap_techniques or 0,
        coverage_breakdown=calc_coverage_breakdown,
    )


# Organisation Coverage Endpoints


@router.get("/organization/{cloud_organization_id}", response_model=OrgCoverageResponse)
async def get_org_coverage(
    cloud_organization_id: UUID,
    auth: AuthContext = Depends(get_auth_context),
    db: AsyncSession = Depends(get_db),
):
    """Get the latest aggregate coverage for a cloud organisation."""
    # Verify org exists and belongs to user's organization
    org_result = await db.execute(
        select(CloudOrganization).where(
            CloudOrganization.id == cloud_organization_id,
            CloudOrganization.organization_id == auth.organization_id,
        )
    )
    cloud_org = org_result.scalar_one_or_none()
    if not cloud_org:
        raise HTTPException(status_code=404, detail="Cloud organisation not found")

    # Get latest org coverage snapshot
    result = await db.execute(
        select(OrgCoverageSnapshot)
        .where(OrgCoverageSnapshot.cloud_organization_id == cloud_organization_id)
        .order_by(desc(OrgCoverageSnapshot.created_at))
        .limit(1)
    )
    snapshot = result.scalar_one_or_none()

    if not snapshot:
        raise HTTPException(
            status_code=404,
            detail="No org coverage data found. Run a scan on member accounts first.",
        )

    # Transform tactic coverage
    tactic_list = []
    for tactic_id, data in snapshot.tactic_coverage.items():
        tactic_list.append(
            OrgTacticCoverage(
                tactic_id=tactic_id,
                tactic_name=data.get("tactic_name", tactic_id),
                total_techniques=data.get("total_techniques", 0),
                union_covered=data.get("union_covered", 0),
                minimum_covered=data.get("minimum_covered", 0),
                union_percent=data.get("union_percent", 0.0),
                minimum_percent=data.get("minimum_percent", 0.0),
            )
        )

    # Get per-account details
    per_account_list = []
    if snapshot.per_account_coverage:
        # Get account details
        account_ids = [UUID(aid) for aid in snapshot.per_account_coverage.keys()]
        if account_ids:
            accounts_result = await db.execute(
                select(CloudAccount).where(CloudAccount.id.in_(account_ids))
            )
            accounts = {str(a.id): a for a in accounts_result.scalars().all()}

            for account_id_str, coverage in snapshot.per_account_coverage.items():
                account = accounts.get(account_id_str)
                if account:
                    per_account_list.append(
                        AccountCoverageSummary(
                            cloud_account_id=UUID(account_id_str),
                            account_name=account.name,
                            account_id=account.account_id,
                            coverage_percent=coverage,
                            covered_techniques=int(
                                coverage * snapshot.total_techniques / 100
                            ),
                            total_techniques=snapshot.total_techniques,
                        )
                    )

    return OrgCoverageResponse(
        id=snapshot.id,
        cloud_organization_id=snapshot.cloud_organization_id,
        total_member_accounts=snapshot.total_member_accounts,
        connected_accounts=snapshot.connected_accounts,
        total_techniques=snapshot.total_techniques,
        union_covered_techniques=snapshot.union_covered_techniques,
        minimum_covered_techniques=snapshot.minimum_covered_techniques,
        average_coverage_percent=snapshot.average_coverage_percent,
        union_coverage_percent=snapshot.union_coverage_percent,
        minimum_coverage_percent=snapshot.minimum_coverage_percent,
        org_detection_count=snapshot.org_detection_count,
        org_covered_techniques=snapshot.org_covered_techniques,
        tactic_coverage=tactic_list,
        per_account_coverage=per_account_list,
        mitre_version=snapshot.mitre_version,
        created_at=snapshot.created_at,
    )


@router.post(
    "/organization/{cloud_organization_id}/calculate",
    response_model=OrgCoverageResponse,
)
async def calculate_org_coverage(
    cloud_organization_id: UUID,
    auth: AuthContext = Depends(get_auth_context),
    db: AsyncSession = Depends(get_db),
):
    """Manually trigger aggregate coverage calculation for an organisation."""
    # Verify org exists and belongs to user's organization
    org_result = await db.execute(
        select(CloudOrganization).where(
            CloudOrganization.id == cloud_organization_id,
            CloudOrganization.organization_id == auth.organization_id,
        )
    )
    cloud_org = org_result.scalar_one_or_none()
    if not cloud_org:
        raise HTTPException(status_code=404, detail="Cloud organisation not found")

    coverage_service = CoverageService(db)
    snapshot = await coverage_service.calculate_org_coverage(cloud_organization_id)

    # Transform tactic coverage
    tactic_list = []
    for tactic_id, data in snapshot.tactic_coverage.items():
        tactic_list.append(
            OrgTacticCoverage(
                tactic_id=tactic_id,
                tactic_name=data.get("tactic_name", tactic_id),
                total_techniques=data.get("total_techniques", 0),
                union_covered=data.get("union_covered", 0),
                minimum_covered=data.get("minimum_covered", 0),
                union_percent=data.get("union_percent", 0.0),
                minimum_percent=data.get("minimum_percent", 0.0),
            )
        )

    # Get per-account details
    per_account_list = []
    if snapshot.per_account_coverage:
        account_ids = [UUID(aid) for aid in snapshot.per_account_coverage.keys()]
        if account_ids:
            accounts_result = await db.execute(
                select(CloudAccount).where(CloudAccount.id.in_(account_ids))
            )
            accounts = {str(a.id): a for a in accounts_result.scalars().all()}

            for account_id_str, coverage in snapshot.per_account_coverage.items():
                account = accounts.get(account_id_str)
                if account:
                    per_account_list.append(
                        AccountCoverageSummary(
                            cloud_account_id=UUID(account_id_str),
                            account_name=account.name,
                            account_id=account.account_id,
                            coverage_percent=coverage,
                            covered_techniques=int(
                                coverage * snapshot.total_techniques / 100
                            ),
                            total_techniques=snapshot.total_techniques,
                        )
                    )

    return OrgCoverageResponse(
        id=snapshot.id,
        cloud_organization_id=snapshot.cloud_organization_id,
        total_member_accounts=snapshot.total_member_accounts,
        connected_accounts=snapshot.connected_accounts,
        total_techniques=snapshot.total_techniques,
        union_covered_techniques=snapshot.union_covered_techniques,
        minimum_covered_techniques=snapshot.minimum_covered_techniques,
        average_coverage_percent=snapshot.average_coverage_percent,
        union_coverage_percent=snapshot.union_coverage_percent,
        minimum_coverage_percent=snapshot.minimum_coverage_percent,
        org_detection_count=snapshot.org_detection_count,
        org_covered_techniques=snapshot.org_covered_techniques,
        tactic_coverage=tactic_list,
        per_account_coverage=per_account_list,
        mitre_version=snapshot.mitre_version,
        created_at=snapshot.created_at,
    )


# Drift Detection Endpoints


@router.get("/{cloud_account_id}/drift", response_model=DriftHistoryResponse)
async def get_drift_history(
    cloud_account_id: UUID,
    days: int = Query(30, ge=1, le=365),
    auth: AuthContext = Depends(get_auth_context),
    db: AsyncSession = Depends(get_db),
):
    """Get coverage drift history for trend analysis."""
    if not auth.organization_id:
        raise HTTPException(status_code=401, detail="Organisation context required")

    service = DriftDetectionService(db)
    history = await service.get_coverage_history(
        cloud_account_id, auth.organization_id, days
    )

    return DriftHistoryResponse(
        cloud_account_id=str(cloud_account_id),
        history=[DriftHistoryItem(**h) for h in history],
    )


@router.post("/{cloud_account_id}/drift/snapshot")
async def record_drift_snapshot(
    cloud_account_id: UUID,
    auth: AuthContext = Depends(get_auth_context),
    db: AsyncSession = Depends(get_db),
):
    """Manually record a coverage snapshot for drift tracking."""
    # Verify account belongs to organization
    account_result = await db.execute(
        select(CloudAccount).where(
            CloudAccount.id == cloud_account_id,
            CloudAccount.organization_id == auth.organization_id,
        )
    )
    if not account_result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Cloud account not found")

    service = DriftDetectionService(db)
    snapshot = await service.record_coverage_snapshot(cloud_account_id)

    return {
        "id": str(snapshot.id),
        "coverage_percent": snapshot.coverage_percent,
        "coverage_delta": snapshot.coverage_delta,
        "drift_severity": snapshot.drift_severity.value,
        "techniques_added": len(snapshot.techniques_added or []),
        "techniques_removed": len(snapshot.techniques_removed or []),
        "recorded_at": snapshot.recorded_at.isoformat(),
    }


@router.get("/drift/alerts", response_model=DriftAlertsResponse)
async def get_drift_alerts(
    cloud_account_id: Optional[UUID] = None,
    acknowledged: Optional[bool] = None,
    days: int = Query(30, ge=1, le=365),
    auth: AuthContext = Depends(get_auth_context),
    db: AsyncSession = Depends(get_db),
):
    """Get coverage drift alerts for the organization."""
    if not auth.organization_id:
        raise HTTPException(status_code=401, detail="Organisation context required")

    service = DriftDetectionService(db)
    alerts = await service.get_drift_alerts(
        auth.organization_id, cloud_account_id, acknowledged, days
    )

    return DriftAlertsResponse(
        alerts=[DriftAlertItem(**a) for a in alerts],
        total=len(alerts),
    )


@router.post("/drift/alerts/{alert_id}/acknowledge")
async def acknowledge_drift_alert(
    alert_id: UUID,
    auth: AuthContext = Depends(get_auth_context),
    db: AsyncSession = Depends(get_db),
):
    """Acknowledge a coverage drift alert."""
    if not auth.organization_id or not auth.user_id:
        raise HTTPException(status_code=401, detail="Authentication required")

    service = DriftDetectionService(db)
    success = await service.acknowledge_alert(
        alert_id, auth.organization_id, auth.user_id
    )

    if not success:
        raise HTTPException(status_code=404, detail="Alert not found")

    return {"message": "Alert acknowledged"}


@router.get("/drift/summary", response_model=DriftSummaryResponse)
async def get_drift_summary(
    cloud_account_id: Optional[UUID] = None,
    auth: AuthContext = Depends(get_auth_context),
    db: AsyncSession = Depends(get_db),
):
    """Get drift summary statistics for the organization."""
    if not auth.organization_id:
        raise HTTPException(status_code=401, detail="Organisation context required")

    service = DriftDetectionService(db)
    summary = await service.get_drift_summary(auth.organization_id, cloud_account_id)

    return DriftSummaryResponse(**summary)
