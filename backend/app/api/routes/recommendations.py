"""Remediation recommendations endpoints."""

from typing import List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.core.database import get_db
from app.core.security import AuthContext, get_auth_context, require_scope
from app.models.cloud_account import CloudAccount
from app.models.coverage import CoverageSnapshot
from app.services.remediation_service import (
    remediation_service,
)
from app.services.mitre_threat_service import MitreThreatService

router = APIRouter()


# Pydantic models for API responses
class TechniqueInfo(BaseModel):
    """Summary info for a technique with remediation template."""

    technique_id: str
    technique_name: str
    tactic_ids: List[str]
    severity_score: int
    strategy_count: int
    total_effort_hours: float
    coverage_improvement: str


class StrategySummary(BaseModel):
    """Summary of a detection strategy."""

    strategy_id: str
    name: str
    detection_type: str
    aws_service: str
    implementation_effort: str
    estimated_time: str
    estimated_monthly_cost: str
    detection_coverage: str
    false_positive_rate: str


class TechniqueRemediationResponse(BaseModel):
    """Full remediation response for a technique."""

    technique_id: str
    technique_name: str
    mitre_url: str
    tactic_ids: List[str]
    threat_description: str
    attacker_goal: str
    why_technique: List[str]
    known_threat_actors: List[str]
    severity_score: int
    severity_reasoning: str
    business_impact: List[str]
    prevalence: str
    trend: str
    recommended_order: List[str]
    total_effort_hours: float
    coverage_improvement: str
    strategies: List[StrategySummary]


class StrategyDetailResponse(BaseModel):
    """Detailed strategy implementation response."""

    strategy_id: str
    name: str
    description: str
    detection_type: str
    # AWS fields
    aws_service: Optional[str] = None
    query: Optional[str] = None  # CloudWatch Logs Insights query
    event_pattern: Optional[dict] = None
    guardduty_finding_types: Optional[List[str]] = None
    cloudformation_template: Optional[str] = None
    terraform_template: Optional[str] = None  # AWS Terraform
    # GCP fields
    gcp_service: Optional[str] = None
    gcp_logging_query: Optional[str] = None
    gcp_terraform_template: Optional[str] = None
    # Cloud provider indicator
    cloud_provider: Optional[str] = None  # "aws", "gcp", or "multi"
    # Common fields
    alert_severity: str
    alert_title: str
    alert_description_template: str
    investigation_steps: List[str]
    containment_actions: List[str]
    estimated_false_positive_rate: str
    false_positive_tuning: str
    detection_coverage: str
    evasion_considerations: str
    implementation_effort: str
    implementation_time: str
    estimated_monthly_cost: str
    prerequisites: List[str]


class QuickWin(BaseModel):
    """Quick win detection strategy."""

    technique_id: str
    technique_name: str
    strategy_id: str
    strategy_name: str
    detection_type: str
    implementation_effort: str
    implementation_time: str
    detection_coverage: str
    severity_score: int
    estimated_hours: float


class ImplementationPhase(BaseModel):
    """Phase of an implementation plan."""

    phase_number: int
    estimated_hours: float
    strategies: List[dict]


class ImplementationPlanResponse(BaseModel):
    """Implementation plan response."""

    total_techniques: int
    techniques_with_templates: int
    total_phases: int
    total_estimated_hours: float
    phases: List[ImplementationPhase]


@router.get(
    "/techniques",
    response_model=List[TechniqueInfo],
    dependencies=[Depends(require_scope("read:recommendations"))],
)
async def list_available_techniques(
    auth: AuthContext = Depends(get_auth_context),
) -> dict:
    """
    List all MITRE ATT&CK techniques that have remediation templates.

    Returns a summary of each technique including severity and effort estimates.
    """
    techniques = remediation_service.get_available_techniques()
    return [TechniqueInfo(**t) for t in techniques]


@router.get(
    "/techniques/{technique_id}",
    response_model=TechniqueRemediationResponse,
    dependencies=[Depends(require_scope("read:recommendations"))],
)
async def get_technique_remediation(
    technique_id: str,
    db: AsyncSession = Depends(get_db),
    auth: AuthContext = Depends(get_auth_context),
) -> dict:
    """
    Get complete remediation guidance for a MITRE ATT&CK technique.

    Includes threat context, detection strategies, and implementation guidance.
    """
    remediation = remediation_service.get_technique_remediation(technique_id)

    if not remediation:
        raise HTTPException(
            status_code=404,
            detail=f"No remediation template found for technique {technique_id}",
        )

    # Fetch threat actors from authoritative MITRE data (not hardcoded)
    threat_service = MitreThreatService(db)
    threat_groups = await threat_service.get_groups_for_technique(
        technique_id.upper(), limit=20
    )
    known_threat_actors = [f"{g.name} ({g.external_id})" for g in threat_groups]

    # Convert dataclass to response model
    strategies = [
        StrategySummary(
            strategy_id=s.strategy_id,
            name=s.name,
            detection_type=s.detection_type,
            aws_service=s.aws_service,
            implementation_effort=s.implementation_effort,
            estimated_time=s.estimated_time,
            estimated_monthly_cost=s.estimated_monthly_cost,
            detection_coverage=s.detection_coverage,
            false_positive_rate=s.false_positive_rate,
        )
        for s in remediation.strategies
    ]

    return TechniqueRemediationResponse(
        technique_id=remediation.technique_id,
        technique_name=remediation.technique_name,
        mitre_url=remediation.mitre_url,
        tactic_ids=remediation.tactic_ids,
        threat_description=remediation.threat_description,
        attacker_goal=remediation.attacker_goal,
        why_technique=remediation.why_technique,
        known_threat_actors=known_threat_actors,  # From MITRE sync data
        severity_score=remediation.severity_score,
        severity_reasoning=remediation.severity_reasoning,
        business_impact=remediation.business_impact,
        prevalence=remediation.prevalence,
        trend=remediation.trend,
        recommended_order=remediation.recommended_order,
        total_effort_hours=remediation.total_effort_hours,
        coverage_improvement=remediation.coverage_improvement,
        strategies=strategies,
    )


@router.get(
    "/techniques/{technique_id}/strategies/{strategy_id}",
    response_model=StrategyDetailResponse,
    dependencies=[Depends(require_scope("read:recommendations"))],
)
async def get_strategy_details(
    technique_id: str,
    strategy_id: str,
    auth: AuthContext = Depends(get_auth_context),
) -> dict:
    """
    Get detailed implementation guidance for a specific detection strategy.

    Includes CloudWatch queries, CloudFormation templates, and response guidance.
    """
    details = remediation_service.get_strategy_details(technique_id, strategy_id)

    if not details:
        raise HTTPException(
            status_code=404,
            detail=f"Strategy {strategy_id} not found for technique {technique_id}",
        )

    return StrategyDetailResponse(
        strategy_id=details.strategy_id,
        name=details.name,
        description=details.description,
        detection_type=details.detection_type,
        # AWS fields
        aws_service=details.aws_service,
        query=details.query,
        event_pattern=details.event_pattern,
        guardduty_finding_types=details.guardduty_finding_types,
        cloudformation_template=details.cloudformation_template,
        terraform_template=details.terraform_template,
        # GCP fields
        gcp_service=details.gcp_service,
        gcp_logging_query=details.gcp_logging_query,
        gcp_terraform_template=details.gcp_terraform_template,
        # Cloud provider indicator
        cloud_provider=details.cloud_provider,
        # Common fields
        alert_severity=details.alert_severity,
        alert_title=details.alert_title,
        alert_description_template=details.alert_description_template,
        investigation_steps=details.investigation_steps,
        containment_actions=details.containment_actions,
        estimated_false_positive_rate=details.estimated_false_positive_rate,
        false_positive_tuning=details.false_positive_tuning,
        detection_coverage=details.detection_coverage,
        evasion_considerations=details.evasion_considerations,
        implementation_effort=details.implementation_effort,
        implementation_time=details.implementation_time,
        estimated_monthly_cost=details.estimated_monthly_cost,
        prerequisites=details.prerequisites,
    )


@router.get(
    "/by-tactic/{tactic_id}",
    response_model=List[TechniqueInfo],
    dependencies=[Depends(require_scope("read:recommendations"))],
)
async def get_techniques_by_tactic(
    tactic_id: str,
    auth: AuthContext = Depends(get_auth_context),
) -> dict:
    """
    Get all techniques with remediation templates for a specific MITRE tactic.
    """
    techniques = remediation_service.get_techniques_by_tactic(tactic_id)
    return [TechniqueInfo(**t) for t in techniques]


@router.get(
    "/{cloud_account_id}/quick-wins",
    response_model=List[QuickWin],
    dependencies=[Depends(require_scope("read:recommendations"))],
)
async def get_quick_wins(
    cloud_account_id: UUID,
    max_hours: float = Query(2.0, description="Maximum implementation time in hours"),
    limit: int = Query(10, ge=1, le=50),
    auth: AuthContext = Depends(get_auth_context),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """
    Get quick-win detection strategies for a cloud account's coverage gaps.

    These are low-effort, high-value detections that can be implemented quickly.
    """
    # Verify account exists and belongs to user's organization
    account_result = await db.execute(
        select(CloudAccount).where(
            CloudAccount.id == cloud_account_id,
            CloudAccount.organization_id == auth.organization_id,
        )
    )
    if not account_result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Cloud account not found")

    # Get latest coverage snapshot for gap techniques
    result = await db.execute(
        select(CoverageSnapshot)
        .where(CoverageSnapshot.cloud_account_id == cloud_account_id)
        .order_by(CoverageSnapshot.created_at.desc())
        .limit(1)
    )
    snapshot = result.scalar_one_or_none()

    if not snapshot or not snapshot.top_gaps:
        return []

    # Extract technique IDs from gaps
    technique_ids = [
        gap.get("technique_id") for gap in snapshot.top_gaps if gap.get("technique_id")
    ]

    quick_wins = remediation_service.get_quick_wins(
        technique_ids=technique_ids, max_effort_hours=max_hours
    )

    return [QuickWin(**qw) for qw in quick_wins[:limit]]


@router.get(
    "/{cloud_account_id}/plan",
    response_model=ImplementationPlanResponse,
    dependencies=[Depends(require_scope("read:recommendations"))],
)
async def get_implementation_plan(
    cloud_account_id: UUID,
    budget_hours: Optional[float] = Query(
        None, description="Optional time budget constraint"
    ),
    auth: AuthContext = Depends(get_auth_context),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """
    Generate a prioritised implementation plan for addressing coverage gaps.

    Phases are organised by severity with estimated effort for each.
    """
    # Verify account exists and belongs to user's organization
    account_result = await db.execute(
        select(CloudAccount).where(
            CloudAccount.id == cloud_account_id,
            CloudAccount.organization_id == auth.organization_id,
        )
    )
    if not account_result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Cloud account not found")

    # Get latest coverage snapshot for gap techniques
    result = await db.execute(
        select(CoverageSnapshot)
        .where(CoverageSnapshot.cloud_account_id == cloud_account_id)
        .order_by(CoverageSnapshot.created_at.desc())
        .limit(1)
    )
    snapshot = result.scalar_one_or_none()

    if not snapshot or not snapshot.top_gaps:
        return ImplementationPlanResponse(
            total_techniques=0,
            techniques_with_templates=0,
            total_phases=0,
            total_estimated_hours=0,
            phases=[],
        )

    # Extract technique IDs from gaps
    technique_ids = [
        gap.get("technique_id") for gap in snapshot.top_gaps if gap.get("technique_id")
    ]

    plan = remediation_service.generate_implementation_plan(
        technique_ids=technique_ids, budget_hours=budget_hours
    )

    phases = [
        ImplementationPhase(
            phase_number=p["phase_number"],
            estimated_hours=p["estimated_hours"],
            strategies=p["strategies"],
        )
        for p in plan["phases"]
    ]

    return ImplementationPlanResponse(
        total_techniques=plan["total_techniques"],
        techniques_with_templates=plan["techniques_with_templates"],
        total_phases=plan["total_phases"],
        total_estimated_hours=plan["total_estimated_hours"],
        phases=phases,
    )
