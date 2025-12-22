"""Technique and remediation template API endpoints."""

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.security import AuthContext, require_role
from app.models.user import UserRole
from app.models.mitre import Tactic
from app.data.remediation_templates.template_loader import get_template

router = APIRouter(prefix="/techniques", tags=["techniques"])


# Response schemas
class CampaignResponse(BaseModel):
    """Known campaign using this technique."""

    name: str
    year: int
    description: str
    reference_url: Optional[str] = None


class ThreatContextResponse(BaseModel):
    """Threat intelligence context for a technique."""

    description: str
    attacker_goal: str
    why_technique: list[str]
    known_threat_actors: list[str]
    recent_campaigns: list[CampaignResponse]
    prevalence: str
    trend: str
    severity_score: int
    severity_reasoning: str
    business_impact: list[str]
    typical_attack_phase: str
    often_precedes: list[str]
    often_follows: list[str]


class DetectionImplementationResponse(BaseModel):
    """Implementation details for a detection strategy."""

    query: Optional[str] = None
    gcp_logging_query: Optional[str] = None
    guardduty_finding_types: Optional[list[str]] = None
    cloudformation_template: Optional[str] = None
    terraform_template: Optional[str] = None
    gcp_terraform_template: Optional[str] = None
    alert_severity: str
    alert_title: str
    alert_description_template: str
    investigation_steps: list[str]
    containment_actions: list[str]


class DetectionStrategyResponse(BaseModel):
    """A detection strategy for a technique."""

    strategy_id: str
    name: str
    description: str
    detection_type: str
    aws_service: Optional[str] = None
    gcp_service: Optional[str] = None
    cloud_provider: str
    implementation: DetectionImplementationResponse
    estimated_false_positive_rate: str
    false_positive_tuning: Optional[str] = None
    detection_coverage: Optional[str] = None
    evasion_considerations: Optional[str] = None
    implementation_effort: str
    implementation_time: Optional[str] = None
    estimated_monthly_cost: Optional[str] = None
    prerequisites: list[str]


class TechniqueDetailResponse(BaseModel):
    """Full technique detail with remediation templates."""

    technique_id: str
    technique_name: str
    tactic_ids: list[str]
    tactic_names: list[str]
    mitre_url: str
    threat_context: ThreatContextResponse
    detection_strategies: list[DetectionStrategyResponse]
    recommended_order: list[str]
    total_effort_hours: float
    coverage_improvement: str


class TechniqueSummaryResponse(BaseModel):
    """Brief technique summary."""

    technique_id: str
    technique_name: str
    tactic_ids: list[str]
    has_template: bool
    strategy_count: int


@router.get("/{technique_id}", response_model=TechniqueDetailResponse)
async def get_technique_detail(
    technique_id: str,
    db: AsyncSession = Depends(get_db),
    auth: AuthContext = Depends(
        require_role(UserRole.MEMBER, UserRole.VIEWER, UserRole.ADMIN, UserRole.OWNER)
    ),
) -> TechniqueDetailResponse:
    """Get detailed technique information with remediation templates.

    Returns threat context, detection strategies with IaC templates,
    and implementation guidance.
    """
    # Normalise technique ID (handle both T1055 and t1055)
    technique_id = technique_id.upper()

    # Get template from our remediation data
    template = get_template(technique_id)
    if not template:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No remediation template available for technique {technique_id}",
        )

    # Get tactic names from database
    tactic_names = []
    for tactic_id in template.tactic_ids:
        result = await db.execute(select(Tactic).where(Tactic.tactic_id == tactic_id))
        tactic = result.scalar_one_or_none()
        if tactic:
            tactic_names.append(tactic.name)

    # Build response
    return TechniqueDetailResponse(
        technique_id=template.technique_id,
        technique_name=template.technique_name,
        tactic_ids=template.tactic_ids,
        tactic_names=tactic_names,
        mitre_url=template.mitre_url,
        threat_context=ThreatContextResponse(
            description=template.threat_context.description,
            attacker_goal=template.threat_context.attacker_goal,
            why_technique=template.threat_context.why_technique,
            known_threat_actors=template.threat_context.known_threat_actors,
            recent_campaigns=[
                CampaignResponse(
                    name=c.name,
                    year=c.year,
                    description=c.description,
                    reference_url=c.reference_url,
                )
                # Sort by year descending (most recent first)
                for c in sorted(
                    template.threat_context.recent_campaigns,
                    key=lambda x: x.year,
                    reverse=True,
                )
            ],
            prevalence=template.threat_context.prevalence,
            trend=template.threat_context.trend,
            severity_score=template.threat_context.severity_score,
            severity_reasoning=template.threat_context.severity_reasoning,
            business_impact=template.threat_context.business_impact,
            typical_attack_phase=template.threat_context.typical_attack_phase,
            often_precedes=template.threat_context.often_precedes,
            often_follows=template.threat_context.often_follows,
        ),
        detection_strategies=[
            DetectionStrategyResponse(
                strategy_id=s.strategy_id,
                name=s.name,
                description=s.description,
                detection_type=s.detection_type.value,
                aws_service=s.aws_service,
                gcp_service=s.gcp_service,
                cloud_provider=s.cloud_provider.value,
                implementation=DetectionImplementationResponse(
                    query=s.implementation.query,
                    gcp_logging_query=s.implementation.gcp_logging_query,
                    guardduty_finding_types=s.implementation.guardduty_finding_types,
                    cloudformation_template=s.implementation.cloudformation_template,
                    terraform_template=s.implementation.terraform_template,
                    gcp_terraform_template=s.implementation.gcp_terraform_template,
                    alert_severity=s.implementation.alert_severity,
                    alert_title=s.implementation.alert_title,
                    alert_description_template=s.implementation.alert_description_template,
                    investigation_steps=s.implementation.investigation_steps,
                    containment_actions=s.implementation.containment_actions,
                ),
                estimated_false_positive_rate=s.estimated_false_positive_rate.value,
                false_positive_tuning=s.false_positive_tuning,
                detection_coverage=s.detection_coverage,
                evasion_considerations=s.evasion_considerations,
                implementation_effort=s.implementation_effort.value,
                implementation_time=s.implementation_time,
                estimated_monthly_cost=s.estimated_monthly_cost,
                prerequisites=s.prerequisites,
            )
            for s in template.detection_strategies
        ],
        recommended_order=template.recommended_order,
        total_effort_hours=template.total_effort_hours,
        coverage_improvement=template.coverage_improvement,
    )


@router.get("", response_model=list[TechniqueSummaryResponse])
async def list_techniques_with_templates(
    db: AsyncSession = Depends(get_db),
    auth: AuthContext = Depends(
        require_role(UserRole.MEMBER, UserRole.VIEWER, UserRole.ADMIN, UserRole.OWNER)
    ),
) -> list[TechniqueSummaryResponse]:
    """List all techniques that have remediation templates available."""
    from app.data.remediation_templates.template_loader import TEMPLATES

    techniques = []
    for technique_id, template in TEMPLATES.items():
        techniques.append(
            TechniqueSummaryResponse(
                technique_id=template.technique_id,
                technique_name=template.technique_name,
                tactic_ids=template.tactic_ids,
                has_template=True,
                strategy_count=len(template.detection_strategies),
            )
        )

    # Sort by technique ID
    techniques.sort(key=lambda t: t.technique_id)
    return techniques
