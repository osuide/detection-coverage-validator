"""Technique and remediation template API endpoints."""

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi_limiter.depends import RateLimiter
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.security import AuthContext, get_client_ip, require_role, require_scope
from app.models.user import UserRole
from app.models.mitre import Tactic
from app.data.remediation_templates.template_loader import get_template
from app.services.mitre_threat_service import MitreThreatService
from app.services.template_access_monitor import get_template_access_monitor

router = APIRouter(prefix="/techniques", tags=["techniques"])


# Response schemas
class AttributedGroupResponse(BaseModel):
    """Threat group attributed to a campaign."""

    external_id: str
    name: str
    mitre_url: str


class CampaignResponse(BaseModel):
    """Known campaign using this technique."""

    name: str
    year: int
    description: str
    reference_url: Optional[str] = None
    attributed_groups: list[AttributedGroupResponse] = []


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
    estimated_monthly_cost: Optional[str] = None  # Legacy field
    prerequisites: list[str]
    # New accurate cost fields
    cost_tier: Optional[str] = None  # "low", "medium", "high"
    pricing_basis: Optional[str] = None  # e.g., "$0.005 per GB scanned"
    pricing_url: Optional[str] = None  # Link to official pricing page


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


@router.get(
    "/{technique_id}",
    response_model=TechniqueDetailResponse,
    dependencies=[
        Depends(require_scope("read:techniques")),
        # Rate limit: 60 requests per minute per user
        Depends(RateLimiter(times=60, seconds=60)),
    ],
)
async def get_technique_detail(
    technique_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    auth: AuthContext = Depends(
        require_role(UserRole.MEMBER, UserRole.VIEWER, UserRole.ADMIN, UserRole.OWNER)
    ),
) -> TechniqueDetailResponse:
    """Get detailed technique information with remediation templates.

    Returns threat context, detection strategies with IaC templates,
    and implementation guidance.

    Rate limited to 60 requests per minute to prevent bulk scraping.
    """
    # Normalise technique ID (handle both T1055 and t1055)
    technique_id = technique_id.upper()

    # Track template access for bulk detection (with db for suspension capability)
    monitor = get_template_access_monitor()
    await monitor.record_access(
        user_id=auth.user_id,
        org_id=auth.organization_id,
        technique_id=technique_id,
        endpoint="/techniques/{technique_id}",
        client_ip=get_client_ip(request),
        db=db,
    )

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

    # Fetch threat actors from authoritative MITRE data (not hardcoded)
    threat_service = MitreThreatService(db)
    threat_groups = await threat_service.get_groups_for_technique(
        technique_id, limit=20
    )
    known_threat_actors = [f"{g.name} ({g.external_id})" for g in threat_groups]

    # Fetch campaigns from authoritative MITRE data (not hardcoded)
    # Limit to 4 most recent campaigns
    mitre_campaigns = await threat_service.get_campaigns_for_technique(
        technique_id, limit=4
    )

    # Map CampaignInfo to CampaignResponse
    recent_campaigns = []
    for c in mitre_campaigns:
        # Extract year from last_seen or first_seen
        year = None
        if c.last_seen:
            year = c.last_seen.year
        elif c.first_seen:
            year = c.first_seen.year

        # Use relationship_description (how campaign uses technique) if available,
        # otherwise fall back to campaign description
        description = c.relationship_description or c.description or ""

        if year:  # Only include campaigns with a known year
            # Map attributed groups (with safety check)
            attributed_groups = [
                AttributedGroupResponse(
                    external_id=g.external_id,
                    name=g.name,
                    mitre_url=g.mitre_url,
                )
                for g in (c.attributed_groups or [])
            ]

            recent_campaigns.append(
                CampaignResponse(
                    name=c.name,
                    year=year,
                    description=description,
                    reference_url=c.mitre_url,
                    attributed_groups=attributed_groups,
                )
            )

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
            known_threat_actors=known_threat_actors,  # From MITRE sync data
            recent_campaigns=recent_campaigns,  # From MITRE sync data
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
                # New cost fields
                cost_tier=s.cost_tier.value if s.cost_tier else None,
                pricing_basis=s.pricing_basis,
                pricing_url=s.pricing_url,
            )
            for s in template.detection_strategies
        ],
        recommended_order=template.recommended_order,
        total_effort_hours=template.total_effort_hours,
        coverage_improvement=template.coverage_improvement,
    )


@router.get(
    "",
    response_model=list[TechniqueSummaryResponse],
    dependencies=[
        Depends(require_scope("read:techniques")),
        # Rate limit: 10 requests per minute (this returns all techniques)
        Depends(RateLimiter(times=10, seconds=60)),
    ],
)
async def list_techniques_with_templates(
    db: AsyncSession = Depends(get_db),
    auth: AuthContext = Depends(
        require_role(UserRole.MEMBER, UserRole.VIEWER, UserRole.ADMIN, UserRole.OWNER)
    ),
) -> list[TechniqueSummaryResponse]:
    """List all techniques that have remediation templates available.

    Rate limited to 10 requests per minute as this returns the full list.
    """
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
