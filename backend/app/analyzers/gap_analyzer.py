"""Gap analyzer following 06-ANALYSIS-AGENT.md design."""

from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any
import structlog

from app.analyzers.coverage_calculator import TechniqueCoverageInfo
from app.mappers.indicator_library import TECHNIQUE_BY_ID, TechniqueIndicator
from app.data.remediation_templates import get_template

logger = structlog.get_logger()


@dataclass
class RecommendedStrategy:
    """A recommended detection strategy from the template library."""

    strategy_id: str
    name: str
    detection_type: str
    aws_service: str
    implementation_effort: str
    estimated_time: str
    detection_coverage: str
    has_query: bool = False
    has_cloudformation: bool = False
    has_terraform: bool = False
    # GCP support
    gcp_service: Optional[str] = None
    cloud_provider: Optional[str] = None
    has_gcp_query: bool = False
    has_gcp_terraform: bool = False


@dataclass
class Gap:
    """A coverage gap with remediation guidance."""

    technique_id: str
    technique_name: str
    tactic_id: str
    tactic_name: str
    priority: str  # "critical", "high", "medium", "low"
    reason: str
    data_sources: list[str]
    recommended_detections: list[str]

    # Enhanced remediation data from templates
    has_template: bool = False
    severity_score: Optional[int] = None
    threat_actors: List[str] = field(default_factory=list)
    business_impact: List[str] = field(default_factory=list)
    recommended_strategies: List[RecommendedStrategy] = field(default_factory=list)
    quick_win_strategy: Optional[str] = None
    total_effort_hours: Optional[float] = None
    mitre_url: Optional[str] = None


class GapAnalyzer:
    """Analyzes coverage gaps and prioritizes them.

    Priority is determined by:
    1. Technique priority from indicator library (based on MITRE prevalence)
    2. Tactic importance (initial access, persistence > collection, discovery)
    3. Whether the technique has any partial coverage
    """

    # Tactic priority weights
    TACTIC_PRIORITY = {
        "TA0001": 1,  # Initial Access - critical
        "TA0003": 1,  # Persistence - critical
        "TA0004": 1,  # Privilege Escalation - critical
        "TA0006": 1,  # Credential Access - critical
        "TA0005": 2,  # Defense Evasion - high
        "TA0040": 2,  # Impact - high
        "TA0010": 2,  # Exfiltration - high
        "TA0008": 3,  # Lateral Movement - medium
        "TA0009": 3,  # Collection - medium
        "TA0007": 4,  # Discovery - low
        "TA0043": 4,  # Reconnaissance - low
    }

    def __init__(self):
        self.logger = logger.bind(component="GapAnalyzer")

    def analyze_gaps(
        self,
        technique_coverage: list[TechniqueCoverageInfo],
        limit: Optional[int] = None,
        cloud_provider: Optional[str] = None,
    ) -> list[Gap]:
        """Analyze and prioritize coverage gaps.

        Args:
            technique_coverage: Coverage info from CoverageCalculator
            limit: Maximum number of gaps to return (None for all)
            cloud_provider: Filter strategies by cloud provider ("aws" or "gcp")

        Returns:
            List of Gap objects sorted by priority
        """
        gaps = []

        for tech in technique_coverage:
            if tech.status == "uncovered":
                priority = self._calculate_priority(tech)
                indicator = TECHNIQUE_BY_ID.get(tech.technique_id)

                # Get remediation template if available
                template = get_template(tech.technique_id)

                gap = Gap(
                    technique_id=tech.technique_id,
                    technique_name=tech.technique_name,
                    tactic_id=tech.tactic_id,
                    tactic_name=tech.tactic_name,
                    priority=priority,
                    reason=self._generate_reason(tech, indicator, template),
                    data_sources=self._get_data_sources(indicator),
                    recommended_detections=self._get_recommendations(indicator, template),
                )

                # Enrich with template data if available
                if template:
                    gap.has_template = True
                    gap.severity_score = template.threat_context.severity_score
                    gap.threat_actors = template.threat_context.known_threat_actors
                    gap.business_impact = template.threat_context.business_impact
                    gap.total_effort_hours = template.total_effort_hours
                    gap.mitre_url = template.mitre_url

                    # Add recommended strategies, filtered by cloud provider if specified
                    for strategy in template.detection_strategies:
                        # Filter by cloud provider if specified
                        strategy_provider = strategy.cloud_provider.value if strategy.cloud_provider else None
                        if cloud_provider and strategy_provider and strategy_provider != cloud_provider:
                            continue  # Skip strategies for other cloud providers

                        rec_strategy = RecommendedStrategy(
                            strategy_id=strategy.strategy_id,
                            name=strategy.name,
                            detection_type=strategy.detection_type.value,
                            aws_service=strategy.aws_service,
                            implementation_effort=strategy.implementation_effort.value,
                            estimated_time=strategy.implementation_time,
                            detection_coverage=strategy.detection_coverage,
                            has_query=strategy.implementation.query is not None,
                            has_cloudformation=strategy.implementation.cloudformation_template is not None,
                            has_terraform=strategy.implementation.terraform_template is not None,
                            # GCP support
                            gcp_service=strategy.gcp_service,
                            cloud_provider=strategy_provider,
                            has_gcp_query=strategy.implementation.gcp_logging_query is not None,
                            has_gcp_terraform=strategy.implementation.gcp_terraform_template is not None,
                        )
                        gap.recommended_strategies.append(rec_strategy)

                    # Set quick win (first low-effort strategy for this provider)
                    for strategy in template.detection_strategies:
                        strategy_provider = strategy.cloud_provider.value if strategy.cloud_provider else None
                        if cloud_provider and strategy_provider and strategy_provider != cloud_provider:
                            continue
                        if strategy.implementation_effort.value == "low":
                            gap.quick_win_strategy = strategy.strategy_id
                            break

                gaps.append(gap)

        # Sort by priority (critical first), then by severity score if available
        priority_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        gaps.sort(key=lambda g: (
            priority_order.get(g.priority, 99),
            -(g.severity_score or 0)  # Higher severity first
        ))

        return gaps[:limit] if limit else gaps

    def _calculate_priority(
        self,
        tech: TechniqueCoverageInfo,
    ) -> str:
        """Calculate gap priority based on tactic and technique importance."""
        tactic_priority = self.TACTIC_PRIORITY.get(tech.tactic_id, 3)

        # Get indicator priority if available
        indicator = TECHNIQUE_BY_ID.get(tech.technique_id)
        technique_priority = indicator.priority if indicator else 2

        # Combined priority
        combined = (tactic_priority + technique_priority) / 2

        if combined <= 1.5:
            return "critical"
        elif combined <= 2:
            return "high"
        elif combined <= 3:
            return "medium"
        else:
            return "low"

    def _generate_reason(
        self,
        tech: TechniqueCoverageInfo,
        indicator: Optional[TechniqueIndicator],
        template=None,
    ) -> str:
        """Generate a human-readable reason for why this gap matters."""
        reasons = []

        # Use template's severity reasoning if available
        if template and template.threat_context.severity_reasoning:
            return template.threat_context.severity_reasoning

        if tech.tactic_id in ["TA0001", "TA0003"]:
            reasons.append("Critical for detecting initial compromise and persistence")
        elif tech.tactic_id in ["TA0004", "TA0006"]:
            reasons.append("Important for detecting privilege escalation attacks")
        elif tech.tactic_id in ["TA0005"]:
            reasons.append("Adversaries commonly use this to evade detection")
        elif tech.tactic_id in ["TA0040", "TA0010"]:
            reasons.append("Last line of defence before impact/data loss")

        if indicator and indicator.priority == 1:
            reasons.append("High prevalence in cloud attacks")

        if template and template.threat_context.known_threat_actors:
            actors = template.threat_context.known_threat_actors[:2]
            reasons.append(f"Used by {', '.join(actors)}")

        if not reasons:
            reasons.append("Recommended coverage for defence in depth")

        return "; ".join(reasons)

    def _get_data_sources(
        self,
        indicator: Optional[TechniqueIndicator],
    ) -> list[str]:
        """Get data sources that could detect this technique."""
        if not indicator:
            return []

        sources = []

        if indicator.cloudtrail_events:
            sources.append("CloudTrail")

        if "ec2" in indicator.aws_services:
            sources.extend(["VPC Flow Logs", "EC2 Instance Logs"])
        if "s3" in indicator.aws_services:
            sources.append("S3 Access Logs")
        if "iam" in indicator.aws_services:
            sources.append("IAM Events")
        if "lambda" in indicator.aws_services:
            sources.append("CloudWatch Logs")

        return list(set(sources))

    def _get_recommendations(
        self,
        indicator: Optional[TechniqueIndicator],
        template=None,
    ) -> list[str]:
        """Get recommended detection approaches."""
        recommendations = []

        # If we have a template, use its strategies as recommendations
        if template and template.detection_strategies:
            for strategy in template.detection_strategies[:3]:  # Top 3 strategies
                effort = strategy.implementation_effort.value
                recommendations.append(
                    f"{strategy.name} ({effort} effort, {strategy.implementation_time})"
                )
            return recommendations

        # Fallback to indicator-based recommendations
        if not indicator:
            return []

        if indicator.cloudtrail_events:
            events = indicator.cloudtrail_events[:3]  # Top 3
            recommendations.append(
                f"Create EventBridge rule for: {', '.join(events)}"
            )

        if indicator.log_patterns:
            recommendations.append(
                "Create CloudWatch Logs Insights query for relevant log patterns"
            )

        if "guardduty" in indicator.keywords or indicator.tactic_id in ["TA0001", "TA0006"]:
            recommendations.append("Enable GuardDuty finding type if available")

        return recommendations
