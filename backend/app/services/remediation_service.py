"""
Remediation Service - Provides technique-specific remediation guidance.

This service leverages the remediation template library to provide intelligent,
context-aware recommendations for addressing MITRE ATT&CK coverage gaps.
"""

from typing import Optional, List, Dict, Any
from dataclasses import dataclass, asdict

from app.data.remediation_templates import (
    get_template,
    get_all_templates,
    get_templates_by_tactic,
    RemediationTemplate,
    DetectionStrategy,
)


@dataclass
class RecommendationSummary:
    """Summary of a detection strategy for quick review."""
    strategy_id: str
    name: str
    detection_type: str
    aws_service: str
    implementation_effort: str
    estimated_time: str
    estimated_monthly_cost: str
    detection_coverage: str
    false_positive_rate: str


@dataclass
class DetailedRecommendation:
    """Full recommendation with implementation details."""
    strategy_id: str
    name: str
    description: str
    detection_type: str
    aws_service: str

    # Implementation artefacts
    query: Optional[str]
    event_pattern: Optional[Dict[str, Any]]
    guardduty_finding_types: Optional[List[str]]
    cloudformation_template: Optional[str]
    terraform_template: Optional[str]

    # Alert configuration
    alert_severity: str
    alert_title: str
    alert_description_template: str

    # Response guidance
    investigation_steps: List[str]
    containment_actions: List[str]

    # Operational context
    estimated_false_positive_rate: str
    false_positive_tuning: str
    detection_coverage: str
    evasion_considerations: str
    implementation_effort: str
    implementation_time: str
    estimated_monthly_cost: str
    prerequisites: List[str]


@dataclass
class TechniqueRemediation:
    """Complete remediation package for a technique."""
    technique_id: str
    technique_name: str
    mitre_url: str
    tactic_ids: List[str]

    # Threat context
    threat_description: str
    attacker_goal: str
    why_technique: List[str]
    known_threat_actors: List[str]
    severity_score: int
    severity_reasoning: str
    business_impact: List[str]
    prevalence: str
    trend: str

    # Detection strategies
    recommended_order: List[str]
    total_effort_hours: float
    coverage_improvement: str
    strategies: List[RecommendationSummary]


class RemediationService:
    """Service for generating remediation recommendations."""

    def get_technique_remediation(
        self,
        technique_id: str
    ) -> Optional[TechniqueRemediation]:
        """
        Get complete remediation guidance for a MITRE ATT&CK technique.

        Args:
            technique_id: MITRE technique ID (e.g., "T1078.004")

        Returns:
            TechniqueRemediation object or None if no template exists
        """
        template = get_template(technique_id)
        if not template:
            return None

        strategies = [
            RecommendationSummary(
                strategy_id=s.strategy_id,
                name=s.name,
                detection_type=s.detection_type.value,
                aws_service=s.aws_service,
                implementation_effort=s.implementation_effort.value,
                estimated_time=s.implementation_time,
                estimated_monthly_cost=s.estimated_monthly_cost,
                detection_coverage=s.detection_coverage,
                false_positive_rate=s.estimated_false_positive_rate.value
            )
            for s in template.detection_strategies
        ]

        return TechniqueRemediation(
            technique_id=template.technique_id,
            technique_name=template.technique_name,
            mitre_url=template.mitre_url,
            tactic_ids=template.tactic_ids,
            threat_description=template.threat_context.description,
            attacker_goal=template.threat_context.attacker_goal,
            why_technique=template.threat_context.why_technique,
            known_threat_actors=template.threat_context.known_threat_actors,
            severity_score=template.threat_context.severity_score,
            severity_reasoning=template.threat_context.severity_reasoning,
            business_impact=template.threat_context.business_impact,
            prevalence=template.threat_context.prevalence,
            trend=template.threat_context.trend,
            recommended_order=template.recommended_order,
            total_effort_hours=template.total_effort_hours,
            coverage_improvement=template.coverage_improvement,
            strategies=strategies
        )

    def get_strategy_details(
        self,
        technique_id: str,
        strategy_id: str
    ) -> Optional[DetailedRecommendation]:
        """
        Get detailed implementation guidance for a specific detection strategy.

        Args:
            technique_id: MITRE technique ID
            strategy_id: Strategy ID within the technique

        Returns:
            DetailedRecommendation object or None if not found
        """
        template = get_template(technique_id)
        if not template:
            return None

        strategy = next(
            (s for s in template.detection_strategies if s.strategy_id == strategy_id),
            None
        )
        if not strategy:
            return None

        impl = strategy.implementation

        return DetailedRecommendation(
            strategy_id=strategy.strategy_id,
            name=strategy.name,
            description=strategy.description,
            detection_type=strategy.detection_type.value,
            aws_service=strategy.aws_service,
            query=impl.query,
            event_pattern=impl.event_pattern,
            guardduty_finding_types=impl.guardduty_finding_types,
            cloudformation_template=impl.cloudformation_template,
            terraform_template=impl.terraform_template,
            alert_severity=impl.alert_severity,
            alert_title=impl.alert_title,
            alert_description_template=impl.alert_description_template,
            investigation_steps=impl.investigation_steps,
            containment_actions=impl.containment_actions,
            estimated_false_positive_rate=strategy.estimated_false_positive_rate.value,
            false_positive_tuning=strategy.false_positive_tuning,
            detection_coverage=strategy.detection_coverage,
            evasion_considerations=strategy.evasion_considerations,
            implementation_effort=strategy.implementation_effort.value,
            implementation_time=strategy.implementation_time,
            estimated_monthly_cost=strategy.estimated_monthly_cost,
            prerequisites=strategy.prerequisites
        )

    def get_available_techniques(self) -> List[Dict[str, Any]]:
        """
        Get list of all techniques with remediation templates.

        Returns:
            List of technique summaries
        """
        templates = get_all_templates()
        return [
            {
                "technique_id": t.technique_id,
                "technique_name": t.technique_name,
                "tactic_ids": t.tactic_ids,
                "severity_score": t.threat_context.severity_score,
                "strategy_count": len(t.detection_strategies),
                "total_effort_hours": t.total_effort_hours,
                "coverage_improvement": t.coverage_improvement
            }
            for t in templates.values()
        ]

    def get_techniques_by_tactic(
        self,
        tactic_id: str
    ) -> List[Dict[str, Any]]:
        """
        Get all techniques with templates for a specific tactic.

        Args:
            tactic_id: MITRE tactic ID (e.g., "TA0001")

        Returns:
            List of technique summaries for the tactic
        """
        templates = get_templates_by_tactic(tactic_id)
        return [
            {
                "technique_id": t.technique_id,
                "technique_name": t.technique_name,
                "severity_score": t.threat_context.severity_score,
                "strategy_count": len(t.detection_strategies),
                "recommended_first": t.recommended_order[0] if t.recommended_order else None
            }
            for t in templates
        ]

    def get_quick_wins(
        self,
        technique_ids: List[str],
        max_effort_hours: float = 2.0
    ) -> List[Dict[str, Any]]:
        """
        Identify quick-win detection strategies for a list of gap techniques.

        These are low-effort, high-value detections that can be implemented quickly.

        Args:
            technique_ids: List of technique IDs representing coverage gaps
            max_effort_hours: Maximum implementation time in hours

        Returns:
            List of quick-win strategies sorted by impact
        """
        quick_wins = []

        for technique_id in technique_ids:
            template = get_template(technique_id)
            if not template:
                continue

            for strategy in template.detection_strategies:
                # Parse implementation time to hours
                time_str = strategy.implementation_time.lower()
                if "minute" in time_str:
                    hours = float(time_str.split()[0]) / 60
                elif "hour" in time_str:
                    # Handle ranges like "1-2 hours"
                    parts = time_str.replace("hours", "").replace("hour", "").strip()
                    if "-" in parts:
                        hours = float(parts.split("-")[0])
                    else:
                        hours = float(parts)
                else:
                    continue

                if hours <= max_effort_hours:
                    quick_wins.append({
                        "technique_id": template.technique_id,
                        "technique_name": template.technique_name,
                        "strategy_id": strategy.strategy_id,
                        "strategy_name": strategy.name,
                        "detection_type": strategy.detection_type.value,
                        "implementation_effort": strategy.implementation_effort.value,
                        "implementation_time": strategy.implementation_time,
                        "detection_coverage": strategy.detection_coverage,
                        "severity_score": template.threat_context.severity_score,
                        "estimated_hours": hours
                    })

        # Sort by severity (highest first), then by implementation time (lowest first)
        quick_wins.sort(key=lambda x: (-x["severity_score"], x["estimated_hours"]))

        return quick_wins

    def generate_implementation_plan(
        self,
        technique_ids: List[str],
        budget_hours: Optional[float] = None
    ) -> Dict[str, Any]:
        """
        Generate a prioritised implementation plan for addressing coverage gaps.

        Args:
            technique_ids: List of technique IDs representing coverage gaps
            budget_hours: Optional time budget constraint

        Returns:
            Implementation plan with phases and estimated outcomes
        """
        all_strategies = []
        total_coverage_improvement = 0

        for technique_id in technique_ids:
            template = get_template(technique_id)
            if not template:
                continue

            # Add the first (recommended) strategy for each technique
            if template.detection_strategies:
                strategy = template.detection_strategies[0]
                all_strategies.append({
                    "technique_id": template.technique_id,
                    "technique_name": template.technique_name,
                    "strategy": strategy,
                    "severity_score": template.threat_context.severity_score
                })

        # Sort by severity
        all_strategies.sort(key=lambda x: -x["severity_score"])

        # Build phases
        phases = []
        current_phase = []
        phase_hours = 0

        for item in all_strategies:
            strategy = item["strategy"]

            # Parse hours
            time_str = strategy.implementation_time.lower()
            if "minute" in time_str:
                hours = float(time_str.split()[0]) / 60
            elif "hour" in time_str:
                parts = time_str.replace("hours", "").replace("hour", "").strip()
                if "-" in parts:
                    hours = float(parts.split("-")[1])  # Take upper bound
                else:
                    hours = float(parts)
            else:
                hours = 2  # Default

            # Check if we should start a new phase (every ~8 hours of work)
            if phase_hours + hours > 8 and current_phase:
                phases.append({
                    "phase_number": len(phases) + 1,
                    "estimated_hours": phase_hours,
                    "strategies": current_phase
                })
                current_phase = []
                phase_hours = 0

            current_phase.append({
                "technique_id": item["technique_id"],
                "technique_name": item["technique_name"],
                "strategy_id": strategy.strategy_id,
                "strategy_name": strategy.name,
                "severity_score": item["severity_score"],
                "estimated_hours": hours
            })
            phase_hours += hours

        # Add final phase
        if current_phase:
            phases.append({
                "phase_number": len(phases) + 1,
                "estimated_hours": phase_hours,
                "strategies": current_phase
            })

        total_hours = sum(p["estimated_hours"] for p in phases)

        return {
            "total_techniques": len(technique_ids),
            "techniques_with_templates": len(all_strategies),
            "total_phases": len(phases),
            "total_estimated_hours": total_hours,
            "phases": phases
        }


# Singleton instance
remediation_service = RemediationService()
