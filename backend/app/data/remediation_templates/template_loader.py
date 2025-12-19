"""
Template Loader - Loads and manages remediation templates.
"""

from dataclasses import dataclass, field
from typing import Optional, Dict, List, Any
from enum import Enum


class DetectionType(str, Enum):
    GUARDDUTY = "guardduty"
    CLOUDWATCH_QUERY = "cloudwatch_query"
    EVENTBRIDGE_RULE = "eventbridge_rule"
    CONFIG_RULE = "config_rule"
    SECURITY_HUB = "security_hub"
    CUSTOM_LAMBDA = "custom_lambda"


class EffortLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class FalsePositiveRate(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass
class Campaign:
    """Real-world campaign using this technique."""
    name: str
    year: int
    description: str
    reference_url: Optional[str] = None


@dataclass
class ThreatContext:
    """Adversarial context for a technique."""
    description: str
    attacker_goal: str
    why_technique: List[str]
    known_threat_actors: List[str]
    recent_campaigns: List[Campaign]
    prevalence: str  # common, moderate, rare
    trend: str  # increasing, stable, decreasing
    severity_score: int  # 1-10
    severity_reasoning: str
    business_impact: List[str]
    typical_attack_phase: str
    often_precedes: List[str] = field(default_factory=list)
    often_follows: List[str] = field(default_factory=list)


@dataclass
class DetectionImplementation:
    """Actual implementation artefacts for a detection."""
    query: Optional[str] = None
    event_pattern: Optional[Dict[str, Any]] = None
    guardduty_finding_types: Optional[List[str]] = None
    config_rule_identifier: Optional[str] = None
    cloudformation_template: Optional[str] = None
    terraform_template: Optional[str] = None
    alert_severity: str = "medium"
    alert_title: str = ""
    alert_description_template: str = ""
    investigation_steps: List[str] = field(default_factory=list)
    containment_actions: List[str] = field(default_factory=list)


@dataclass
class DetectionStrategy:
    """Single detection approach for a technique."""
    strategy_id: str
    name: str
    description: str
    detection_type: DetectionType
    aws_service: str
    implementation: DetectionImplementation
    estimated_false_positive_rate: FalsePositiveRate
    false_positive_tuning: str
    detection_coverage: str
    evasion_considerations: str
    implementation_effort: EffortLevel
    implementation_time: str
    estimated_monthly_cost: str
    prerequisites: List[str] = field(default_factory=list)


@dataclass
class RemediationTemplate:
    """Complete remediation guidance for a MITRE technique."""
    technique_id: str
    technique_name: str
    tactic_ids: List[str]
    mitre_url: str
    threat_context: ThreatContext
    detection_strategies: List[DetectionStrategy]
    recommended_order: List[str]
    total_effort_hours: float
    coverage_improvement: str
    last_updated: str = "2025-12-19"
    version: str = "1.0"


# Import all templates
from .t1078_004_cloud_accounts import TEMPLATE as T1078_004
from .t1110_brute_force import TEMPLATE as T1110
from .t1562_001_disable_security_tools import TEMPLATE as T1562_001
from .t1530_data_from_cloud_storage import TEMPLATE as T1530
from .t1098_account_manipulation import TEMPLATE as T1098

# Template registry
TEMPLATES: Dict[str, RemediationTemplate] = {
    "T1078.004": T1078_004,
    "T1110": T1110,
    "T1562.001": T1562_001,
    "T1530": T1530,
    "T1098": T1098,
}

# Parent technique mappings (for sub-techniques)
PARENT_MAPPINGS = {
    "T1078.004": "T1078",
    "T1562.001": "T1562",
}


def get_template(technique_id: str) -> Optional[RemediationTemplate]:
    """
    Get remediation template for a technique.

    Falls back to parent technique if sub-technique not found.
    """
    # Direct match
    if technique_id in TEMPLATES:
        return TEMPLATES[technique_id]

    # Try parent technique
    if "." in technique_id:
        parent_id = technique_id.split(".")[0]
        if parent_id in TEMPLATES:
            return TEMPLATES[parent_id]

    return None


def get_all_templates() -> Dict[str, RemediationTemplate]:
    """Get all available templates."""
    return TEMPLATES.copy()


def get_templates_by_tactic(tactic_id: str) -> List[RemediationTemplate]:
    """Get all templates for a specific tactic."""
    return [
        template for template in TEMPLATES.values()
        if tactic_id in template.tactic_ids
    ]
