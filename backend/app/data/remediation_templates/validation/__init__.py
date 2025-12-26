"""
Remediation Template Validation Module.

Provides tools to validate detection templates for:
- Structural correctness
- Detection logic effectiveness
- GuardDuty finding type validity
- Best practice compliance
"""

from .guardduty_findings import (
    validate_finding_type,
    get_findings_for_technique,
    technique_has_guardduty_coverage,
    get_recommended_guardduty_findings,
    get_all_finding_types,
    GUARDDUTY_TECHNIQUE_COVERAGE,
)

from .template_validator import (
    TemplateValidator,
    TemplateValidationResult,
    ValidationIssue,
    Severity,
)

__all__ = [
    "validate_finding_type",
    "get_findings_for_technique",
    "technique_has_guardduty_coverage",
    "get_recommended_guardduty_findings",
    "get_all_finding_types",
    "GUARDDUTY_TECHNIQUE_COVERAGE",
    "TemplateValidator",
    "TemplateValidationResult",
    "ValidationIssue",
    "Severity",
]
