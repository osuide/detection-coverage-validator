"""
Remediation Template Library

This module provides technique-specific remediation guidance for MITRE ATT&CK coverage gaps.
Each template includes:
- Threat context (why this technique matters, who uses it)
- Detection strategies (layered approach from managed to custom)
- Implementation artefacts (CloudWatch queries, EventBridge rules, IaC templates)
- Investigation and response guidance
"""

from .template_loader import (
    get_template,
    get_all_templates,
    get_templates_by_tactic,
    RemediationTemplate,
    ThreatContext,
    DetectionStrategy,
)

__all__ = [
    "get_template",
    "get_all_templates",
    "get_templates_by_tactic",
    "RemediationTemplate",
    "ThreatContext",
    "DetectionStrategy",
]
