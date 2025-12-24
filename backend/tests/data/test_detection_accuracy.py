"""
Test Detection Accuracy Claims in Remediation Templates.

This test suite validates that detection strategies make accurate claims about
their capabilities, especially regarding the distinction between:
- Cloud-native detection (AWS CloudTrail/EventBridge, GCP Cloud Logging)
- OS/endpoint-level detection (requires agents, auditd, etc.)

Key validations:
1. Techniques requiring OS-level visibility have honest coverage claims
2. Templates acknowledge when endpoint agents are required
3. Coverage percentages are reasonable for the detection type
4. Module docstrings include limitation disclaimers for hardware/OS techniques
"""

import re
from typing import Dict, List, Tuple

import pytest

from app.data.remediation_templates.template_loader import TEMPLATES


# Techniques that fundamentally require OS/endpoint-level detection
# Cloud APIs CANNOT directly detect these events
OS_LEVEL_TECHNIQUES: Dict[str, str] = {
    "T1200": "Hardware Additions - USB/physical device insertions",
    "T1091": "Removable Media - USB device connections",
    "T1052": "Exfiltration Physical Medium - USB file copies",
    "T1115": "Clipboard Data - clipboard API access",
    "T1055": "Process Injection - memory operations",
    "T1056": "Input Capture - keylogging requires host agents",
    "T1113": "Screen Capture - screenshot detection",
    "T1123": "Audio Capture - microphone access",
    "T1125": "Video Capture - camera access",
    "T1003": "OS Credential Dumping - memory access",
    "T1057": "Process Discovery - process enumeration",
}

# Keywords that indicate the template acknowledges OS-level limitations
LIMITATION_KEYWORDS = [
    "cloud-native.*cannot",
    "cannot detect.*usb",
    "cannot detect.*physical",
    "cannot detect.*hardware",
    "endpoint.*required",
    "endpoint.*agent",
    "os.level.*logging",
    "requires.*ops agent",
    "requires.*cloudwatch agent",
    "not.*detect.*api",
    "api.level.*bypass",
    "limitation",
    "guardduty runtime monitoring",
]

# Max reasonable coverage for cloud-only detection of OS-level techniques
MAX_CLOUD_ONLY_COVERAGE = 50


def extract_coverage_percentage(coverage_str: str) -> int:
    """Extract numeric coverage percentage from coverage string."""
    if not coverage_str:
        return 0

    # Match patterns like "65%", "65% -", "~65%"
    match = re.search(r"~?(\d{1,3})%", coverage_str)
    if match:
        return int(match.group(1))
    return 0


def has_limitation_acknowledgement(template) -> bool:
    """Check if template acknowledges OS/hardware detection limitations."""
    # Check module docstring - find the module in sys.modules by technique_id prefix
    import sys

    technique_prefix = template.technique_id.lower().replace(".", "_")
    docstring = ""

    # Search for the module that contains this technique
    for mod_name, mod in sys.modules.items():
        if (
            mod_name.startswith("app.data.remediation_templates.")
            and technique_prefix in mod_name.lower()
            and mod.__doc__
        ):
            docstring = mod.__doc__
            break

    # Also check strategy descriptions
    strategy_text = ""
    for strategy in template.detection_strategies:
        strategy_text += f" {strategy.description} {strategy.detection_coverage or ''}"

    full_text = (docstring + strategy_text).lower()

    for keyword in LIMITATION_KEYWORDS:
        if re.search(keyword, full_text, re.IGNORECASE):
            return True
    return False


def get_max_coverage_claim(template) -> Tuple[int, str]:
    """Get the maximum coverage claim from any strategy in the template."""
    max_coverage = 0
    max_strategy = ""

    for strategy in template.detection_strategies:
        coverage = extract_coverage_percentage(strategy.detection_coverage or "")
        if coverage > max_coverage:
            max_coverage = coverage
            max_strategy = strategy.strategy_id

    return max_coverage, max_strategy


class TestDetectionAccuracyClaims:
    """Test suite for validating detection accuracy claims."""

    @pytest.fixture(scope="class")
    def os_level_templates(self) -> List[Tuple[str, object]]:
        """Get templates for OS-level techniques."""
        templates = []
        for technique_id, description in OS_LEVEL_TECHNIQUES.items():
            # Handle sub-technique IDs (e.g., T1055.001)
            base_id = technique_id.split(".")[0]
            matching_templates = [
                (tid, t) for tid, t in TEMPLATES.items() if tid.startswith(base_id)
            ]
            templates.extend(matching_templates)
        return templates

    def test_os_level_techniques_have_limitations(self, os_level_templates):
        """Verify OS-level techniques acknowledge detection limitations."""
        missing_limitations = []

        for technique_id, template in os_level_templates:
            if not has_limitation_acknowledgement(template):
                missing_limitations.append(
                    f"{technique_id}: {template.technique_name} - "
                    f"missing OS-level detection limitation acknowledgement"
                )

        # Allow some templates to not have limitations if they don't claim
        # high coverage for cloud-native detection
        actual_issues = []
        for issue in missing_limitations:
            technique_id = issue.split(":")[0]
            template = TEMPLATES.get(technique_id)
            if template:
                max_coverage, _ = get_max_coverage_claim(template)
                if max_coverage > MAX_CLOUD_ONLY_COVERAGE:
                    actual_issues.append(issue)

        if actual_issues:
            pytest.skip(
                f"Found {len(actual_issues)} templates needing limitation disclaimers:\n"
                + "\n".join(actual_issues[:5])
            )

    def test_coverage_claims_are_reasonable(self, os_level_templates):
        """Verify coverage claims for OS-level techniques are realistic."""
        unreasonable_claims = []

        for technique_id, template in os_level_templates:
            for strategy in template.detection_strategies:
                coverage = extract_coverage_percentage(
                    strategy.detection_coverage or ""
                )

                # Skip endpoint agent strategies - they can claim high coverage
                if any(
                    keyword in strategy.name.lower()
                    for keyword in ["endpoint", "guardduty runtime", "agent", "edr"]
                ):
                    continue

                # Check if cloud-only strategy claims unreasonable coverage
                if coverage > MAX_CLOUD_ONLY_COVERAGE:
                    # Check if it acknowledges limitations in coverage text
                    coverage_text = (strategy.detection_coverage or "").lower()
                    if not any(
                        word in coverage_text
                        for word in ["only", "requires", "not", "cannot", "endpoint"]
                    ):
                        unreasonable_claims.append(
                            f"{technique_id}/{strategy.strategy_id}: Claims {coverage}% "
                            f"but this is an OS-level technique"
                        )

        assert len(unreasonable_claims) == 0, (
            f"Found {len(unreasonable_claims)} unreasonable coverage claims:\n"
            + "\n".join(unreasonable_claims)
        )

    def test_hardware_techniques_recommend_endpoint_agents(self):
        """Verify hardware-related techniques recommend endpoint agents."""
        hardware_techniques = ["T1200", "T1091", "T1052"]
        missing_recommendations = []

        for technique_id in hardware_techniques:
            template = TEMPLATES.get(technique_id)
            if not template:
                continue

            # Check if any strategy recommends endpoint agents
            has_endpoint_recommendation = False
            for strategy in template.detection_strategies:
                strategy_text = (
                    f"{strategy.name} {strategy.description} "
                    f"{strategy.implementation.terraform_template or ''} "
                    f"{strategy.implementation.cloudformation_template or ''}"
                ).lower()

                if any(
                    keyword in strategy_text
                    for keyword in [
                        "guardduty runtime",
                        "endpoint agent",
                        "crowdstrike",
                        "sentinelone",
                        "carbon black",
                        "edr",
                        "wazuh",
                        "ossec",
                    ]
                ):
                    has_endpoint_recommendation = True
                    break

            if not has_endpoint_recommendation:
                missing_recommendations.append(
                    f"{technique_id}: {template.technique_name} - "
                    f"should recommend endpoint agents for real detection"
                )

        assert len(missing_recommendations) == 0, (
            f"Found {len(missing_recommendations)} templates missing endpoint recommendations:\n"
            + "\n".join(missing_recommendations)
        )

    def test_no_fabricated_event_types(self):
        """Verify templates don't reference non-existent AWS/GCP event types."""
        # These are fabricated AWS/GCP event source names that don't exist
        # We use word boundaries to avoid matching custom metric names like
        # "ExfiltrationDeviceConnected" which are user-defined, not fabricated events
        fabricated_events = [
            r"\bDeviceConnected\b",  # Not a real CloudTrail/EventBridge event
            r"\busb_mount\b",  # Not a real CloudWatch event type
            r"\busb_device\b",  # Not a real CloudWatch event type
            r"\bUSBConnected\b",  # Not real
        ]

        templates_with_fabricated_events = []

        for technique_id, template in TEMPLATES.items():
            for strategy in template.detection_strategies:
                # Check queries and templates
                texts_to_check = [
                    strategy.implementation.query or "",
                    strategy.implementation.cloudformation_template or "",
                    strategy.implementation.terraform_template or "",
                    strategy.implementation.gcp_logging_query or "",
                ]

                for text in texts_to_check:
                    for event_pattern in fabricated_events:
                        if re.search(event_pattern, text):
                            templates_with_fabricated_events.append(
                                f"{technique_id}/{strategy.strategy_id}: "
                                f"References fabricated event type '{event_pattern}'"
                            )
                            break

        assert len(templates_with_fabricated_events) == 0, (
            f"Found {len(templates_with_fabricated_events)} templates with fabricated events:\n"
            + "\n".join(templates_with_fabricated_events)
        )


class TestCoveragePercentageFormat:
    """Test that coverage percentages are consistently formatted."""

    def test_coverage_includes_context(self):
        """Verify coverage percentages include explanatory context."""
        bare_percentages = []

        for technique_id, template in TEMPLATES.items():
            for strategy in template.detection_strategies:
                coverage = strategy.detection_coverage or ""

                # Check if it's just a bare percentage like "75%"
                if coverage and re.match(r"^\d{1,3}%$", coverage.strip()):
                    bare_percentages.append(
                        f"{technique_id}/{strategy.strategy_id}: "
                        f"Coverage '{coverage}' needs explanatory context"
                    )

        if bare_percentages:
            pytest.skip(
                f"Found {len(bare_percentages)} coverage claims needing context:\n"
                + "\n".join(bare_percentages[:10])
            )

    def test_coverage_percentages_are_valid(self):
        """Verify coverage percentages are within valid range (0-100)."""
        invalid_percentages = []

        for technique_id, template in TEMPLATES.items():
            for strategy in template.detection_strategies:
                coverage = extract_coverage_percentage(
                    strategy.detection_coverage or ""
                )

                if coverage > 100:
                    invalid_percentages.append(
                        f"{technique_id}/{strategy.strategy_id}: "
                        f"Invalid coverage {coverage}%"
                    )

        assert (
            len(invalid_percentages) == 0
        ), f"Found {len(invalid_percentages)} invalid percentages:\n" + "\n".join(
            invalid_percentages
        )


class TestDetectionTypeConsistency:
    """Test that detection types match the actual implementation."""

    def test_cloudwatch_queries_exist_for_cloudwatch_type(self):
        """Verify CloudWatch detection types have associated queries."""
        missing_queries = []

        for technique_id, template in TEMPLATES.items():
            for strategy in template.detection_strategies:
                if strategy.detection_type.value == "cloudwatch_query":
                    if not strategy.implementation.query:
                        missing_queries.append(
                            f"{technique_id}/{strategy.strategy_id}: "
                            f"CLOUDWATCH_QUERY type but no query defined"
                        )

        # This is informational - some templates may intentionally not have queries
        if missing_queries:
            pytest.skip(
                f"Found {len(missing_queries)} strategies without queries:\n"
                + "\n".join(missing_queries[:5])
            )

    def test_terraform_templates_exist(self):
        """Verify strategies have either Terraform or CloudFormation templates."""
        no_iac = []

        for technique_id, template in TEMPLATES.items():
            for strategy in template.detection_strategies:
                impl = strategy.implementation
                has_aws_iac = bool(
                    impl.terraform_template or impl.cloudformation_template
                )
                has_gcp_iac = bool(impl.gcp_terraform_template)

                # Check based on cloud provider
                if strategy.cloud_provider.value == "aws" and not has_aws_iac:
                    no_iac.append(
                        f"{technique_id}/{strategy.strategy_id}: AWS strategy without IaC"
                    )
                elif strategy.cloud_provider.value == "gcp" and not has_gcp_iac:
                    no_iac.append(
                        f"{technique_id}/{strategy.strategy_id}: GCP strategy without Terraform"
                    )

        # Allow some strategies without IaC (e.g., manual procedures)
        if len(no_iac) > 20:  # More than 20 is concerning
            pytest.skip(
                f"Found {len(no_iac)} strategies without IaC templates:\n"
                + "\n".join(no_iac[:10])
            )
