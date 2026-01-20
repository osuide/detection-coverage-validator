"""Region coverage analysis utilities.

This module provides utilities for analysing regional detection coverage,
identifying which regions lack coverage for detections that should exist
per-region (regional services) versus globally (global services).

Uses the service_registry to determine service classification.
"""

from typing import Optional

from app.core.service_registry import is_global_service

# Map detection types to their underlying service for regional classification.
# A None value means the detection type is for a global/aggregated service
# that should NOT be checked for regional gaps.
DETECTION_TYPE_SERVICE_MAP: dict[str, Optional[str]] = {
    # AWS Regional Services - SHOULD check for regional gaps
    "cloudwatch_logs_insights": "cloudwatch-logs",
    "cloudwatch_alarm": "cloudwatch-logs",
    "eventbridge_rule": "eventbridge",
    "guardduty_finding": "guardduty",
    "config_rule": "config",
    "inspector_finding": "inspector",
    "macie_finding": "macie",
    "custom_lambda": "lambda",
    # AWS Global/Aggregated - should NOT check regions
    "security_hub": None,  # Cross-region aggregation view
    # GCP Regional Services - SHOULD check for regional gaps
    "gcp_eventarc": "eventarc",
    "gcp_cloud_function": "cloud-functions",
    # GCP Global/Org-level - should NOT check regions
    "gcp_security_command_center": None,  # Organisation-level
    "gcp_cloud_logging": None,  # Default buckets are global
    "gcp_cloud_monitoring": None,  # Typically project-wide
    "gcp_chronicle": None,  # Org-level SIEM
}


def is_regional_detection_type(detection_type: str, provider: str) -> bool:
    """Check if a detection type represents a regional service.

    Regional detection types should exist per-region and we should flag
    when they're missing from in-scope regions. Global detection types
    (like Security Hub aggregated findings) should not be flagged.

    Args:
        detection_type: The detection type (e.g., "guardduty_finding")
        provider: Cloud provider ("aws" or "gcp")

    Returns:
        True if this detection type should exist per-region
    """
    service_key = DETECTION_TYPE_SERVICE_MAP.get(detection_type)
    if service_key is None:
        return False  # Global/aggregated service - no regional check needed

    # Check if the service itself is classified as global
    return not is_global_service(provider, service_key)


def calculate_unprotected_regions(
    detection_type: str,
    covered_regions: list[str],
    effective_regions: list[str],
    provider: str,
) -> list[str]:
    """Calculate which regions lack coverage for a detection.

    For regional detection types, compares the regions where the detection
    exists against the regions that are in scope for the account.

    Args:
        detection_type: Type of detection (for service classification)
        covered_regions: Regions where this detection exists
        effective_regions: Regions in scope for the account
        provider: Cloud provider ("aws" or "gcp")

    Returns:
        List of region codes that lack this detection, empty for global services
    """
    if not is_regional_detection_type(detection_type, provider):
        return []  # Global service - no regional gaps possible

    covered_set = set(covered_regions)
    return [r for r in effective_regions if r not in covered_set]


def get_regional_detection_types() -> set[str]:
    """Get the set of detection types that are regional.

    Useful for frontend to determine which detection types should
    display unprotected region warnings.

    Returns:
        Set of detection type strings that are regional
    """
    return {
        dt for dt, service in DETECTION_TYPE_SERVICE_MAP.items() if service is not None
    }
