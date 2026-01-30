"""Terraform HCL parser for quick scan — handles untrusted input.

Uses python-hcl2 for parsing. No regex fallback. No dynamic code paths.
All input is untrusted and size-bounded before parsing.
"""

import asyncio
import io
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

import hcl2
import structlog

from app.scanners.base import RawDetection
from app.models.detection import DetectionType

logger = structlog.get_logger()

# Hard limits for untrusted input
MAX_CONTENT_BYTES = 256_000  # 250 KB
MAX_DETECTIONS = 500
PARSE_TIMEOUT_SECONDS = 10

# Dedicated thread pool for HCL parsing — isolates parser threads from
# the main asyncio thread pool and caps concurrent parses.
_parse_executor = ThreadPoolExecutor(max_workers=10, thread_name_prefix="hcl-parse")

# Substrings that indicate a key contains sensitive data.
# Any key whose lowercased form contains one of these is stripped.
_SECRET_SUBSTRINGS = {
    "password",
    "secret",
    "token",
    "private_key",
    "access_key",
    "api_key",
    "connection_string",
    "credential",
    "auth",
}

# Terraform resource type -> DetectionType mapping
RESOURCE_TYPE_MAP: dict[str, DetectionType] = {
    "aws_cloudwatch_metric_alarm": DetectionType.CLOUDWATCH_ALARM,
    "aws_cloudwatch_log_metric_filter": DetectionType.CLOUDWATCH_LOGS_INSIGHTS,
    "aws_cloudwatch_event_rule": DetectionType.EVENTBRIDGE_RULE,
    "aws_config_config_rule": DetectionType.CONFIG_RULE,
    "aws_guardduty_detector": DetectionType.GUARDDUTY_FINDING,
    "aws_securityhub_account": DetectionType.SECURITY_HUB,
    "aws_inspector2_enabler": DetectionType.INSPECTOR_FINDING,
    "aws_lambda_function": DetectionType.CUSTOM_LAMBDA,
    "aws_macie2_account": DetectionType.MACIE_FINDING,
    "google_logging_metric": DetectionType.GCP_CLOUD_LOGGING,
    "google_monitoring_alert_policy": DetectionType.GCP_CLOUD_MONITORING,
    "google_scc_notification_config": DetectionType.GCP_SECURITY_COMMAND_CENTER,
    "google_eventarc_trigger": DetectionType.GCP_EVENTARC,
    "google_cloudfunctions_function": DetectionType.GCP_CLOUD_FUNCTION,
    "google_cloudfunctions2_function": DetectionType.GCP_CLOUD_FUNCTION,
    "azurerm_security_center_subscription_pricing": DetectionType.AZURE_DEFENDER,
    "azurerm_policy_assignment": DetectionType.AZURE_POLICY,
    "azurerm_policy_definition": DetectionType.AZURE_POLICY,
}


@dataclass
class ParseResult:
    """Result of parsing Terraform HCL content."""

    detections: list[RawDetection]
    resource_count: int
    truncated: bool = False


def _validate_content(content: str) -> str:
    """Validate and sanitise raw content before parsing.

    Raises ValueError for content that exceeds limits or is empty.
    """
    if not content or not content.strip():
        raise ValueError("Empty content")

    content_bytes = len(content.encode("utf-8"))
    if content_bytes > MAX_CONTENT_BYTES:
        raise ValueError(
            f"Content exceeds maximum size: {content_bytes} bytes "
            f"(limit: {MAX_CONTENT_BYTES} bytes)"
        )

    return content


def _parse_hcl_sync(content: str) -> dict:
    """Parse HCL content synchronously (runs in dedicated thread pool).

    Uses python-hcl2 library. No regex fallback.
    """
    return hcl2.load(io.StringIO(content))


def _sanitise_config(config: dict) -> dict:
    """Recursively remove keys containing known secret substrings.

    This prevents accidental leakage of credentials that users may have
    embedded in their Terraform configurations.
    """
    sanitised = {}
    for k, v in config.items():
        if any(pat in k.lower() for pat in _SECRET_SUBSTRINGS):
            continue
        if isinstance(v, dict):
            sanitised[k] = _sanitise_config(v)
        elif isinstance(v, list):
            sanitised[k] = [
                _sanitise_config(item) if isinstance(item, dict) else item for item in v
            ]
        else:
            sanitised[k] = v
    return sanitised


def _extract_detections(parsed: dict) -> list[RawDetection]:
    """Extract RawDetection objects from parsed HCL dict.

    python-hcl2 returns resource blocks as:
    {"resource": [{"aws_type": {"name": {config_dict}}}]}

    Values inside config dicts are wrapped in single-element lists
    by python-hcl2 (e.g., {"alarm_name": ["my-alarm"]}).
    """
    detections: list[RawDetection] = []
    resource_blocks = parsed.get("resource", [])

    for block in resource_blocks:
        if not isinstance(block, dict):
            continue

        for resource_type, instances in block.items():
            detection_type = RESOURCE_TYPE_MAP.get(resource_type)
            if detection_type is None:
                continue  # Not a detection resource

            if not isinstance(instances, dict):
                continue

            for resource_name, config in instances.items():
                if not isinstance(config, dict):
                    continue

                sanitised = _sanitise_config(config)

                detection = RawDetection(
                    name=f"{resource_type}.{resource_name}",
                    detection_type=detection_type,
                    source_arn=f"iac://terraform/{resource_type}/{resource_name}",
                    region="iac-static",
                    raw_config=sanitised,
                    description=_unwrap_hcl_value(sanitised.get("description", "")),
                    event_pattern=_unwrap_hcl_value(sanitised.get("event_pattern")),
                )
                detections.append(detection)

                if len(detections) >= MAX_DETECTIONS:
                    return detections

    return detections


def _unwrap_hcl_value(value: object) -> object:
    """Unwrap python-hcl2 single-element list values.

    python-hcl2 wraps all values in lists, e.g.:
    {"alarm_name": ["my-alarm"]} -> "my-alarm"
    """
    if isinstance(value, list) and len(value) == 1:
        return value[0]
    return value


async def parse_terraform_content(content: str) -> ParseResult:
    """Parse Terraform HCL content with timeout and size limits.

    This is the main entry point. Runs the parser in a dedicated
    ThreadPoolExecutor with an asyncio timeout to prevent resource
    exhaustion.

    Args:
        content: Raw Terraform HCL string (untrusted user input).

    Returns:
        ParseResult with detections and metadata.

    Raises:
        ValueError: If content is empty or exceeds size limits.
        asyncio.TimeoutError: If parsing takes longer than 10 seconds.
    """
    validated = _validate_content(content)

    loop = asyncio.get_running_loop()
    parsed = await asyncio.wait_for(
        loop.run_in_executor(_parse_executor, _parse_hcl_sync, validated),
        timeout=PARSE_TIMEOUT_SECONDS,
    )

    detections = _extract_detections(parsed)
    truncated = len(detections) >= MAX_DETECTIONS

    return ParseResult(
        detections=detections,
        resource_count=len(parsed.get("resource", [])),
        truncated=truncated,
    )
