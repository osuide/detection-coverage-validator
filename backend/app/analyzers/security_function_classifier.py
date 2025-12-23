"""Security Function Classifier - NIST CSF-based detection categorisation.

Classifies detections by their security function (NIST CSF aligned):
- DETECT: Threat detection - maps to MITRE ATT&CK techniques
- PROTECT: Preventive controls - access controls, encryption, MFA
- IDENTIFY: Visibility controls - logging, monitoring, posture management
- RECOVER: Recovery controls - backup, DR, versioning
- OPERATIONAL: Non-security controls - tagging, cost, performance

This classifier is called during detection scanning to categorise each detection,
explaining WHY some detections don't map to MITRE ATT&CK techniques.
"""

import re
from dataclasses import dataclass
from typing import Optional

import structlog

from app.models.detection import SecurityFunction

logger = structlog.get_logger()


@dataclass
class ClassificationResult:
    """Result of security function classification."""

    security_function: SecurityFunction
    confidence: float  # 0.0 - 1.0
    matched_patterns: list[str]
    rationale: str


# Pattern keywords for each security function
# Order matters - more specific patterns should come first
FUNCTION_PATTERNS: dict[SecurityFunction, list[str]] = {
    # PROTECT: Preventive controls
    SecurityFunction.PROTECT: [
        # Access control
        "MFA",
        "MULTI_FACTOR",
        "PASSWORD",
        "ACCESS_KEY",
        "POLICY",
        "PERMISSION",
        "IAM",
        "ROLE",
        "PRINCIPAL",
        # Encryption
        "ENCRYPTED",
        "ENCRYPTION",
        "KMS",
        "CMK",
        "SSL",
        "TLS",
        "HTTPS",
        "CERTIFICATE",
        # Network security
        "SECURITY_GROUP",
        "NACL",
        "FIREWALL",
        "WAF",
        "PROHIBITED",
        "BLOCKED",
        "RESTRICTED",
        "NO_PUBLIC",
        "PRIVATE",
        # Access restrictions
        "PUBLIC_READ",
        "PUBLIC_WRITE",
        "PUBLIC_ACCESS",
        "VPC_ONLY",
        "ENDPOINT",
    ],
    # IDENTIFY: Visibility and posture controls
    SecurityFunction.IDENTIFY: [
        # Logging
        "LOGGING",
        "LOGS",
        "LOG_ENABLED",
        "CLOUDTRAIL",
        "FLOW_LOG",
        "AUDIT",
        "TRAIL",
        # Monitoring
        "MONITORING",
        "ALARM",
        "METRIC",
        "CLOUDWATCH",
        "ENABLED",
        # Configuration management
        "CONFIG",
        "CONFIGURATION",
        "INVENTORY",
        "DISCOVERY",
        "ASSET",
    ],
    # RECOVER: Recovery and resilience controls
    SecurityFunction.RECOVER: [
        "BACKUP",
        "VERSIONING",
        "RECOVERY",
        "PITR",
        "POINT_IN_TIME",
        "REPLICATION",
        "SNAPSHOT",
        "RETENTION",
        "DISASTER",
        "FAILOVER",
        "MULTI_AZ",
        "CROSS_REGION",
        "RESTORE",
    ],
    # OPERATIONAL: Non-security controls
    SecurityFunction.OPERATIONAL: [
        "TAG",
        "TAGGED",
        "REQUIRED_TAG",
        "NAMING",
        "NAME_CHECK",
        "APPROVED",
        "AUTOSCALING",
        "SCALING",
        "CONCURRENCY",
        "LIFECYCLE",
        "COST",
        "BUDGET",
        "LIMIT",
        "QUOTA",
        "INSTANCE_TYPE",
        "INSTANCE_SIZE",
        "TENANCY",
    ],
}

# Priority order for classification when multiple patterns match
FUNCTION_PRIORITY = [
    SecurityFunction.PROTECT,  # Highest priority - preventive controls
    SecurityFunction.IDENTIFY,  # Visibility/logging
    SecurityFunction.RECOVER,  # Backup/DR
    SecurityFunction.OPERATIONAL,  # Lowest - non-security
]


class SecurityFunctionClassifier:
    """Classifies detections by their NIST CSF security function.

    Classification logic:
    1. If detection has MITRE ATT&CK mappings -> DETECT
    2. Pattern match on detection name/description -> Matching function
    3. Default -> OPERATIONAL (flagged for review)
    """

    def __init__(self) -> None:
        self.logger = logger.bind(classifier="SecurityFunctionClassifier")
        # Pre-compile regex patterns for performance
        self._compiled_patterns: dict[SecurityFunction, list[re.Pattern]] = {}
        for func, patterns in FUNCTION_PATTERNS.items():
            self._compiled_patterns[func] = [
                re.compile(rf"\b{p}\b", re.IGNORECASE) for p in patterns
            ]

    def classify(
        self,
        detection_name: str,
        detection_description: Optional[str] = None,
        has_mitre_mappings: bool = False,
        source_identifier: Optional[str] = None,
    ) -> ClassificationResult:
        """Classify a detection by its security function.

        Args:
            detection_name: Name of the detection (e.g., Config rule name)
            detection_description: Optional description text
            has_mitre_mappings: Whether this detection has MITRE ATT&CK mappings
            source_identifier: Optional source identifier (e.g., AWS Config rule ID)

        Returns:
            ClassificationResult with function, confidence, and rationale
        """
        # Rule 1: If MITRE-mapped -> DETECT
        if has_mitre_mappings:
            return ClassificationResult(
                security_function=SecurityFunction.DETECT,
                confidence=1.0,
                matched_patterns=["mitre_mapping"],
                rationale="Detection maps to MITRE ATT&CK techniques",
            )

        # Build search text from name, description, and source identifier
        search_parts = [detection_name]
        if detection_description:
            search_parts.append(detection_description)
        if source_identifier:
            search_parts.append(source_identifier)

        search_text = " ".join(search_parts)
        # Normalise: replace hyphens with underscores for pattern matching
        normalised_text = search_text.replace("-", "_").upper()

        # Rule 2: Pattern match in priority order
        for func in FUNCTION_PRIORITY:
            patterns = self._compiled_patterns[func]
            matched = []
            for i, pattern in enumerate(patterns):
                if pattern.search(normalised_text):
                    matched.append(FUNCTION_PATTERNS[func][i])

            if matched:
                # Calculate confidence based on number of matches
                confidence = min(0.5 + (len(matched) * 0.1), 0.9)
                return ClassificationResult(
                    security_function=func,
                    confidence=confidence,
                    matched_patterns=matched,
                    rationale=self._get_rationale(func, matched),
                )

        # Rule 3: Default to OPERATIONAL
        self.logger.debug(
            "no_pattern_match",
            detection_name=detection_name,
            defaulting_to="operational",
        )
        return ClassificationResult(
            security_function=SecurityFunction.OPERATIONAL,
            confidence=0.3,
            matched_patterns=[],
            rationale="No security function patterns matched - classified as operational",
        )

    def _get_rationale(
        self, func: SecurityFunction, matched_patterns: list[str]
    ) -> str:
        """Generate human-readable rationale for classification."""
        pattern_str = ", ".join(matched_patterns[:3])
        if len(matched_patterns) > 3:
            pattern_str += f" (+{len(matched_patterns) - 3} more)"

        rationales = {
            SecurityFunction.PROTECT: f"Preventive control - matched: {pattern_str}",
            SecurityFunction.IDENTIFY: f"Visibility/posture control - matched: {pattern_str}",
            SecurityFunction.RECOVER: f"Recovery/resilience control - matched: {pattern_str}",
            SecurityFunction.OPERATIONAL: f"Operational control - matched: {pattern_str}",
        }
        return rationales.get(func, f"Matched patterns: {pattern_str}")

    def classify_batch(
        self,
        detections: list[dict],
    ) -> dict[str, ClassificationResult]:
        """Classify multiple detections.

        Args:
            detections: List of dicts with keys:
                - id: Detection ID
                - name: Detection name
                - description: Optional description
                - has_mitre_mappings: Boolean
                - source_identifier: Optional source ID

        Returns:
            Dict mapping detection ID to ClassificationResult
        """
        results = {}
        for det in detections:
            results[det["id"]] = self.classify(
                detection_name=det["name"],
                detection_description=det.get("description"),
                has_mitre_mappings=det.get("has_mitre_mappings", False),
                source_identifier=det.get("source_identifier"),
            )
        return results


# Module-level classifier instance for convenience
_classifier: Optional[SecurityFunctionClassifier] = None


def get_classifier() -> SecurityFunctionClassifier:
    """Get or create the global classifier instance."""
    global _classifier
    if _classifier is None:
        _classifier = SecurityFunctionClassifier()
    return _classifier


def classify_detection(
    detection_name: str,
    detection_description: Optional[str] = None,
    has_mitre_mappings: bool = False,
    source_identifier: Optional[str] = None,
) -> SecurityFunction:
    """Convenience function to classify a detection.

    Returns just the SecurityFunction enum value.
    """
    result = get_classifier().classify(
        detection_name=detection_name,
        detection_description=detection_description,
        has_mitre_mappings=has_mitre_mappings,
        source_identifier=source_identifier,
    )
    return result.security_function
