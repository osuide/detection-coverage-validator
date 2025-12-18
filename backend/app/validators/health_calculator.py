"""Health calculator for aggregating validation results."""

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Optional

import structlog

from app.models.detection import HealthStatus
from app.validators.base_validator import ValidationResult, ValidationSeverity

logger = structlog.get_logger()


@dataclass
class HealthScore:
    """Overall health score for a detection."""

    score: float  # 0.0 to 1.0
    status: HealthStatus
    issues: list[dict]
    component_scores: dict[str, float]
    calculated_at: datetime


class HealthCalculator:
    """Calculates overall detection health from validation results.

    Combines scores from:
    - Staleness validator (30% weight)
    - Syntax validator (40% weight)
    - Reference validator (30% weight)
    """

    # Component weights
    WEIGHTS = {
        "staleness": 0.30,
        "syntax": 0.40,
        "references": 0.30,
    }

    # Score thresholds for status
    HEALTHY_THRESHOLD = 0.8
    DEGRADED_THRESHOLD = 0.5

    def __init__(self):
        self.logger = logger.bind(component="HealthCalculator")

    def calculate(
        self,
        staleness_result: Optional[ValidationResult] = None,
        syntax_result: Optional[ValidationResult] = None,
        reference_result: Optional[ValidationResult] = None,
    ) -> HealthScore:
        """Calculate overall health score from validation results.

        Args:
            staleness_result: Result from StalenessValidator
            syntax_result: Result from SyntaxValidator
            reference_result: Result from ReferenceValidator

        Returns:
            HealthScore with overall assessment
        """
        component_scores = {}
        all_issues = []
        total_weight = 0.0
        weighted_sum = 0.0

        # Process staleness
        if staleness_result:
            component_scores["staleness"] = staleness_result.score
            weighted_sum += staleness_result.score * self.WEIGHTS["staleness"]
            total_weight += self.WEIGHTS["staleness"]
            all_issues.extend(self._convert_issues(staleness_result))

        # Process syntax
        if syntax_result:
            component_scores["syntax"] = syntax_result.score
            weighted_sum += syntax_result.score * self.WEIGHTS["syntax"]
            total_weight += self.WEIGHTS["syntax"]
            all_issues.extend(self._convert_issues(syntax_result))

        # Process references
        if reference_result:
            component_scores["references"] = reference_result.score
            weighted_sum += reference_result.score * self.WEIGHTS["references"]
            total_weight += self.WEIGHTS["references"]
            all_issues.extend(self._convert_issues(reference_result))

        # Calculate weighted average
        if total_weight > 0:
            final_score = weighted_sum / total_weight
        else:
            final_score = 1.0  # No validation performed, assume healthy

        # Normalize to 0-1 range
        final_score = max(0.0, min(1.0, final_score))

        # Determine status
        status = self._score_to_status(final_score, all_issues)

        return HealthScore(
            score=round(final_score, 2),
            status=status,
            issues=all_issues,
            component_scores=component_scores,
            calculated_at=datetime.utcnow(),
        )

    def _score_to_status(
        self,
        score: float,
        issues: list[dict],
    ) -> HealthStatus:
        """Convert score to health status."""
        # Check for critical issues first
        has_critical = any(
            i.get("severity") == "critical" or i.get("severity") == ValidationSeverity.CRITICAL
            for i in issues
        )

        if has_critical:
            return HealthStatus.BROKEN

        if score >= self.HEALTHY_THRESHOLD:
            return HealthStatus.HEALTHY
        elif score >= self.DEGRADED_THRESHOLD:
            return HealthStatus.DEGRADED
        else:
            return HealthStatus.BROKEN

    def _convert_issues(self, result: ValidationResult) -> list[dict]:
        """Convert ValidationResult issues to dict format."""
        issues = []

        for issue in result.issues:
            severity = issue.severity
            if hasattr(severity, "value"):
                severity = severity.value

            issues.append({
                "validator": result.validator_name,
                "message": issue.message,
                "severity": severity,
                "code": issue.code,
                "details": issue.details or {},
            })

        return issues


class DetectionHealthService:
    """Service for validating detection health."""

    def __init__(
        self,
        staleness_validator: Any = None,
        syntax_validator: Any = None,
        reference_validator: Any = None,
    ):
        from app.validators import StalenessValidator, SyntaxValidator, ReferenceValidator

        self.staleness_validator = staleness_validator or StalenessValidator()
        self.syntax_validator = syntax_validator or SyntaxValidator()
        self.reference_validator = reference_validator or ReferenceValidator()
        self.health_calculator = HealthCalculator()
        self.logger = logger.bind(component="DetectionHealthService")

    async def validate_detection(
        self,
        detection: Any,
        cloud_session: Optional[Any] = None,
        skip_references: bool = False,
    ) -> HealthScore:
        """Validate a detection and calculate health score.

        Args:
            detection: Detection model instance
            cloud_session: Cloud session for reference validation
            skip_references: Skip resource reference validation

        Returns:
            HealthScore with validation results
        """
        self.logger.info(
            "validating_detection",
            detection_id=str(detection.id),
            detection_name=detection.name,
        )

        # Run validators
        staleness_result = await self.staleness_validator.validate(detection)
        syntax_result = await self.syntax_validator.validate(detection)

        reference_result = None
        if not skip_references and cloud_session:
            reference_result = await self.reference_validator.validate(
                detection, cloud_session
            )

        # Calculate health score
        health_score = self.health_calculator.calculate(
            staleness_result=staleness_result,
            syntax_result=syntax_result,
            reference_result=reference_result,
        )

        self.logger.info(
            "detection_validated",
            detection_id=str(detection.id),
            health_score=health_score.score,
            health_status=health_score.status.value,
            issue_count=len(health_score.issues),
        )

        return health_score

    async def validate_batch(
        self,
        detections: list[Any],
        cloud_session: Optional[Any] = None,
        skip_references: bool = False,
    ) -> dict[str, HealthScore]:
        """Validate multiple detections.

        Args:
            detections: List of Detection model instances
            cloud_session: Cloud session for reference validation
            skip_references: Skip resource reference validation

        Returns:
            Dict mapping detection ID to HealthScore
        """
        results = {}

        for detection in detections:
            try:
                health_score = await self.validate_detection(
                    detection=detection,
                    cloud_session=cloud_session,
                    skip_references=skip_references,
                )
                results[str(detection.id)] = health_score
            except Exception as e:
                self.logger.error(
                    "detection_validation_error",
                    detection_id=str(detection.id),
                    error=str(e),
                )
                # Return unknown status on error
                results[str(detection.id)] = HealthScore(
                    score=0.0,
                    status=HealthStatus.UNKNOWN,
                    issues=[{
                        "validator": "health_service",
                        "message": f"Validation failed: {str(e)}",
                        "severity": "critical",
                        "code": "VALIDATION_ERROR",
                        "details": {"error": str(e)},
                    }],
                    component_scores={},
                    calculated_at=datetime.utcnow(),
                )

        self.logger.info(
            "batch_validation_complete",
            total_detections=len(detections),
            healthy_count=sum(
                1 for hs in results.values() if hs.status == HealthStatus.HEALTHY
            ),
            degraded_count=sum(
                1 for hs in results.values() if hs.status == HealthStatus.DEGRADED
            ),
            broken_count=sum(
                1 for hs in results.values() if hs.status == HealthStatus.BROKEN
            ),
        )

        return results
