"""Staleness validator for detection health monitoring."""

from datetime import datetime
from typing import Any, Optional

from app.validators.base_validator import (
    BaseValidator,
    ValidationResult,
    ValidationSeverity,
)


class StalenessValidator(BaseValidator):
    """Validates detection staleness based on configuration age and trigger history.

    Staleness indicators:
    - Detection config not updated in a long time
    - Detection has never triggered
    - Detection hasn't triggered in a long time
    """

    # Staleness thresholds (days)
    CONFIG_STALENESS_WARNING = 30
    CONFIG_STALENESS_CRITICAL = 90
    TRIGGER_STALENESS_WARNING = 30
    TRIGGER_STALENESS_CRITICAL = 90
    NEW_DETECTION_GRACE_PERIOD = 7  # Days before we expect triggers

    @property
    def name(self) -> str:
        return "staleness"

    async def validate(
        self,
        detection: Any,
        session: Optional[Any] = None,
    ) -> ValidationResult:
        """Validate detection staleness.

        Args:
            detection: Detection model instance
            session: Not used for staleness validation

        Returns:
            ValidationResult with staleness assessment
        """
        now = datetime.utcnow()
        issues = []
        score = 1.0

        # Check config staleness
        config_score, config_issues = self._check_config_staleness(detection, now)
        issues.extend(config_issues)
        score = min(score, config_score)

        # Check trigger staleness
        trigger_score, trigger_issues = self._check_trigger_staleness(detection, now)
        issues.extend(trigger_issues)
        score = min(score, trigger_score)

        result = self._create_result(
            is_valid=score > 0.5,
            score=score,
        )
        result.issues = issues
        result.metadata = {
            "days_since_update": self._days_since(detection.updated_at, now),
            "days_since_trigger": self._days_since(detection.last_triggered_at, now),
            "is_new_detection": self._is_new_detection(detection, now),
        }

        return result

    def _check_config_staleness(
        self,
        detection: Any,
        now: datetime,
    ) -> tuple[float, list]:
        """Check if detection configuration is stale."""
        issues = []
        score = 1.0

        updated_at = detection.updated_at
        if not updated_at:
            # If no update timestamp, assume created_at
            updated_at = getattr(detection, "discovered_at", now)

        days_since_update = self._days_since(updated_at, now)

        if days_since_update is None:
            return score, issues

        if days_since_update > self.CONFIG_STALENESS_CRITICAL:
            issues.append(
                {
                    "message": f"Detection config not updated in {days_since_update} days",
                    "severity": ValidationSeverity.CRITICAL,
                    "code": "STALE_CONFIG_CRITICAL",
                    "details": {"days_since_update": days_since_update},
                }
            )
            score = 0.3
        elif days_since_update > self.CONFIG_STALENESS_WARNING:
            issues.append(
                {
                    "message": f"Detection config not updated in {days_since_update} days",
                    "severity": ValidationSeverity.WARNING,
                    "code": "STALE_CONFIG_WARNING",
                    "details": {"days_since_update": days_since_update},
                }
            )
            score = 0.6

        return score, [self._issue_dict_to_issue(i) for i in issues]

    def _check_trigger_staleness(
        self,
        detection: Any,
        now: datetime,
    ) -> tuple[float, list]:
        """Check if detection trigger history is stale."""
        issues = []
        score = 1.0

        # Skip trigger check for managed detections (GuardDuty, SCC)
        if getattr(detection, "is_managed", False):
            return score, issues

        # Skip trigger check for very new detections
        if self._is_new_detection(detection, now):
            return score, issues

        last_triggered = detection.last_triggered_at

        if last_triggered is None:
            # Detection has never triggered
            issues.append(
                {
                    "message": "Detection has never triggered - may be misconfigured or unnecessary",
                    "severity": ValidationSeverity.WARNING,
                    "code": "NEVER_TRIGGERED",
                    "details": {},
                }
            )
            score = 0.7
        else:
            days_since_trigger = self._days_since(last_triggered, now)

            if (
                days_since_trigger
                and days_since_trigger > self.TRIGGER_STALENESS_CRITICAL
            ):
                issues.append(
                    {
                        "message": f"Detection hasn't triggered in {days_since_trigger} days",
                        "severity": ValidationSeverity.WARNING,
                        "code": "STALE_TRIGGER",
                        "details": {"days_since_trigger": days_since_trigger},
                    }
                )
                score = 0.6
            elif (
                days_since_trigger
                and days_since_trigger > self.TRIGGER_STALENESS_WARNING
            ):
                issues.append(
                    {
                        "message": f"Detection hasn't triggered in {days_since_trigger} days",
                        "severity": ValidationSeverity.INFO,
                        "code": "TRIGGER_AGING",
                        "details": {"days_since_trigger": days_since_trigger},
                    }
                )
                score = 0.8

        return score, [self._issue_dict_to_issue(i) for i in issues]

    def _is_new_detection(self, detection: Any, now: datetime) -> bool:
        """Check if detection was recently discovered."""
        discovered_at = getattr(detection, "discovered_at", None)
        if not discovered_at:
            return False

        days_since_discovery = self._days_since(discovered_at, now)
        return (
            days_since_discovery is not None
            and days_since_discovery <= self.NEW_DETECTION_GRACE_PERIOD
        )

    def _days_since(
        self, timestamp: Optional[datetime], now: datetime
    ) -> Optional[int]:
        """Calculate days since a timestamp."""
        if not timestamp:
            return None

        # Handle timezone-naive datetimes
        if timestamp.tzinfo is not None and now.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=None)
        elif timestamp.tzinfo is None and now.tzinfo is not None:
            now = now.replace(tzinfo=None)

        delta = now - timestamp
        return delta.days

    def _issue_dict_to_issue(self, issue_dict: dict) -> Any:
        """Convert issue dict to ValidationIssue-compatible format."""
        from app.validators.base_validator import ValidationIssue

        return ValidationIssue(
            message=issue_dict["message"],
            severity=issue_dict["severity"],
            code=issue_dict["code"],
            details=issue_dict.get("details"),
        )
