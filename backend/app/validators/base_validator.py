"""Base validator interface for detection health validation."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Optional

import structlog

logger = structlog.get_logger()


class ValidationSeverity(str, Enum):
    """Severity levels for validation issues."""

    CRITICAL = "critical"
    WARNING = "warning"
    INFO = "info"


@dataclass
class ValidationIssue:
    """A single validation issue found."""

    message: str
    severity: ValidationSeverity
    code: str  # Machine-readable error code
    details: Optional[dict[str, Any]] = None


@dataclass
class ValidationResult:
    """Result of a validation check."""

    validator_name: str
    is_valid: bool
    score: float  # 0.0 to 1.0
    issues: list[ValidationIssue] = field(default_factory=list)
    validated_at: datetime = field(default_factory=datetime.utcnow)
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def has_critical_issues(self) -> bool:
        """Check if there are any critical issues."""
        return any(
            issue.severity == ValidationSeverity.CRITICAL for issue in self.issues
        )

    @property
    def has_warnings(self) -> bool:
        """Check if there are any warnings."""
        return any(
            issue.severity == ValidationSeverity.WARNING for issue in self.issues
        )

    def add_issue(
        self,
        message: str,
        severity: ValidationSeverity,
        code: str,
        details: Optional[dict[str, Any]] = None,
    ) -> Any:
        """Add a validation issue."""
        self.issues.append(
            ValidationIssue(
                message=message,
                severity=severity,
                code=code,
                details=details,
            )
        )


class BaseValidator(ABC):
    """Abstract base class for detection validators.

    Validators check different aspects of detection health:
    - Staleness: Is the detection config stale?
    - Syntax: Is the detection query/pattern valid?
    - References: Do referenced resources exist?
    """

    def __init__(self) -> None:
        self.logger = logger.bind(validator=self.__class__.__name__)

    @property
    @abstractmethod
    def name(self) -> str:
        """Name of this validator."""
        pass

    @abstractmethod
    async def validate(
        self,
        detection: Any,
        session: Optional[Any] = None,
    ) -> ValidationResult:
        """Validate a detection.

        Args:
            detection: Detection model instance
            session: Optional cloud session (boto3/gcp) for resource checks

        Returns:
            ValidationResult with score and any issues found
        """
        pass

    def _create_result(self, is_valid: bool, score: float) -> ValidationResult:
        """Create a base validation result."""
        return ValidationResult(
            validator_name=self.name,
            is_valid=is_valid,
            score=score,
        )
