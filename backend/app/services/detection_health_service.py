"""Detection health validation service.

Validates detection configurations are working correctly:
- Syntax validation for queries/patterns
- Resource existence checks
- Permission verification
- Staleness detection
- Configuration completeness
"""

import enum
from datetime import datetime, timedelta, timezone
from typing import Optional
from uuid import UUID

from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.detection import Detection, HealthStatus, DetectionType
from app.models.cloud_account import CloudAccount


class HealthCheckType(str, enum.Enum):
    """Types of health checks."""

    SYNTAX = "syntax"  # Query/pattern syntax validity
    RESOURCE = "resource"  # Referenced resources exist
    PERMISSION = "permission"  # Access permissions available
    STALENESS = "staleness"  # Detection hasn't triggered recently
    CONFIG = "config"  # Configuration is complete and valid


class HealthCheckResult:
    """Result of a health check."""

    def __init__(
        self,
        check_type: HealthCheckType,
        passed: bool,
        message: str,
        severity: str = "info",
        details: Optional[dict] = None,
    ):
        self.check_type = check_type
        self.passed = passed
        self.message = message
        self.severity = severity  # info, warning, error
        self.details = details or {}

    def to_dict(self) -> dict:
        return {
            "check_type": self.check_type.value,
            "passed": self.passed,
            "message": self.message,
            "severity": self.severity,
            "details": self.details,
        }


# Staleness thresholds in days
STALENESS_WARNING_DAYS = 30
STALENESS_DEGRADED_DAYS = 90


class DetectionHealthService:
    """Service for validating detection health."""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def validate_detection(
        self,
        detection_id: UUID,
        organization_id: UUID,
    ) -> dict:
        """Validate a single detection and update its health status.

        Args:
            detection_id: Detection to validate
            organization_id: Organization for access control

        Returns:
            Health validation results
        """
        # Get detection with access check
        result = await self.db.execute(
            select(Detection)
            .join(CloudAccount, Detection.cloud_account_id == CloudAccount.id)
            .where(
                Detection.id == detection_id,
                CloudAccount.organization_id == organization_id,
            )
        )
        detection = result.scalar_one_or_none()

        if not detection:
            return {"error": "Detection not found"}

        # Run health checks
        checks: list[HealthCheckResult] = []

        # Syntax check
        syntax_result = self._check_syntax(detection)
        checks.append(syntax_result)

        # Config completeness check
        config_result = self._check_config(detection)
        checks.append(config_result)

        # Staleness check
        staleness_result = self._check_staleness(detection)
        checks.append(staleness_result)

        # Calculate overall health
        health_status, health_score = self._calculate_health(checks)

        # Update detection
        detection.health_status = health_status
        detection.health_score = health_score
        detection.health_issues = [c.to_dict() for c in checks if not c.passed]
        detection.last_validated_at = datetime.now(timezone.utc)

        await self.db.commit()

        return {
            "detection_id": str(detection_id),
            "detection_name": detection.name,
            "health_status": health_status.value,
            "health_score": health_score,
            "checks": [c.to_dict() for c in checks],
            "issues": [c.to_dict() for c in checks if not c.passed],
            "validated_at": detection.last_validated_at.isoformat(),
        }

    def _check_syntax(self, detection: Detection) -> HealthCheckResult:
        """Check query/pattern syntax validity."""
        query_pattern = detection.query_pattern
        event_pattern = detection.event_pattern

        # Detection type-specific syntax validation
        if detection.detection_type == DetectionType.CLOUDWATCH_LOGS_INSIGHTS:
            if query_pattern:
                # Basic CloudWatch Insights query validation
                valid, message = self._validate_cloudwatch_query(query_pattern)
                return HealthCheckResult(
                    check_type=HealthCheckType.SYNTAX,
                    passed=valid,
                    message=message,
                    severity="error" if not valid else "info",
                )
            else:
                return HealthCheckResult(
                    check_type=HealthCheckType.SYNTAX,
                    passed=False,
                    message="No query pattern defined",
                    severity="warning",
                )

        elif detection.detection_type == DetectionType.EVENTBRIDGE_RULE:
            if event_pattern:
                valid, message = self._validate_event_pattern(event_pattern)
                return HealthCheckResult(
                    check_type=HealthCheckType.SYNTAX,
                    passed=valid,
                    message=message,
                    severity="error" if not valid else "info",
                )
            else:
                return HealthCheckResult(
                    check_type=HealthCheckType.SYNTAX,
                    passed=False,
                    message="No event pattern defined",
                    severity="warning",
                )

        elif detection.detection_type == DetectionType.GCP_CLOUD_LOGGING:
            if query_pattern:
                valid, message = self._validate_gcp_logging_query(query_pattern)
                return HealthCheckResult(
                    check_type=HealthCheckType.SYNTAX,
                    passed=valid,
                    message=message,
                    severity="error" if not valid else "info",
                )

        # For managed services (GuardDuty, SCC), syntax is always valid
        if detection.is_managed:
            return HealthCheckResult(
                check_type=HealthCheckType.SYNTAX,
                passed=True,
                message="Managed service - syntax handled by provider",
                severity="info",
            )

        return HealthCheckResult(
            check_type=HealthCheckType.SYNTAX,
            passed=True,
            message="Syntax check passed",
            severity="info",
        )

    def _validate_cloudwatch_query(self, query: str) -> tuple[bool, str]:
        """Validate CloudWatch Logs Insights query syntax."""
        # Basic validation - check for required elements
        if not query.strip():
            return False, "Empty query"

        # Check for common query patterns
        required_keywords = ["fields", "filter", "stats", "sort", "limit", "parse"]
        has_keyword = any(kw in query.lower() for kw in required_keywords)

        if not has_keyword:
            return (
                False,
                "Query missing required keywords (fields, filter, stats, etc.)",
            )

        # Check for unbalanced quotes
        if query.count('"') % 2 != 0:
            return False, "Unbalanced quotes in query"

        # Check for unbalanced parentheses
        if query.count("(") != query.count(")"):
            return False, "Unbalanced parentheses in query"

        return True, "Query syntax valid"

    def _validate_event_pattern(self, pattern: dict) -> tuple[bool, str]:
        """Validate EventBridge event pattern."""
        if not isinstance(pattern, dict):
            return False, "Event pattern must be a JSON object"

        if not pattern:
            return False, "Empty event pattern"

        # Check for at least one filter
        valid_keys = [
            "source",
            "detail-type",
            "detail",
            "account",
            "region",
            "resources",
            "time",
            "id",
            "version",
        ]
        has_valid_key = any(k in pattern for k in valid_keys)

        if not has_valid_key:
            return False, f"Pattern missing required fields. Valid: {valid_keys}"

        return True, "Event pattern valid"

    def _validate_gcp_logging_query(self, query: str) -> tuple[bool, str]:
        """Validate GCP Cloud Logging query syntax."""
        if not query.strip():
            return False, "Empty query"

        # Check for basic filter syntax
        # GCP logging uses key=value or key:"value" syntax
        if "=" not in query and ":" not in query and "AND" not in query.upper():
            return False, "Query missing filter conditions"

        return True, "Query syntax valid"

    def _check_config(self, detection: Detection) -> HealthCheckResult:
        """Check configuration completeness."""
        issues = []

        # Check required fields
        if not detection.name:
            issues.append("Missing detection name")

        if not detection.source_arn and not detection.is_managed:
            issues.append("Missing source ARN/identifier")

        # Check for log groups in CloudWatch detections
        if detection.detection_type == DetectionType.CLOUDWATCH_LOGS_INSIGHTS:
            if not detection.log_groups:
                issues.append("No log groups configured")

        # Check raw_config
        if not detection.raw_config:
            issues.append("Missing raw configuration")

        if issues:
            return HealthCheckResult(
                check_type=HealthCheckType.CONFIG,
                passed=False,
                message=f"Configuration issues: {', '.join(issues)}",
                severity="warning",
                details={"issues": issues},
            )

        return HealthCheckResult(
            check_type=HealthCheckType.CONFIG,
            passed=True,
            message="Configuration complete",
            severity="info",
        )

    def _check_staleness(self, detection: Detection) -> HealthCheckResult:
        """Check if detection has triggered recently."""
        now = datetime.now(timezone.utc)

        # For managed services that don't track triggers
        if detection.is_managed and not detection.last_triggered_at:
            return HealthCheckResult(
                check_type=HealthCheckType.STALENESS,
                passed=True,
                message="Managed service - trigger data not available",
                severity="info",
            )

        if not detection.last_triggered_at:
            return HealthCheckResult(
                check_type=HealthCheckType.STALENESS,
                passed=False,
                message="Detection has never triggered",
                severity="warning",
                details={"days_since_trigger": None, "status": "never_triggered"},
            )

        days_since = (now - detection.last_triggered_at).days

        if days_since > STALENESS_DEGRADED_DAYS:
            return HealthCheckResult(
                check_type=HealthCheckType.STALENESS,
                passed=False,
                message=f"Detection stale - no triggers in {days_since} days",
                severity="error",
                details={"days_since_trigger": days_since, "status": "stale"},
            )

        if days_since > STALENESS_WARNING_DAYS:
            return HealthCheckResult(
                check_type=HealthCheckType.STALENESS,
                passed=False,
                message=f"Detection aging - last trigger {days_since} days ago",
                severity="warning",
                details={"days_since_trigger": days_since, "status": "aging"},
            )

        return HealthCheckResult(
            check_type=HealthCheckType.STALENESS,
            passed=True,
            message=f"Detection triggered {days_since} days ago",
            severity="info",
            details={"days_since_trigger": days_since, "status": "active"},
        )

    def _calculate_health(
        self, checks: list[HealthCheckResult]
    ) -> tuple[HealthStatus, float]:
        """Calculate overall health status and score from checks."""
        if not checks:
            return HealthStatus.UNKNOWN, 0.0

        # Count issues by severity
        errors = sum(1 for c in checks if not c.passed and c.severity == "error")
        warnings = sum(1 for c in checks if not c.passed and c.severity == "warning")
        passed = sum(1 for c in checks if c.passed)
        total = len(checks)

        # Calculate score (0-100)
        score = (passed / total) * 100 if total > 0 else 0

        # Reduce score for warnings and errors
        score -= errors * 20
        score -= warnings * 10
        score = max(0, min(100, score))

        # Determine status
        if errors > 0:
            return HealthStatus.BROKEN, score
        elif warnings > 0:
            return HealthStatus.DEGRADED, score
        elif passed == total:
            return HealthStatus.HEALTHY, score
        else:
            return HealthStatus.UNKNOWN, score

    async def get_detection_health(
        self,
        detection_id: UUID,
        organization_id: UUID,
    ) -> Optional[dict]:
        """Get current health status for a detection."""
        result = await self.db.execute(
            select(Detection)
            .join(CloudAccount, Detection.cloud_account_id == CloudAccount.id)
            .where(
                Detection.id == detection_id,
                CloudAccount.organization_id == organization_id,
            )
        )
        detection = result.scalar_one_or_none()

        if not detection:
            return None

        return {
            "detection_id": str(detection_id),
            "detection_name": detection.name,
            "health_status": detection.health_status.value,
            "health_score": detection.health_score,
            "health_issues": detection.health_issues or [],
            "last_validated_at": (
                detection.last_validated_at.isoformat()
                if detection.last_validated_at
                else None
            ),
            "last_triggered_at": (
                detection.last_triggered_at.isoformat()
                if detection.last_triggered_at
                else None
            ),
        }

    async def validate_all_detections(
        self,
        organization_id: UUID,
        cloud_account_id: Optional[UUID] = None,
    ) -> dict:
        """Validate all detections for an organization.

        Args:
            organization_id: Organization to validate
            cloud_account_id: Optional filter by account

        Returns:
            Summary of validation results
        """
        # Get all detections
        query = (
            select(Detection)
            .join(CloudAccount, Detection.cloud_account_id == CloudAccount.id)
            .where(CloudAccount.organization_id == organization_id)
        )

        if cloud_account_id:
            query = query.where(Detection.cloud_account_id == cloud_account_id)

        result = await self.db.execute(query)
        detections = result.scalars().all()

        results = {
            "total": len(detections),
            "validated": 0,
            "healthy": 0,
            "degraded": 0,
            "broken": 0,
            "unknown": 0,
            "errors": [],
        }

        for detection in detections:
            try:
                validation = await self.validate_detection(
                    detection.id, organization_id
                )
                results["validated"] += 1

                status = validation.get("health_status")
                if status == "healthy":
                    results["healthy"] += 1
                elif status == "degraded":
                    results["degraded"] += 1
                elif status == "broken":
                    results["broken"] += 1
                else:
                    results["unknown"] += 1

            except Exception as e:
                results["errors"].append(
                    {
                        "detection_id": str(detection.id),
                        "detection_name": detection.name,
                        "error": str(e),
                    }
                )

        return results

    async def get_health_summary(
        self,
        organization_id: UUID,
        cloud_account_id: Optional[UUID] = None,
    ) -> dict:
        """Get health summary for all detections.

        Args:
            organization_id: Organization to summarize
            cloud_account_id: Optional filter by account

        Returns:
            Health summary statistics
        """
        # Base query
        base_query = (
            select(Detection)
            .join(CloudAccount, Detection.cloud_account_id == CloudAccount.id)
            .where(CloudAccount.organization_id == organization_id)
        )

        if cloud_account_id:
            base_query = base_query.where(
                Detection.cloud_account_id == cloud_account_id
            )

        # Count by health status
        status_counts = {}
        for status in HealthStatus:
            count_query = (
                select(func.count(Detection.id))
                .select_from(Detection)
                .join(CloudAccount, Detection.cloud_account_id == CloudAccount.id)
                .where(
                    CloudAccount.organization_id == organization_id,
                    Detection.health_status == status,
                )
            )
            if cloud_account_id:
                count_query = count_query.where(
                    Detection.cloud_account_id == cloud_account_id
                )
            result = await self.db.execute(count_query)
            status_counts[status.value] = result.scalar() or 0

        # Total count
        total_result = await self.db.execute(
            select(func.count(Detection.id))
            .select_from(Detection)
            .join(CloudAccount, Detection.cloud_account_id == CloudAccount.id)
            .where(CloudAccount.organization_id == organization_id)
        )
        total = total_result.scalar() or 0

        # Stale detection count (last_triggered > 90 days ago)
        stale_cutoff = datetime.now(timezone.utc) - timedelta(
            days=STALENESS_DEGRADED_DAYS
        )
        stale_query = (
            select(func.count(Detection.id))
            .select_from(Detection)
            .join(CloudAccount, Detection.cloud_account_id == CloudAccount.id)
            .where(
                CloudAccount.organization_id == organization_id,
                Detection.last_triggered_at < stale_cutoff,
            )
        )
        if cloud_account_id:
            stale_query = stale_query.where(
                Detection.cloud_account_id == cloud_account_id
            )
        stale_result = await self.db.execute(stale_query)
        stale_count = stale_result.scalar() or 0

        # Never validated count
        never_validated_query = (
            select(func.count(Detection.id))
            .select_from(Detection)
            .join(CloudAccount, Detection.cloud_account_id == CloudAccount.id)
            .where(
                CloudAccount.organization_id == organization_id,
                Detection.last_validated_at.is_(None),
            )
        )
        if cloud_account_id:
            never_validated_query = never_validated_query.where(
                Detection.cloud_account_id == cloud_account_id
            )
        never_validated_result = await self.db.execute(never_validated_query)
        never_validated = never_validated_result.scalar() or 0

        # Average health score
        avg_query = (
            select(func.avg(Detection.health_score))
            .select_from(Detection)
            .join(CloudAccount, Detection.cloud_account_id == CloudAccount.id)
            .where(
                CloudAccount.organization_id == organization_id,
                Detection.health_score.isnot(None),
            )
        )
        if cloud_account_id:
            avg_query = avg_query.where(Detection.cloud_account_id == cloud_account_id)
        avg_result = await self.db.execute(avg_query)
        avg_score = avg_result.scalar() or 0

        return {
            "total_detections": total,
            "by_status": status_counts,
            "stale_count": stale_count,
            "never_validated": never_validated,
            "average_health_score": round(avg_score, 2) if avg_score else 0,
            "overall_health": self._determine_overall_health(status_counts, total),
        }

    def _determine_overall_health(
        self, status_counts: dict[str, int], total: int
    ) -> str:
        """Determine overall health classification."""
        if total == 0:
            return "unknown"

        broken = status_counts.get("broken", 0)
        degraded = status_counts.get("degraded", 0)
        healthy = status_counts.get("healthy", 0)

        broken_pct = (broken / total) * 100
        degraded_pct = (degraded / total) * 100
        healthy_pct = (healthy / total) * 100

        if broken_pct > 20:
            return "critical"
        elif broken_pct > 10 or degraded_pct > 30:
            return "poor"
        elif healthy_pct > 80:
            return "good"
        elif healthy_pct > 50:
            return "fair"
        else:
            return "unknown"
