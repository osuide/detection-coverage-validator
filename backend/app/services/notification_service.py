"""Notification service for sending alerts through various channels."""

from datetime import datetime, timezone
from typing import Optional
from uuid import UUID
import json

import httpx
import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.alert import (
    AlertConfig,
    AlertHistory,
    AlertType,
    AlertSeverity,
    NotificationChannel,
)
from app.models.coverage import CoverageSnapshot
from app.models.scan import Scan, ScanStatus
from app.core.config import get_settings

logger = structlog.get_logger()
settings = get_settings()


class NotificationService:
    """Service for sending notifications through configured channels."""

    def __init__(self, db: AsyncSession):
        self.db = db
        self.logger = logger.bind(service="NotificationService")

    async def check_and_trigger_alerts(
        self,
        cloud_account_id: UUID,
        scan_id: Optional[UUID] = None,
        coverage_snapshot: Optional[CoverageSnapshot] = None,
    ) -> list[AlertHistory]:
        """Check alert conditions and trigger notifications if needed."""
        triggered_alerts = []

        # Get active alerts for this account (and global alerts)
        result = await self.db.execute(
            select(AlertConfig).where(
                AlertConfig.is_active.is_(True),
                (AlertConfig.cloud_account_id == cloud_account_id)
                | (AlertConfig.cloud_account_id.is_(None)),
            )
        )
        alerts = result.scalars().all()

        for alert in alerts:
            should_trigger, details = await self._check_alert_condition(
                alert, cloud_account_id, scan_id, coverage_snapshot
            )

            if should_trigger:
                history = await self._trigger_alert(
                    alert, cloud_account_id, details
                )
                if history:
                    triggered_alerts.append(history)

        return triggered_alerts

    async def _check_alert_condition(
        self,
        alert: AlertConfig,
        cloud_account_id: UUID,
        scan_id: Optional[UUID],
        coverage_snapshot: Optional[CoverageSnapshot],
    ) -> tuple[bool, dict]:
        """Check if an alert condition is met."""
        details = {}

        # Check cooldown
        if alert.last_triggered_at:
            cooldown_end = alert.last_triggered_at.timestamp() + (
                alert.cooldown_minutes * 60
            )
            if datetime.now(timezone.utc).timestamp() < cooldown_end:
                return False, {}

        if alert.alert_type == AlertType.COVERAGE_THRESHOLD:
            if coverage_snapshot and alert.threshold_value is not None:
                coverage = coverage_snapshot.coverage_percent
                threshold = alert.threshold_value
                op = alert.threshold_operator or "lt"

                triggered = False
                if op == "lt" and coverage < threshold:
                    triggered = True
                elif op == "lte" and coverage <= threshold:
                    triggered = True
                elif op == "gt" and coverage > threshold:
                    triggered = True
                elif op == "gte" and coverage >= threshold:
                    triggered = True
                elif op == "eq" and coverage == threshold:
                    triggered = True

                if triggered:
                    details = {
                        "coverage_percent": coverage,
                        "threshold": threshold,
                        "operator": op,
                    }
                    return True, details

        elif alert.alert_type == AlertType.SCAN_COMPLETED:
            if scan_id:
                result = await self.db.execute(
                    select(Scan).where(Scan.id == scan_id)
                )
                scan = result.scalar_one_or_none()
                if scan and scan.status == ScanStatus.COMPLETED:
                    details = {
                        "scan_id": str(scan.id),
                        "detections_found": scan.detections_found,
                        "detections_new": scan.detections_new,
                    }
                    return True, details

        elif alert.alert_type == AlertType.SCAN_FAILED:
            if scan_id:
                result = await self.db.execute(
                    select(Scan).where(Scan.id == scan_id)
                )
                scan = result.scalar_one_or_none()
                if scan and scan.status == ScanStatus.FAILED:
                    details = {
                        "scan_id": str(scan.id),
                        "errors": scan.errors,
                    }
                    return True, details

        elif alert.alert_type == AlertType.GAP_DETECTED:
            if coverage_snapshot and coverage_snapshot.top_gaps:
                # Check if there are high-priority gaps
                high_priority_gaps = [
                    g for g in coverage_snapshot.top_gaps
                    if g.get("priority", 0) >= 7
                ]
                if high_priority_gaps:
                    details = {
                        "gap_count": len(high_priority_gaps),
                        "top_gaps": high_priority_gaps[:5],
                    }
                    return True, details

        return False, {}

    async def _trigger_alert(
        self,
        alert: AlertConfig,
        cloud_account_id: UUID,
        details: dict,
    ) -> Optional[AlertHistory]:
        """Trigger an alert and send notifications."""
        # Generate alert message
        title, message = self._generate_alert_message(alert, details)

        # Create history record
        history = AlertHistory(
            alert_config_id=alert.id,
            cloud_account_id=cloud_account_id,
            severity=alert.severity,
            title=title,
            message=message,
            details=details,
            channels_notified=[],
            notification_errors=[],
        )
        self.db.add(history)
        await self.db.flush()

        # Send notifications
        errors = []
        notified = []

        for channel_config in alert.channels:
            channel_type = channel_config.get("type")
            try:
                if channel_type == NotificationChannel.WEBHOOK.value:
                    await self._send_webhook(channel_config, alert, title, message, details)
                    notified.append(channel_type)
                elif channel_type == NotificationChannel.SLACK.value:
                    await self._send_slack(channel_config, alert, title, message, details)
                    notified.append(channel_type)
                elif channel_type == NotificationChannel.EMAIL.value:
                    # Email would require SMTP setup - log for now
                    self.logger.info(
                        "email_notification_skipped",
                        reason="SMTP not configured",
                        recipient=channel_config.get("email"),
                    )
            except Exception as e:
                errors.append({
                    "channel": channel_type,
                    "error": str(e),
                })
                self.logger.error(
                    "notification_failed",
                    channel=channel_type,
                    error=str(e),
                )

        # Update history and alert
        history.channels_notified = notified
        history.notification_errors = errors if errors else None

        alert.last_triggered_at = datetime.now(timezone.utc)
        alert.trigger_count += 1

        await self.db.commit()

        self.logger.info(
            "alert_triggered",
            alert_id=str(alert.id),
            alert_name=alert.name,
            channels_notified=notified,
        )

        return history

    def _generate_alert_message(
        self,
        alert: AlertConfig,
        details: dict,
    ) -> tuple[str, str]:
        """Generate alert title and message."""
        if alert.alert_type == AlertType.COVERAGE_THRESHOLD:
            title = f"Coverage Alert: {alert.name}"
            coverage = details.get("coverage_percent", 0)
            threshold = details.get("threshold", 0)
            message = (
                f"Detection coverage has fallen below the threshold.\n"
                f"Current coverage: {coverage:.1f}%\n"
                f"Threshold: {threshold:.1f}%"
            )
        elif alert.alert_type == AlertType.SCAN_COMPLETED:
            title = f"Scan Completed: {alert.name}"
            found = details.get("detections_found", 0)
            new = details.get("detections_new", 0)
            message = (
                f"Security scan completed successfully.\n"
                f"Detections found: {found}\n"
                f"New detections: {new}"
            )
        elif alert.alert_type == AlertType.SCAN_FAILED:
            title = f"Scan Failed: {alert.name}"
            errors = details.get("errors", [])
            message = f"Security scan failed.\nErrors: {json.dumps(errors)}"
        elif alert.alert_type == AlertType.GAP_DETECTED:
            title = f"Coverage Gap Alert: {alert.name}"
            gap_count = details.get("gap_count", 0)
            message = f"High-priority coverage gaps detected.\nGaps found: {gap_count}"
        else:
            title = f"Alert: {alert.name}"
            message = f"Alert triggered. Details: {json.dumps(details)}"

        return title, message

    async def _send_webhook(
        self,
        config: dict,
        alert: AlertConfig,
        title: str,
        message: str,
        details: dict,
    ) -> None:
        """Send webhook notification."""
        url = config.get("url")
        if not url:
            raise ValueError("Webhook URL not configured")

        payload = {
            "alert_name": alert.name,
            "alert_type": alert.alert_type.value,
            "severity": alert.severity.value,
            "title": title,
            "message": message,
            "details": details,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        headers = config.get("headers", {})
        headers["Content-Type"] = "application/json"

        async with httpx.AsyncClient() as client:
            response = await client.post(
                url,
                json=payload,
                headers=headers,
                timeout=10.0,
            )
            response.raise_for_status()

        self.logger.info("webhook_sent", url=url)

    async def _send_slack(
        self,
        config: dict,
        alert: AlertConfig,
        title: str,
        message: str,
        details: dict,
    ) -> None:
        """Send Slack notification."""
        webhook_url = config.get("webhook_url")
        if not webhook_url:
            raise ValueError("Slack webhook URL not configured")

        # Color based on severity
        color = {
            AlertSeverity.INFO: "#36a64f",
            AlertSeverity.WARNING: "#ffcc00",
            AlertSeverity.CRITICAL: "#ff0000",
        }.get(alert.severity, "#808080")

        payload = {
            "attachments": [
                {
                    "color": color,
                    "title": title,
                    "text": message,
                    "fields": [
                        {
                            "title": "Severity",
                            "value": alert.severity.value.upper(),
                            "short": True,
                        },
                        {
                            "title": "Type",
                            "value": alert.alert_type.value.replace("_", " ").title(),
                            "short": True,
                        },
                    ],
                    "footer": "Detection Coverage Validator",
                    "ts": int(datetime.now(timezone.utc).timestamp()),
                }
            ]
        }

        async with httpx.AsyncClient() as client:
            response = await client.post(
                webhook_url,
                json=payload,
                timeout=10.0,
            )
            response.raise_for_status()

        self.logger.info("slack_notification_sent")


async def trigger_scan_alerts(
    db: AsyncSession,
    cloud_account_id: UUID,
    scan_id: UUID,
    coverage_snapshot: Optional[CoverageSnapshot] = None,
) -> list[AlertHistory]:
    """Convenience function to trigger scan-related alerts."""
    service = NotificationService(db)
    return await service.check_and_trigger_alerts(
        cloud_account_id, scan_id, coverage_snapshot
    )
