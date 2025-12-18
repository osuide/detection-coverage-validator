"""Scan orchestration service."""

from datetime import datetime
from typing import Optional
from uuid import UUID
import boto3
import structlog

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.models.cloud_account import CloudAccount, CloudProvider
from app.models.detection import Detection, DetectionType, DetectionStatus
from app.models.mapping import DetectionMapping, MappingSource
from app.models.scan import Scan, ScanStatus
from app.scanners.aws.cloudwatch_scanner import CloudWatchLogsInsightsScanner
from app.scanners.aws.eventbridge_scanner import EventBridgeScanner
from app.scanners.aws.guardduty_scanner import GuardDutyScanner
from app.scanners.aws.config_scanner import ConfigRulesScanner
from app.scanners.aws.securityhub_scanner import SecurityHubScanner
from app.scanners.base import RawDetection
from app.mappers.pattern_mapper import PatternMapper
from app.services.coverage_service import CoverageService
from app.services.notification_service import trigger_scan_alerts

logger = structlog.get_logger()


class ScanService:
    """Orchestrates the scanning and mapping process."""

    def __init__(self, db: AsyncSession):
        self.db = db
        self.logger = logger.bind(service="ScanService")
        self.mapper = PatternMapper()

    async def execute_scan(self, scan_id: UUID) -> None:
        """Execute a scan job.

        This is called as a background task and will:
        1. Update scan status to RUNNING
        2. Scan for detections using appropriate scanners
        3. Map detections to MITRE techniques
        4. Update scan status to COMPLETED or FAILED
        """
        self.logger.info("starting_scan", scan_id=str(scan_id))

        # Get scan and account
        scan = await self._get_scan(scan_id)
        if not scan:
            self.logger.error("scan_not_found", scan_id=str(scan_id))
            return

        account = await self._get_account(scan.cloud_account_id)
        if not account:
            await self._fail_scan(scan, "Cloud account not found")
            return

        try:
            # Update to running
            scan.status = ScanStatus.RUNNING
            scan.started_at = datetime.utcnow()
            scan.current_step = "Initializing"
            await self.db.commit()

            # Get boto3 session
            session = self._get_boto3_session(account)

            # Determine regions to scan
            regions = scan.regions or account.regions or ["us-east-1"]

            # Scan for detections
            scan.current_step = "Scanning for detections"
            scan.progress_percent = 10
            await self.db.commit()

            raw_detections = await self._scan_detections(
                session, regions, scan.detection_types
            )

            # Process detections
            scan.current_step = "Processing detections"
            scan.progress_percent = 50
            await self.db.commit()

            stats = await self._process_detections(
                account.id, raw_detections
            )

            # Map to MITRE techniques
            scan.current_step = "Mapping to MITRE ATT&CK"
            scan.progress_percent = 80
            await self.db.commit()

            await self._map_detections(account.id)

            # Calculate coverage snapshot
            scan.current_step = "Calculating coverage"
            scan.progress_percent = 90
            await self.db.commit()

            coverage_service = CoverageService(self.db)
            coverage_snapshot = await coverage_service.calculate_coverage(account.id, scan.id)

            # Trigger alerts based on scan results
            try:
                await trigger_scan_alerts(
                    self.db, account.id, scan.id, coverage_snapshot
                )
            except Exception as alert_error:
                self.logger.warning(
                    "alert_trigger_failed",
                    scan_id=str(scan_id),
                    error=str(alert_error),
                )

            # Update scan results
            scan.status = ScanStatus.COMPLETED
            scan.completed_at = datetime.utcnow()
            scan.current_step = "Complete"
            scan.progress_percent = 100
            scan.detections_found = stats["found"]
            scan.detections_new = stats["new"]
            scan.detections_updated = stats["updated"]

            # Update account last scan time
            account.last_scan_at = datetime.utcnow()

            await self.db.commit()

            self.logger.info(
                "scan_complete",
                scan_id=str(scan_id),
                found=stats["found"],
                new=stats["new"],
                updated=stats["updated"],
            )

        except Exception as e:
            self.logger.exception("scan_failed", scan_id=str(scan_id), error=str(e))
            await self._fail_scan(scan, str(e))

    async def _get_scan(self, scan_id: UUID) -> Optional[Scan]:
        """Get scan by ID."""
        result = await self.db.execute(select(Scan).where(Scan.id == scan_id))
        return result.scalar_one_or_none()

    async def _get_account(self, account_id: UUID) -> Optional[CloudAccount]:
        """Get cloud account by ID."""
        result = await self.db.execute(
            select(CloudAccount).where(CloudAccount.id == account_id)
        )
        return result.scalar_one_or_none()

    def _get_boto3_session(self, account: CloudAccount) -> boto3.Session:
        """Get boto3 session for the account."""
        # For now, use default credentials
        # In production, would use credentials_arn to assume role
        return boto3.Session()

    async def _scan_detections(
        self,
        session: boto3.Session,
        regions: list[str],
        detection_types: list[str],
    ) -> list[RawDetection]:
        """Run all applicable scanners."""
        all_detections = []

        # Determine which scanners to use
        scanners = []
        if not detection_types or "cloudwatch_logs_insights" in detection_types:
            scanners.append(CloudWatchLogsInsightsScanner(session))
        if not detection_types or "eventbridge_rule" in detection_types:
            scanners.append(EventBridgeScanner(session))
        if not detection_types or "guardduty_finding" in detection_types:
            scanners.append(GuardDutyScanner(session))
        if not detection_types or "config_rule" in detection_types:
            scanners.append(ConfigRulesScanner(session))
        if not detection_types or "security_hub" in detection_types:
            scanners.append(SecurityHubScanner(session))

        # Run scanners
        for scanner in scanners:
            try:
                detections = await scanner.scan(regions)
                all_detections.extend(detections)
                self.logger.info(
                    "scanner_complete",
                    scanner=scanner.__class__.__name__,
                    count=len(detections),
                )
            except Exception as e:
                self.logger.error(
                    "scanner_error",
                    scanner=scanner.__class__.__name__,
                    error=str(e),
                )

        return all_detections

    async def _process_detections(
        self,
        cloud_account_id: UUID,
        raw_detections: list[RawDetection],
    ) -> dict[str, int]:
        """Process raw detections into database records."""
        stats = {"found": len(raw_detections), "new": 0, "updated": 0}

        for raw in raw_detections:
            # Check if detection already exists
            existing = await self.db.execute(
                select(Detection).where(
                    Detection.cloud_account_id == cloud_account_id,
                    Detection.source_arn == raw.source_arn,
                )
            )
            detection = existing.scalar_one_or_none()

            if detection:
                # Update existing
                detection.name = raw.name
                detection.raw_config = raw.raw_config
                detection.query_pattern = raw.query_pattern
                detection.event_pattern = raw.event_pattern
                detection.log_groups = raw.log_groups
                detection.description = raw.description
                detection.status = DetectionStatus.ACTIVE
                detection.updated_at = datetime.utcnow()
                stats["updated"] += 1
            else:
                # Create new
                detection = Detection(
                    cloud_account_id=cloud_account_id,
                    name=raw.name,
                    detection_type=raw.detection_type,
                    status=DetectionStatus.ACTIVE,
                    source_arn=raw.source_arn,
                    region=raw.region,
                    raw_config=raw.raw_config,
                    query_pattern=raw.query_pattern,
                    event_pattern=raw.event_pattern,
                    log_groups=raw.log_groups,
                    description=raw.description,
                    is_managed=raw.is_managed,
                    discovered_at=raw.discovered_at,
                )
                self.db.add(detection)
                stats["new"] += 1

        await self.db.flush()
        return stats

    async def _map_detections(self, cloud_account_id: UUID) -> None:
        """Map all detections to MITRE techniques."""
        # Get all detections for account
        result = await self.db.execute(
            select(Detection).where(
                Detection.cloud_account_id == cloud_account_id,
                Detection.status == DetectionStatus.ACTIVE,
            )
        )
        detections = result.scalars().all()

        for detection in detections:
            # Delete existing mappings
            await self.db.execute(
                select(DetectionMapping).where(
                    DetectionMapping.detection_id == detection.id
                )
            )

            # Create RawDetection for mapper
            raw = RawDetection(
                name=detection.name,
                detection_type=detection.detection_type,
                source_arn=detection.source_arn or "",
                region=detection.region,
                raw_config=detection.raw_config,
                query_pattern=detection.query_pattern,
                event_pattern=detection.event_pattern,
                log_groups=detection.log_groups,
                description=detection.description,
            )

            # Get mappings from pattern mapper
            mappings = self.mapper.map_detection(raw, min_confidence=0.4)

            # Create mapping records
            # Note: This requires technique records to exist in DB
            # For now, we store technique_id as string reference
            for mapping in mappings:
                # Look up technique in DB
                from app.models.mitre import Technique
                tech_result = await self.db.execute(
                    select(Technique).where(
                        Technique.technique_id == mapping.technique_id
                    )
                )
                technique = tech_result.scalar_one_or_none()

                if technique:
                    dm = DetectionMapping(
                        detection_id=detection.id,
                        technique_id=technique.id,
                        confidence=mapping.confidence,
                        mapping_source=MappingSource.PATTERN_MATCH,
                        rationale=mapping.rationale,
                        matched_indicators=mapping.matched_indicators,
                    )
                    self.db.add(dm)

        await self.db.flush()

    async def _fail_scan(self, scan: Scan, error: str) -> None:
        """Mark scan as failed."""
        scan.status = ScanStatus.FAILED
        scan.completed_at = datetime.utcnow()
        scan.errors = [{"message": error}]
        await self.db.commit()
