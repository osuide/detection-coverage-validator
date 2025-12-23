"""Scan orchestration service."""

import os
from dataclasses import dataclass
from datetime import datetime, timezone, date
from typing import Any, Optional
from uuid import UUID
import boto3
import structlog

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, delete

from app.models.cloud_account import CloudAccount, CloudProvider
from app.models.cloud_credential import (
    CloudCredential,
    CredentialType,
    CredentialStatus,
)
from app.models.detection import Detection, DetectionStatus
from app.analyzers.security_function_classifier import classify_detection
from app.models.mapping import DetectionMapping, MappingSource
from app.models.scan import Scan, ScanStatus
from app.scanners.aws.cloudwatch_scanner import CloudWatchLogsInsightsScanner
from app.scanners.aws.eventbridge_scanner import EventBridgeScanner
from app.scanners.aws.guardduty_scanner import GuardDutyScanner
from app.scanners.aws.config_scanner import ConfigRulesScanner
from app.scanners.aws.securityhub_scanner import SecurityHubScanner
from app.scanners.base import RawDetection, BaseScanner
from app.mappers.pattern_mapper import PatternMapper
from app.services.coverage_service import CoverageService
from app.services.drift_detection_service import DriftDetectionService
from app.services.notification_service import trigger_scan_alerts
from app.services.aws_credential_service import aws_credential_service
from app.services.region_discovery_service import region_discovery_service
from app.core.service_registry import get_all_regions, get_default_regions
from app.models.cloud_account import RegionScanMode

logger = structlog.get_logger()


def _serialize_for_jsonb(obj: Any) -> Any:
    """Recursively serialize datetime objects for JSONB storage.

    AWS SDK returns datetime objects that aren't JSON serializable.
    This converts them to ISO format strings.
    """
    if isinstance(obj, (datetime, date)):
        return obj.isoformat()
    elif isinstance(obj, dict):
        return {k: _serialize_for_jsonb(v) for k, v in obj.items()}
    elif isinstance(obj, (list, tuple)):
        return [_serialize_for_jsonb(item) for item in obj]
    return obj


@dataclass
class RegionConfig:
    """Configuration for multi-region scanning."""

    regional_regions: list[str]  # Regions to scan for regional services
    global_region: str  # Region to use for global services (e.g., us-east-1 for AWS)


def _is_dev_mode_allowed() -> bool:
    """Check if DEV_MODE is allowed in current environment.

    Security: DEV_MODE bypasses real AWS credential validation.
    It must be blocked in production/staging to prevent abuse.
    """
    dev_mode_requested = os.environ.get("A13E_DEV_MODE", "false").lower() == "true"
    environment = os.environ.get("ENVIRONMENT", "development")

    # DEV_MODE only allowed in development/local environments
    if dev_mode_requested and environment in ("production", "staging"):
        logger.warning(
            "dev_mode_blocked",
            environment=environment,
            message="DEV_MODE requested but blocked in non-development environment",
        )
        return False
    return dev_mode_requested


# Development mode - skip real AWS calls (blocked in production/staging)
DEV_MODE = _is_dev_mode_allowed()


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
            scan.started_at = datetime.now(timezone.utc)
            scan.current_step = "Initializing"
            await self.db.commit()

            # Get boto3 session (with assumed role credentials)
            session = await self._get_boto3_session(account)

            # Determine regions to scan using new multi-region logic
            # This may trigger auto-discovery if mode=AUTO and no regions cached
            region_config = await self._determine_scan_regions(scan, account, session)

            self.logger.info(
                "scan_regions_determined",
                scan_id=str(scan_id),
                regional_regions=region_config.regional_regions,
                global_region=region_config.global_region,
                mode=(
                    account.get_region_scan_mode().value
                    if account.region_config
                    else "default"
                ),
            )

            # Scan for detections
            scan.current_step = "Scanning for detections"
            scan.progress_percent = 10
            await self.db.commit()

            raw_detections, scanner_errors = await self._scan_detections(
                session, region_config, scan.detection_types
            )

            # Store any scanner errors in scan results
            if scanner_errors:
                scan.errors = [
                    {"message": e, "type": "scanner"} for e in scanner_errors
                ]

            # Process detections
            scan.current_step = "Processing detections"
            scan.progress_percent = 50
            await self.db.commit()

            stats = await self._process_detections(account.id, raw_detections)

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
            coverage_snapshot = await coverage_service.calculate_coverage(
                account.id, scan.id
            )

            # Record coverage history for drift detection
            try:
                drift_service = DriftDetectionService(self.db)
                await drift_service.record_coverage_snapshot(account.id, scan.id)
            except Exception as drift_error:
                self.logger.warning(
                    "drift_detection_failed",
                    scan_id=str(scan_id),
                    error=str(drift_error),
                )

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
            scan.completed_at = datetime.now(timezone.utc)
            scan.current_step = "Complete"
            scan.progress_percent = 100
            scan.detections_found = stats["found"]
            scan.detections_new = stats["new"]
            scan.detections_updated = stats["updated"]

            # Update account last scan time
            account.last_scan_at = datetime.now(timezone.utc)

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

    async def _determine_scan_regions(
        self,
        scan: Scan,
        account: CloudAccount,
        session: boto3.Session,
    ) -> RegionConfig:
        """Determine which regions to scan based on account configuration.

        This method implements the multi-region scanning logic:
        - For "all" mode: Scan all available regions (minus exclusions)
        - For "auto" mode: Auto-discover active regions if not already done
        - For "selected" mode: Use explicitly configured regions
        - Fallback: Use default enabled regions for the provider

        Args:
            scan: The scan request (may have region overrides)
            account: The cloud account with region configuration
            session: boto3 session for AWS API calls (used for auto-discovery)

        Returns:
            RegionConfig with regions for regional and global services
        """
        # Scan-level override takes precedence
        if scan.regions:
            self.logger.info(
                "using_scan_level_regions",
                account_id=str(account.id),
                regions=scan.regions,
            )
            return RegionConfig(
                regional_regions=scan.regions,
                global_region=self._get_global_region(account),
            )

        # Get all available regions for this provider
        provider = account.provider.value if account.provider else "aws"
        all_regions = get_all_regions(provider)
        default_regions = get_default_regions(provider)

        # Get the current mode
        mode = account.get_region_scan_mode()

        if mode == RegionScanMode.ALL:
            # Scan all regions except exclusions
            excluded = set(
                account.region_config.get("excluded_regions", [])
                if account.region_config
                else []
            )
            effective_regions = [r for r in all_regions if r not in excluded]
            self.logger.info(
                "using_all_regions_mode",
                account_id=str(account.id),
                total_regions=len(effective_regions),
                excluded=list(excluded),
            )

        elif mode == RegionScanMode.AUTO:
            # Check for already-discovered regions
            discovered = (
                account.region_config.get("discovered_regions", [])
                if account.region_config
                else []
            )

            if discovered:
                effective_regions = discovered
                self.logger.info(
                    "using_discovered_regions",
                    account_id=str(account.id),
                    regions=effective_regions,
                )
            else:
                # No discovered regions - run auto-discovery now
                self.logger.info(
                    "running_auto_discovery",
                    account_id=str(account.id),
                    reason="no_discovered_regions_cached",
                )
                try:
                    if account.provider == CloudProvider.AWS:
                        effective_regions = (
                            await region_discovery_service.discover_aws_active_regions(
                                session,
                                check_ec2=True,
                                check_guardduty=True,
                                check_cloudwatch=True,
                            )
                        )
                        # Save discovered regions to account for future scans
                        account.set_auto_discovered_regions(effective_regions)
                        await self.db.commit()
                        self.logger.info(
                            "auto_discovery_complete",
                            account_id=str(account.id),
                            discovered_regions=effective_regions,
                        )
                    else:
                        # GCP discovery not implemented, use defaults
                        self.logger.warning(
                            "gcp_discovery_not_implemented",
                            account_id=str(account.id),
                        )
                        effective_regions = default_regions
                except Exception as e:
                    # Discovery failed - fall back to default regions
                    self.logger.warning(
                        "auto_discovery_failed",
                        account_id=str(account.id),
                        error=str(e),
                        fallback="default_regions",
                    )
                    effective_regions = default_regions

        else:  # SELECTED mode
            # Use explicitly configured regions
            config_regions = (
                account.region_config.get("regions", [])
                if account.region_config
                else []
            )
            # Fall back to legacy regions field, then to default region
            effective_regions = config_regions or []
            if not effective_regions:
                # Don't use legacy self.regions - it often has stale us-east-1
                # Instead use the account's default region
                default_region = account.get_default_region()
                effective_regions = [default_region]
                self.logger.warning(
                    "no_regions_in_selected_mode",
                    account_id=str(account.id),
                    fallback_region=default_region,
                )
            else:
                self.logger.info(
                    "using_selected_regions",
                    account_id=str(account.id),
                    regions=effective_regions,
                )

        # Final fallback - should never reach here but just in case
        if not effective_regions:
            default_region = account.get_default_region()
            self.logger.warning(
                "no_regions_configured",
                account_id=str(account.id),
                fallback_region=default_region,
            )
            effective_regions = [default_region]

        return RegionConfig(
            regional_regions=effective_regions,
            global_region=self._get_global_region(account),
        )

    def _get_global_region(self, account: CloudAccount) -> str:
        """Get the region to use for global service API calls.

        Args:
            account: The cloud account

        Returns:
            Region code for global service endpoints
        """
        if account.provider == CloudProvider.AWS:
            return "us-east-1"  # AWS global services use us-east-1
        elif account.provider == CloudProvider.GCP:
            return "global"  # GCP uses "global" for organisation-level services
        return "us-east-1"

    async def _get_boto3_session(self, account: CloudAccount) -> boto3.Session:
        """Get boto3 session for the account using stored credentials.

        This method:
        1. Looks up the CloudCredential for the account
        2. Uses STS AssumeRole to get temporary credentials
        3. Returns a boto3 Session with those credentials

        In DEV_MODE, returns a default session for testing.
        """
        if DEV_MODE:
            self.logger.info(
                "dev_mode_session",
                account_id=str(account.id),
                msg="Using default credentials in dev mode",
            )
            return boto3.Session()

        # Get the credential for this account
        result = await self.db.execute(
            select(CloudCredential).where(
                CloudCredential.cloud_account_id == account.id
            )
        )
        credential = result.scalar_one_or_none()

        if not credential:
            raise ValueError(f"No credentials found for account {account.account_id}")

        if credential.status != CredentialStatus.VALID:
            raise ValueError(
                f"Credentials for account {account.account_id} are not valid. "
                f"Status: {credential.status.value}. Please re-validate credentials."
            )

        if credential.credential_type != CredentialType.AWS_IAM_ROLE:
            raise ValueError(
                f"Unsupported credential type: {credential.credential_type.value}. "
                f"Only AWS IAM Role is currently supported for scanning."
            )

        if not credential.aws_role_arn or not credential.aws_external_id:
            raise ValueError(
                f"Incomplete AWS credentials for account {account.account_id}. "
                f"Missing role ARN or external ID."
            )

        # Assume the role and get temporary credentials
        self.logger.info(
            "assuming_role",
            account_id=str(account.id),
            role_arn=credential.aws_role_arn,
        )

        try:
            creds = aws_credential_service.assume_role(
                role_arn=credential.aws_role_arn,
                external_id=credential.aws_external_id,
                session_name=f"A13E-Scan-{str(account.id)[:8]}",
            )

            # Create session with assumed credentials
            return boto3.Session(
                aws_access_key_id=creds["access_key_id"],
                aws_secret_access_key=creds["secret_access_key"],
                aws_session_token=creds["session_token"],
            )
        except Exception as e:
            self.logger.error(
                "assume_role_failed",
                account_id=str(account.id),
                role_arn=credential.aws_role_arn,
                error=str(e),
            )
            raise ValueError(
                f"Failed to assume role for account {account.account_id}: {str(e)}"
            )

    async def _scan_detections(
        self,
        session: boto3.Session,
        region_config: RegionConfig,
        detection_types: list[str],
    ) -> tuple[list[RawDetection], list[str]]:
        """Run all applicable scanners with proper global/regional handling.

        Global services (like IAM) are scanned once from the global_region.
        Regional services (like GuardDuty) are scanned in each regional_region.

        Args:
            session: boto3 session with credentials
            region_config: Configuration specifying regional and global regions
            detection_types: List of detection types to scan for

        Returns:
            Tuple of (detections, errors) where errors is a list of
            scanner failure messages to include in scan results.
        """
        all_detections = []
        scan_errors = []

        # Determine which scanners to use
        scanners: list[BaseScanner] = []
        if not detection_types or "cloudwatch_logs_insights" in detection_types:
            scanners.append(CloudWatchLogsInsightsScanner(session))
        # CloudWatch Alarms scanner disabled until database migration is run
        # if not detection_types or "cloudwatch_alarm" in detection_types:
        #     scanners.append(CloudWatchMetricAlarmScanner(session))
        if not detection_types or "eventbridge_rule" in detection_types:
            scanners.append(EventBridgeScanner(session))
        if not detection_types or "guardduty_finding" in detection_types:
            scanners.append(GuardDutyScanner(session))
        if not detection_types or "config_rule" in detection_types:
            scanners.append(ConfigRulesScanner(session))
        if not detection_types or "security_hub" in detection_types:
            scanners.append(SecurityHubScanner(session))

        # Run scanners with appropriate regions based on global/regional classification
        for scanner in scanners:
            try:
                # Determine which regions to use for this scanner
                if scanner.is_global_service:
                    # Global services scan once from the designated global region
                    scan_regions = [scanner.global_scan_region]
                    self.logger.debug(
                        "scanning_global_service",
                        scanner=scanner.__class__.__name__,
                        region=scanner.global_scan_region,
                    )
                else:
                    # Regional services scan all specified regions
                    scan_regions = region_config.regional_regions
                    self.logger.debug(
                        "scanning_regional_service",
                        scanner=scanner.__class__.__name__,
                        regions=scan_regions,
                    )

                detections = await scanner.scan(scan_regions)
                all_detections.extend(detections)
                self.logger.info(
                    "scanner_complete",
                    scanner=scanner.__class__.__name__,
                    count=len(detections),
                    regions_scanned=len(scan_regions),
                )
            except Exception as e:
                error_msg = f"{scanner.__class__.__name__}: {str(e)}"
                scan_errors.append(error_msg)
                self.logger.error(
                    "scanner_error",
                    scanner=scanner.__class__.__name__,
                    error=str(e),
                )

        return all_detections, scan_errors

    async def _process_detections(
        self,
        cloud_account_id: UUID,
        raw_detections: list[RawDetection],
    ) -> dict[str, int]:
        """Process raw detections into database records."""
        stats = {"found": len(raw_detections), "new": 0, "updated": 0}

        # Clean up any duplicate detections first (keep oldest by id)
        await self._cleanup_duplicate_detections(cloud_account_id)

        for raw in raw_detections:
            # Check if detection already exists
            existing = await self.db.execute(
                select(Detection)
                .where(
                    Detection.cloud_account_id == cloud_account_id,
                    Detection.source_arn == raw.source_arn,
                )
                .limit(1)
            )
            detection = existing.scalar_one_or_none()

            if detection:
                # Update existing
                detection.name = raw.name
                # Serialize JSONB fields to handle datetime from AWS SDK
                detection.raw_config = _serialize_for_jsonb(raw.raw_config)
                detection.query_pattern = raw.query_pattern
                detection.event_pattern = _serialize_for_jsonb(raw.event_pattern)
                detection.log_groups = raw.log_groups
                detection.description = raw.description
                detection.target_services = raw.target_services
                detection.status = DetectionStatus.ACTIVE
                detection.updated_at = datetime.now(timezone.utc)
                stats["updated"] += 1
            else:
                # Create new
                # Serialize JSONB fields to handle datetime from AWS SDK
                detection = Detection(
                    cloud_account_id=cloud_account_id,
                    name=raw.name,
                    detection_type=raw.detection_type,
                    status=DetectionStatus.ACTIVE,
                    source_arn=raw.source_arn,
                    region=raw.region,
                    raw_config=_serialize_for_jsonb(raw.raw_config),
                    query_pattern=raw.query_pattern,
                    event_pattern=_serialize_for_jsonb(raw.event_pattern),
                    log_groups=raw.log_groups,
                    description=raw.description,
                    is_managed=raw.is_managed,
                    discovered_at=raw.discovered_at,
                    target_services=raw.target_services,
                )
                self.db.add(detection)
                stats["new"] += 1

        await self.db.flush()
        return stats

    async def _cleanup_duplicate_detections(self, cloud_account_id: UUID) -> None:
        """Remove duplicate detections keeping only the oldest one per source_arn."""
        from sqlalchemy import func

        # Find source_arns with duplicates
        subq = (
            select(Detection.source_arn)
            .where(Detection.cloud_account_id == cloud_account_id)
            .group_by(Detection.source_arn)
            .having(func.count(Detection.id) > 1)
        )
        result = await self.db.execute(subq)
        duplicate_arns = [row[0] for row in result.all()]

        if not duplicate_arns:
            return

        self.logger.info(
            "cleaning_duplicate_detections",
            account_id=str(cloud_account_id),
            duplicate_count=len(duplicate_arns),
        )

        for arn in duplicate_arns:
            # Get all detections for this ARN, ordered by discovered_at
            dups = await self.db.execute(
                select(Detection)
                .where(
                    Detection.cloud_account_id == cloud_account_id,
                    Detection.source_arn == arn,
                )
                .order_by(Detection.discovered_at)
            )
            detections = list(dups.scalars().all())

            # Keep the first (oldest), delete the rest
            for dup in detections[1:]:
                # Delete mappings for this detection first
                await self.db.execute(
                    delete(DetectionMapping).where(
                        DetectionMapping.detection_id == dup.id
                    )
                )
                await self.db.delete(dup)

        await self.db.flush()

    async def _map_detections(self, cloud_account_id: UUID) -> None:
        """Map all detections to MITRE techniques.

        Optimised to avoid N+1 queries by bulk-fetching techniques.
        """
        from app.models.mitre import Technique

        # Get all detections for account
        result = await self.db.execute(
            select(Detection).where(
                Detection.cloud_account_id == cloud_account_id,
                Detection.status == DetectionStatus.ACTIVE,
            )
        )
        detections = result.scalars().all()

        if not detections:
            return

        # Phase 1: Delete existing mappings for all detections (bulk operation)
        detection_ids = [d.id for d in detections]
        await self.db.execute(
            delete(DetectionMapping).where(
                DetectionMapping.detection_id.in_(detection_ids)
            )
        )

        # Phase 2: Collect all technique IDs needed
        detection_mappings_list = []  # [(detection, [mappings])]
        technique_ids_needed = set()

        for detection in detections:
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
            mappings = self.mapper.map_detection(raw, min_confidence=0.4)
            detection_mappings_list.append((detection, mappings))
            technique_ids_needed.update(m.technique_id for m in mappings)

        # Phase 3: Bulk fetch all techniques in one query
        techniques_map = {}
        if technique_ids_needed:
            tech_result = await self.db.execute(
                select(Technique).where(
                    Technique.technique_id.in_(technique_ids_needed)
                )
            )
            techniques_map = {t.technique_id: t for t in tech_result.scalars().all()}

        # Phase 4: Create all mapping records using cached techniques
        for detection, mappings in detection_mappings_list:
            for mapping in mappings:
                technique = techniques_map.get(mapping.technique_id)
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

        # Phase 5: Classify detections by security function (NIST CSF)
        # This explains WHY unmapped detections don't have MITRE mappings
        for detection, mappings in detection_mappings_list:
            has_mitre_mappings = len(mappings) > 0
            # Get source identifier from raw_config if available
            source_identifier = None
            if detection.raw_config:
                source_identifier = detection.raw_config.get(
                    "source_identifier"
                ) or detection.raw_config.get("rule_id")

            security_function = classify_detection(
                detection_name=detection.name,
                detection_description=detection.description,
                has_mitre_mappings=has_mitre_mappings,
                source_identifier=source_identifier,
            )
            detection.security_function = security_function

        await self.db.flush()

    async def _fail_scan(self, scan: Scan, error: str) -> None:
        """Mark scan as failed."""
        scan.status = ScanStatus.FAILED
        scan.completed_at = datetime.now(timezone.utc)
        scan.errors = [{"message": error}]
        await self.db.commit()
