"""Scan orchestration service."""

import asyncio
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
from app.scanners.aws.cloudwatch_scanner import (
    CloudWatchLogsInsightsScanner,
    CloudWatchMetricAlarmScanner,
)
from app.scanners.aws.eventbridge_scanner import EventBridgeScanner
from app.scanners.aws.guardduty_scanner import GuardDutyScanner
from app.scanners.aws.inspector_scanner import InspectorScanner
from app.scanners.aws.macie_scanner import MacieScanner
from app.scanners.aws.config_scanner import ConfigRulesScanner
from app.scanners.aws.securityhub_scanner import SecurityHubScanner
from app.scanners.base import RawDetection, BaseScanner

# GCP scanners use BaseScanner interface with credentials passed to constructor
from app.scanners.gcp.cloud_logging_scanner import CloudLoggingScanner
from app.scanners.gcp.security_command_center_scanner import (
    SecurityCommandCenterScanner,
)
from app.scanners.gcp.eventarc_scanner import EventarcScanner
from app.mappers.pattern_mapper import PatternMapper
from app.services.coverage_service import CoverageService
from app.services.drift_detection_service import DriftDetectionService
from app.services.notification_service import trigger_scan_alerts
from app.services.evaluation_history_service import (
    record_batch_evaluation_snapshots,
    create_state_change_alert,
)
from app.services.aws_credential_service import aws_credential_service
from app.services.gcp_wif_service import gcp_wif_service, GCPWIFError, WIFConfiguration
from app.services.region_discovery_service import region_discovery_service
from app.core.service_registry import get_all_regions, get_default_regions
from app.core.cache import (
    cache_scan_status,
    delete_scan_status_cache,
    invalidate_billing_scan_status,
    should_force_full_scan,
    set_last_full_scan,
)
from app.core.database import get_db_session
from app.models.cloud_account import RegionScanMode

logger = structlog.get_logger()


async def execute_scan_background(scan_id: UUID, organization_id: UUID) -> None:
    """Execute a scan in a background task with its own database session.

    This is the entry point for background scan execution. It creates a fresh
    database session to avoid holding connections from the request handler.

    Args:
        scan_id: The scan ID to execute
        organization_id: The organisation ID (for cache invalidation)
    """
    async with get_db_session() as db:
        service = ScanService(db)
        try:
            await service.execute_scan(scan_id)
        finally:
            # Invalidate billing cache so next poll gets fresh data
            await invalidate_billing_scan_status(str(organization_id))


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
    if dev_mode_requested and environment in ("production", "prod", "staging"):
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
        # Set when account is fetched, used for cache ownership verification
        self._current_organization_id: Optional[UUID] = None

    async def _cache_scan_status(self, scan: Scan) -> None:
        """Cache scan status to Redis for fast polling.

        Called after each db.commit() to keep Redis in sync with database.
        Failures are logged but don't affect scan execution.

        Includes organization_id when available to enable ownership verification
        without database queries on cache hits.
        """
        try:
            scan_data = {
                "id": str(scan.id),
                "cloud_account_id": str(scan.cloud_account_id),
                "status": scan.status.value,
                "regions": scan.regions or [],
                "detection_types": scan.detection_types or [],
                "progress_percent": scan.progress_percent,
                "current_step": scan.current_step,
                "detections_found": scan.detections_found,
                "detections_new": scan.detections_new,
                "detections_updated": scan.detections_updated,
                "detections_removed": scan.detections_removed,
                "errors": scan.errors,
                "started_at": (
                    scan.started_at.isoformat() if scan.started_at else None
                ),
                "completed_at": (
                    scan.completed_at.isoformat() if scan.completed_at else None
                ),
                "created_at": (
                    scan.created_at.isoformat() if scan.created_at else None
                ),
            }
            # Include organization_id for ownership verification on cache hits
            if self._current_organization_id:
                scan_data["organization_id"] = str(self._current_organization_id)
            await cache_scan_status(scan_data)
        except Exception as e:
            # Log but don't fail scan - cache is optional optimisation
            self.logger.warning(
                "scan_status_cache_failed",
                scan_id=str(scan.id),
                error=str(e),
            )

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

        # Store organization_id for cache ownership verification
        self._current_organization_id = account.organization_id

        try:
            # Update to running
            scan.status = ScanStatus.RUNNING
            scan.started_at = datetime.now(timezone.utc)
            scan.current_step = "Initializing"
            await self.db.commit()
            await self._cache_scan_status(scan)

            # Route to provider-specific credential and scan logic
            is_gcp = account.provider == CloudProvider.GCP

            if is_gcp:
                # GCP: Use Workload Identity Federation
                gcp_credentials, wif_config = await self._get_gcp_credentials(account)

                # For GCP, use default regions if not specified
                region_config = await self._determine_gcp_scan_regions(scan, account)

                self.logger.info(
                    "gcp_scan_regions_determined",
                    scan_id=str(scan_id),
                    project_id=wif_config.project_id,
                    locations=region_config.regional_regions,
                )

                # Scan for detections
                scan.current_step = "Scanning GCP for detections"
                scan.progress_percent = 10
                await self.db.commit()
                await self._cache_scan_status(scan)

                # Determine if this should be a full scan
                force_full_scan = await should_force_full_scan(str(account.id))
                effective_last_scan_at = (
                    None if force_full_scan else account.last_scan_at
                )

                if force_full_scan:
                    self.logger.info(
                        "forcing_full_scan",
                        account_id=str(account.id),
                        reason="weekly_fallback",
                    )

                raw_detections, scanner_errors = await self._scan_gcp_detections(
                    gcp_credentials,
                    wif_config,
                    region_config,
                    scan.detection_types,
                    last_scan_at=effective_last_scan_at,
                )
            else:
                # AWS: Use IAM Role assumption
                session = await self._get_boto3_session(account)

                # Determine regions to scan using new multi-region logic
                # This may trigger auto-discovery if mode=AUTO and no regions cached
                region_config = await self._determine_scan_regions(
                    scan, account, session
                )

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
                await self._cache_scan_status(scan)

                # Determine if this should be a full scan or incremental scan
                # Full scan is forced weekly to ensure accurate compliance data
                force_full_scan = await should_force_full_scan(str(account.id))
                effective_last_scan_at = (
                    None if force_full_scan else account.last_scan_at
                )

                if force_full_scan:
                    self.logger.info(
                        "forcing_full_scan",
                        account_id=str(account.id),
                        reason="weekly_fallback",
                    )

                raw_detections, scanner_errors = await self._scan_detections(
                    session,
                    region_config,
                    scan.detection_types,
                    last_scan_at=effective_last_scan_at,
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
            await self._cache_scan_status(scan)

            stats = await self._process_detections(account.id, raw_detections)

            # Map to MITRE techniques
            scan.current_step = "Mapping to MITRE ATT&CK"
            scan.progress_percent = 80
            await self.db.commit()
            await self._cache_scan_status(scan)

            await self._map_detections(account.id)

            # Calculate coverage snapshot
            scan.current_step = "Calculating coverage"
            scan.progress_percent = 90
            await self.db.commit()
            await self._cache_scan_status(scan)

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

            # Record evaluation history for compliance tracking
            try:
                # Get all detections with evaluation data for this account
                detections_result = await self.db.execute(
                    select(Detection).where(
                        Detection.cloud_account_id == account.id,
                        Detection.evaluation_summary.isnot(None),
                    )
                )
                detections_with_eval = detections_result.scalars().all()

                if detections_with_eval:
                    history_records = await record_batch_evaluation_snapshots(
                        self.db, detections_with_eval, scan.id
                    )

                    # Create alerts for state changes
                    for record in history_records:
                        if record.state_changed:
                            detection = next(
                                (
                                    d
                                    for d in detections_with_eval
                                    if d.id == record.detection_id
                                ),
                                None,
                            )
                            if detection:
                                await create_state_change_alert(
                                    self.db,
                                    account.organization_id,
                                    record,
                                    detection,
                                )

                    self.logger.info(
                        "evaluation_history_recorded",
                        scan_id=str(scan_id),
                        records_created=len(history_records),
                        state_changes=sum(
                            1 for r in history_records if r.state_changed
                        ),
                    )
            except Exception as eval_history_error:
                self.logger.warning(
                    "evaluation_history_failed",
                    scan_id=str(scan_id),
                    error=str(eval_history_error),
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
            # Cache final status then clean up - TTL ensures eventual cleanup
            await self._cache_scan_status(scan)
            await delete_scan_status_cache(str(scan.id))

            # Record full scan timestamp if this was a full scan
            # This is used to determine when to force the next full scan
            if force_full_scan:
                await set_last_full_scan(
                    str(account.id),
                    datetime.now(timezone.utc).isoformat(),
                )

            self.logger.info(
                "scan_complete",
                scan_id=str(scan_id),
                found=stats["found"],
                new=stats["new"],
                updated=stats["updated"],
                removed=stats.get("removed", 0),
                full_scan=force_full_scan,
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

    async def _determine_gcp_scan_regions(
        self,
        scan: Scan,
        account: CloudAccount,
    ) -> RegionConfig:
        """Determine which GCP locations to scan.

        GCP scanning is generally project-scoped rather than region-scoped,
        but some services (like Eventarc) are regional.

        Args:
            scan: The scan request (may have region overrides)
            account: The cloud account with region configuration

        Returns:
            RegionConfig with locations to scan
        """
        # Scan-level override takes precedence
        if scan.regions:
            return RegionConfig(
                regional_regions=scan.regions,
                global_region="global",
            )

        # Get configured regions from account, or use GCP defaults
        provider = "gcp"
        default_regions = get_default_regions(provider)

        # Check account configuration
        if account.region_config:
            config_regions = account.region_config.get("regions", [])
            if config_regions:
                return RegionConfig(
                    regional_regions=config_regions,
                    global_region="global",
                )

        # Default: scan common GCP regions
        # Most GCP security services are global or multi-regional
        effective_regions = (
            default_regions
            if default_regions
            else [
                "us-central1",
                "us-east1",
                "europe-west1",
                "asia-east1",
            ]
        )

        return RegionConfig(
            regional_regions=effective_regions,
            global_region="global",
        )

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

    async def _get_gcp_credentials(
        self, account: CloudAccount
    ) -> tuple[Any, WIFConfiguration]:
        """Get GCP credentials for the account using Workload Identity Federation.

        This method:
        1. Looks up the CloudCredential for the account
        2. Validates it's a GCP WIF credential
        3. Uses the WIF service to obtain short-lived credentials

        Returns:
            Tuple of (credentials, wif_config)

        Raises:
            ValueError: If credentials are invalid or WIF fails
        """
        if DEV_MODE:
            self.logger.info(
                "dev_mode_gcp_session",
                account_id=str(account.id),
                msg="Using default GCP credentials in dev mode",
            )
            # In dev mode, use application default credentials
            from google.auth import default as gcp_default

            creds, project = gcp_default()
            # Create a mock WIF config for dev mode
            wif_config = WIFConfiguration(
                project_id=account.account_id,
                service_account_email=f"dev-scanner@{account.account_id}.iam.gserviceaccount.com",
            )
            return creds, wif_config

        # Get the credential for this account
        result = await self.db.execute(
            select(CloudCredential).where(
                CloudCredential.cloud_account_id == account.id
            )
        )
        credential = result.scalar_one_or_none()

        if not credential:
            raise ValueError(
                f"No credentials found for GCP account {account.account_id}"
            )

        if credential.status != CredentialStatus.VALID:
            raise ValueError(
                f"Credentials for GCP account {account.account_id} are not valid. "
                f"Status: {credential.status.value}. Please re-validate credentials."
            )

        if credential.credential_type != CredentialType.GCP_WORKLOAD_IDENTITY:
            raise ValueError(
                f"Unsupported GCP credential type: {credential.credential_type.value}. "
                f"Only Workload Identity Federation is supported for security reasons. "
                f"Service account keys are not accepted."
            )

        # Get WIF configuration from credential
        wif_config = credential.get_wif_configuration()
        if not wif_config:
            raise ValueError(
                f"Incomplete WIF configuration for GCP account {account.account_id}. "
                f"Missing project_id or service_account_email."
            )

        # Get credentials via WIF
        self.logger.info(
            "obtaining_gcp_wif_credentials",
            account_id=str(account.id),
            project_id=wif_config.project_id,
            service_account=wif_config.service_account_email,
        )

        try:
            result = await gcp_wif_service.get_credentials(wif_config)
            return result.credentials, wif_config
        except GCPWIFError as e:
            self.logger.error(
                "gcp_wif_failed",
                account_id=str(account.id),
                project_id=wif_config.project_id,
                error=str(e),
            )
            raise ValueError(
                f"Failed to obtain GCP credentials for account {account.account_id}: {str(e)}"
            )

    async def _scan_gcp_detections(
        self,
        credentials: Any,
        wif_config: WIFConfiguration,
        region_config: RegionConfig,
        detection_types: list[str],
        last_scan_at: Optional[datetime] = None,
    ) -> tuple[list[RawDetection], list[str]]:
        """Run all applicable GCP scanners in parallel.

        GCP scanners use the BaseScanner interface with:
        - session = GCP credentials
        - options["project_id"] = GCP project ID

        Args:
            credentials: GCP credentials obtained via WIF
            wif_config: WIF configuration with project details
            region_config: Configuration specifying locations to scan
            detection_types: List of detection types to scan for
            last_scan_at: Optional datetime of last successful scan

        Returns:
            Tuple of (detections, errors) where errors is a list of
            scanner failure messages to include in scan results.
        """
        scan_options: dict[str, Any] = {
            "project_id": wif_config.project_id,
        }
        if last_scan_at:
            scan_options["last_scan_at"] = last_scan_at

        # Build list of GCP scanners
        # GCP scanners use BaseScanner(session=credentials)
        scanners: list[BaseScanner] = []

        if not detection_types or "gcp_cloud_logging" in detection_types:
            scanners.append(CloudLoggingScanner(credentials))
        if not detection_types or "gcp_security_command_center" in detection_types:
            scanners.append(SecurityCommandCenterScanner(credentials))
        if not detection_types or "gcp_eventarc" in detection_types:
            scanners.append(EventarcScanner(credentials))

        async def run_gcp_scanner(
            scanner: BaseScanner,
        ) -> tuple[list[RawDetection], str | None]:
            """Run a GCP scanner."""
            try:
                # GCP services are mostly global, use "global" as region
                # Regional services like Eventarc will handle locations internally
                locations = region_config.regional_regions or ["global"]

                detections = await scanner.scan(locations, options=scan_options)

                self.logger.info(
                    "gcp_scanner_complete",
                    scanner=scanner.__class__.__name__,
                    count=len(detections),
                    locations_scanned=len(locations),
                )
                return detections, None
            except Exception as e:
                error_msg = f"{scanner.__class__.__name__}: {str(e)}"
                self.logger.error(
                    "gcp_scanner_error",
                    scanner=scanner.__class__.__name__,
                    error=str(e),
                )
                return [], error_msg

        self.logger.info(
            "starting_gcp_parallel_scan",
            scanner_count=len(scanners),
            scanners=[s.__class__.__name__ for s in scanners],
            project_id=wif_config.project_id,
        )

        results = await asyncio.gather(
            *[run_gcp_scanner(scanner) for scanner in scanners],
            return_exceptions=False,
        )

        all_detections: list[RawDetection] = []
        scan_errors: list[str] = []

        for detections, error in results:
            all_detections.extend(detections)
            if error:
                scan_errors.append(error)

        self.logger.info(
            "gcp_parallel_scan_complete",
            total_detections=len(all_detections),
            scanner_errors=len(scan_errors),
            project_id=wif_config.project_id,
        )

        return all_detections, scan_errors

    async def _scan_detections(
        self,
        session: boto3.Session,
        region_config: RegionConfig,
        detection_types: list[str],
        last_scan_at: Optional[datetime] = None,
    ) -> tuple[list[RawDetection], list[str]]:
        """Run all applicable scanners in parallel with proper global/regional handling.

        Scanners are executed concurrently using asyncio.gather for improved
        performance. Global services (like IAM) are scanned once from the
        global_region. Regional services (like GuardDuty) are scanned in each
        regional_region.

        Incremental Scanning:
        When last_scan_at is provided, scanners that support it will only fetch
        resources updated since that time. This significantly reduces API calls
        and data transfer for subsequent scans. Scanners without incremental
        support will do a full scan.

        Args:
            session: boto3 session with credentials
            region_config: Configuration specifying regional and global regions
            detection_types: List of detection types to scan for
            last_scan_at: Optional datetime of last successful scan for incremental scanning

        Returns:
            Tuple of (detections, errors) where errors is a list of
            scanner failure messages to include in scan results.
        """
        # Prepare scan options with incremental scanning support
        scan_options: dict[str, Any] = {}
        if last_scan_at:
            scan_options["last_scan_at"] = last_scan_at
            self.logger.info(
                "incremental_scan_enabled",
                last_scan_at=last_scan_at.isoformat(),
            )
        # Determine which scanners to use
        scanners: list[BaseScanner] = []
        if not detection_types or "cloudwatch_logs_insights" in detection_types:
            scanners.append(CloudWatchLogsInsightsScanner(session))
        if not detection_types or "cloudwatch_alarm" in detection_types:
            scanners.append(CloudWatchMetricAlarmScanner(session))
        if not detection_types or "eventbridge_rule" in detection_types:
            scanners.append(EventBridgeScanner(session))
        if not detection_types or "guardduty_finding" in detection_types:
            scanners.append(GuardDutyScanner(session))
        if not detection_types or "inspector_finding" in detection_types:
            scanners.append(InspectorScanner(session))
        if not detection_types or "macie_finding" in detection_types:
            scanners.append(MacieScanner(session))
        if not detection_types or "config_rule" in detection_types:
            scanners.append(ConfigRulesScanner(session))
        if not detection_types or "security_hub" in detection_types:
            scanners.append(SecurityHubScanner(session))

        async def run_scanner(
            scanner: BaseScanner,
        ) -> tuple[list[RawDetection], str | None]:
            """Run a single scanner and return results or error.

            Args:
                scanner: The scanner instance to run

            Returns:
                Tuple of (detections, error_message or None)
            """
            try:
                # Determine which regions to use for this scanner
                if scanner.is_global_service:
                    scan_regions = [scanner.global_scan_region]
                    self.logger.debug(
                        "scanning_global_service",
                        scanner=scanner.__class__.__name__,
                        region=scanner.global_scan_region,
                    )
                else:
                    scan_regions = region_config.regional_regions
                    self.logger.debug(
                        "scanning_regional_service",
                        scanner=scanner.__class__.__name__,
                        regions=scan_regions,
                    )

                detections = await scanner.scan(scan_regions, options=scan_options)
                self.logger.info(
                    "scanner_complete",
                    scanner=scanner.__class__.__name__,
                    count=len(detections),
                    regions_scanned=len(scan_regions),
                    incremental=bool(scan_options.get("last_scan_at")),
                )
                return detections, None
            except Exception as e:
                error_msg = f"{scanner.__class__.__name__}: {str(e)}"
                self.logger.error(
                    "scanner_error",
                    scanner=scanner.__class__.__name__,
                    error=str(e),
                )
                return [], error_msg

        # Run all scanners in parallel using asyncio.gather
        self.logger.info(
            "starting_parallel_scan",
            scanner_count=len(scanners),
            scanners=[s.__class__.__name__ for s in scanners],
        )

        results = await asyncio.gather(
            *[run_scanner(scanner) for scanner in scanners],
            return_exceptions=False,  # Exceptions handled in run_scanner
        )

        # Aggregate results
        all_detections: list[RawDetection] = []
        scan_errors: list[str] = []

        for detections, error in results:
            all_detections.extend(detections)
            if error:
                scan_errors.append(error)

        self.logger.info(
            "parallel_scan_complete",
            total_detections=len(all_detections),
            scanner_errors=len(scan_errors),
        )

        return all_detections, scan_errors

    async def _process_detections(
        self,
        cloud_account_id: UUID,
        raw_detections: list[RawDetection],
    ) -> dict[str, int]:
        """Process raw detections into database records.

        Also marks detections as REMOVED if they're no longer found in the
        cloud account (e.g., deleted alarms, rules, etc.).
        """
        stats = {"found": len(raw_detections), "new": 0, "updated": 0, "removed": 0}

        # Clean up any duplicate detections first (keep oldest by id)
        await self._cleanup_duplicate_detections(cloud_account_id)

        # Track which ARNs are found in this scan (used later for removal detection)
        found_arns = set(raw.source_arn for raw in raw_detections)

        for idx, raw in enumerate(raw_detections):
            # Yield control every 20 detections to prevent event loop blocking
            # This allows HTTP requests to be processed during long scans
            if idx > 0 and idx % 20 == 0:
                await asyncio.sleep(0)

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
                detection.status = self._determine_detection_status(raw)
                detection.updated_at = datetime.now(timezone.utc)
                # Update evaluation summary if provided
                if raw.evaluation_summary:
                    detection.evaluation_summary = raw.evaluation_summary
                    detection.evaluation_updated_at = datetime.now(timezone.utc)
                stats["updated"] += 1
            else:
                # Create new
                # Serialize JSONB fields to handle datetime from AWS SDK
                detection = Detection(
                    cloud_account_id=cloud_account_id,
                    name=raw.name,
                    detection_type=raw.detection_type,
                    status=self._determine_detection_status(raw),
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
                    evaluation_summary=raw.evaluation_summary,
                    evaluation_updated_at=(
                        datetime.now(timezone.utc) if raw.evaluation_summary else None
                    ),
                )
                self.db.add(detection)
                stats["new"] += 1

        # Mark detections no longer found as REMOVED
        # Safety: Only mark as removed for detection types that were actually scanned
        # This prevents marking everything as removed if a scanner fails
        scanned_types = set(raw.detection_type for raw in raw_detections)

        if scanned_types:
            # Get existing detections that are candidates for removal
            # (only for detection types we actually scanned)
            removal_candidates_result = await self.db.execute(
                select(
                    Detection.id, Detection.source_arn, Detection.detection_type
                ).where(
                    Detection.cloud_account_id == cloud_account_id,
                    Detection.status != DetectionStatus.REMOVED,
                    Detection.detection_type.in_(scanned_types),
                )
            )
            removal_candidates = {
                row.source_arn: row.id for row in removal_candidates_result.fetchall()
            }

            # Find ARNs that exist but weren't found in this scan
            missing_arns = set(removal_candidates.keys()) - found_arns

            if missing_arns:
                # Safety: Don't remove more than 50% of detections in one scan
                # This prevents catastrophic removal if something goes wrong
                removal_ratio = (
                    len(missing_arns) / len(removal_candidates)
                    if removal_candidates
                    else 0
                )
                if removal_ratio > 0.5 and len(missing_arns) > 5:
                    self.logger.warning(
                        "skipping_mass_removal",
                        cloud_account_id=str(cloud_account_id),
                        would_remove=len(missing_arns),
                        total=len(removal_candidates),
                        ratio=removal_ratio,
                        reason="Would remove >50% of detections - possible scanner issue",
                    )
                else:
                    missing_ids = [removal_candidates[arn] for arn in missing_arns]
                    await self.db.execute(
                        Detection.__table__.update()
                        .where(Detection.id.in_(missing_ids))
                        .values(
                            status=DetectionStatus.REMOVED,
                            updated_at=datetime.now(timezone.utc),
                        )
                    )
                    stats["removed"] = len(missing_arns)
                    self.logger.info(
                        "marked_detections_removed",
                        cloud_account_id=str(cloud_account_id),
                        count=len(missing_arns),
                    )

        await self.db.flush()
        return stats

    def _determine_detection_status(self, raw: RawDetection) -> DetectionStatus:
        """Determine detection status based on raw config and evaluation data.

        For Config Rules: Check rule_state (ACTIVE, DELETING, etc.)
        For EventBridge Rules: Check state (ENABLED, DISABLED)
        For CloudWatch Alarms: Always ACTIVE if exists
        """
        from app.models.detection import DetectionType

        # For Config Rules, check if rule is in an active state
        if raw.detection_type == DetectionType.CONFIG_RULE:
            rule_state = raw.raw_config.get("rule_state", "ACTIVE")
            if rule_state not in ("ACTIVE", "EVALUATING"):
                return DetectionStatus.DISABLED

        # For EventBridge Rules, check state
        if raw.detection_type == DetectionType.EVENTBRIDGE_RULE:
            state = raw.raw_config.get("State", "ENABLED")
            if state != "ENABLED":
                return DetectionStatus.DISABLED

        return DetectionStatus.ACTIVE

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

        for idx, detection in enumerate(detections):
            # Yield control every 10 detections during CPU-intensive mapping
            # Pattern matching is the most CPU-heavy operation in the scan
            if idx > 0 and idx % 10 == 0:
                await asyncio.sleep(0)

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
        # Cache final status then clean up
        await self._cache_scan_status(scan)
        await delete_scan_status_cache(str(scan.id))
