"""Scheduler service for automated scans using APScheduler."""

from datetime import datetime, timezone
from typing import Any, Optional
from uuid import UUID

import structlog
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.jobstores.memory import MemoryJobStore
from sqlalchemy import select
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker

from app.core.config import get_settings
from app.models.schedule import ScanSchedule
from app.models.scan import Scan, ScanStatus
from app.models.cloud_account import CloudAccount
from app.services.scan_service import ScanService
from app.services.scan_limit_service import ScanLimitService
from app.services.evaluation_history_service import calculate_daily_summary
from app.scripts.telemetry_bridge import fetch_metrics, parse_metrics, push_to_sheets

logger = structlog.get_logger()
settings = get_settings()


class SchedulerService:
    """Manages scheduled scans using APScheduler."""

    _instance: Optional["SchedulerService"] = None
    _scheduler: Optional[AsyncIOScheduler] = None

    # Job IDs
    MITRE_SYNC_JOB_ID = "mitre_sync_scheduled"
    DAILY_SUMMARY_JOB_ID = "evaluation_daily_summary"
    TELEMETRY_JOB_ID = "telemetry_push"

    def __new__(cls) -> "SchedulerService":
        """Singleton pattern for scheduler service."""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self) -> None:
        if self._initialized:
            return

        self.logger = logger.bind(service="SchedulerService")
        self._scheduler = AsyncIOScheduler(
            jobstores={"default": MemoryJobStore()},
            job_defaults={
                "coalesce": True,
                "max_instances": 1,
                "misfire_grace_time": 60 * 60,  # 1 hour grace period
            },
        )
        self._engine = create_async_engine(settings.database_url)
        self._session_factory = async_sessionmaker(self._engine, expire_on_commit=False)
        self._initialized = True

    @property
    def scheduler(self) -> AsyncIOScheduler:
        """Get the scheduler instance."""
        return self._scheduler

    async def start(self) -> None:
        """Start the scheduler and load all active schedules."""
        self.logger.info("starting_scheduler")

        # Load all active schedules from database
        await self._load_schedules()

        # Load MITRE sync schedule from platform settings
        await self._load_mitre_schedule()

        # Load daily compliance summary calculation job
        await self._load_daily_summary_schedule()

        # Load telemetry push job
        await self._load_telemetry_schedule()

        # Start the scheduler FIRST, then update next_run_times
        self._scheduler.start()
        self.logger.info("scheduler_started")

        # Now update next_run_at for all schedules (scheduler must be running)
        await self._update_schedule_next_run_times()

    async def stop(self) -> None:
        """Stop the scheduler."""
        self.logger.info("stopping_scheduler")
        self._scheduler.shutdown(wait=True)
        self.logger.info("scheduler_stopped")

    async def _load_schedules(self) -> None:
        """Load all active schedules from the database."""
        async with self._session_factory() as session:
            result = await session.execute(
                select(ScanSchedule).where(ScanSchedule.is_active.is_(True))
            )
            schedules = result.scalars().all()

            for schedule in schedules:
                await self._add_schedule_job(schedule, update_next_run=False)

            self.logger.info(
                "schedules_loaded",
                count=len(schedules),
            )

    async def _update_schedule_next_run_times(self) -> None:
        """Update next_run_at for all loaded schedules after scheduler starts."""
        async with self._session_factory() as session:
            result = await session.execute(
                select(ScanSchedule).where(ScanSchedule.is_active.is_(True))
            )
            schedules = result.scalars().all()

            for schedule in schedules:
                job = self._scheduler.get_job(f"scan_schedule_{schedule.id}")
                if job:
                    schedule.next_run_at = self._get_job_next_run_time(job)

            await session.commit()

    def _get_job_next_run_time(self, job: Any) -> Optional[datetime]:
        """Safely get next run time from a job.

        APScheduler 3.x jobs may not have next_run_time computed
        until the scheduler is running.
        """
        if job is None:
            return None
        # Use getattr for safe access - attribute may not exist before scheduler starts
        return getattr(job, "next_run_time", None)

    async def _add_schedule_job(
        self, schedule: ScanSchedule, update_next_run: bool = True
    ) -> None:
        """Add a schedule job to APScheduler.

        Args:
            schedule: The schedule to add
            update_next_run: Whether to update schedule.next_run_at
                            (only works if scheduler is running)
        """
        job_id = f"scan_schedule_{schedule.id}"

        # Remove existing job if present
        if self._scheduler.get_job(job_id):
            self._scheduler.remove_job(job_id)

        # Create cron trigger
        trigger_args = schedule.get_cron_trigger_args()
        if not trigger_args:
            self.logger.warning(
                "invalid_schedule_config",
                schedule_id=str(schedule.id),
            )
            return

        trigger = CronTrigger(**trigger_args)

        # Add job
        self._scheduler.add_job(
            self._execute_scheduled_scan,
            trigger=trigger,
            id=job_id,
            args=[schedule.id],
            name=f"Scheduled scan: {schedule.name}",
        )

        # Update next_run_at if scheduler is running
        if update_next_run:
            job = self._scheduler.get_job(job_id)
            if job:
                schedule.next_run_at = self._get_job_next_run_time(job)

        self.logger.info(
            "schedule_job_added",
            schedule_id=str(schedule.id),
            name=schedule.name,
            trigger_args=trigger_args,
        )

    async def _execute_scheduled_scan(self, schedule_id: UUID) -> None:
        """Execute a scheduled scan."""
        self.logger.info("executing_scheduled_scan", schedule_id=str(schedule_id))

        async with self._session_factory() as session:
            # Get the schedule
            result = await session.execute(
                select(ScanSchedule).where(ScanSchedule.id == schedule_id)
            )
            schedule = result.scalar_one_or_none()

            if not schedule:
                self.logger.error("schedule_not_found", schedule_id=str(schedule_id))
                return

            if not schedule.is_active:
                self.logger.info(
                    "schedule_inactive",
                    schedule_id=str(schedule_id),
                )
                return

            # Get the cloud account to find organization_id
            account_result = await session.execute(
                select(CloudAccount).where(CloudAccount.id == schedule.cloud_account_id)
            )
            account = account_result.scalar_one_or_none()

            if not account:
                self.logger.error(
                    "scheduled_scan_account_not_found",
                    schedule_id=str(schedule_id),
                    cloud_account_id=str(schedule.cloud_account_id),
                )
                return

            # Check scan limits (respects disable_scan_limits setting)
            scan_limit_service = ScanLimitService(session)
            can_scan, reason, next_available = (
                await scan_limit_service.can_scan_and_record(account.organization_id)
            )

            if not can_scan:
                self.logger.warning(
                    "scheduled_scan_limit_reached",
                    schedule_id=str(schedule_id),
                    organization_id=str(account.organization_id),
                    reason=reason,
                    next_available=(
                        next_available.isoformat() if next_available else None
                    ),
                )
                # Update next_run_at but don't execute the scan
                job = self._scheduler.get_job(f"scan_schedule_{schedule_id}")
                if job:
                    schedule.next_run_at = self._get_job_next_run_time(job)
                await session.commit()
                return

            # Create a new scan
            scan = Scan(
                cloud_account_id=schedule.cloud_account_id,
                regions=schedule.regions,
                detection_types=schedule.detection_types,
                status=ScanStatus.PENDING,
            )
            session.add(scan)
            await session.flush()
            await session.refresh(scan)

            # Update schedule tracking
            schedule.last_run_at = datetime.now(timezone.utc)
            schedule.run_count += 1
            schedule.last_scan_id = scan.id

            # Calculate next run time
            job = self._scheduler.get_job(f"scan_schedule_{schedule_id}")
            if job:
                schedule.next_run_at = self._get_job_next_run_time(job)

            await session.commit()

            # Execute the scan
            scan_service = ScanService(session)
            try:
                await scan_service.execute_scan(scan.id)
                self.logger.info(
                    "scheduled_scan_complete",
                    schedule_id=str(schedule_id),
                    scan_id=str(scan.id),
                )
            except Exception as e:
                self.logger.exception(
                    "scheduled_scan_failed",
                    schedule_id=str(schedule_id),
                    scan_id=str(scan.id),
                    error=str(e),
                )

    async def add_schedule(self, schedule: ScanSchedule) -> None:
        """Add a new schedule to the scheduler."""
        await self._add_schedule_job(schedule)

        # Calculate and update next run time (already done in _add_schedule_job)
        job = self._scheduler.get_job(f"scan_schedule_{schedule.id}")
        if job:
            schedule.next_run_at = self._get_job_next_run_time(job)

    async def update_schedule(self, schedule: ScanSchedule) -> None:
        """Update an existing schedule."""
        if schedule.is_active:
            await self._add_schedule_job(schedule)
            job = self._scheduler.get_job(f"scan_schedule_{schedule.id}")
            if job:
                schedule.next_run_at = self._get_job_next_run_time(job)
        else:
            await self.remove_schedule(schedule.id)

    async def remove_schedule(self, schedule_id: UUID) -> None:
        """Remove a schedule from the scheduler."""
        job_id = f"scan_schedule_{schedule_id}"
        if self._scheduler.get_job(job_id):
            self._scheduler.remove_job(job_id)
            self.logger.info(
                "schedule_job_removed",
                schedule_id=str(schedule_id),
            )

    def get_job_status(self, schedule_id: UUID) -> Optional[dict]:
        """Get the status of a scheduled job."""
        job_id = f"scan_schedule_{schedule_id}"
        job = self._scheduler.get_job(job_id)
        if job:
            return {
                "job_id": job.id,
                "name": getattr(job, "name", None),
                "next_run_time": self._get_job_next_run_time(job),
                "pending": getattr(job, "pending", False),
            }
        return None

    # ============ MITRE Sync Scheduling ============

    MITRE_SYNC_JOB_ID = "mitre_sync_scheduled"

    async def _load_mitre_schedule(self) -> None:
        """Load MITRE sync schedule from platform settings."""
        from app.models.platform_settings import SettingKeys

        async with self._session_factory() as session:
            from app.services.platform_settings_service import PlatformSettingsService

            settings_service = PlatformSettingsService(session)

            enabled_str = await settings_service.get_setting_value(
                SettingKeys.MITRE_SYNC_ENABLED
            )
            cron_expression = await settings_service.get_setting_value(
                SettingKeys.MITRE_SYNC_CRON
            )

            enabled = enabled_str is not None and enabled_str.lower() in (
                "true",
                "1",
                "yes",
            )

            if enabled and cron_expression:
                await self.update_mitre_sync_schedule(cron_expression)
                self.logger.info(
                    "mitre_sync_schedule_loaded",
                    cron_expression=cron_expression,
                )

    async def _execute_mitre_sync(self) -> None:
        """Execute a scheduled MITRE sync."""
        self.logger.info("executing_scheduled_mitre_sync")

        async with self._session_factory() as session:
            from app.services.mitre_sync_service import MitreSyncService
            from app.models.mitre_threat import SyncTriggerType

            sync_service = MitreSyncService(session)

            try:
                await sync_service.sync_all(
                    admin_id=None,  # Scheduled sync, no admin
                    trigger_type=SyncTriggerType.SCHEDULED.value,
                )
                self.logger.info("scheduled_mitre_sync_complete")
            except Exception as e:
                self.logger.exception(
                    "scheduled_mitre_sync_failed",
                    error=str(e),
                )

    async def update_mitre_sync_schedule(
        self, cron_expression: str
    ) -> Optional[datetime]:
        """Update or create the MITRE sync schedule.

        Args:
            cron_expression: Cron expression (minute hour day month day_of_week)

        Returns:
            Next scheduled run time, or None if invalid
        """
        # Remove existing job if present
        if self._scheduler.get_job(self.MITRE_SYNC_JOB_ID):
            self._scheduler.remove_job(self.MITRE_SYNC_JOB_ID)

        # Parse cron expression
        parts = cron_expression.split()
        if len(parts) != 5:
            self.logger.error(
                "invalid_mitre_sync_cron",
                cron_expression=cron_expression,
            )
            return None

        trigger = CronTrigger(
            minute=parts[0],
            hour=parts[1],
            day=parts[2],
            month=parts[3],
            day_of_week=parts[4],
            timezone="UTC",
        )

        # Add job
        self._scheduler.add_job(
            self._execute_mitre_sync,
            trigger=trigger,
            id=self.MITRE_SYNC_JOB_ID,
            name="Scheduled MITRE ATT&CK Sync",
        )

        job = self._scheduler.get_job(self.MITRE_SYNC_JOB_ID)
        next_run = self._get_job_next_run_time(job)

        self.logger.info(
            "mitre_sync_schedule_updated",
            cron_expression=cron_expression,
            next_run=str(next_run) if next_run else None,
        )

        return next_run

    async def remove_mitre_sync_schedule(self) -> None:
        """Remove the MITRE sync schedule."""
        if self._scheduler.get_job(self.MITRE_SYNC_JOB_ID):
            self._scheduler.remove_job(self.MITRE_SYNC_JOB_ID)
            self.logger.info("mitre_sync_schedule_removed")

    def get_mitre_sync_job_status(self) -> Optional[dict]:
        """Get the status of the MITRE sync scheduled job."""
        job = self._scheduler.get_job(self.MITRE_SYNC_JOB_ID)
        if job:
            return {
                "job_id": job.id,
                "name": getattr(job, "name", None),
                "next_run_time": self._get_job_next_run_time(job),
                "pending": getattr(job, "pending", False),
            }
        return None

    # ============ Daily Compliance Summary Calculation ============

    DAILY_SUMMARY_JOB_ID = "evaluation_daily_summary"

    async def _load_daily_summary_schedule(self) -> None:
        """Load the daily summary calculation job.

        Runs daily at 02:00 UTC to calculate summaries for the previous day.
        """
        # Remove existing job if present
        if self._scheduler.get_job(self.DAILY_SUMMARY_JOB_ID):
            self._scheduler.remove_job(self.DAILY_SUMMARY_JOB_ID)

        # Run at 02:00 UTC daily (after midnight to ensure full day data)
        trigger = CronTrigger(
            hour=2,
            minute=0,
            timezone="UTC",
        )

        self._scheduler.add_job(
            self._execute_daily_summary_calculation,
            trigger=trigger,
            id=self.DAILY_SUMMARY_JOB_ID,
            name="Daily Compliance Summary Calculation",
        )

        job = self._scheduler.get_job(self.DAILY_SUMMARY_JOB_ID)
        next_run = self._get_job_next_run_time(job)

        self.logger.info(
            "daily_summary_schedule_loaded",
            next_run=str(next_run) if next_run else None,
        )

    async def _execute_daily_summary_calculation(self) -> None:
        """Execute daily summary calculation for all accounts.

        Calculates summaries for yesterday across all cloud accounts
        that have evaluation history data.
        """
        from datetime import date, timedelta
        from sqlalchemy import distinct

        self.logger.info("starting_daily_summary_calculation")

        summary_date = date.today() - timedelta(days=1)

        async with self._session_factory() as session:
            try:
                # Get all distinct cloud account IDs with evaluation history
                from app.models.detection_evaluation_history import (
                    DetectionEvaluationHistory,
                )

                result = await session.execute(
                    select(distinct(DetectionEvaluationHistory.cloud_account_id))
                )
                account_ids = [row[0] for row in result.all()]

                if not account_ids:
                    self.logger.info("no_accounts_with_evaluation_history")
                    return

                # Calculate summary for each account
                success_count = 0
                error_count = 0

                for account_id in account_ids:
                    try:
                        await calculate_daily_summary(session, account_id, summary_date)
                        success_count += 1
                    except Exception as e:
                        self.logger.warning(
                            "account_summary_calculation_failed",
                            cloud_account_id=str(account_id),
                            error=str(e),
                        )
                        error_count += 1

                await session.commit()

                self.logger.info(
                    "daily_summary_calculation_complete",
                    summary_date=summary_date.isoformat(),
                    accounts_processed=success_count,
                    accounts_failed=error_count,
                )

            except Exception as e:
                self.logger.exception(
                    "daily_summary_calculation_failed",
                    error=str(e),
                )

    def get_daily_summary_job_status(self) -> Optional[dict]:
        """Get the status of the daily summary scheduled job."""
        job = self._scheduler.get_job(self.DAILY_SUMMARY_JOB_ID)
        if job:
            return {
                "job_id": job.id,
                "name": getattr(job, "name", None),
                "next_run_time": self._get_job_next_run_time(job),
                "pending": getattr(job, "pending", False),
            }
        return None

    # ============ Telemetry Push (Dashboard) ============

    async def _load_telemetry_schedule(self) -> None:
        """Load the telemetry push job.

        Runs every 5 minutes to feed the Looker Studio dashboard.
        """
        # Safety Check: Only schedule if configured
        if not settings.telemetry_sheet_id:
            return

        # Remove existing job if present
        if self._scheduler.get_job(self.TELEMETRY_JOB_ID):
            self._scheduler.remove_job(self.TELEMETRY_JOB_ID)

        # Run every 5 minutes
        trigger = CronTrigger(minute="*/5", timezone="UTC")

        self._scheduler.add_job(
            self._execute_telemetry_push,
            trigger=trigger,
            id=self.TELEMETRY_JOB_ID,
            name="System Telemetry Push",
            replace_existing=True,
        )

        self.logger.info("telemetry_schedule_loaded", interval="5m")

    async def _execute_telemetry_push(self) -> None:
        """Fetch metrics and push to Google Sheets.

        Includes retry logic for auth failures - if the first attempt fails
        with an auth error, credentials are invalidated and a retry is attempted.
        """
        from googleapiclient.errors import HttpError
        from app.services.google_workspace_service import get_workspace_service

        max_retries = 1
        last_error = None

        for attempt in range(max_retries + 1):
            try:
                raw = await fetch_metrics()
                if raw:
                    data = parse_metrics(raw)
                    await push_to_sheets(data)
                    if attempt > 0:
                        self.logger.info(
                            "telemetry_push_recovered",
                            attempt=attempt + 1,
                        )
                return  # Success
            except HttpError as e:
                last_error = e
                if e.resp.status in (401, 403) and attempt < max_retries:
                    # Auth error - invalidate credentials and retry
                    self.logger.warning(
                        "telemetry_auth_error_retrying",
                        status=e.resp.status,
                        attempt=attempt + 1,
                    )
                    try:
                        ws = get_workspace_service()
                        ws.invalidate_credentials()
                    except Exception:
                        pass  # Best effort invalidation
                    continue
                # Non-auth error or final attempt - log and exit
                self.logger.error(
                    "telemetry_push_failed",
                    error=str(e),
                    status=getattr(e.resp, "status", None),
                    attempt=attempt + 1,
                )
                return
            except Exception as e:
                last_error = e
                self.logger.error(
                    "telemetry_push_failed",
                    error=str(e),
                    error_type=type(e).__name__,
                    attempt=attempt + 1,
                )
                return

        # Should not reach here, but log if we do
        if last_error:
            self.logger.error(
                "telemetry_push_exhausted_retries",
                error=str(last_error),
            )


# Singleton instance for import
scheduler_service = SchedulerService()
