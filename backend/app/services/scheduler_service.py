"""Scheduler service for automated scans using APScheduler."""

from datetime import datetime, timezone
from typing import Optional
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
from app.services.scan_service import ScanService

logger = structlog.get_logger()
settings = get_settings()


class SchedulerService:
    """Manages scheduled scans using APScheduler."""

    _instance: Optional["SchedulerService"] = None
    _scheduler: Optional[AsyncIOScheduler] = None

    def __new__(cls):
        """Singleton pattern for scheduler service."""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
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

    def _get_job_next_run_time(self, job) -> Optional[datetime]:
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


# Global scheduler instance
scheduler_service = SchedulerService()
