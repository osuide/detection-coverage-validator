"""Pydantic schemas for MITRE admin endpoints."""

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field


class MitreStatusResponse(BaseModel):
    """MITRE data sync status response."""

    is_synced: bool = Field(description="Whether any MITRE data has been synced")
    mitre_version: Optional[str] = Field(
        None, description="Current MITRE ATT&CK version"
    )
    stix_version: Optional[str] = Field(None, description="STIX format version")
    last_sync_at: Optional[datetime] = Field(
        None, description="When last sync occurred"
    )
    last_sync_status: Optional[str] = Field(None, description="Status of last sync")
    total_groups: int = Field(0, description="Number of threat groups")
    total_campaigns: int = Field(0, description="Number of campaigns")
    total_software: int = Field(0, description="Number of software/malware")
    total_relationships: int = Field(0, description="Number of technique relationships")
    next_scheduled_sync: Optional[datetime] = Field(
        None, description="Next scheduled sync time"
    )
    schedule_enabled: bool = Field(
        False, description="Whether scheduled sync is enabled"
    )


class MitreSyncResponse(BaseModel):
    """Response when triggering a sync."""

    sync_id: str = Field(description="Unique ID of the sync operation")
    status: str = Field(description="Current status (started, queued)")
    message: str = Field(description="Human-readable message")
    estimated_duration_seconds: int = Field(
        60, description="Estimated sync duration in seconds"
    )


class MitreSyncHistoryResponse(BaseModel):
    """Sync history entry response."""

    id: str
    started_at: datetime
    completed_at: Optional[datetime]
    status: str
    mitre_version: Optional[str]
    stix_version: Optional[str]
    trigger_type: str
    triggered_by_email: Optional[str] = None
    stats: dict = Field(default_factory=dict)
    error_message: Optional[str] = None
    duration_seconds: Optional[int] = None


class MitreScheduleResponse(BaseModel):
    """Sync schedule configuration response."""

    enabled: bool = Field(description="Whether scheduled sync is enabled")
    cron_expression: Optional[str] = Field(
        None, description="Cron expression for schedule"
    )
    next_run_at: Optional[datetime] = Field(None, description="Next scheduled run time")
    timezone: str = Field("UTC", description="Timezone for schedule")


class UpdateScheduleRequest(BaseModel):
    """Request to update sync schedule."""

    enabled: bool = Field(description="Enable or disable scheduled sync")
    cron_expression: Optional[str] = Field(
        None,
        description="Cron expression (required if enabled)",
        examples=["0 0 * * 0"],  # Weekly on Sundays at midnight
    )


class ThreatGroupSummary(BaseModel):
    """Summary of a threat group for listing."""

    id: str
    external_id: str = Field(description="MITRE ID (e.g., G0007)")
    name: str
    aliases: list[str] = Field(default_factory=list)
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    techniques_count: int = Field(0, description="Number of techniques used")
    mitre_url: str


class CampaignSummary(BaseModel):
    """Summary of a campaign for listing."""

    id: str
    external_id: str = Field(description="MITRE ID (e.g., C0001)")
    name: str
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    techniques_count: int = Field(0, description="Number of techniques used")
    mitre_url: str


class SoftwareSummary(BaseModel):
    """Summary of software for listing."""

    id: str
    external_id: str = Field(description="MITRE ID (e.g., S0001)")
    name: str
    software_type: str = Field(description="malware or tool")
    platforms: list[str] = Field(default_factory=list)
    techniques_count: int = Field(0, description="Number of techniques implemented")
    mitre_url: str


class MitreStatisticsResponse(BaseModel):
    """MITRE data statistics response."""

    is_synced: bool
    mitre_version: Optional[str] = None
    stix_version: Optional[str] = None
    last_sync_at: Optional[datetime] = None
    total_groups: int = 0
    total_campaigns: int = 0
    total_software: int = 0
    total_relationships: int = 0
    groups_by_activity: dict = Field(
        default_factory=dict, description="Groups categorised by activity period"
    )
    software_by_type: dict = Field(
        default_factory=dict, description="Software counts by type"
    )


class PaginatedResponse(BaseModel):
    """Generic paginated response."""

    items: list
    total: int
    skip: int
    limit: int
    has_more: bool
