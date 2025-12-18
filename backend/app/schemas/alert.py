"""Pydantic schemas for alerts and notifications."""

from datetime import datetime
from typing import Optional
from uuid import UUID

from pydantic import BaseModel, Field

from app.models.alert import AlertType, AlertSeverity, NotificationChannel


class ChannelConfig(BaseModel):
    """Configuration for a notification channel."""

    type: NotificationChannel
    url: Optional[str] = None  # For webhook
    webhook_url: Optional[str] = None  # For Slack
    email: Optional[str] = None  # For email
    headers: Optional[dict] = None  # Custom headers for webhook


class AlertConfigBase(BaseModel):
    """Base schema for alert configuration."""

    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = Field(None, max_length=500)
    alert_type: AlertType
    severity: AlertSeverity = AlertSeverity.WARNING
    threshold_value: Optional[float] = None
    threshold_operator: Optional[str] = Field(
        None, pattern="^(lt|gt|eq|lte|gte)$"
    )
    channels: list[ChannelConfig] = Field(default_factory=list)
    cooldown_minutes: int = Field(60, ge=1, le=1440)


class AlertConfigCreate(AlertConfigBase):
    """Schema for creating an alert configuration."""

    cloud_account_id: Optional[UUID] = None  # NULL for global alerts


class AlertConfigUpdate(BaseModel):
    """Schema for updating an alert configuration."""

    name: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = Field(None, max_length=500)
    severity: Optional[AlertSeverity] = None
    threshold_value: Optional[float] = None
    threshold_operator: Optional[str] = Field(None, pattern="^(lt|gt|eq|lte|gte)$")
    channels: Optional[list[ChannelConfig]] = None
    cooldown_minutes: Optional[int] = Field(None, ge=1, le=1440)
    is_active: Optional[bool] = None


class AlertConfigResponse(BaseModel):
    """Schema for alert configuration response."""

    id: UUID
    cloud_account_id: Optional[UUID]
    name: str
    description: Optional[str]
    alert_type: AlertType
    severity: AlertSeverity
    threshold_value: Optional[float]
    threshold_operator: Optional[str]
    channels: list[dict]
    cooldown_minutes: int
    last_triggered_at: Optional[datetime]
    is_active: bool
    trigger_count: int
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class AlertConfigListResponse(BaseModel):
    """Schema for list of alert configurations."""

    items: list[AlertConfigResponse]
    total: int
    page: int
    page_size: int


class AlertHistoryResponse(BaseModel):
    """Schema for alert history response."""

    id: UUID
    alert_config_id: UUID
    cloud_account_id: Optional[UUID]
    severity: AlertSeverity
    title: str
    message: str
    details: Optional[dict]
    channels_notified: list[str]
    notification_errors: Optional[list[dict]]
    is_resolved: bool
    resolved_at: Optional[datetime]
    triggered_at: datetime

    class Config:
        from_attributes = True


class AlertHistoryListResponse(BaseModel):
    """Schema for list of alert history."""

    items: list[AlertHistoryResponse]
    total: int
    page: int
    page_size: int


class TestAlertRequest(BaseModel):
    """Schema for testing an alert."""

    channel_index: int = Field(
        0, ge=0, description="Index of the channel to test"
    )
