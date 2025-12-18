"""Application configuration."""

from functools import lru_cache
from typing import Optional

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    # Application
    app_name: str = "Detection Coverage Validator"
    app_version: str = "0.1.0"
    debug: bool = False
    environment: str = "development"

    # Database
    database_url: str = "postgresql+asyncpg://postgres:postgres@localhost:5432/dcv"
    database_pool_size: int = 5
    database_max_overflow: int = 10

    # Redis
    redis_url: str = "redis://localhost:6379/0"

    # AWS
    aws_region: str = "eu-west-2"
    aws_access_key_id: Optional[str] = None
    aws_secret_access_key: Optional[str] = None

    # Security & Auth
    secret_key: str = "change-me-in-production"
    access_token_expire_minutes: int = 30
    refresh_token_expire_days: int = 7
    password_reset_expire_hours: int = 24
    email_verification_expire_hours: int = 48
    invite_expire_days: int = 7
    max_login_attempts: int = 5
    lockout_duration_minutes: int = 30

    # CORS
    cors_origins: str = "http://localhost:3000,http://localhost:3001"

    # AWS Cognito
    cognito_user_pool_id: Optional[str] = None
    cognito_client_id: Optional[str] = None
    cognito_domain: Optional[str] = None  # e.g., "dcv-dev-abc123"

    # OAuth (optional - for direct OAuth without Cognito)
    google_client_id: Optional[str] = None
    google_client_secret: Optional[str] = None

    # Stripe
    stripe_secret_key: Optional[str] = None
    stripe_publishable_key: Optional[str] = None
    stripe_webhook_secret: Optional[str] = None
    stripe_price_id_subscriber: Optional[str] = None
    stripe_price_id_additional_account: Optional[str] = None

    # Email (optional - for sending invites, password resets, etc.)
    smtp_host: Optional[str] = None
    smtp_port: int = 587
    smtp_username: Optional[str] = None
    smtp_password: Optional[str] = None
    smtp_from_email: str = "noreply@detectioncoverage.io"

    # Coverage Thresholds
    confidence_threshold_covered: float = 0.6
    confidence_threshold_partial: float = 0.4

    # Scanning
    scan_timeout_seconds: int = 900  # 15 minutes
    max_concurrent_scans: int = 5

    # MITRE ATT&CK
    mitre_attack_version: str = "14.1"

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


@lru_cache
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()
