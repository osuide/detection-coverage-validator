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
    aws_region: str = "us-east-1"
    aws_access_key_id: Optional[str] = None
    aws_secret_access_key: Optional[str] = None

    # Security
    secret_key: str = "change-me-in-production"
    access_token_expire_minutes: int = 30

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
