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
    # CRITICAL: Must be set to a cryptographically random value
    # Generate with: python -c "import secrets; print(secrets.token_urlsafe(32))"
    # No default value - must be explicitly set via SECRET_KEY environment variable
    secret_key: str

    # Session binding: Optionally validate IP and User-Agent on session refresh
    # Set to True for higher security (may cause issues for mobile users on changing networks)
    session_bind_ip: bool = False
    session_bind_user_agent: bool = False

    # HaveIBeenPwned password checking
    # When enabled, passwords are checked against the HIBP database during signup/password change
    # Uses k-anonymity API - only first 5 chars of hash sent, privacy-preserving
    hibp_password_check_enabled: bool = True
    hibp_min_breach_count: int = 1  # Minimum breach count to reject password
    # Fail-closed mode: if True, reject password when HIBP API is unavailable (recommended for prod)
    # If False, allow password when API fails (fail-open, less secure but more available)
    hibp_fail_closed: bool = False  # Set to True in production for maximum security

    @staticmethod
    def _calculate_entropy(s: str) -> float:
        """Calculate Shannon entropy of a string (bits per character)."""
        import math
        from collections import Counter

        if not s:
            return 0.0

        length = len(s)
        freq = Counter(s)
        entropy = 0.0

        for count in freq.values():
            probability = count / length
            entropy -= probability * math.log2(probability)

        return entropy

    def model_post_init(self, __context) -> None:
        """Validate critical security settings after initialization."""
        # Validate SECRET_KEY length in all environments
        if len(self.secret_key) < 32:
            raise ValueError(
                "CRITICAL: SECRET_KEY must be at least 32 characters long for security. "
                'Generate with: python -c "import secrets; print(secrets.token_urlsafe(32))"'
            )

        # Validate SECRET_KEY entropy (prevent weak keys like 'aaaa....')
        entropy = self._calculate_entropy(self.secret_key)
        if entropy < 3.0:  # Minimum ~3 bits per character for reasonable randomness
            raise ValueError(
                f"CRITICAL: SECRET_KEY has insufficient entropy ({entropy:.2f} bits/char). "
                "The key appears to be non-random (e.g., repeated characters). "
                'Generate with: python -c "import secrets; print(secrets.token_urlsafe(32))"'
            )

        # Validate CREDENTIAL_ENCRYPTION_KEY if set
        if self.credential_encryption_key:
            try:
                from cryptography.fernet import Fernet

                Fernet(self.credential_encryption_key.encode())
            except Exception as e:
                raise ValueError(
                    f"CRITICAL: CREDENTIAL_ENCRYPTION_KEY is invalid: {e}. "
                    'Generate with: python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"'
                )
        elif self.environment == "production":
            # Fail in production - cloud credential storage is a core feature
            raise ValueError(
                "CRITICAL: CREDENTIAL_ENCRYPTION_KEY is required in production. "
                "Cloud credential storage will not work without it. "
                'Generate with: python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"'
            )
        elif self.environment not in ("development", "test"):
            # Warn in staging - should be configured but not fatal
            import logging

            logging.warning(
                "CREDENTIAL_ENCRYPTION_KEY not set - cloud credential storage will be disabled. "
                "This should be configured before production deployment."
            )

        # Validate DATABASE_URL doesn't use default credentials in production/staging
        if self.environment in ("production", "staging"):
            if "postgres:postgres" in self.database_url:
                raise ValueError(
                    "CRITICAL: Default database credentials detected in production/staging. "
                    "Set DATABASE_URL with secure credentials."
                )

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

    # OAuth Providers (used by Cognito identity providers)
    google_client_id: Optional[str] = None
    google_client_secret: Optional[str] = None
    github_client_id: Optional[str] = None
    github_client_secret: Optional[str] = None
    microsoft_client_id: Optional[str] = None
    microsoft_client_secret: Optional[str] = None

    # Stripe
    stripe_secret_key: Optional[str] = None
    stripe_publishable_key: Optional[str] = None
    stripe_webhook_secret: Optional[str] = None
    stripe_price_id_subscriber: Optional[str] = None
    stripe_price_id_enterprise: Optional[str] = None
    stripe_price_id_additional_account: Optional[str] = None

    # Cloud Credentials Encryption
    # Generate with: python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
    credential_encryption_key: Optional[str] = None

    # A13E Cloud Infrastructure (for cross-account access)
    a13e_aws_account_id: str = "123080274263"  # A13E's AWS account for AssumeRole trust

    # Email (optional - for sending invites, password resets, etc.)
    smtp_host: Optional[str] = None
    smtp_port: int = 587
    smtp_username: Optional[str] = None
    smtp_password: Optional[str] = None
    smtp_from_email: str = "noreply@a13e.com"  # Single source of truth for email sender

    # Coverage Thresholds
    confidence_threshold_covered: float = 0.6
    confidence_threshold_partial: float = 0.4

    # Scanning
    scan_timeout_seconds: int = 900  # 15 minutes
    max_concurrent_scans: int = 5
    disable_scan_limits: bool = (
        False  # Set to True in staging/dev to bypass scan limits
    )

    # MITRE ATT&CK
    mitre_attack_version: str = "14.1"

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


@lru_cache
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()
