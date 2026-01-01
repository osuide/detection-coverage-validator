"""Application configuration."""

from functools import lru_cache
from typing import Any, Optional

from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    # Application
    app_name: str = "Detection Coverage Validator"
    app_version: str = "0.1.0"
    debug: bool = False
    environment: str = "development"

    # Database
    database_url: str = "postgresql+asyncpg://postgres:postgres@localhost:5432/dcv"
    database_pool_size: int = 20  # Increased from 5 for better concurrency
    database_max_overflow: int = 30  # Increased from 10 for burst handling
    database_pool_pre_ping: bool = True  # Validate connections before use
    database_pool_recycle: int = 3600  # Recycle connections every hour (seconds)
    database_pool_timeout: int = 30  # Fail fast if pool exhausted (seconds)

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
    # M16: Using SecretStr to prevent accidental exposure in logs/repr
    secret_key: SecretStr

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
    # Security: Enabled by default for production safety - override with HIBP_FAIL_CLOSED=false if needed
    hibp_fail_closed: bool = True

    # Fraud Prevention
    # Controls email quality validation (disposable email blocking, MX record check)
    # Note: Cloud account uniqueness and email binding checks are always enabled
    # Note: IP blocking is handled by AWS WAF at the edge, not application code
    fraud_prevention_enabled: bool = True

    # WebAuthn/FIDO2 (Passkeys, YubiKey, Touch ID, Windows Hello)
    # RP ID must match the domain name (e.g., 'a13e.com' or 'staging.a13e.com')
    # For local development, use 'localhost'
    webauthn_rp_id: str = "localhost"
    webauthn_rp_name: str = "A13E Detection Coverage Validator"

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

    def model_post_init(self, __context: Any) -> None:
        """Validate critical security settings after initialization."""
        # M16: Get secret value for validation
        secret_key_value = self.secret_key.get_secret_value()

        # Validate SECRET_KEY length in all environments
        if len(secret_key_value) < 32:
            raise ValueError(
                "CRITICAL: SECRET_KEY must be at least 32 characters long for security. "
                'Generate with: python -c "import secrets; print(secrets.token_urlsafe(32))"'
            )

        # Validate SECRET_KEY entropy (prevent weak keys like 'aaaa....')
        entropy = self._calculate_entropy(secret_key_value)
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

                Fernet(self.credential_encryption_key.get_secret_value().encode())
            except Exception as e:
                raise ValueError(
                    f"CRITICAL: CREDENTIAL_ENCRYPTION_KEY is invalid: {e}. "
                    'Generate with: python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"'
                )
        elif self.environment in ("production", "prod"):
            # Fail in production - cloud credential storage is a core feature
            raise ValueError(
                "CRITICAL: CREDENTIAL_ENCRYPTION_KEY is required in production. "
                "Cloud credential storage will not work without it. "
                'Generate with: python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"'
            )
        elif self.environment not in ("development", "dev", "test"):
            # Warn in staging - should be configured but not fatal
            import logging

            logging.warning(
                "CREDENTIAL_ENCRYPTION_KEY not set - cloud credential storage will be disabled. "
                "This should be configured before production deployment."
            )

        # Validate DATABASE_URL doesn't use default credentials in production/staging
        if self.environment in ("production", "prod", "staging"):
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

    # Trusted Proxy Configuration
    # Security: Controls whether to trust X-Forwarded-For and Forwarded headers
    # Only enable when behind a trusted reverse proxy (ALB, CloudFront, nginx, etc.)
    trust_proxy_headers: bool = False  # Default: safe - don't trust forwarded headers

    # CIDR ranges of trusted proxies (comma-separated)
    # When trust_proxy_headers is True, X-Forwarded-For is only trusted if the
    # immediate peer (request.client.host) matches one of these CIDRs
    # Examples: "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16" for private networks
    # AWS ALB/CloudFront IPs can be obtained from https://ip-ranges.amazonaws.com/ip-ranges.json
    trusted_proxy_cidrs: str = ""

    # CORS
    cors_origins: str = "http://localhost:3000,http://localhost:3001"

    # Cookie domain for cross-subdomain auth (e.g., ".a13e.com")
    # Required when frontend and API are on different subdomains
    # Leave empty for same-origin setups (localhost development)
    cookie_domain: Optional[str] = None

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
    credential_encryption_key: Optional[SecretStr] = (
        None  # SecretStr prevents accidental exposure
    )

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

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")


@lru_cache
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()
