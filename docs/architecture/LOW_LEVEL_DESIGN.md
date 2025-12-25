# A13E Detection Coverage Validator - Low-Level Design Document

**Document Version:** 1.1
**Last Updated:** 25 December 2025
**Classification:** Internal
**Author:** Architecture Team

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Backend Implementation](#2-backend-implementation)
3. [Database Schema](#3-database-schema)
4. [API Specifications](#4-api-specifications)
5. [Scanner Implementation](#5-scanner-implementation)
6. [Mapping Engine](#6-mapping-engine)
7. [Frontend Implementation](#7-frontend-implementation)
8. [Infrastructure Specifications](#8-infrastructure-specifications)
9. [Security Implementation](#9-security-implementation)
10. [Error Handling](#10-error-handling)

---

## 1. Introduction

### 1.1 Purpose

This Low-Level Design (LLD) document provides detailed implementation specifications for the A13E Detection Coverage Validator. It complements the High-Level Design (HLD) by describing specific code structures, database schemas, API contracts, and implementation patterns.

### 1.2 Scope

This document covers:
- Database table definitions and relationships
- API endpoint specifications with request/response schemas
- Scanner implementation details
- Mapping algorithm specifications
- Frontend component architecture
- Infrastructure configuration details
- Security implementation patterns

### 1.3 Directory Structure

```
a13e/
├── backend/
│   ├── app/
│   │   ├── api/
│   │   │   ├── routes/           # API endpoint handlers
│   │   │   │   ├── admin/        # Admin portal routes
│   │   │   │   └── ...
│   │   │   └── deps/             # Dependencies (auth, rate limit)
│   │   ├── core/                 # Core utilities
│   │   │   ├── config.py         # Configuration management
│   │   │   ├── database.py       # Database connection
│   │   │   └── security.py       # Auth/RBAC implementation
│   │   ├── models/               # SQLAlchemy ORM models
│   │   ├── schemas/              # Pydantic request/response schemas
│   │   ├── services/             # Business logic services
│   │   ├── scanners/             # Cloud scanner implementations
│   │   │   ├── aws/              # AWS-specific scanners
│   │   │   ├── gcp/              # GCP-specific scanners
│   │   │   └── base.py           # Base scanner abstract class
│   │   ├── mappers/              # Detection-to-technique mappers
│   │   ├── analyzers/            # Coverage/compliance calculators
│   │   └── data/
│   │       └── remediation_templates/  # IaC templates per technique
│   ├── alembic/
│   │   └── versions/             # Database migrations
│   ├── tests/                    # Test suites
│   └── requirements.txt
├── frontend/
│   ├── src/
│   │   ├── components/           # Reusable React components
│   │   ├── pages/                # Page-level components
│   │   ├── services/             # API client modules
│   │   ├── stores/               # Zustand state stores
│   │   ├── contexts/             # React contexts
│   │   ├── hooks/                # Custom React hooks
│   │   └── utils/                # Utility functions
│   ├── public/
│   └── package.json
├── infrastructure/
│   └── terraform/
│       ├── modules/              # Reusable Terraform modules
│       │   ├── vpc/
│       │   ├── database/
│       │   ├── cache/
│       │   ├── backend/
│       │   ├── frontend/
│       │   ├── cognito/
│       │   └── security/
│       ├── environments/         # Environment-specific configs
│       └── main.tf
└── docs/
    └── architecture/
```

---

## 2. Backend Implementation

### 2.1 Application Entry Point

**File:** `backend/app/main.py`

```python
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager

from app.api.routes import router as api_router
from app.core.config import settings
from app.core.middleware import (
    RequestIDMiddleware,
    SecureLoggingMiddleware,
    SecurityHeadersMiddleware,
)

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: initialise database, Redis, rate limiter
    await initialise_services()
    yield
    # Shutdown: cleanup connections
    await cleanup_services()

app = FastAPI(
    title="A13E Detection Coverage Validator",
    version="1.0.0",
    lifespan=lifespan,
)

# Middleware stack (order matters - first added = last executed)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(SecureLoggingMiddleware)
app.add_middleware(RequestIDMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(api_router, prefix="/api/v1")
```

### 2.2 Configuration Management

**File:** `backend/app/core/config.py`

```python
from pydantic_settings import BaseSettings
from typing import Optional, List
import secrets

class Settings(BaseSettings):
    # Application
    environment: str = "development"
    debug: bool = False

    # Security
    secret_key: str  # Must be >= 32 chars with sufficient entropy
    credential_encryption_key: str  # Fernet-compatible key

    # Database
    database_url: str
    database_pool_size: int = 10
    max_overflow: int = 20

    # Redis
    redis_url: str

    # AWS
    aws_region: str = "eu-west-2"
    aws_account_id: str = "123080274263"

    # Cognito
    cognito_user_pool_id: Optional[str] = None
    cognito_client_id: Optional[str] = None
    cognito_domain: Optional[str] = None

    # Stripe
    stripe_secret_key: Optional[str] = None
    stripe_webhook_secret: Optional[str] = None

    # Feature Flags
    fraud_prevention_enabled: bool = True
    hibp_password_check_enabled: bool = True

    # MITRE
    mitre_attack_version: str = "14.1"

    # CORS
    cors_origins: List[str] = ["http://localhost:3000"]

    @validator("secret_key")
    def validate_secret_key(cls, v, values):
        if len(v) < 32:
            raise ValueError("SECRET_KEY must be at least 32 characters")
        # Check entropy
        if len(set(v)) < 10:
            raise ValueError("SECRET_KEY has insufficient entropy")
        return v

    class Config:
        env_file = ".env"
        case_sensitive = False

settings = Settings()
```

### 2.3 Database Connection

**File:** `backend/app/core/database.py`

```python
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    create_async_engine,
    async_sessionmaker,
)
from sqlalchemy.orm import declarative_base

from app.core.config import settings

engine = create_async_engine(
    settings.database_url,
    pool_size=settings.database_pool_size,
    max_overflow=settings.max_overflow,
    pool_pre_ping=True,  # Test connections before use
)

AsyncSessionLocal = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
)

Base = declarative_base()

async def get_db() -> AsyncSession:
    """Dependency for database sessions."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
```

### 2.4 Service Layer Pattern

**File:** `backend/app/services/scan_service.py` (excerpt)

```python
from typing import Optional
from uuid import UUID
import structlog

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.models.scan import Scan, ScanStatus
from app.models.cloud_account import CloudAccount
from app.models.detection import Detection
from app.scanners.aws import (
    CloudWatchLogsInsightsScanner,
    EventBridgeScanner,
    GuardDutyScanner,
    ConfigRulesScanner,
    SecurityHubScanner,
    ServiceDiscoveryScanner,
)
from app.mappers.pattern_mapper import PatternMapper
from app.services.aws_credential_service import aws_credential_service

logger = structlog.get_logger()

class ScanService:
    """Orchestrates the complete scan workflow."""

    def __init__(self, db: AsyncSession):
        self.db = db
        self.pattern_mapper = PatternMapper()

    async def execute_scan(
        self,
        scan_id: UUID,
        cloud_account_id: UUID,
    ) -> Scan:
        """Execute a complete scan for a cloud account."""

        # 1. Load scan and account
        scan = await self._get_scan(scan_id)
        account = await self._get_account(cloud_account_id)

        try:
            # 2. Update status to RUNNING
            await self._update_scan_status(scan, ScanStatus.RUNNING)

            # 3. Assume customer credentials
            credentials = await aws_credential_service.assume_role(
                account.credential.role_arn
            )

            # 4. Discover target regions
            regions = await self._resolve_regions(account, credentials)

            # 5. Run scanners
            raw_detections = []
            total_steps = len(regions) * 6  # 6 scanner types
            current_step = 0

            for region in regions:
                for scanner_class in self._get_scanners():
                    scanner = scanner_class(credentials, region)
                    detections = await scanner.scan()
                    raw_detections.extend(detections)

                    current_step += 1
                    await self._update_progress(scan, current_step, total_steps)

            # 6. Map detections to MITRE techniques
            mapped_detections = []
            for raw in raw_detections:
                mappings = self.pattern_mapper.map_detection(raw)
                mapped_detections.append((raw, mappings))

            # 7. Persist detections with drift detection
            await self._persist_detections(account.id, mapped_detections)

            # 8. Update scan status
            await self._update_scan_status(scan, ScanStatus.COMPLETED)

            return scan

        except Exception as e:
            logger.error("scan_failed", scan_id=str(scan_id), error=str(e))
            await self._update_scan_status(scan, ScanStatus.FAILED, error=str(e))
            raise

    def _get_scanners(self):
        """Return list of scanner classes to execute."""
        return [
            CloudWatchLogsInsightsScanner,
            EventBridgeScanner,
            GuardDutyScanner,
            ConfigRulesScanner,
            SecurityHubScanner,
            ServiceDiscoveryScanner,
        ]
```

---

## 3. Database Schema

### 3.1 Entity Relationship Diagram

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                              CORE ENTITIES                                       │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                  │
│  ┌─────────────┐       ┌─────────────────┐       ┌─────────────┐               │
│  │    users    │       │  organization_  │       │organizations│               │
│  │             │       │    members      │       │             │               │
│  │ id (PK)     │       │                 │       │ id (PK)     │               │
│  │ email       │──────▶│ id (PK)         │◀──────│ name        │               │
│  │ password_   │       │ user_id (FK)    │       │ slug        │               │
│  │   hash      │       │ org_id (FK)     │       │ is_active   │               │
│  │ full_name   │       │ role            │       │ created_at  │               │
│  │ mfa_secret  │       │ status          │       │ updated_at  │               │
│  │ email_      │       │ allowed_        │       └──────┬──────┘               │
│  │   verified  │       │   account_ids   │              │                      │
│  └─────────────┘       └─────────────────┘              │                      │
│                                                          │                      │
│                                                          ▼                      │
│                                                   ┌─────────────┐               │
│                                                   │subscriptions│               │
│                                                   │             │               │
│                                                   │ id (PK)     │               │
│                                                   │ org_id (FK) │               │
│                                                   │ tier        │               │
│                                                   │ status      │               │
│                                                   │ stripe_*    │               │
│                                                   └─────────────┘               │
│                                                                                  │
└─────────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────────┐
│                           CLOUD ACCOUNT ENTITIES                                 │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                  │
│  ┌─────────────────┐     ┌─────────────┐     ┌─────────────────────┐           │
│  │ cloud_accounts  │     │   scans     │     │     detections      │           │
│  │                 │     │             │     │                     │           │
│  │ id (PK)         │────▶│ id (PK)     │────▶│ id (PK)             │           │
│  │ org_id (FK)     │     │ account_id  │     │ account_id (FK)     │           │
│  │ name            │     │   (FK)      │     │ name                │           │
│  │ provider        │     │ status      │     │ detection_type      │           │
│  │ account_id      │     │ progress    │     │ source_arn          │           │
│  │ regions         │     │ started_at  │     │ region              │           │
│  │ region_config   │     │ completed_  │     │ raw_config (JSONB)  │           │
│  │ discovered_     │     │   at        │     │ target_services     │           │
│  │   services      │     │ detections_ │     │   (JSONB)           │           │
│  │ global_account_ │     │   new       │     │ status              │           │
│  │   hash          │     │ detections_ │     │ health_status       │           │
│  │ is_active       │     │   removed   │     │ security_function   │           │
│  └─────────────────┘     └─────────────┘     │ last_seen_at        │           │
│          │                                    │ created_at          │           │
│          ▼                                    └──────────┬──────────┘           │
│  ┌─────────────────┐                                     │                      │
│  │cloud_credentials│                                     ▼                      │
│  │                 │                          ┌─────────────────────┐           │
│  │ id (PK)         │                          │ detection_mappings  │           │
│  │ account_id (FK) │                          │                     │           │
│  │ credential_type │                          │ id (PK)             │           │
│  │ encrypted_      │                          │ detection_id (FK)   │           │
│  │   credentials   │                          │ technique_id (FK)   │           │
│  │ status          │                          │ confidence          │           │
│  └─────────────────┘                          │ matched_indicators  │           │
│                                               │ rationale           │           │
│                                               └─────────────────────┘           │
│                                                                                  │
└─────────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────────┐
│                           MITRE ATT&CK ENTITIES                                  │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                  │
│  ┌─────────────┐     ┌─────────────────┐     ┌─────────────────────┐           │
│  │   tactics   │     │   techniques    │     │ mitre_threat_groups │           │
│  │             │     │                 │     │                     │           │
│  │ id (PK)     │◀────│ id (PK)         │────▶│ id (PK)             │           │
│  │ tactic_id   │     │ technique_id    │     │ group_id            │           │
│  │ name        │     │ name            │     │ name                │           │
│  │ description │     │ description     │     │ aliases             │           │
│  │ short_name  │     │ tactic_id (FK)  │     │ description         │           │
│  │ url         │     │ parent_         │     │ techniques (rel)    │           │
│  └─────────────┘     │   technique_id  │     └─────────────────────┘           │
│                      │ platforms       │                                        │
│                      │ data_sources    │     ┌─────────────────────┐           │
│                      │ detection       │     │   mitre_software    │           │
│                      │ mitigations     │     │                     │           │
│                      │ url             │     │ id (PK)             │           │
│                      │ is_subtechnique │     │ software_id         │           │
│                      └─────────────────┘     │ name                │           │
│                                               │ type (malware/tool) │           │
│                                               │ platforms           │           │
│                                               │ techniques (rel)    │           │
│                                               └─────────────────────┘           │
│                                                                                  │
└─────────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────────┐
│                           COMPLIANCE ENTITIES                                    │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                  │
│  ┌───────────────────┐   ┌───────────────────┐   ┌─────────────────────┐       │
│  │compliance_        │   │compliance_        │   │control_technique_   │       │
│  │  frameworks       │   │  controls         │   │  mappings           │       │
│  │                   │   │                   │   │                     │       │
│  │ id (PK)           │──▶│ id (PK)           │──▶│ id (PK)             │       │
│  │ name              │   │ framework_id (FK) │   │ control_id (FK)     │       │
│  │ version           │   │ control_id        │   │ technique_id (FK)   │       │
│  │ description       │   │ title             │   │ rationale           │       │
│  │ is_active         │   │ description       │   └─────────────────────┘       │
│  └───────────────────┘   │ family            │                                  │
│                          │ priority          │                                  │
│                          │ cloud_context     │                                  │
│                          │   (JSONB)         │                                  │
│                          └───────────────────┘                                  │
│                                                                                  │
└─────────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────────┐
│                           FRAUD PREVENTION ENTITIES                              │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                  │
│  ┌─────────────────────────┐        ┌─────────────────────────────┐            │
│  │cloud_account_global_    │        │free_email_cloud_account_    │            │
│  │  registry               │        │  bindings                   │            │
│  │                         │        │                             │            │
│  │ id (PK)                 │        │ id (PK)                     │            │
│  │ account_hash (UNIQUE)   │        │ email_hash (UNIQUE)         │            │
│  │ provider                │        │ cloud_account_hash          │            │
│  │ first_registered_org_id │        │ provider                    │            │
│  │ first_registered_at     │        │ created_at                  │            │
│  │ registration_count      │        │                             │            │
│  │ is_free_tier_locked     │        │                             │            │
│  └─────────────────────────┘        └─────────────────────────────┘            │
│                                                                                  │
└─────────────────────────────────────────────────────────────────────────────────┘
```

### 3.2 Key Table Definitions

#### 3.2.1 Users Table

```sql
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    full_name VARCHAR(255) NOT NULL,
    mfa_secret BYTEA,  -- Fernet encrypted
    mfa_enabled BOOLEAN DEFAULT FALSE,
    email_verified BOOLEAN DEFAULT FALSE,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_users_email ON users(email);
```

#### 3.2.2 Cloud Accounts Table

```sql
CREATE TABLE cloud_accounts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id),
    name VARCHAR(255) NOT NULL,
    provider VARCHAR(10) NOT NULL CHECK (provider IN ('aws', 'gcp')),
    account_id VARCHAR(255) NOT NULL,
    regions JSONB DEFAULT '[]'::jsonb,
    region_scan_mode VARCHAR(20) DEFAULT 'ALL',
    region_config JSONB,
    discovered_services JSONB DEFAULT '[]'::jsonb,
    discovered_services_at TIMESTAMPTZ,
    global_account_hash VARCHAR(64) NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),

    UNIQUE (organization_id, provider, account_id)
);

CREATE INDEX idx_cloud_accounts_org ON cloud_accounts(organization_id);
CREATE INDEX idx_cloud_accounts_hash ON cloud_accounts(global_account_hash);
```

#### 3.2.3 Detections Table

```sql
CREATE TABLE detections (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    cloud_account_id UUID REFERENCES cloud_accounts(id),
    cloud_organization_id UUID REFERENCES cloud_organizations(id),
    detection_scope VARCHAR(20) NOT NULL DEFAULT 'account',
    name VARCHAR(500) NOT NULL,
    detection_type VARCHAR(50) NOT NULL,
    source_arn VARCHAR(2048) NOT NULL,
    region VARCHAR(50) NOT NULL,
    raw_config JSONB NOT NULL,
    query_pattern TEXT,
    event_pattern JSONB,
    log_groups JSONB,
    description TEXT,
    target_services JSONB DEFAULT '[]'::jsonb,
    is_managed BOOLEAN DEFAULT FALSE,
    status VARCHAR(20) DEFAULT 'active',
    health_status VARCHAR(20) DEFAULT 'unknown',
    security_function VARCHAR(20),
    last_seen_at TIMESTAMPTZ DEFAULT NOW(),
    first_seen_at TIMESTAMPTZ DEFAULT NOW(),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),

    CONSTRAINT detection_scope_check CHECK (
        (detection_scope = 'account' AND cloud_account_id IS NOT NULL) OR
        (detection_scope = 'organization' AND cloud_organization_id IS NOT NULL)
    )
);

CREATE INDEX idx_detections_account ON detections(cloud_account_id);
CREATE INDEX idx_detections_type ON detections(detection_type);
CREATE INDEX idx_detections_services ON detections USING GIN (target_services);
```

#### 3.2.4 Techniques Table

```sql
CREATE TABLE techniques (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    technique_id VARCHAR(20) NOT NULL UNIQUE,  -- e.g., "T1078" or "T1078.001"
    name VARCHAR(255) NOT NULL,
    description TEXT,
    tactic_id UUID NOT NULL REFERENCES tactics(id),
    parent_technique_id UUID REFERENCES techniques(id),
    platforms JSONB DEFAULT '[]'::jsonb,  -- ["Windows", "Linux", "macOS", "AWS", "GCP"]
    data_sources JSONB DEFAULT '[]'::jsonb,
    detection TEXT,
    mitigations JSONB DEFAULT '[]'::jsonb,
    url VARCHAR(500),
    is_subtechnique BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_techniques_technique_id ON techniques(technique_id);
CREATE INDEX idx_techniques_tactic ON techniques(tactic_id);
CREATE INDEX idx_techniques_parent ON techniques(parent_technique_id);
```

### 3.3 Migration Strategy

**Alembic Configuration:** `backend/alembic/env.py`

```python
from alembic import context
from sqlalchemy.ext.asyncio import AsyncEngine
from app.core.database import Base, engine

def run_migrations_online():
    """Run migrations in 'online' mode with async engine."""

    async def do_run_migrations(connection):
        context.configure(
            connection=connection,
            target_metadata=Base.metadata,
            compare_type=True,
        )
        with context.begin_transaction():
            context.run_migrations()

    async def run_async_migrations():
        async with engine.connect() as connection:
            await connection.run_sync(do_run_migrations)

    asyncio.run(run_async_migrations())
```

**Migration Naming Convention:** `{sequence}_{description}.py`
- Example: `033_add_fraud_prevention.py`

---

## 4. API Specifications

### 4.1 Authentication Endpoints

#### POST /api/v1/auth/login

**Request:**
```json
{
  "email": "user@example.com",
  "password": "SecureP@ssw0rd!"
}
```

**Response (Success):**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer",
  "expires_in": 1800,
  "user": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "email": "user@example.com",
    "full_name": "John Smith"
  },
  "organization": {
    "id": "660e8400-e29b-41d4-a716-446655440001",
    "name": "Acme Corp",
    "slug": "acme-corp"
  }
}
```

**Response (MFA Required):**
```json
{
  "requires_mfa": true,
  "mfa_token": "temp_token_for_mfa_verification"
}
```

**Cookies Set:**
- `dcv_refresh_token`: httpOnly, Secure, SameSite=Strict, 7-day expiry
- `dcv_csrf_token`: Secure, SameSite=Strict

#### POST /api/v1/auth/signup

**Request:**
```json
{
  "email": "newuser@company.com",
  "password": "SecureP@ssw0rd!",
  "full_name": "Jane Doe",
  "organization_name": "New Company Ltd"
}
```

**Validation Rules:**
- Email: Valid format, not disposable domain
- Password: >= 12 chars, mixed case, numbers, symbols, not breached (HIBP)
- Organisation name: >= 3 chars, unique slug generation

**Response:**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer",
  "user": { ... },
  "organization": { ... },
  "verification_required": true
}
```

### 4.2 Cloud Account Endpoints

#### POST /api/v1/accounts

**Request:**
```json
{
  "name": "Production AWS Account",
  "provider": "aws",
  "account_id": "123456789012",
  "regions": ["eu-west-2", "us-east-1"]
}
```

**Validation:**
- AWS account_id: 12-digit numeric string
- GCP project_id: 6-30 chars, lowercase, hyphens allowed

**Response:**
```json
{
  "id": "770e8400-e29b-41d4-a716-446655440002",
  "name": "Production AWS Account",
  "provider": "aws",
  "account_id": "123456789012",
  "regions": ["eu-west-2", "us-east-1"],
  "is_active": true,
  "created_at": "2025-12-24T10:30:00Z"
}
```

#### POST /api/v1/accounts/{account_id}/scans

**Request:**
```json
{
  "scan_type": "full",
  "regions": ["eu-west-2"]  // Optional: defaults to all configured
}
```

**Response:**
```json
{
  "id": "880e8400-e29b-41d4-a716-446655440003",
  "status": "pending",
  "cloud_account_id": "770e8400-e29b-41d4-a716-446655440002",
  "created_at": "2025-12-24T10:35:00Z"
}
```

#### GET /api/v1/accounts/{account_id}/scans/{scan_id}

**Response:**
```json
{
  "id": "880e8400-e29b-41d4-a716-446655440003",
  "status": "completed",
  "progress_percent": 100,
  "current_step": "Completed",
  "started_at": "2025-12-24T10:35:05Z",
  "completed_at": "2025-12-24T10:42:30Z",
  "detections_new": 15,
  "detections_updated": 3,
  "detections_removed": 1
}
```

### 4.3 Coverage Endpoints

#### GET /api/v1/coverage

**Query Parameters:**
- `cloud_account_id`: UUID (required)
- `framework`: string (optional, e.g., "mitre_attack")

**Response:**
```json
{
  "cloud_account_id": "770e8400-e29b-41d4-a716-446655440002",
  "overall_coverage_percent": 42.5,
  "total_techniques": 201,
  "covered_techniques": 85,
  "partial_techniques": 23,
  "uncovered_techniques": 93,
  "tactics": [
    {
      "tactic_id": "TA0001",
      "name": "Initial Access",
      "coverage_percent": 55.0,
      "techniques_covered": 6,
      "techniques_total": 11
    }
  ],
  "updated_at": "2025-12-24T10:42:30Z"
}
```

#### GET /api/v1/coverage/techniques/{technique_id}

**Response:**
```json
{
  "technique_id": "T1078",
  "name": "Valid Accounts",
  "tactic": "Initial Access",
  "coverage_status": "partial",
  "confidence_score": 0.75,
  "detections": [
    {
      "id": "990e8400-e29b-41d4-a716-446655440004",
      "name": "IAM User Login Alert",
      "detection_type": "eventbridge_rule",
      "confidence": 0.85,
      "target_services": ["IAM", "CloudTrail"]
    }
  ],
  "service_coverage": {
    "in_scope_services": ["IAM", "SSO", "Cognito"],
    "covered_services": ["IAM"],
    "uncovered_services": ["SSO", "Cognito"],
    "service_coverage_percent": 33.3
  },
  "remediation": {
    "priority": "high",
    "templates_available": ["cloudformation", "terraform"]
  }
}
```

### 4.4 Compliance Endpoints

#### GET /api/v1/compliance/frameworks

**Response:**
```json
{
  "frameworks": [
    {
      "id": "aa0e8400-e29b-41d4-a716-446655440005",
      "name": "CIS AWS Foundations Benchmark",
      "version": "3.0.0",
      "controls_count": 58,
      "is_active": true
    },
    {
      "id": "bb0e8400-e29b-41d4-a716-446655440006",
      "name": "NIST Cybersecurity Framework",
      "version": "2.0",
      "controls_count": 108,
      "is_active": true
    }
  ]
}
```

#### GET /api/v1/compliance/coverage

**Query Parameters:**
- `cloud_account_id`: UUID (required)
- `framework_id`: UUID (required)

**Response:**
```json
{
  "framework": {
    "id": "aa0e8400-e29b-41d4-a716-446655440005",
    "name": "CIS AWS Foundations Benchmark"
  },
  "overall_coverage_percent": 68.5,
  "controls": [
    {
      "control_id": "1.1",
      "title": "Maintain current contact details",
      "status": "covered",
      "coverage_percent": 100,
      "mapped_techniques": 2,
      "covered_techniques": 2,
      "service_coverage": {
        "in_scope_services": ["IAM"],
        "covered_services": ["IAM"],
        "service_coverage_percent": 100
      }
    },
    {
      "control_id": "3.5",
      "title": "Ensure S3 bucket logging is enabled",
      "status": "partial",
      "coverage_percent": 65,
      "mapped_techniques": 3,
      "covered_techniques": 2,
      "service_coverage": {
        "in_scope_services": ["S3", "RDS", "DynamoDB"],
        "covered_services": ["S3"],
        "uncovered_services": ["RDS", "DynamoDB"],
        "service_coverage_percent": 33.3
      }
    }
  ],
  "family_summary": [
    {
      "family": "Identity and Access Management",
      "coverage_percent": 75.0,
      "controls_covered": 12,
      "controls_total": 16
    }
  ]
}
```

### 4.5 Error Response Format

**Standard Error Response:**
```json
{
  "detail": "Human-readable error message",
  "error_code": "VALIDATION_ERROR",
  "field_errors": [
    {
      "field": "email",
      "message": "Invalid email format"
    }
  ]
}
```

**HTTP Status Codes:**
| Code | Usage |
|------|-------|
| 200 | Success (GET, PATCH) |
| 201 | Created (POST) |
| 204 | No Content (DELETE) |
| 400 | Bad Request (validation errors) |
| 401 | Unauthorised (invalid/missing token) |
| 403 | Forbidden (insufficient permissions) |
| 404 | Not Found |
| 409 | Conflict (duplicate resource) |
| 422 | Unprocessable Entity (business rule violation) |
| 429 | Too Many Requests (rate limited) |
| 500 | Internal Server Error |

---

## 5. Scanner Implementation

### 5.1 Base Scanner Interface

**File:** `backend/app/scanners/base.py`

```python
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional

from app.models.detection import DetectionType

@dataclass
class RawDetection:
    """Represents a detection discovered by a scanner."""

    name: str
    detection_type: DetectionType
    source_arn: str
    region: str
    raw_config: dict[str, Any]
    query_pattern: Optional[str] = None
    event_pattern: Optional[dict[str, Any]] = None
    log_groups: Optional[list[str]] = None
    description: Optional[str] = None
    target_services: Optional[list[str]] = None
    is_managed: bool = False
    discovered_at: datetime = field(default_factory=datetime.utcnow)


class BaseScanner(ABC):
    """Abstract base class for all cloud scanners."""

    def __init__(self, credentials: dict, region: str):
        self.credentials = credentials
        self.region = region

    @property
    @abstractmethod
    def detection_type(self) -> DetectionType:
        """Return the type of detection this scanner finds."""
        pass

    @property
    def is_global_service(self) -> bool:
        """Whether this service is global (scanned once, not per-region)."""
        return False

    @property
    def global_scan_region(self) -> str:
        """Region to use for global services."""
        return "us-east-1"

    @abstractmethod
    async def scan(self) -> list[RawDetection]:
        """Execute the scan and return discovered detections."""
        pass

    def _create_client(self, service_name: str):
        """Create a boto3 client with assumed credentials."""
        import boto3
        return boto3.client(
            service_name,
            region_name=self.region,
            aws_access_key_id=self.credentials["AccessKeyId"],
            aws_secret_access_key=self.credentials["SecretAccessKey"],
            aws_session_token=self.credentials["SessionToken"],
        )
```

### 5.2 EventBridge Scanner

**File:** `backend/app/scanners/aws/eventbridge_scanner.py`

```python
from typing import Optional
import structlog

from app.scanners.base import BaseScanner, RawDetection
from app.models.detection import DetectionType
from app.scanners.aws.service_mappings import extract_services_from_event_pattern

logger = structlog.get_logger()

class EventBridgeScanner(BaseScanner):
    """Scans AWS EventBridge for detection rules."""

    @property
    def detection_type(self) -> DetectionType:
        return DetectionType.EVENTBRIDGE_RULE

    async def scan(self) -> list[RawDetection]:
        """Scan EventBridge rules."""
        client = self._create_client("events")
        detections = []

        paginator = client.get_paginator("list_rules")

        for page in paginator.paginate():
            for rule in page.get("Rules", []):
                try:
                    detection = await self._process_rule(client, rule)
                    if detection:
                        detections.append(detection)
                except Exception as e:
                    logger.warning(
                        "eventbridge_rule_processing_failed",
                        rule_name=rule.get("Name"),
                        error=str(e),
                    )

        return detections

    async def _process_rule(
        self, client, rule: dict
    ) -> Optional[RawDetection]:
        """Process a single EventBridge rule."""

        rule_name = rule.get("Name", "")
        event_pattern_str = rule.get("EventPattern")

        if not event_pattern_str:
            return None

        import json
        event_pattern = json.loads(event_pattern_str)

        # Extract target services from the event pattern
        target_services = extract_services_from_event_pattern(event_pattern)

        # Get rule details for ARN
        rule_arn = rule.get("Arn", f"arn:aws:events:{self.region}::rule/{rule_name}")

        return RawDetection(
            name=rule_name,
            detection_type=self.detection_type,
            source_arn=rule_arn,
            region=self.region,
            raw_config=rule,
            event_pattern=event_pattern,
            description=rule.get("Description"),
            target_services=target_services,
            is_managed=self._is_managed_rule(rule_name),
        )

    def _is_managed_rule(self, rule_name: str) -> bool:
        """Check if rule is AWS-managed."""
        managed_prefixes = [
            "aws.",
            "AWS-",
            "awsconfig-",
        ]
        return any(rule_name.startswith(p) for p in managed_prefixes)
```

### 5.3 Service Discovery Scanner

**File:** `backend/app/scanners/aws/service_discovery_scanner.py`

```python
from app.scanners.base import BaseScanner, RawDetection
from app.models.detection import DetectionType
from app.scanners.aws.service_mappings import CORE_SERVICES

class ServiceDiscoveryScanner(BaseScanner):
    """Discovers which AWS services have resources in the account."""

    @property
    def detection_type(self) -> DetectionType:
        return DetectionType.SERVICE_DISCOVERY

    @property
    def is_global_service(self) -> bool:
        return True  # Run once, not per-region

    async def scan(self) -> list[str]:
        """Discover services with active resources."""
        discovered_services = []

        # Check each core service
        service_checks = [
            ("s3", self._check_s3),
            ("rds", self._check_rds),
            ("dynamodb", self._check_dynamodb),
            ("ebs", self._check_ebs),
            ("efs", self._check_efs),
            ("elasticache", self._check_elasticache),
            ("secretsmanager", self._check_secrets_manager),
            ("ecr", self._check_ecr),
        ]

        for service_name, check_func in service_checks:
            try:
                if await check_func():
                    discovered_services.append(service_name)
            except Exception:
                pass  # Service may not be enabled

        return discovered_services

    async def _check_s3(self) -> bool:
        """Check if S3 buckets exist."""
        client = self._create_client("s3")
        response = client.list_buckets()
        return len(response.get("Buckets", [])) > 0

    async def _check_rds(self) -> bool:
        """Check if RDS instances exist."""
        client = self._create_client("rds")
        response = client.describe_db_instances()
        return len(response.get("DBInstances", [])) > 0

    async def _check_dynamodb(self) -> bool:
        """Check if DynamoDB tables exist."""
        client = self._create_client("dynamodb")
        response = client.list_tables()
        return len(response.get("TableNames", [])) > 0

    # ... similar methods for other services
```

### 5.4 Service Mappings

**File:** `backend/app/scanners/aws/service_mappings.py`

```python
"""Service mapping constants and utilities."""

# Core services for service-aware coverage
CORE_SERVICES = {
    "s3",
    "ebs",
    "efs",
    "rds",
    "dynamodb",
    "redshift",
    "elasticache",
    "secretsmanager",
    "cloudwatch_logs",
    "ecr",
}

# EventBridge source to service mapping
AWS_EVENT_SOURCE_TO_SERVICE = {
    "aws.s3": "s3",
    "aws.ec2": "ec2",
    "aws.rds": "rds",
    "aws.dynamodb": "dynamodb",
    "aws.iam": "iam",
    "aws.cloudtrail": "cloudtrail",
    "aws.guardduty": "guardduty",
    "aws.securityhub": "securityhub",
    "aws.config": "config",
    "aws.lambda": "lambda",
    "aws.ecs": "ecs",
    "aws.eks": "eks",
    "aws.kms": "kms",
    "aws.secretsmanager": "secretsmanager",
}

# CloudFormation resource type to service mapping
AWS_RESOURCE_TO_SERVICE = {
    "AWS::S3::Bucket": "s3",
    "AWS::EC2::Instance": "ec2",
    "AWS::EC2::Volume": "ebs",
    "AWS::RDS::DBInstance": "rds",
    "AWS::DynamoDB::Table": "dynamodb",
    "AWS::Lambda::Function": "lambda",
    "AWS::ECS::Cluster": "ecs",
    "AWS::EKS::Cluster": "eks",
    # ... more mappings
}

def extract_services_from_event_pattern(event_pattern: dict) -> list[str]:
    """Extract target services from an EventBridge event pattern."""
    services = set()

    # Check source field
    sources = event_pattern.get("source", [])
    if isinstance(sources, str):
        sources = [sources]

    for source in sources:
        if source in AWS_EVENT_SOURCE_TO_SERVICE:
            services.add(AWS_EVENT_SOURCE_TO_SERVICE[source])

    # Check detail-type for CloudTrail events
    detail_types = event_pattern.get("detail-type", [])
    if "AWS API Call via CloudTrail" in detail_types:
        # Extract from eventSource in detail
        detail = event_pattern.get("detail", {})
        event_sources = detail.get("eventSource", [])
        if isinstance(event_sources, str):
            event_sources = [event_sources]

        for es in event_sources:
            # eventSource format: "s3.amazonaws.com"
            service = es.split(".")[0]
            services.add(service)

    return list(services)
```

### 5.5 Optimised EventBridge Template Pattern

All remediation templates using EventBridge follow this optimised pattern with DLQ, retry, and scoped SNS policies:

**File:** `backend/app/data/remediation_templates/template_example.py` (Terraform excerpt)

```hcl
# Optimised EventBridge Detection Pattern
# Components: EventBridge Rule → SNS Topic (KMS) → Email
# With: DLQ, Retry Policy, Scoped SNS Policy, Input Transformer

variable "name_prefix" {
  type        = string
  default     = "t1543-ecs-task"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

data "aws_caller_identity" "current" {}

# SNS Topic with KMS encryption
resource "aws_sns_topic" "alerts" {
  name              = "${var.name_prefix}-alerts"
  display_name      = "Security Alerts"
  kms_master_key_id = "alias/aws/sns"
}

# EventBridge Rule
resource "aws_cloudwatch_event_rule" "detection" {
  name        = "${var.name_prefix}-detection"
  description = "Detect security events (MITRE ATT&CK technique)"

  event_pattern = jsonencode({
    source        = ["aws.ecs"]
    "detail-type" = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["ecs.amazonaws.com"]
      eventName   = ["RegisterTaskDefinition", "UpdateService"]
    }
  })
}

# Dead Letter Queue (14-day retention)
resource "aws_sqs_queue" "dlq" {
  name                      = "${var.name_prefix}-dlq"
  message_retention_seconds = 1209600  # 14 days
}

# EventBridge Target with DLQ and Retry
resource "aws_cloudwatch_event_target" "to_sns" {
  rule      = aws_cloudwatch_event_rule.detection.name
  target_id = "SNSTarget"
  arn       = aws_sns_topic.alerts.arn

  # Retry policy: 8 attempts, 1-hour max age
  retry_policy {
    maximum_event_age_in_seconds = 3600
    maximum_retry_attempts       = 8
  }

  # Dead letter queue for failed deliveries
  dead_letter_config {
    arn = aws_sqs_queue.dlq.arn
  }

  # Human-readable alert format
  input_transformer {
    input_paths = {
      time      = "$.time"
      account   = "$.account"
      region    = "$.detail.awsRegion"
      eventName = "$.detail.eventName"
      actor     = "$.detail.userIdentity.arn"
      sourceIp  = "$.detail.sourceIPAddress"
    }

    input_template = <<-EOT
"ALERT: Security Event Detected
time=<time>
account=<account> region=<region>
event=<eventName>
actor=<actor>
source_ip=<sourceIp>"
EOT
  }
}

# Scoped SNS Topic Policy (prevents confused deputy)
resource "aws_sns_topic_policy" "allow_eventbridge" {
  arn = aws_sns_topic.alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowEventBridgePublishScoped"
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.alerts.arn
      Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
        ArnEquals = {
          "aws:SourceArn" = aws_cloudwatch_event_rule.detection.arn
        }
      }
    }]
  })
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}
```

**Key Security Features:**

| Feature | Implementation | Purpose |
|---------|---------------|---------|
| `kms_master_key_id` | `alias/aws/sns` | Encrypt SNS messages at rest |
| `message_retention_seconds` | `1209600` (14 days) | Retain failed messages for analysis |
| `maximum_retry_attempts` | `8` | Retry delivery during transient failures |
| `maximum_event_age_in_seconds` | `3600` (1 hour) | Discard stale events |
| `AWS:SourceAccount` | Current account ID | Prevent cross-account confused deputy |
| `aws:SourceArn` | Specific rule ARN | Prevent rule impersonation |

---

## 6. Mapping Engine

### 6.1 Pattern Mapper

**File:** `backend/app/mappers/pattern_mapper.py`

```python
from dataclasses import dataclass
from typing import Optional

from app.scanners.base import RawDetection
from app.mappers.indicator_library import TECHNIQUE_INDICATORS
from app.mappers.guardduty_mappings import GUARDDUTY_TO_TECHNIQUE
from app.mappers.cloudtrail_mappings import CLOUDTRAIL_EVENT_TO_TECHNIQUES

@dataclass
class MappingResult:
    """Result of mapping a detection to a MITRE technique."""

    technique_id: str
    technique_name: str
    tactic_id: str
    tactic_name: str
    confidence: float  # 0.4 - 1.0
    matched_indicators: list[str]
    rationale: str


class PatternMapper:
    """Maps detections to MITRE ATT&CK techniques."""

    def __init__(self):
        self._load_technique_metadata()

    def map_detection(self, detection: RawDetection) -> list[MappingResult]:
        """Map a detection to MITRE techniques."""
        results = []

        # 1. Check vendor-specific mappings (highest confidence)
        vendor_mappings = self._check_vendor_mappings(detection)
        results.extend(vendor_mappings)

        # 2. Check CloudTrail event mappings
        if detection.event_pattern:
            cloudtrail_mappings = self._check_cloudtrail_mappings(detection)
            results.extend(cloudtrail_mappings)

        # 3. Check indicator library (keyword matching)
        indicator_mappings = self._check_indicator_library(detection)
        results.extend(indicator_mappings)

        # Deduplicate and sort by confidence
        return self._deduplicate_results(results)

    def _check_vendor_mappings(
        self, detection: RawDetection
    ) -> list[MappingResult]:
        """Check vendor-specific mappings (GuardDuty, SCC, etc.)."""
        results = []

        if detection.detection_type.value == "guardduty_finding":
            finding_type = detection.raw_config.get("Type", "")
            if finding_type in GUARDDUTY_TO_TECHNIQUE:
                mapping = GUARDDUTY_TO_TECHNIQUE[finding_type]
                results.append(MappingResult(
                    technique_id=mapping["technique_id"],
                    technique_name=mapping["technique_name"],
                    tactic_id=mapping["tactic_id"],
                    tactic_name=mapping["tactic_name"],
                    confidence=0.95,  # High confidence for vendor mappings
                    matched_indicators=[f"GuardDuty:{finding_type}"],
                    rationale=f"Direct mapping from GuardDuty finding type",
                ))

        return results

    def _check_cloudtrail_mappings(
        self, detection: RawDetection
    ) -> list[MappingResult]:
        """Extract and map CloudTrail events from EventBridge patterns."""
        results = []

        event_pattern = detection.event_pattern or {}
        detail = event_pattern.get("detail", {})
        event_names = detail.get("eventName", [])

        if isinstance(event_names, str):
            event_names = [event_names]

        for event_name in event_names:
            if event_name in CLOUDTRAIL_EVENT_TO_TECHNIQUES:
                for technique in CLOUDTRAIL_EVENT_TO_TECHNIQUES[event_name]:
                    results.append(MappingResult(
                        technique_id=technique["technique_id"],
                        technique_name=technique["technique_name"],
                        tactic_id=technique["tactic_id"],
                        tactic_name=technique["tactic_name"],
                        confidence=0.85,
                        matched_indicators=[f"CloudTrail:{event_name}"],
                        rationale=f"CloudTrail event {event_name} maps to technique",
                    ))

        return results

    def _check_indicator_library(
        self, detection: RawDetection
    ) -> list[MappingResult]:
        """Match detection against indicator library."""
        results = []

        # Build searchable text from detection
        search_text = f"{detection.name} {detection.description or ''}"
        search_text = search_text.lower()

        for technique_id, indicators in TECHNIQUE_INDICATORS.items():
            matched = []
            for indicator in indicators["keywords"]:
                if indicator.lower() in search_text:
                    matched.append(indicator)

            if matched:
                # Confidence based on number of matches
                confidence = min(0.4 + (len(matched) * 0.1), 0.8)

                results.append(MappingResult(
                    technique_id=technique_id,
                    technique_name=indicators["name"],
                    tactic_id=indicators["tactic_id"],
                    tactic_name=indicators["tactic_name"],
                    confidence=confidence,
                    matched_indicators=matched,
                    rationale=f"Keyword match: {', '.join(matched)}",
                ))

        return results

    def _deduplicate_results(
        self, results: list[MappingResult]
    ) -> list[MappingResult]:
        """Deduplicate and keep highest confidence per technique."""
        by_technique = {}

        for result in results:
            if result.technique_id not in by_technique:
                by_technique[result.technique_id] = result
            elif result.confidence > by_technique[result.technique_id].confidence:
                by_technique[result.technique_id] = result

        return sorted(
            by_technique.values(),
            key=lambda r: r.confidence,
            reverse=True,
        )
```

### 6.2 Indicator Library Structure

**File:** `backend/app/mappers/indicator_library.py` (excerpt)

```python
"""MITRE ATT&CK technique indicators for keyword-based mapping."""

TECHNIQUE_INDICATORS = {
    "T1078": {
        "name": "Valid Accounts",
        "tactic_id": "TA0001",
        "tactic_name": "Initial Access",
        "keywords": [
            "login",
            "authentication",
            "credential",
            "signin",
            "console login",
            "iam user",
            "root login",
            "mfa",
            "password",
            "access key",
        ],
    },
    "T1190": {
        "name": "Exploit Public-Facing Application",
        "tactic_id": "TA0001",
        "tactic_name": "Initial Access",
        "keywords": [
            "waf",
            "web application firewall",
            "sql injection",
            "xss",
            "cross-site scripting",
            "rce",
            "remote code execution",
            "exploit",
            "vulnerability",
        ],
    },
    "T1566": {
        "name": "Phishing",
        "tactic_id": "TA0001",
        "tactic_name": "Initial Access",
        "keywords": [
            "phishing",
            "email",
            "ses",
            "workmail",
            "attachment",
            "suspicious email",
            "malicious link",
        ],
    },
    # ... 200+ more techniques
}
```

---

## 7. Frontend Implementation

### 7.1 State Management

**File:** `frontend/src/stores/authStore.ts`

```typescript
import { create } from 'zustand';
import { persist } from 'zustand/middleware';

interface User {
  id: string;
  email: string;
  fullName: string;
  mfaEnabled: boolean;
}

interface Organization {
  id: string;
  name: string;
  slug: string;
}

interface AuthState {
  // State
  accessToken: string | null;
  csrfToken: string | null;
  user: User | null;
  organization: Organization | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  isInitialised: boolean;

  // Actions
  setAuth: (data: {
    accessToken: string;
    user: User;
    organization: Organization;
  }) => void;
  clearAuth: () => void;
  setLoading: (loading: boolean) => void;
  updateUser: (user: User) => void;
  updateOrganization: (org: Organization) => void;
  setAccessToken: (token: string) => void;
  initialise: () => void;
}

export const useAuthStore = create<AuthState>()(
  // Note: We do NOT persist accessToken (security)
  (set, get) => ({
    accessToken: null,
    csrfToken: null,
    user: null,
    organization: null,
    isAuthenticated: false,
    isLoading: true,
    isInitialised: false,

    setAuth: (data) => set({
      accessToken: data.accessToken,
      user: data.user,
      organization: data.organization,
      isAuthenticated: true,
      isLoading: false,
    }),

    clearAuth: () => set({
      accessToken: null,
      user: null,
      organization: null,
      isAuthenticated: false,
      isLoading: false,
    }),

    setLoading: (loading) => set({ isLoading: loading }),

    updateUser: (user) => set({ user }),

    updateOrganization: (org) => set({ organization: org }),

    setAccessToken: (token) => set({ accessToken: token }),

    initialise: () => set({ isInitialised: true, isLoading: false }),
  })
);
```

### 7.2 API Client

**File:** `frontend/src/services/api.ts`

```typescript
import axios, { AxiosInstance, AxiosError } from 'axios';
import { useAuthStore } from '../stores/authStore';

const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';

// Create axios instance
const api: AxiosInstance = axios.create({
  baseURL: `${API_BASE_URL}/api/v1`,
  withCredentials: true, // Include cookies
  headers: {
    'Content-Type': 'application/json',
  },
});

// Request interceptor - add auth header
api.interceptors.request.use(
  (config) => {
    const { accessToken } = useAuthStore.getState();
    if (accessToken) {
      config.headers.Authorization = `Bearer ${accessToken}`;
    }
    return config;
  },
  (error) => Promise.reject(error)
);

// Response interceptor - handle 401 and refresh tokens
let isRefreshing = false;
let failedQueue: Array<{
  resolve: (value: unknown) => void;
  reject: (reason?: unknown) => void;
}> = [];

const processQueue = (error: Error | null, token: string | null = null) => {
  failedQueue.forEach((prom) => {
    if (error) {
      prom.reject(error);
    } else {
      prom.resolve(token);
    }
  });
  failedQueue = [];
};

api.interceptors.response.use(
  (response) => response,
  async (error: AxiosError) => {
    const originalRequest = error.config;

    if (error.response?.status === 401 && originalRequest) {
      if (isRefreshing) {
        // Queue this request while refresh is in progress
        return new Promise((resolve, reject) => {
          failedQueue.push({ resolve, reject });
        }).then((token) => {
          originalRequest.headers.Authorization = `Bearer ${token}`;
          return api(originalRequest);
        });
      }

      isRefreshing = true;

      try {
        // Attempt to refresh the token
        const response = await axios.post(
          `${API_BASE_URL}/api/v1/auth/refresh-session`,
          {},
          { withCredentials: true }
        );

        const { access_token } = response.data;
        useAuthStore.getState().setAccessToken(access_token);

        processQueue(null, access_token);

        // Retry original request
        originalRequest.headers.Authorization = `Bearer ${access_token}`;
        return api(originalRequest);

      } catch (refreshError) {
        processQueue(refreshError as Error, null);
        useAuthStore.getState().clearAuth();
        window.location.href = '/login';
        return Promise.reject(refreshError);

      } finally {
        isRefreshing = false;
      }
    }

    return Promise.reject(error);
  }
);

export default api;
```

### 7.3 Coverage Heatmap Component

**File:** `frontend/src/components/MitreHeatmap.tsx`

```typescript
import React, { useMemo } from 'react';

interface TechniqueCoverage {
  techniqueId: string;
  name: string;
  tacticId: string;
  coveragePercent: number;
  status: 'covered' | 'partial' | 'uncovered';
  detectionCount: number;
}

interface MitreHeatmapProps {
  techniques: TechniqueCoverage[];
  onTechniqueClick?: (techniqueId: string) => void;
}

const TACTICS_ORDER = [
  { id: 'TA0043', name: 'Reconnaissance' },
  { id: 'TA0042', name: 'Resource Development' },
  { id: 'TA0001', name: 'Initial Access' },
  { id: 'TA0002', name: 'Execution' },
  { id: 'TA0003', name: 'Persistence' },
  { id: 'TA0004', name: 'Privilege Escalation' },
  { id: 'TA0005', name: 'Defence Evasion' },
  { id: 'TA0006', name: 'Credential Access' },
  { id: 'TA0007', name: 'Discovery' },
  { id: 'TA0008', name: 'Lateral Movement' },
  { id: 'TA0009', name: 'Collection' },
  { id: 'TA0011', name: 'Command and Control' },
  { id: 'TA0010', name: 'Exfiltration' },
  { id: 'TA0040', name: 'Impact' },
];

export const MitreHeatmap: React.FC<MitreHeatmapProps> = ({
  techniques,
  onTechniqueClick,
}) => {
  // Group techniques by tactic
  const techniquesByTactic = useMemo(() => {
    const grouped: Record<string, TechniqueCoverage[]> = {};

    for (const tactic of TACTICS_ORDER) {
      grouped[tactic.id] = techniques
        .filter((t) => t.tacticId === tactic.id)
        .sort((a, b) => a.name.localeCompare(b.name));
    }

    return grouped;
  }, [techniques]);

  const getCellColour = (status: string, coverage: number): string => {
    if (status === 'covered' || coverage >= 80) {
      return 'bg-coverage-high';
    } else if (status === 'partial' || coverage >= 40) {
      return 'bg-coverage-medium';
    }
    return 'bg-coverage-low';
  };

  return (
    <div className="overflow-x-auto">
      <div className="flex gap-1">
        {TACTICS_ORDER.map((tactic) => (
          <div key={tactic.id} className="flex-1 min-w-[120px]">
            {/* Tactic Header */}
            <div className="text-xs font-medium text-tactical-muted p-2 text-center border-b border-tactical-border">
              {tactic.name}
            </div>

            {/* Technique Cells */}
            <div className="flex flex-col gap-1 p-1">
              {techniquesByTactic[tactic.id]?.map((technique) => (
                <button
                  key={technique.techniqueId}
                  onClick={() => onTechniqueClick?.(technique.techniqueId)}
                  className={`
                    p-2 rounded text-xs text-left
                    ${getCellColour(technique.status, technique.coveragePercent)}
                    hover:opacity-80 transition-opacity
                  `}
                  title={`${technique.name} (${technique.coveragePercent}%)`}
                >
                  <div className="font-mono">{technique.techniqueId}</div>
                  <div className="truncate">{technique.name}</div>
                </button>
              ))}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};
```

### 7.4 Component Directory Structure

```
frontend/src/components/
├── Layout.tsx                    # Main application layout with sidebar
├── AccountSelector.tsx           # Cloud account dropdown
├── CoverageGauge.tsx            # Radial progress gauge
├── MitreHeatmap.tsx             # MITRE ATT&CK heatmap
├── TacticHeatmap.tsx            # Tactic-level summary
├── DetectionDetailModal.tsx     # Detection details popup
├── TechniqueDetailModal.tsx     # Technique breakdown popup
├── CredentialWizard.tsx         # AWS/GCP credential setup
├── SocialLoginButtons.tsx       # OAuth provider buttons
├── ProtectedRoute.tsx           # Auth guard wrapper
├── compliance/
│   ├── ComplianceCoverageContent.tsx
│   ├── ControlsTable.tsx
│   ├── CoverageDetailModal.tsx
│   ├── TechniqueBreakdown.tsx
│   ├── FamilyCoverageChart.tsx
│   └── ServiceCoverageIndicator.tsx
└── admin/
    ├── AdminLayout.tsx
    ├── AdminSidebar.tsx
    └── StatsCard.tsx
```

---

## 8. Infrastructure Specifications

### 8.1 Terraform Module: Backend

**File:** `infrastructure/terraform/modules/backend/main.tf` (excerpt)

```hcl
# ECS Cluster
resource "aws_ecs_cluster" "main" {
  name = "${var.project}-${var.environment}-backend"

  setting {
    name  = "containerInsights"
    value = "enabled"
  }

  tags = var.tags
}

# Task Definition
resource "aws_ecs_task_definition" "backend" {
  family                   = "${var.project}-${var.environment}-backend"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = var.task_cpu
  memory                   = var.task_memory
  execution_role_arn       = aws_iam_role.ecs_execution.arn
  task_role_arn           = aws_iam_role.ecs_task.arn

  container_definitions = jsonencode([
    {
      name  = "backend"
      image = "${var.ecr_repository_url}:${var.image_tag}"

      portMappings = [
        {
          containerPort = 8000
          protocol      = "tcp"
        }
      ]

      environment = [
        { name = "ENVIRONMENT", value = var.environment },
        { name = "AWS_REGION", value = var.aws_region },
        { name = "DATABASE_URL", value = var.database_url },
        { name = "REDIS_URL", value = var.redis_url },
        { name = "COGNITO_USER_POOL_ID", value = var.cognito_user_pool_id },
        { name = "COGNITO_CLIENT_ID", value = var.cognito_client_id },
        { name = "FRONTEND_URL", value = var.frontend_url },
      ]

      secrets = [
        {
          name      = "SECRET_KEY"
          valueFrom = var.secret_key_arn
        },
        {
          name      = "CREDENTIAL_ENCRYPTION_KEY"
          valueFrom = var.credential_key_arn
        },
        {
          name      = "STRIPE_SECRET_KEY"
          valueFrom = var.stripe_secret_key_arn
        },
      ]

      logConfiguration = {
        logDriver = "awslogs"
        options = {
          awslogs-group         = aws_cloudwatch_log_group.backend.name
          awslogs-region        = var.aws_region
          awslogs-stream-prefix = "backend"
        }
      }

      healthCheck = {
        command     = ["CMD-SHELL", "curl -f http://localhost:8000/health || exit 1"]
        interval    = 30
        timeout     = 5
        retries     = 3
        startPeriod = 60
      }
    }
  ])

  tags = var.tags
}

# ECS Service
resource "aws_ecs_service" "backend" {
  name            = "${var.project}-${var.environment}-backend"
  cluster         = aws_ecs_cluster.main.id
  task_definition = aws_ecs_task_definition.backend.arn
  desired_count   = var.desired_count
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = var.private_subnet_ids
    security_groups  = [aws_security_group.ecs.id]
    assign_public_ip = false
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.backend.arn
    container_name   = "backend"
    container_port   = 8000
  }

  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  tags = var.tags
}

# WAF Web ACL
resource "aws_wafv2_web_acl" "api" {
  name        = "${var.project}-${var.environment}-api-waf"
  description = "WAF rules for API protection"
  scope       = "REGIONAL"

  default_action {
    allow {}
  }

  # Rule 1: Rate limiting
  rule {
    name     = "RateLimit"
    priority = 1

    override_action {
      none {}
    }

    statement {
      rate_based_statement {
        limit              = 2000
        aggregate_key_type = "IP"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name               = "RateLimitRule"
      sampled_requests_enabled  = true
    }
  }

  # Rule 2: AWS Managed Common Rule Set
  rule {
    name     = "AWSManagedRulesCommonRuleSet"
    priority = 2

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name               = "CommonRuleSet"
      sampled_requests_enabled  = true
    }
  }

  # Rule 5: Block anonymous IPs for signup
  rule {
    name     = "BlockAnonymousIPsForSignup"
    priority = 5

    action {
      block {}
    }

    statement {
      and_statement {
        statement {
          managed_rule_group_statement {
            name        = "AWSManagedRulesAnonymousIpList"
            vendor_name = "AWS"
          }
        }
        statement {
          byte_match_statement {
            field_to_match {
              uri_path {}
            }
            positional_constraint = "STARTS_WITH"
            search_string         = "/api/v1/auth/signup"
            text_transformation {
              priority = 0
              type     = "LOWERCASE"
            }
          }
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name               = "AnonymousIPBlock"
      sampled_requests_enabled  = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name               = "APIWebACL"
    sampled_requests_enabled  = true
  }

  tags = var.tags
}
```

### 8.2 Environment Variables

**Staging Environment:** `infrastructure/terraform/staging.tfvars`

```hcl
project     = "a13e"
environment = "staging"
aws_region  = "eu-west-2"

# VPC
vpc_cidr = "10.0.0.0/16"

# Database
db_instance_class    = "db.t3.medium"
db_allocated_storage = 20
db_max_storage       = 100

# Cache
cache_node_type = "cache.t3.micro"

# ECS
task_cpu      = 512
task_memory   = 1024
desired_count = 2

# Frontend
frontend_domain = "staging.a13e.com"

# API
api_domain = "api.staging.a13e.com"

tags = {
  Project     = "a13e"
  Environment = "staging"
  ManagedBy   = "terraform"
}
```

---

## 9. Security Implementation

### 9.1 Authentication Flow

**File:** `backend/app/core/security.py` (excerpt)

```python
from datetime import datetime, timedelta, timezone
from typing import Optional
from uuid import UUID
import jwt
from passlib.context import CryptContext

from app.core.config import settings

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

class AuthService:
    """Authentication and token management."""

    @staticmethod
    def hash_password(password: str) -> str:
        """Hash password with BCrypt (12 rounds)."""
        return pwd_context.hash(password)

    @staticmethod
    def verify_password(plain: str, hashed: str) -> bool:
        """Verify password against hash."""
        return pwd_context.verify(plain, hashed)

    @staticmethod
    def generate_access_token(
        user_id: UUID,
        organization_id: UUID,
        expires_delta: Optional[timedelta] = None,
    ) -> str:
        """Generate JWT access token."""
        if expires_delta is None:
            expires_delta = timedelta(minutes=30)

        expire = datetime.now(timezone.utc) + expires_delta

        payload = {
            "sub": str(user_id),
            "org": str(organization_id),
            "exp": expire,
            "iat": datetime.now(timezone.utc),
            "type": "access",
            "jti": str(uuid.uuid4()),  # Unique token ID
        }

        return jwt.encode(payload, settings.secret_key, algorithm="HS256")

    @staticmethod
    def decode_token(token: str) -> dict:
        """Decode and validate JWT token."""
        try:
            payload = jwt.decode(
                token,
                settings.secret_key,
                algorithms=["HS256"],
            )
            return payload
        except jwt.ExpiredSignatureError:
            raise TokenExpiredError("Token has expired")
        except jwt.InvalidTokenError as e:
            raise InvalidTokenError(f"Invalid token: {e}")


def require_role(*allowed_roles: UserRole):
    """Dependency that requires specific user roles.

    IMPORTANT: This is exact match, NOT hierarchical.
    You must explicitly list all allowed roles.

    Example:
        # Allows Owner, Admin, and Member
        @router.get("/resource")
        async def get_resource(
            auth: AuthContext = Depends(
                require_role(UserRole.OWNER, UserRole.ADMIN, UserRole.MEMBER)
            )
        ):
            ...
    """
    async def dependency(
        request: Request,
        db: AsyncSession = Depends(get_db),
    ) -> AuthContext:
        # Extract and validate token
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Missing or invalid authorization header",
            )

        token = auth_header.split(" ")[1]
        payload = AuthService.decode_token(token)

        # Reject admin tokens on user endpoints
        if payload.get("type") == "admin":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Admin tokens cannot access user endpoints",
            )

        # Load user and membership
        user_id = UUID(payload["sub"])
        org_id = UUID(payload["org"])

        user = await get_user_by_id(db, user_id)
        membership = await get_membership(db, user_id, org_id)

        # Check role
        if membership.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Role {membership.role.value} not permitted",
            )

        return AuthContext(
            user=user,
            organization=membership.organization,
            membership=membership,
        )

    return dependency
```

### 9.2 Rate Limiting

**File:** `backend/app/api/deps/rate_limit.py`

```python
from fastapi import Request, HTTPException, status
from fastapi_limiter.depends import RateLimiter

# Auth endpoints: 5 attempts per 30 minutes per IP
auth_rate_limit = RateLimiter(times=5, minutes=30)

# Signup: 10 per hour per IP
signup_rate_limit = RateLimiter(times=10, hours=1)

# Password reset: 3 per hour per email
password_reset_rate_limit = RateLimiter(times=3, hours=1)

# General API: 100 per minute per user
general_rate_limit = RateLimiter(times=100, minutes=1)

async def check_rate_limit(
    request: Request,
    limiter: RateLimiter,
) -> None:
    """Check rate limit and raise 429 if exceeded."""
    allowed = await limiter(request)
    if not allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded. Please try again later.",
        )
```

### 9.3 Credential Encryption

**File:** `backend/app/services/credential_encryption.py`

```python
from cryptography.fernet import Fernet
from app.core.config import settings

class CredentialEncryption:
    """Encrypt/decrypt cloud credentials using Fernet."""

    def __init__(self):
        self.fernet = Fernet(settings.credential_encryption_key.encode())

    def encrypt(self, plaintext: str) -> bytes:
        """Encrypt credential string."""
        return self.fernet.encrypt(plaintext.encode())

    def decrypt(self, ciphertext: bytes) -> str:
        """Decrypt credential bytes."""
        return self.fernet.decrypt(ciphertext).decode()

credential_encryption = CredentialEncryption()
```

---

## 10. Error Handling

### 10.1 Exception Hierarchy

```python
# backend/app/core/exceptions.py

class A13EException(Exception):
    """Base exception for A13E application."""

    def __init__(self, message: str, error_code: str = "UNKNOWN_ERROR"):
        self.message = message
        self.error_code = error_code
        super().__init__(message)


class AuthenticationError(A13EException):
    """Authentication failed."""

    def __init__(self, message: str = "Authentication failed"):
        super().__init__(message, "AUTH_ERROR")


class TokenExpiredError(AuthenticationError):
    """JWT token has expired."""

    def __init__(self, message: str = "Token has expired"):
        super().__init__(message)
        self.error_code = "TOKEN_EXPIRED"


class AuthorisationError(A13EException):
    """User not authorised for this action."""

    def __init__(self, message: str = "Not authorised"):
        super().__init__(message, "AUTHORISATION_ERROR")


class ResourceNotFoundError(A13EException):
    """Requested resource not found."""

    def __init__(self, resource: str, identifier: str):
        message = f"{resource} with identifier '{identifier}' not found"
        super().__init__(message, "NOT_FOUND")


class ValidationError(A13EException):
    """Input validation failed."""

    def __init__(self, message: str, field_errors: list[dict] = None):
        super().__init__(message, "VALIDATION_ERROR")
        self.field_errors = field_errors or []


class RateLimitError(A13EException):
    """Rate limit exceeded."""

    def __init__(self, message: str = "Rate limit exceeded"):
        super().__init__(message, "RATE_LIMIT_EXCEEDED")


class ScanError(A13EException):
    """Error during cloud scanning."""

    def __init__(self, message: str, cloud_provider: str = None):
        super().__init__(message, "SCAN_ERROR")
        self.cloud_provider = cloud_provider
```

### 10.2 Global Exception Handler

**File:** `backend/app/core/exception_handlers.py`

```python
from fastapi import Request
from fastapi.responses import JSONResponse
from app.core.exceptions import (
    A13EException,
    AuthenticationError,
    AuthorisationError,
    ResourceNotFoundError,
    ValidationError,
    RateLimitError,
)
import structlog

logger = structlog.get_logger()

async def a13e_exception_handler(
    request: Request, exc: A13EException
) -> JSONResponse:
    """Handle A13E application exceptions."""

    # Map exception types to HTTP status codes
    status_map = {
        AuthenticationError: 401,
        AuthorisationError: 403,
        ResourceNotFoundError: 404,
        ValidationError: 400,
        RateLimitError: 429,
    }

    status_code = status_map.get(type(exc), 500)

    # Log error
    logger.warning(
        "application_error",
        error_code=exc.error_code,
        message=exc.message,
        path=request.url.path,
        status_code=status_code,
    )

    response = {
        "detail": exc.message,
        "error_code": exc.error_code,
    }

    # Include field errors for validation exceptions
    if isinstance(exc, ValidationError) and exc.field_errors:
        response["field_errors"] = exc.field_errors

    return JSONResponse(
        status_code=status_code,
        content=response,
    )


async def generic_exception_handler(
    request: Request, exc: Exception
) -> JSONResponse:
    """Handle unexpected exceptions."""

    logger.error(
        "unhandled_exception",
        error=str(exc),
        path=request.url.path,
        exc_info=True,
    )

    return JSONResponse(
        status_code=500,
        content={
            "detail": "An unexpected error occurred",
            "error_code": "INTERNAL_ERROR",
        },
    )
```

---

## Appendices

### A. API Endpoint Summary

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| POST | /auth/signup | Create account | No |
| POST | /auth/login | Authenticate | No |
| POST | /auth/logout | End session | Yes |
| POST | /auth/refresh-session | Refresh token | Cookie |
| GET | /accounts | List accounts | Yes |
| POST | /accounts | Create account | Yes (Admin+) |
| GET | /accounts/{id} | Get account | Yes |
| DELETE | /accounts/{id} | Delete account | Yes (Admin+) |
| POST | /accounts/{id}/scans | Start scan | Yes (Member+) |
| GET | /scans/{id} | Get scan status | Yes |
| GET | /detections | List detections | Yes |
| GET | /coverage | Get coverage | Yes |
| GET | /compliance/frameworks | List frameworks | Yes |
| GET | /compliance/coverage | Get compliance | Yes |
| GET | /gaps | List gaps | Yes |

### B. Database Migration Commands

```bash
# Create new migration
alembic revision --autogenerate -m "description"

# Apply migrations
alembic upgrade head

# Rollback one migration
alembic downgrade -1

# Show current revision
alembic current

# Show migration history
alembic history
```

### C. Local Development

```bash
# Backend
cd backend
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

# Frontend
cd frontend
npm install
npm run dev

# Database (Docker)
docker-compose up -d postgres redis
```

---

**Document Control**

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 24 Dec 2025 | Architecture Team | Initial release |
| 1.1 | 25 Dec 2025 | Architecture Team | Added Optimised EventBridge Template Pattern (§5.5) |
