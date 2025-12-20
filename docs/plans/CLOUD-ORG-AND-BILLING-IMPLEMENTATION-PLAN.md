# Cloud Organisation & Billing Model Implementation Plan

**Document Version:** 1.1
**Created:** 2024-12-20
**Status:** Planning
**Estimated Total Effort:** 8-12 weeks

---

## Executive Summary

This plan outlines the implementation of two major features:

1. **Simplified Billing Model**: Replace complex per-account pricing with a clear three-tier structure (Individual, Pro, Enterprise)
2. **Cloud Organisation Support**: Enable scanning of AWS Organizations and GCP Organizations with centralised detection coverage

These features are interconnected—Pro tier unlocks organisation-level capabilities.

**Supported Cloud Providers:** AWS and GCP (both included in all tiers)

---

## Table of Contents

1. [Data Model](#1-data-model)
2. [New Billing Model](#2-new-billing-model)
3. [Cloud Organisation Architecture](#3-cloud-organisation-architecture)
4. [Phase 1: Billing Model Update](#phase-1-billing-model-update)
5. [Phase 2: Cloud Organisation Foundation](#phase-2-cloud-organisation-foundation)
6. [Phase 3: AWS Organisation Scanning](#phase-3-aws-organisation-scanning)
7. [Phase 4: GCP Organisation Scanning](#phase-4-gcp-organisation-scanning)
8. [Phase 5: Coverage Calculation Updates](#phase-5-coverage-calculation-updates)
9. [Phase 6: Frontend Organisation UX](#phase-6-frontend-organisation-ux)
10. [Migration Strategy](#migration-strategy)
11. [Testing Strategy](#testing-strategy)
12. [Rollback Plan](#rollback-plan)

---

## 1. Data Model

### 1.1 Entity Relationship Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              TENANT LAYER                                    │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌──────────────────┐         ┌──────────────────┐                          │
│  │   Organization   │─────────│   Subscription   │                          │
│  │   (our tenant)   │   1:1   │   (billing)      │                          │
│  └────────┬─────────┘         └──────────────────┘                          │
│           │                                                                  │
│           │ 1:N                                                              │
│           ▼                                                                  │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │                     CLOUD PROVIDER LAYER                              │   │
│  ├──────────────────────────────────────────────────────────────────────┤   │
│  │                                                                       │   │
│  │  ┌─────────────────────┐                ┌─────────────────────┐      │   │
│  │  │  CloudOrganization  │                │  CloudOrganization  │      │   │
│  │  │  (AWS Organization) │                │  (GCP Organization) │      │   │
│  │  │  provider: "aws"    │                │  provider: "gcp"    │      │   │
│  │  │  cloud_org_id:      │                │  cloud_org_id:      │      │   │
│  │  │  "o-xxxxxxxxxx"     │                │  "organizations/123"│      │   │
│  │  └──────────┬──────────┘                └──────────┬──────────┘      │   │
│  │             │                                      │                  │   │
│  │             │ 1:N                                  │ 1:N              │   │
│  │             ▼                                      ▼                  │   │
│  │  ┌─────────────────────┐                ┌─────────────────────┐      │   │
│  │  │ CloudOrgMember      │                │ CloudOrgMember      │      │   │
│  │  │ (AWS Account)       │                │ (GCP Project)       │      │   │
│  │  │ account_id: "123.." │                │ project_id: "my-pr."│      │   │
│  │  │ ou_path: "Prod/Web" │                │ folder_path: "Prod" │      │   │
│  │  └──────────┬──────────┘                └──────────┬──────────┘      │   │
│  │             │                                      │                  │   │
│  │             │ 1:1 (when connected)                 │ 1:1              │   │
│  │             ▼                                      ▼                  │   │
│  │  ┌───────────────────────────────────────────────────────────────┐   │   │
│  │  │                      CloudAccount                              │   │   │
│  │  │  (Connected account - has credentials & can be scanned)       │   │   │
│  │  │  provider: "aws" | "gcp"                                       │   │   │
│  │  │  account_id: "123456789012" | "my-project-id"                 │   │   │
│  │  │  cloud_organization_id: FK (nullable for standalone)          │   │   │
│  │  └───────────────────────────────────────────────────────────────┘   │   │
│  │                                                                       │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│                            DETECTION LAYER                                   │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  Detections can be scoped to:                                                │
│  • CloudOrganization (org-level, applies to all/some member accounts)       │
│  • CloudAccount (account-specific)                                           │
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │                          Detection                                   │    │
│  │  cloud_organization_id: FK (nullable)  ← Org-level detection        │    │
│  │  cloud_account_id: FK (nullable)       ← Account-level detection    │    │
│  │  applies_to_all_accounts: bool         ← For org detections         │    │
│  │  applies_to_account_ids: JSONB         ← Specific accounts          │    │
│  │                                                                      │    │
│  │  CHECK: cloud_organization_id IS NOT NULL                           │    │
│  │         OR cloud_account_id IS NOT NULL                             │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│                            COVERAGE LAYER                                    │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  Coverage calculation includes:                                              │
│  • Account-specific detections                                               │
│  • Inherited org-level detections (if account belongs to a CloudOrg)       │
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │                     CoverageSnapshot                                 │    │
│  │  cloud_account_id: FK           ← Per-account snapshot              │    │
│  │  cloud_organization_id: FK      ← Org-wide snapshot (aggregate)     │    │
│  │  includes_org_detections: bool  ← Did we include org detections?    │    │
│  │  org_detection_count: int       ← How many from org level           │    │
│  │  org_covered_techniques: int    ← Techniques covered by org dets    │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 1.2 New Tables

#### `cloud_organizations`

Represents an AWS Organization or GCP Organization.

```sql
CREATE TABLE cloud_organizations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,

    -- Cloud provider identity
    provider VARCHAR(10) NOT NULL CHECK (provider IN ('aws', 'gcp')),
    cloud_org_id VARCHAR(64) NOT NULL,
    name VARCHAR(255) NOT NULL,

    -- AWS Organization specific fields
    aws_org_arn VARCHAR(255),                    -- arn:aws:organizations::123:organization/o-xxx
    management_account_id VARCHAR(20),            -- AWS management account ID
    management_account_email VARCHAR(255),

    -- GCP Organization specific fields
    gcp_display_name VARCHAR(255),
    gcp_directory_customer_id VARCHAR(64),        -- Google Workspace customer ID
    gcp_lifecycle_state VARCHAR(50),              -- ACTIVE, DELETE_REQUESTED, etc.

    -- Connection state
    is_connected BOOLEAN DEFAULT FALSE,
    connection_status VARCHAR(50) DEFAULT 'pending'
        CHECK (connection_status IN (
            'pending', 'discovering', 'connected', 'partial', 'error', 'disconnected'
        )),
    connection_error TEXT,
    last_connection_attempt TIMESTAMPTZ,

    -- Discovery tracking
    last_discovered_at TIMESTAMPTZ,
    discovered_accounts_count INTEGER DEFAULT 0,
    connected_accounts_count INTEGER DEFAULT 0,

    -- Org-level credential (for management/admin account)
    org_credential_id UUID REFERENCES cloud_credentials(id) ON DELETE SET NULL,

    -- Metadata
    settings JSONB DEFAULT '{}',                  -- Provider-specific settings
    tags JSONB DEFAULT '{}',                      -- User-defined tags

    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),

    -- Constraints
    UNIQUE(organization_id, provider, cloud_org_id)
);

-- Indexes
CREATE INDEX idx_cloud_orgs_org_id ON cloud_organizations(organization_id);
CREATE INDEX idx_cloud_orgs_provider ON cloud_organizations(provider);
CREATE INDEX idx_cloud_orgs_status ON cloud_organizations(connection_status);
```

#### `cloud_organization_members`

Tracks discovered member accounts/projects (before they're connected as CloudAccounts).

```sql
CREATE TABLE cloud_organization_members (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    cloud_organization_id UUID NOT NULL REFERENCES cloud_organizations(id) ON DELETE CASCADE,

    -- Cloud provider identity
    provider VARCHAR(10) NOT NULL CHECK (provider IN ('aws', 'gcp')),

    -- AWS Account fields
    aws_account_id VARCHAR(20),                   -- 12-digit AWS account ID
    aws_account_name VARCHAR(255),
    aws_account_email VARCHAR(255),
    aws_account_status VARCHAR(50),               -- ACTIVE, SUSPENDED, PENDING_CLOSURE
    aws_joined_method VARCHAR(50),                -- INVITED, CREATED

    -- GCP Project fields
    gcp_project_id VARCHAR(64),                   -- my-project-id
    gcp_project_number VARCHAR(20),               -- 123456789
    gcp_project_name VARCHAR(255),
    gcp_project_state VARCHAR(50),                -- ACTIVE, DELETE_REQUESTED, etc.
    gcp_parent_type VARCHAR(20),                  -- folder, organization
    gcp_parent_id VARCHAR(64),

    -- Hierarchy path (for both providers)
    -- AWS: "Root/Production/WebServices"
    -- GCP: "folders/123/folders/456"
    hierarchy_path VARCHAR(512),
    hierarchy_level INTEGER DEFAULT 0,

    -- AWS OU information
    ou_id VARCHAR(64),
    ou_name VARCHAR(255),

    -- GCP Folder information
    folder_id VARCHAR(64),
    folder_display_name VARCHAR(255),

    -- Connection to our CloudAccount (once connected)
    linked_cloud_account_id UUID REFERENCES cloud_accounts(id) ON DELETE SET NULL,
    is_auto_connected BOOLEAN DEFAULT FALSE,
    auto_connect_failed_reason TEXT,

    -- Discovery metadata
    discovered_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    last_sync_at TIMESTAMPTZ,

    -- Constraints
    UNIQUE(cloud_organization_id, provider, COALESCE(aws_account_id, gcp_project_id))
);

-- Indexes
CREATE INDEX idx_org_members_cloud_org ON cloud_organization_members(cloud_organization_id);
CREATE INDEX idx_org_members_linked ON cloud_organization_members(linked_cloud_account_id);
CREATE INDEX idx_org_members_aws_account ON cloud_organization_members(aws_account_id) WHERE aws_account_id IS NOT NULL;
CREATE INDEX idx_org_members_gcp_project ON cloud_organization_members(gcp_project_id) WHERE gcp_project_id IS NOT NULL;
CREATE INDEX idx_org_members_hierarchy ON cloud_organization_members(hierarchy_path);
```

### 1.3 Modified Tables

#### `cloud_accounts` (add columns)

```sql
-- Add cloud organization relationship
ALTER TABLE cloud_accounts
ADD COLUMN cloud_organization_id UUID REFERENCES cloud_organizations(id) ON DELETE SET NULL;

-- Add role flags (for AWS delegated admin, GCP service account)
ALTER TABLE cloud_accounts
ADD COLUMN is_management_account BOOLEAN DEFAULT FALSE,
ADD COLUMN is_delegated_admin BOOLEAN DEFAULT FALSE,
ADD COLUMN delegated_admin_services JSONB DEFAULT '[]';  -- ['guardduty', 'securityhub', 'config']

-- Add hierarchy information
ALTER TABLE cloud_accounts
ADD COLUMN hierarchy_path VARCHAR(512),  -- Same as org_member for easy querying
ADD COLUMN ou_id VARCHAR(64),            -- AWS OU ID
ADD COLUMN folder_id VARCHAR(64);        -- GCP Folder ID

-- Indexes
CREATE INDEX idx_accounts_cloud_org ON cloud_accounts(cloud_organization_id);
CREATE INDEX idx_accounts_hierarchy ON cloud_accounts(hierarchy_path);
```

#### `detections` (support org-level)

```sql
-- Make cloud_account_id nullable (was NOT NULL)
ALTER TABLE detections
ALTER COLUMN cloud_account_id DROP NOT NULL;

-- Add org-level detection support
ALTER TABLE detections
ADD COLUMN cloud_organization_id UUID REFERENCES cloud_organizations(id) ON DELETE CASCADE,
ADD COLUMN detection_scope VARCHAR(20) DEFAULT 'account'
    CHECK (detection_scope IN ('account', 'organization')),
ADD COLUMN applies_to_all_accounts BOOLEAN DEFAULT FALSE,
ADD COLUMN applies_to_account_ids JSONB;  -- Specific account IDs if not all

-- Ensure detection has proper scope
ALTER TABLE detections
ADD CONSTRAINT detection_scope_check
CHECK (
    (detection_scope = 'account' AND cloud_account_id IS NOT NULL)
    OR
    (detection_scope = 'organization' AND cloud_organization_id IS NOT NULL)
);

-- Index for org-level queries
CREATE INDEX idx_detections_cloud_org ON detections(cloud_organization_id)
    WHERE cloud_organization_id IS NOT NULL;
CREATE INDEX idx_detections_scope ON detections(detection_scope);
```

#### `coverage_snapshots` (track org contribution)

```sql
ALTER TABLE coverage_snapshots
ADD COLUMN includes_org_detections BOOLEAN DEFAULT FALSE,
ADD COLUMN org_detection_count INTEGER DEFAULT 0,
ADD COLUMN org_covered_techniques INTEGER DEFAULT 0,
ADD COLUMN cloud_organization_id UUID REFERENCES cloud_organizations(id) ON DELETE CASCADE,
ADD COLUMN coverage_breakdown JSONB DEFAULT '{}';
-- coverage_breakdown example:
-- {
--   "account_detections": 15,
--   "org_detections": 8,
--   "account_techniques": 25,
--   "org_techniques": 12,
--   "overlap_techniques": 5  -- Techniques covered by BOTH
-- }

-- Index for org-level coverage queries
CREATE INDEX idx_coverage_cloud_org ON coverage_snapshots(cloud_organization_id)
    WHERE cloud_organization_id IS NOT NULL;
```

#### `subscriptions` (new tier system)

```sql
-- First, add new tier values if using enum
-- ALTER TYPE account_tier ADD VALUE 'pro' IF NOT EXISTS;

-- Update subscription fields for new model
ALTER TABLE subscriptions
ADD COLUMN IF NOT EXISTS max_accounts INTEGER,
ADD COLUMN IF NOT EXISTS max_team_members INTEGER,
ADD COLUMN IF NOT EXISTS org_features_enabled BOOLEAN DEFAULT FALSE,
ADD COLUMN IF NOT EXISTS history_retention_days INTEGER DEFAULT 30,
ADD COLUMN IF NOT EXISTS tier_config JSONB DEFAULT '{}';

-- Note: Actual tier limits defined in application code (billing_config.py)
```

### 1.4 New Enums

```python
# backend/app/models/enums.py

class CloudOrgConnectionStatus(str, Enum):
    """Connection status for a cloud organization."""
    PENDING = "pending"              # Initial state
    DISCOVERING = "discovering"      # Discovery in progress
    CONNECTED = "connected"          # Fully connected
    PARTIAL = "partial"              # Some accounts connected
    ERROR = "error"                  # Connection failed
    DISCONNECTED = "disconnected"    # Manually disconnected

class DetectionScope(str, Enum):
    """Scope of a detection."""
    ACCOUNT = "account"              # Specific to one account
    ORGANIZATION = "organization"    # Applies to org/multiple accounts

class OrgMemberStatus(str, Enum):
    """Status of an org member account/project."""
    DISCOVERED = "discovered"        # Found but not connected
    CONNECTING = "connecting"        # Connection in progress
    CONNECTED = "connected"          # Linked to CloudAccount
    FAILED = "failed"                # Connection failed
    EXCLUDED = "excluded"            # Manually excluded by user
```

### 1.5 SQLAlchemy Models

#### `CloudOrganization`

```python
# backend/app/models/cloud_organization.py

from sqlalchemy import Column, String, Boolean, Integer, ForeignKey, DateTime, Enum as SQLEnum, Text
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import relationship, Mapped, mapped_column
from uuid import uuid4
from datetime import datetime

from app.core.database import Base
from app.models.enums import CloudProvider, CloudOrgConnectionStatus


class CloudOrganization(Base):
    """Represents an AWS Organization or GCP Organization."""

    __tablename__ = "cloud_organizations"

    id: Mapped[UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    organization_id: Mapped[UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )

    # Cloud provider identity
    provider: Mapped[CloudProvider] = mapped_column(SQLEnum(CloudProvider), nullable=False)
    cloud_org_id: Mapped[str] = mapped_column(String(64), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)

    # AWS-specific
    aws_org_arn: Mapped[str | None] = mapped_column(String(255))
    management_account_id: Mapped[str | None] = mapped_column(String(20))
    management_account_email: Mapped[str | None] = mapped_column(String(255))

    # GCP-specific
    gcp_display_name: Mapped[str | None] = mapped_column(String(255))
    gcp_directory_customer_id: Mapped[str | None] = mapped_column(String(64))
    gcp_lifecycle_state: Mapped[str | None] = mapped_column(String(50))

    # Connection state
    is_connected: Mapped[bool] = mapped_column(Boolean, default=False)
    connection_status: Mapped[CloudOrgConnectionStatus] = mapped_column(
        SQLEnum(CloudOrgConnectionStatus),
        default=CloudOrgConnectionStatus.PENDING
    )
    connection_error: Mapped[str | None] = mapped_column(Text)
    last_connection_attempt: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    # Discovery tracking
    last_discovered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    discovered_accounts_count: Mapped[int] = mapped_column(Integer, default=0)
    connected_accounts_count: Mapped[int] = mapped_column(Integer, default=0)

    # Org-level credential
    org_credential_id: Mapped[UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("cloud_credentials.id", ondelete="SET NULL")
    )

    # Metadata
    settings: Mapped[dict] = mapped_column(JSONB, default=dict)
    tags: Mapped[dict] = mapped_column(JSONB, default=dict)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=datetime.utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=datetime.utcnow,
        onupdate=datetime.utcnow
    )

    # Relationships
    organization = relationship("Organization", back_populates="cloud_organizations")
    cloud_accounts = relationship("CloudAccount", back_populates="cloud_organization")
    members = relationship("CloudOrganizationMember", back_populates="cloud_organization", cascade="all, delete-orphan")
    org_detections = relationship(
        "Detection",
        back_populates="cloud_organization",
        foreign_keys="Detection.cloud_organization_id"
    )
    org_credential = relationship("CloudCredential", foreign_keys=[org_credential_id])

    def __repr__(self) -> str:
        return f"<CloudOrganization {self.provider}:{self.cloud_org_id}>"
```

#### `CloudOrganizationMember`

```python
# backend/app/models/cloud_organization.py (continued)

class CloudOrganizationMember(Base):
    """Represents a discovered member account/project in a cloud organization."""

    __tablename__ = "cloud_organization_members"

    id: Mapped[UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    cloud_organization_id: Mapped[UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("cloud_organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    provider: Mapped[CloudProvider] = mapped_column(SQLEnum(CloudProvider), nullable=False)

    # AWS Account fields
    aws_account_id: Mapped[str | None] = mapped_column(String(20), index=True)
    aws_account_name: Mapped[str | None] = mapped_column(String(255))
    aws_account_email: Mapped[str | None] = mapped_column(String(255))
    aws_account_status: Mapped[str | None] = mapped_column(String(50))
    aws_joined_method: Mapped[str | None] = mapped_column(String(50))

    # GCP Project fields
    gcp_project_id: Mapped[str | None] = mapped_column(String(64), index=True)
    gcp_project_number: Mapped[str | None] = mapped_column(String(20))
    gcp_project_name: Mapped[str | None] = mapped_column(String(255))
    gcp_project_state: Mapped[str | None] = mapped_column(String(50))
    gcp_parent_type: Mapped[str | None] = mapped_column(String(20))
    gcp_parent_id: Mapped[str | None] = mapped_column(String(64))

    # Hierarchy (both providers)
    hierarchy_path: Mapped[str | None] = mapped_column(String(512), index=True)
    hierarchy_level: Mapped[int] = mapped_column(Integer, default=0)

    # AWS OU
    ou_id: Mapped[str | None] = mapped_column(String(64))
    ou_name: Mapped[str | None] = mapped_column(String(255))

    # GCP Folder
    folder_id: Mapped[str | None] = mapped_column(String(64))
    folder_display_name: Mapped[str | None] = mapped_column(String(255))

    # Link to CloudAccount
    linked_cloud_account_id: Mapped[UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("cloud_accounts.id", ondelete="SET NULL"),
        index=True
    )
    is_auto_connected: Mapped[bool] = mapped_column(Boolean, default=False)
    auto_connect_failed_reason: Mapped[str | None] = mapped_column(Text)

    # Timestamps
    discovered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow, onupdate=datetime.utcnow)
    last_sync_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    # Relationships
    cloud_organization = relationship("CloudOrganization", back_populates="members")
    linked_cloud_account = relationship("CloudAccount", back_populates="org_member")

    @property
    def account_id(self) -> str:
        """Return the account/project ID regardless of provider."""
        return self.aws_account_id or self.gcp_project_id or ""

    @property
    def display_name(self) -> str:
        """Return a display name regardless of provider."""
        return self.aws_account_name or self.gcp_project_name or self.account_id

    def __repr__(self) -> str:
        return f"<CloudOrganizationMember {self.provider}:{self.account_id}>"
```

### 1.6 Provider-Specific Hierarchy

#### AWS Organization Structure

```
AWS Organization (o-xxxxxxxxxx)
│
├── Root (r-xxxx)
│   │
│   ├── OU: Security (ou-xxxx-xxxxxxxx)
│   │   └── Account: security-tooling (123456789012)
│   │       is_delegated_admin: true
│   │       delegated_admin_services: ['guardduty', 'securityhub']
│   │
│   ├── OU: Production (ou-xxxx-yyyyyyyy)
│   │   ├── OU: WebServices (ou-xxxx-zzzzzzzz)
│   │   │   ├── Account: prod-web-1 (234567890123)
│   │   │   └── Account: prod-web-2 (345678901234)
│   │   │
│   │   └── OU: DataServices (ou-xxxx-aaaaaaaa)
│   │       └── Account: prod-data-1 (456789012345)
│   │
│   └── OU: Development (ou-xxxx-bbbbbbbb)
│       └── Account: dev-sandbox (567890123456)
│
└── Management Account (111111111111)
    is_management_account: true
```

**Hierarchy Path Examples:**
- `Root/Security` → security-tooling
- `Root/Production/WebServices` → prod-web-1, prod-web-2
- `Root/Production/DataServices` → prod-data-1
- `Root/Development` → dev-sandbox

#### GCP Organization Structure

```
GCP Organization (organizations/123456789)
│
├── Folder: Production (folders/111111111111)
│   │
│   ├── Folder: Web (folders/222222222222)
│   │   ├── Project: prod-web-frontend (prod-web-frontend-a1b2)
│   │   └── Project: prod-web-backend (prod-web-backend-c3d4)
│   │
│   └── Folder: Data (folders/333333333333)
│       └── Project: prod-data-warehouse (prod-data-wh-e5f6)
│
├── Folder: Development (folders/444444444444)
│   └── Project: dev-sandbox (dev-sandbox-g7h8)
│
├── Folder: Security (folders/555555555555)
│   └── Project: security-monitoring (sec-mon-i9j0)
│       has_scc_premium: true
│       has_org_log_sinks: true
│
└── Standalone Projects (directly under org)
    └── Project: legacy-app (legacy-app-k1l2)
```

**Hierarchy Path Examples:**
- `Production/Web` → prod-web-frontend, prod-web-backend
- `Production/Data` → prod-data-warehouse
- `Development` → dev-sandbox
- `Security` → security-monitoring
- `` (empty) → legacy-app (standalone)

---

## 2. New Billing Model

### 2.1 Tier Structure

| Tier | Monthly Price | Account Limit | Key Differentiator |
|------|---------------|---------------|-------------------|
| **Free** | $0 | 1 account | Try it out |
| **Individual** | $29/month | Up to 6 accounts | Account-level policies only |
| **Pro** | $250/month | Up to 500 accounts | Org-level + account-level policies |
| **Enterprise** | Custom | 500+ accounts | SSO, dedicated support, SLAs |

### 2.2 Upgrade Logic

```
User has 1 account       → Free (or Individual for extra features)
User has 2-6 accounts    → Individual ($29/month)
User has 7+ accounts     → Pro ($250/month) *required*
User wants org features  → Pro ($250/month) *even with <7 accounts*
User has 500+ accounts   → Enterprise (contact sales)
```

### 2.3 Feature Matrix

| Feature | Free | Individual | Pro | Enterprise |
|---------|------|------------|-----|------------|
| AWS account connection | ✓ | ✓ | ✓ | ✓ |
| GCP project connection | ✓ | ✓ | ✓ | ✓ |
| All detection scanners | ✓ | ✓ | ✓ | ✓ |
| MITRE ATT&CK mapping | ✓ | ✓ | ✓ | ✓ |
| Remediation templates | ✓ | ✓ | ✓ | ✓ |
| Account-level policies | ✓ | ✓ | ✓ | ✓ |
| Scheduled scans | - | ✓ | ✓ | ✓ |
| API access | - | ✓ | ✓ | ✓ |
| Team members | 1 | 3 | 10 | Unlimited |
| History retention | 30 days | 90 days | 1 year | Unlimited |
| **AWS Organisation connection** | - | - | ✓ | ✓ |
| **GCP Organisation connection** | - | - | ✓ | ✓ |
| **Auto-discovery of accounts** | - | - | ✓ | ✓ |
| **Org-level detection scanning** | - | - | ✓ | ✓ |
| **Unified org coverage dashboard** | - | - | ✓ | ✓ |
| **Delegated admin scanning** | - | - | ✓ | ✓ |
| SSO/SAML | - | - | - | ✓ |
| Dedicated support | - | - | - | ✓ |
| Custom SLAs | - | - | - | ✓ |

### 2.4 Billing Configuration

```python
# backend/app/core/billing_config.py

from app.models.billing import AccountTier

# Prices in cents (USD)
TIER_CONFIG = {
    AccountTier.FREE: {
        "display_name": "Free",
        "price_monthly_cents": 0,
        "max_accounts": 1,
        "max_team_members": 1,
        "history_retention_days": 30,
        "features": {
            "scheduled_scans": False,
            "api_access": False,
            "org_features": False,
            "export_reports": False,
        },
    },
    AccountTier.INDIVIDUAL: {
        "display_name": "Individual",
        "price_monthly_cents": 2900,  # $29/month
        "max_accounts": 6,
        "max_team_members": 3,
        "history_retention_days": 90,
        "features": {
            "scheduled_scans": True,
            "api_access": True,
            "org_features": False,  # Account-level only
            "export_reports": True,
        },
    },
    AccountTier.PRO: {
        "display_name": "Pro",
        "price_monthly_cents": 25000,  # $250/month
        "max_accounts": 500,
        "max_team_members": 10,
        "history_retention_days": 365,
        "features": {
            "scheduled_scans": True,
            "api_access": True,
            "org_features": True,  # Org + Account level
            "export_reports": True,
            "org_dashboard": True,
            "auto_discovery": True,
            "delegated_scanning": True,
        },
    },
    AccountTier.ENTERPRISE: {
        "display_name": "Enterprise",
        "price_monthly_cents": None,  # Custom pricing
        "max_accounts": None,  # Unlimited (500+)
        "max_team_members": None,  # Unlimited
        "history_retention_days": None,  # Unlimited
        "features": {
            "scheduled_scans": True,
            "api_access": True,
            "org_features": True,
            "export_reports": True,
            "org_dashboard": True,
            "auto_discovery": True,
            "delegated_scanning": True,
            "sso_saml": True,
            "dedicated_support": True,
            "custom_integrations": True,
            "sla": True,
        },
    },
}

def get_required_tier(account_count: int, wants_org_features: bool) -> AccountTier:
    """Determine the minimum required tier based on usage."""
    if wants_org_features:
        return AccountTier.PRO
    if account_count > 500:
        return AccountTier.ENTERPRISE
    if account_count > 6:
        return AccountTier.PRO
    if account_count > 1:
        return AccountTier.INDIVIDUAL
    return AccountTier.FREE
```

---

## 3. Cloud Organisation Architecture

### 3.1 Detection Inheritance Model

```
                    ┌─────────────────────────────────┐
                    │      CloudOrganization          │
                    │      (AWS Org / GCP Org)        │
                    └───────────────┬─────────────────┘
                                    │
                    ┌───────────────▼─────────────────┐
                    │     Org-Level Detections        │
                    │                                  │
                    │ AWS:                             │
                    │ • Organization CloudTrail        │
                    │ • Delegated GuardDuty           │
                    │ • Security Hub Aggregator       │
                    │ • Config Aggregator             │
                    │                                  │
                    │ GCP:                             │
                    │ • Org Log Sinks                 │
                    │ • Security Command Center       │
                    │ • Organization Policies         │
                    └───────────────┬─────────────────┘
                                    │
            ┌───────────────────────┼───────────────────────┐
            │                       │                       │
            ▼                       ▼                       ▼
    ┌───────────────┐       ┌───────────────┐       ┌───────────────┐
    │ Account A     │       │ Account B     │       │ Account C     │
    │ (AWS/GCP)     │       │ (AWS/GCP)     │       │ (AWS/GCP)     │
    │               │       │               │       │               │
    │ Own dets: 5   │       │ Own dets: 12  │       │ Own dets: 3   │
    │ + Org: 8      │       │ + Org: 8      │       │ + Org: 8      │
    │ ─────────     │       │ ─────────     │       │ ─────────     │
    │ Total: 13     │       │ Total: 20     │       │ Total: 11     │
    │ Coverage: 68% │       │ Coverage: 82% │       │ Coverage: 61% │
    └───────────────┘       └───────────────┘       └───────────────┘
```

### 3.2 Org-Level Detection Types

#### AWS Organization

| Detection Type | Source | Applies To |
|---------------|--------|------------|
| Organization CloudTrail | Management account | All member accounts |
| Delegated GuardDuty | Delegated admin account | All enabled members |
| Security Hub Aggregator | Aggregator account | All linked accounts |
| Config Aggregator | Aggregator account | All linked accounts/regions |
| SCPs | Organization | All accounts in scope |

#### GCP Organization

| Detection Type | Source | Applies To |
|---------------|--------|------------|
| Org Log Sinks | Organization | All projects |
| Folder Log Sinks | Folder | All projects in folder |
| Security Command Center | Organization | All projects |
| Organization Policies | Org/Folder | Projects in scope |
| Asset Inventory | Organization | All projects |

---

## Phase 1: Billing Model Update

**Duration:** 1-2 weeks
**Dependencies:** None

### Tasks

#### Backend

- [ ] **1.1** Update `AccountTier` enum with new values
- [ ] **1.2** Create `billing_config.py` with tier configuration
- [ ] **1.3** Update `Subscription` model with new fields
- [ ] **1.4** Create `BillingService.check_feature_enabled()` method
- [ ] **1.5** Create `require_org_features` dependency for protected routes
- [ ] **1.6** Update `/billing/pricing` endpoint for new tiers
- [ ] **1.7** Create database migration for subscription changes
- [ ] **1.8** Create data migration for existing subscribers

#### Frontend

- [ ] **1.9** Update pricing page with new tiers
- [ ] **1.10** Add usage meters (accounts used vs limit)
- [ ] **1.11** Add upgrade prompts for org features
- [ ] **1.12** Update settings page subscription display

### Acceptance Criteria

- [ ] New tiers correctly limit account creation
- [ ] Org features blocked for Free/Individual tiers
- [ ] Existing subscribers migrated appropriately
- [ ] Pricing page displays new structure

---

## Phase 2: Cloud Organisation Foundation

**Duration:** 2-3 weeks
**Dependencies:** Phase 1

### Tasks

#### Database

- [ ] **2.1** Create migration for `cloud_organizations` table
- [ ] **2.2** Create migration for `cloud_organization_members` table
- [ ] **2.3** Create migration for `cloud_accounts` new columns
- [ ] **2.4** Create migration for `detections` org-level support
- [ ] **2.5** Create migration for `coverage_snapshots` org tracking

#### Models

- [ ] **2.6** Create `CloudOrganization` SQLAlchemy model
- [ ] **2.7** Create `CloudOrganizationMember` SQLAlchemy model
- [ ] **2.8** Update `CloudAccount` model with org relationship
- [ ] **2.9** Update `Detection` model with org scope
- [ ] **2.10** Update `CoverageSnapshot` model

#### Schemas

- [ ] **2.11** Create `CloudOrganizationCreate` schema
- [ ] **2.12** Create `CloudOrganizationResponse` schema
- [ ] **2.13** Create `CloudOrganizationMemberResponse` schema
- [ ] **2.14** Create `OrgDiscoveryResult` schema

#### API Routes

- [ ] **2.15** Create `/cloud-organizations` router
- [ ] **2.16** Implement `GET /cloud-organizations`
- [ ] **2.17** Implement `POST /cloud-organizations/aws/discover`
- [ ] **2.18** Implement `POST /cloud-organizations/gcp/discover`
- [ ] **2.19** Implement `GET /cloud-organizations/{id}`
- [ ] **2.20** Implement `GET /cloud-organizations/{id}/members`
- [ ] **2.21** Implement `DELETE /cloud-organizations/{id}`

### Acceptance Criteria

- [ ] CloudOrganization CRUD operations work
- [ ] Can store AWS and GCP org structures
- [ ] Member accounts tracked with hierarchy
- [ ] Pro tier gate enforced

---

## Phase 3: AWS Organisation Scanning

**Duration:** 3-4 weeks
**Dependencies:** Phase 2

### Tasks

#### Discovery Service

- [ ] **3.1** Create `AWSOrganizationDiscoveryService`
- [ ] **3.2** Implement `discover_organization()` - calls Organizations API
- [ ] **3.3** Implement `build_ou_tree()` - builds hierarchy
- [ ] **3.4** Implement `discover_delegated_admins()` - finds GuardDuty/SecHub admins
- [ ] **3.5** Implement `sync_membership()` - updates member list

#### Org-Level Scanners

- [ ] **3.6** Create `OrganizationCloudTrailScanner`
- [ ] **3.7** Create `DelegatedGuardDutyScanner`
- [ ] **3.8** Create `SecurityHubAggregatorScanner`
- [ ] **3.9** Create `ConfigAggregatorScanner`
- [ ] **3.10** Create `SCPScanner` (preventive controls)

#### Org Scan Service

- [ ] **3.11** Create `OrgScanService.scan_organization()`
- [ ] **3.12** Implement org-level detection storage
- [ ] **3.13** Implement bulk member account scanning
- [ ] **3.14** Create scan status tracking for org scans

#### API Endpoints

- [ ] **3.15** Implement `POST /cloud-organizations/{id}/scan`
- [ ] **3.16** Implement `POST /cloud-organizations/{id}/scan/members`
- [ ] **3.17** Implement `GET /cloud-organizations/{id}/detections`
- [ ] **3.18** Implement `GET /cloud-organizations/{id}/scan-status`

### Acceptance Criteria

- [ ] AWS Organization discovered from management account
- [ ] OU hierarchy correctly parsed
- [ ] Org-level CloudTrail detected
- [ ] Delegated GuardDuty/Security Hub detected
- [ ] Org detections stored with correct scope

---

## Phase 4: GCP Organisation Scanning

**Duration:** 3-4 weeks
**Dependencies:** Phase 2 (can run parallel to Phase 3)

### Tasks

#### Discovery Service

- [ ] **4.1** Create `GCPOrganizationDiscoveryService`
- [ ] **4.2** Implement `discover_organization()` - calls Resource Manager API
- [ ] **4.3** Implement `build_folder_tree()` - builds folder hierarchy
- [ ] **4.4** Implement `discover_org_resources()` - finds SCC, log sinks

#### Org-Level Scanners

- [ ] **4.5** Create `GCPOrgLogSinkScanner` - org-level log sinks
- [ ] **4.6** Enhance `SecurityCommandCenterScanner` for org-level
- [ ] **4.7** Create `GCPOrgPolicyScanner` - organization policies
- [ ] **4.8** Create `GCPAssetInventoryScanner` - asset discovery

#### GCP-Specific Features

- [ ] **4.9** Support folder-level log sinks
- [ ] **4.10** Support folder-level policies
- [ ] **4.11** Handle project lifecycle states

#### API Integration

- [ ] **4.12** Wire up GCP discovery endpoints
- [ ] **4.13** Wire up GCP org scanning
- [ ] **4.14** Handle GCP-specific credential flow

### Acceptance Criteria

- [ ] GCP Organization discovered
- [ ] Folder hierarchy correctly parsed
- [ ] Org-level log sinks detected
- [ ] Security Command Center findings detected
- [ ] Org detections stored with correct scope

---

## Phase 5: Coverage Calculation Updates

**Duration:** 1-2 weeks
**Dependencies:** Phases 3 & 4

### Tasks

- [ ] **5.1** Update `CoverageCalculator` to include org detections
- [ ] **5.2** Implement `calculate_account_coverage_with_org()`
- [ ] **5.3** Implement `calculate_org_coverage()` - aggregate
- [ ] **5.4** Create coverage breakdown (account vs org contribution)
- [ ] **5.5** Update `CoverageSnapshot` creation with org tracking
- [ ] **5.6** Update `GET /coverage/{account_id}` response
- [ ] **5.7** Create `GET /coverage/organization/{org_id}`
- [ ] **5.8** Create `GET /coverage/organization/{org_id}/breakdown`

### Acceptance Criteria

- [ ] Account coverage includes org detections
- [ ] Coverage shows account vs org breakdown
- [ ] Org-wide coverage aggregation works
- [ ] API returns enhanced coverage data

---

## Phase 6: Frontend Organisation UX

**Duration:** 2-3 weeks
**Dependencies:** Phase 5

### Tasks

#### Connection Flow

- [ ] **6.1** Create `ConnectOrganization` page
- [ ] **6.2** Create provider selection (AWS/GCP)
- [ ] **6.3** Create credential input step
- [ ] **6.4** Create discovery results view
- [ ] **6.5** Create account selection tree (with hierarchy)
- [ ] **6.6** Create confirmation step

#### Organisation Dashboard

- [ ] **6.7** Create `OrganizationDashboard` page
- [ ] **6.8** Create org-wide coverage gauge
- [ ] **6.9** Create account coverage breakdown table
- [ ] **6.10** Create org-level detections list
- [ ] **6.11** Create org scan history

#### Navigation

- [ ] **6.12** Add Organizations to sidebar
- [ ] **6.13** Create org switcher component
- [ ] **6.14** Update existing pages for org context

### Acceptance Criteria

- [ ] Can connect AWS/GCP organization via UI
- [ ] Hierarchy displayed correctly
- [ ] Org dashboard shows aggregate coverage
- [ ] Org detections visible and filterable

---

## Migration Strategy

### Existing Customer Tiers

| Current Tier | Account Count | New Tier | Action |
|--------------|---------------|----------|--------|
| free_scan | 1 | Free | Automatic |
| subscriber | 1-6 | Individual ($29) | Automatic - better value! |
| subscriber | 7+ | Pro ($250) | Contact customer - likely saving money |
| enterprise | Any | Enterprise | No change |

### Migration Notes

1. **Subscribers with 1-3 accounts** previously paying ~$27 ($9×3) now pay $29 for up to 6 - communicate the extra value
2. **Subscribers with 4-6 accounts** previously paying $36-54 now pay $29 - immediate savings
3. **Subscribers with 7+ accounts** previously paying $63+ now pay $250 flat - savings for 28+ accounts, slight increase for 7-27 accounts (but they get org features)
4. **Grace period**: Give existing 7-27 account customers 3 months at their current rate before requiring Pro

### Database Migration Order

1. Add new columns (nullable)
2. Create new tables
3. Run data migration
4. Add constraints
5. Create indexes

---

## Testing Strategy

### Unit Tests

- [ ] Billing tier logic
- [ ] Feature gate checks
- [ ] Coverage calculation with org detections
- [ ] Detection inheritance

### Integration Tests

- [ ] AWS Organization discovery (mocked)
- [ ] GCP Organization discovery (mocked)
- [ ] Org-level scanner tests
- [ ] API endpoints with org context

### E2E Tests

- [ ] Full org connection flow
- [ ] Coverage reflects org detections
- [ ] Billing limits enforced

---

## Appendix: Effort Estimates

| Phase | Duration | Backend | Frontend |
|-------|----------|---------|----------|
| Phase 1: Billing | 1-2 weeks | 4 days | 3 days |
| Phase 2: Foundation | 2-3 weeks | 7 days | 2 days |
| Phase 3: AWS Scanning | 3-4 weeks | 10 days | 2 days |
| Phase 4: GCP Scanning | 3-4 weeks | 10 days | 2 days |
| Phase 5: Coverage | 1-2 weeks | 4 days | 2 days |
| Phase 6: Frontend UX | 2-3 weeks | 2 days | 10 days |
| **Total** | **12-18 weeks** | **37 days** | **21 days** |

---

## Document History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2024-12-20 | Claude | Initial plan |
| 1.1 | 2024-12-20 | Claude | Moved data model to top, enhanced GCP coverage |

---

*This document should be reviewed and updated as implementation progresses.*
