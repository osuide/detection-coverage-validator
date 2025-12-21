# Multi-Region Scanning Implementation Plan

## Problem Statement

The A13E Detection Coverage Validator currently defaults to scanning only `us-east-1` when no regions are specified, causing detections in other regions (such as GuardDuty in `eu-west-2`) to be missed.

**Current problematic code (scan_service.py:101):**
```python
regions = scan.regions or account.regions or ["us-east-1"]
```

---

## Phase 1: Database Schema Enhancements

### 1.1 New Migration

**File:** `backend/alembic/versions/025_add_region_configuration.py`

Add `region_config` JSONB column to `cloud_accounts` table:
```python
{
    "mode": "all" | "selected" | "auto",
    "regions": ["us-east-1", "eu-west-2"],
    "excluded_regions": [],
    "auto_discovered_at": "2025-01-15T10:00:00Z",
    "discovered_regions": ["us-east-1", "eu-west-2"]
}
```

### 1.2 Update CloudAccount Model

**File:** `backend/app/models/cloud_account.py`

Add:
- `region_config: Mapped[dict] = mapped_column(JSONB, default=dict)`
- `get_effective_regions() -> list[str]`
- `set_auto_discovered_regions(regions: list[str])`

---

## Phase 2: Service Classification System

### 2.1 Create Service Registry

**New File:** `backend/app/core/service_registry.py`

```python
# AWS Global Services (scan once from us-east-1)
AWS_GLOBAL_SERVICES = {
    "iam": {"endpoint_region": "us-east-1"},
    "cloudfront": {"endpoint_region": "us-east-1"},
    "route53": {"endpoint_region": "us-east-1"},
    "waf-global": {"endpoint_region": "us-east-1"},
    "organizations": {"endpoint_region": "us-east-1"},
}

# AWS Regional Services
AWS_REGIONAL_SERVICES = {
    "guardduty": {"multi_region": True},
    "cloudwatch-logs": {"multi_region": True},
    "eventbridge": {"multi_region": True},
    "config": {"multi_region": True},
    "securityhub": {"multi_region": True},
    "lambda": {"multi_region": True},
    "waf-regional": {"multi_region": True},
}

# GCP Global Services
GCP_GLOBAL_SERVICES = {
    "security-command-center": {"scope": "organization"},
    "cloud-logging": {"scope": "project"},
    "org-policy": {"scope": "organization"},
    "chronicle": {"scope": "organization"},
}

# GCP Regional Services
GCP_REGIONAL_SERVICES = {
    "eventarc": {"multi_region": True},
    "cloud-functions": {"multi_region": True},
    "cloud-run": {"multi_region": True},
}

# Standard AWS region list
AWS_REGIONS = [
    "us-east-1", "us-east-2", "us-west-1", "us-west-2",
    "eu-west-1", "eu-west-2", "eu-west-3", "eu-central-1", "eu-north-1",
    "eu-south-1", "eu-central-2",
    "ap-northeast-1", "ap-northeast-2", "ap-northeast-3",
    "ap-southeast-1", "ap-southeast-2", "ap-southeast-3",
    "ap-south-1", "ap-south-2", "ap-east-1",
    "sa-east-1",
    "me-south-1", "me-central-1",
    "af-south-1",
    "ca-central-1", "ca-west-1",
    "il-central-1",
]

# Standard GCP region list
GCP_REGIONS = [
    "us-central1", "us-east1", "us-east4", "us-west1", "us-west2", "us-west3", "us-west4",
    "europe-west1", "europe-west2", "europe-west3", "europe-west4", "europe-west6",
    "europe-north1", "europe-central2",
    "asia-east1", "asia-east2", "asia-northeast1", "asia-northeast2", "asia-northeast3",
    "asia-south1", "asia-south2", "asia-southeast1", "asia-southeast2",
    "australia-southeast1", "australia-southeast2",
    "southamerica-east1", "southamerica-west1",
    "northamerica-northeast1", "northamerica-northeast2",
    "me-west1", "me-central1",
    "africa-south1",
]
```

### 2.2 Update BaseScanner Interface

**File:** `backend/app/scanners/base.py`

Add to BaseScanner:
```python
@property
def is_global_service(self) -> bool:
    """Override in subclass to indicate this is a global service."""
    return False

@property
def global_scan_region(self) -> str:
    """Region to use for global service scanning."""
    return "us-east-1"
```

---

## Phase 3: Region Auto-Discovery Service

### 3.1 Create Auto-Discovery Service

**New File:** `backend/app/services/region_discovery_service.py`

```python
class RegionDiscoveryService:
    async def discover_aws_active_regions(self, session: boto3.Session) -> list[str]:
        """Discover regions with active AWS resources."""
        # 1. Get enabled regions via EC2 describe_regions
        # 2. Check for CloudTrail events (indicates usage)
        # 3. Return list of active regions

    async def discover_gcp_active_regions(self, credentials, project_id: str) -> list[str]:
        """Discover regions with active GCP resources."""
        # 1. Use Cloud Asset Inventory
        # 2. Check Compute Engine instances per region
```

---

## Phase 4: Scan Service Updates

### 4.1 Update ScanService

**File:** `backend/app/services/scan_service.py`

Replace line 101:
```python
# OLD:
regions = scan.regions or account.regions or ["us-east-1"]

# NEW:
region_config = await self._determine_scan_regions(scan, account)
```

Add new method:
```python
async def _determine_scan_regions(self, scan: Scan, account: CloudAccount) -> dict[str, list[str]]:
    """Determine regions for regional services and global service handling."""
    region_config = account.region_config or {}
    mode = region_config.get("mode", "selected")

    if mode == "all":
        all_regions = AWS_REGIONS if account.provider == CloudProvider.AWS else GCP_REGIONS
        excluded = set(region_config.get("excluded_regions", []))
        regional_regions = [r for r in all_regions if r not in excluded]
    elif mode == "auto":
        regional_regions = region_config.get("discovered_regions", [])
        if not regional_regions:
            regional_regions = await self._auto_discover_regions(account)
    else:  # "selected" mode
        regional_regions = (
            scan.regions or
            region_config.get("regions") or
            account.regions or
            [self._get_default_region(account)]
        )

    return {
        "regional": regional_regions,
        "global_region": "us-east-1" if account.provider == CloudProvider.AWS else "global"
    }
```

### 4.2 Update `_scan_detections` Method

```python
async def _scan_detections(
    self,
    session: boto3.Session,
    region_config: dict[str, list[str]],
    detection_types: list[str],
) -> tuple[list[RawDetection], list[str]]:
    """Run scanners with proper global/regional handling."""
    regional_regions = region_config["regional"]
    global_region = region_config["global_region"]

    for scanner in scanners:
        if scanner.is_global_service:
            detections = await scanner.scan([global_region])
        else:
            detections = await scanner.scan(regional_regions)
```

---

## Phase 5: API Updates

### 5.1 Update Cloud Account Schemas

**File:** `backend/app/schemas/cloud_account.py`

```python
class RegionScanMode(str, Enum):
    ALL = "all"
    SELECTED = "selected"
    AUTO = "auto"

class RegionConfig(BaseModel):
    mode: RegionScanMode = RegionScanMode.SELECTED
    regions: list[str] = Field(default_factory=list)
    excluded_regions: list[str] = Field(default_factory=list)
```

### 5.2 New Endpoints

**File:** `backend/app/api/routes/accounts.py`

```python
@router.post("/{account_id}/discover-regions")
async def discover_regions(account_id: UUID, ...):
    """Discover active regions for this cloud account."""

@router.get("/regions/{provider}")
async def list_available_regions(provider: CloudProvider, ...):
    """Get list of available regions for a cloud provider."""
```

---

## Phase 6: Frontend UI Updates

### 6.1 Region Selector Component

**New File:** `frontend/src/components/RegionSelector.tsx`

Features:
- Region mode selector (All / Selected / Auto-discover)
- Multi-select dropdown for regions
- Grouped by geographic area
- Exclusion list for "all regions" mode
- "Discover Regions" button with loading state

### 6.2 Update Account Form

**File:** `frontend/src/pages/Accounts.tsx`

Add region configuration section to account creation/edit form.

### 6.3 Update Scan Dialog

Allow region override when initiating a scan.

---

## Phase 7: Scanner Classification

| Scanner | Type | Notes |
|---------|------|-------|
| GuardDutyScanner | Regional | Multi-region |
| CloudWatchLogsInsightsScanner | Regional | Multi-region |
| EventBridgeScanner | Regional | Multi-region |
| ConfigRulesScanner | Regional | Multi-region |
| SecurityHubScanner | Regional | Multi-region |
| (Future) IAMScanner | Global | us-east-1 only |
| (Future) WAFGlobalScanner | Global | us-east-1 only |

---

## Phase 8: Migration Strategy

### 8.1 Existing Accounts

1. Add new columns with sensible defaults
2. Migrate existing `regions` data to `region_config`
3. Display banner prompting users to update region configuration

### 8.2 Default Behaviour

Change fallback from `["us-east-1"]` to organisation default or prompt user.

---

## Implementation Order

| Phase | Duration | Focus |
|-------|----------|-------|
| 1 | 2 days | Database migration, service registry |
| 2 | 2 days | Scan service updates, region discovery |
| 3 | 2 days | API layer updates |
| 4 | 3 days | Frontend components |
| 5 | 2 days | Testing & migration |

**Total:** ~11 days

---

## Files to Modify

### Backend (Critical)
- `backend/app/services/scan_service.py` - Core region handling
- `backend/app/models/cloud_account.py` - Region config model
- `backend/app/schemas/cloud_account.py` - API schemas
- `backend/app/api/routes/accounts.py` - New endpoints
- `backend/app/api/routes/scans.py` - Region override support

### Backend (New)
- `backend/app/core/service_registry.py` - Global/regional classification
- `backend/app/services/region_discovery_service.py` - Auto-discovery
- `backend/alembic/versions/025_add_region_configuration.py` - Migration

### Frontend
- `frontend/src/components/RegionSelector.tsx` - New component
- `frontend/src/pages/Accounts.tsx` - Region config UI
- `frontend/src/services/api.ts` - New API methods

---

## Risk Mitigation

| Risk | Mitigation |
|------|------------|
| Performance (more regions = slower) | Parallel scanning, progress per region |
| Cost (more API calls) | Request caching, rate limiting |
| Backwards compatibility | Graceful fallbacks, migration scripts |
| GCP differences | Separate handling paths |
