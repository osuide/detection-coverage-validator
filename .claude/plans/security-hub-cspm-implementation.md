# Security Hub CSPM API Implementation Plan

## Executive Summary

AWS Security Hub has evolved to **AWS Security Hub CSPM** (Cloud Security Posture Management) with a consolidated controls view. This plan details upgrading our scanner to use the new standard-agnostic control APIs while maintaining backward compatibility.

## Current State Analysis

### Current Implementation (`securityhub_scanner.py`)

| API | Status | Purpose |
|-----|--------|---------|
| `describe_hub()` | ✅ Valid | Check if Security Hub is enabled |
| `get_enabled_standards()` | ✅ Valid | List enabled security standards |
| `describe_standards_controls()` | ⚠️ **DEPRECATED** | Get controls per standard |
| `get_insights()` | ✅ Valid | List Security Hub insights |

### Current IAM Permissions (`cloud_credential.py` lines 281-289)

```python
{
    "Sid": "A13ESecurityHubAccess",
    "Action": [
        "securityhub:DescribeHub",
        "securityhub:GetEnabledStandards",
        "securityhub:DescribeStandardsControls",  # DEPRECATED
    ],
}
```

## New Security Hub CSPM APIs

### Key Change: Standard-Agnostic Control IDs

**Old Approach** (standards-based):
- Control IDs were standard-specific: `CIS.1.2`, `FSBP.S3.1`
- Had to query each standard separately
- Same underlying control had different IDs per standard

**New Approach** (consolidated):
- Control IDs are standard-agnostic: `S3.1`, `CodeBuild.3`, `IAM.1`
- Single control ID across all standards
- Query all controls at once, see which standards they apply to

### New API Operations

| API | Purpose | Required Permission |
|-----|---------|---------------------|
| `list_security_control_definitions()` | Get all control definitions (or filter by standard) | `securityhub:ListSecurityControlDefinitions` |
| `batch_get_security_controls()` | Get control details, status, parameters | `securityhub:BatchGetSecurityControls` |
| `list_standards_control_associations()` | See control enablement per standard | `securityhub:ListStandardsControlAssociations` |

### API Details

#### 1. ListSecurityControlDefinitions

```python
# Request
GET /securityControls/definitions?StandardsArn={arn}&MaxResults=100

# Response
{
    "SecurityControlDefinitions": [
        {
            "SecurityControlId": "S3.1",
            "Title": "S3 general purpose buckets should have block public access settings enabled",
            "Description": "...",
            "SeverityRating": "MEDIUM",
            "CurrentRegionAvailability": "AVAILABLE",
            "CustomizableProperties": ["Parameters"],
            "ParameterDefinitions": {...},
            "RemediationUrl": "https://..."
        }
    ]
}
```

#### 2. BatchGetSecurityControls

```python
# Request
POST /securityControls/batchGet
{
    "SecurityControlIds": ["S3.1", "IAM.1", "CodeBuild.3"]
}

# Response
{
    "SecurityControls": [
        {
            "SecurityControlId": "S3.1",
            "SecurityControlArn": "arn:aws:securityhub:eu-west-2:123456789012:security-control/S3.1",
            "Title": "S3 general purpose buckets should have block public access settings enabled",
            "Description": "...",
            "SecurityControlStatus": "ENABLED",  # or "DISABLED"
            "SeverityRating": "MEDIUM",
            "UpdateStatus": "READY",  # or "UPDATING"
            "Parameters": {...},
            "RemediationUrl": "https://..."
        }
    ],
    "UnprocessedIds": []
}
```

#### 3. ListStandardsControlAssociations

```python
# Request
GET /associations?SecurityControlId=S3.1

# Response
{
    "StandardsControlAssociationSummaries": [
        {
            "StandardsArn": "arn:aws:securityhub:::standards/aws-foundational-security-best-practices/v/1.0.0",
            "SecurityControlId": "S3.1",
            "SecurityControlArn": "arn:aws:securityhub:eu-west-2:123456789012:security-control/S3.1",
            "AssociationStatus": "ENABLED",  # or "DISABLED"
            "RelatedRequirements": ["CIS.1.2", "PCI-DSS.1.3.6"],
            "UpdatedAt": "2024-12-01T00:00:00Z"
        }
    ]
}
```

## Implementation Plan

### Phase 1: IAM Policy Update

**File:** `backend/app/models/cloud_credential.py`

**Changes:**
```python
{
    "Sid": "A13ESecurityHubAccess",
    "Effect": "Allow",
    "Action": [
        # Existing (keep for backward compatibility)
        "securityhub:DescribeHub",
        "securityhub:GetEnabledStandards",
        "securityhub:DescribeStandardsControls",  # Keep for graceful fallback
        # New CSPM APIs
        "securityhub:ListSecurityControlDefinitions",
        "securityhub:BatchGetSecurityControls",
        "securityhub:ListStandardsControlAssociations",
        "securityhub:GetInsights",  # Already used, formalise
    ],
    "Resource": "*",
}
```

**Also update:**
- `AWS_REQUIRED_PERMISSIONS` list for UI display
- User documentation

### Phase 2: Scanner Enhancement

**File:** `backend/app/scanners/aws/securityhub_scanner.py`

#### 2.1 Add New Method: `_scan_consolidated_controls()`

```python
def _scan_consolidated_controls(
    self,
    client: Any,
    region: str,
    hub_arn: str,
) -> list[RawDetection]:
    """Scan using new consolidated controls API (Security Hub CSPM)."""
    detections = []

    try:
        # Get all control definitions
        paginator = client.get_paginator("list_security_control_definitions")
        control_ids = []

        for page in paginator.paginate():
            for control_def in page.get("SecurityControlDefinitions", []):
                control_ids.append(control_def["SecurityControlId"])

        # Batch get control details (max 100 per request)
        for batch in _chunk_list(control_ids, 100):
            response = client.batch_get_security_controls(
                SecurityControlIds=batch
            )

            for control in response.get("SecurityControls", []):
                detection = RawDetection(
                    name=f"SecurityHub-Control-{control['SecurityControlId']}",
                    detection_type=DetectionType.SECURITY_HUB,
                    source_arn=control.get("SecurityControlArn", ""),
                    region=region,
                    raw_config={
                        "hub_arn": hub_arn,
                        "control_id": control["SecurityControlId"],
                        "control_arn": control.get("SecurityControlArn"),
                        "title": control.get("Title"),
                        "status": control.get("SecurityControlStatus"),
                        "severity": control.get("SeverityRating"),
                        "update_status": control.get("UpdateStatus"),
                        "parameters": control.get("Parameters", {}),
                        "remediation_url": control.get("RemediationUrl"),
                        "api_version": "cspm",  # Mark as new API
                    },
                    description=control.get("Description", ""),
                    is_managed=True,
                )
                detections.append(detection)

    except ClientError as e:
        if e.response["Error"]["Code"] == "AccessDeniedException":
            # Fall back to legacy API if new permissions not granted
            self.logger.warning(
                "securityhub_cspm_access_denied",
                region=region,
                message="New CSPM APIs not available, using legacy API"
            )
            return []  # Caller should fall back to legacy
        raise

    return detections
```

#### 2.2 Modify `scan_region()` for Graceful Fallback

```python
async def scan_region(
    self,
    region: str,
    options: Optional[dict[str, Any]] = None,
) -> list[RawDetection]:
    """Scan a single region for Security Hub configurations."""
    detections = []
    client = self.session.client("securityhub", region_name=region)

    try:
        # Check if Security Hub is enabled
        hub = client.describe_hub()
        hub_arn = hub.get("HubArn", "")

        # Try new CSPM API first
        cspm_detections = self._scan_consolidated_controls(client, region, hub_arn)

        if cspm_detections:
            # New API worked - use consolidated controls
            detections.extend(cspm_detections)
        else:
            # Fall back to legacy standards-based API
            standards_detections = self._scan_enabled_standards(client, region, hub_arn)
            detections.extend(standards_detections)

        # Scan custom insights (works with both old and new)
        insights_detections = self._scan_insights(client, region, hub_arn)
        detections.extend(insights_detections)

    except ClientError as e:
        # ... existing error handling
```

### Phase 3: Data Model Considerations

#### 3.1 Detection Identification

**Current:** `source_arn` stores `StandardsSubscriptionArn`
**New:** `source_arn` stores `SecurityControlArn`

These are different ARN formats:
- Legacy: `arn:aws:securityhub:region:account:subscription/standards/...`
- CSPM: `arn:aws:securityhub:region:account:security-control/S3.1`

**Solution:** Store both in `raw_config`:
```python
raw_config={
    "control_id": "S3.1",  # Standard-agnostic ID
    "control_arn": "arn:aws:securityhub:...:security-control/S3.1",
    "legacy_subscription_arn": None,  # Only if from legacy API
    "api_version": "cspm",  # or "legacy"
}
```

#### 3.2 Mapping Implications

The MITRE mapping engine uses detection metadata to map to techniques. The new API provides:
- More consistent control IDs
- Better descriptions
- Related requirements (e.g., CIS, PCI-DSS mappings)

**No schema changes required** - the existing `raw_config` JSONB column handles the new structure.

### Phase 4: Backward Compatibility

#### 4.1 Existing Detections

When rescanning, detections from the legacy API need to be matched with new CSPM detections:

```python
def _match_legacy_to_cspm(legacy_detection: Detection, cspm_control: dict) -> bool:
    """Check if a legacy detection matches a CSPM control."""
    legacy_config = legacy_detection.raw_config or {}
    legacy_control_id = legacy_config.get("control_id", "")

    # Legacy: "CIS.1.2" → CSPM: "IAM.1" (need mapping table)
    # Or use related_requirements from CSPM API
    return False  # Implement mapping logic
```

**Recommendation:** Don't try to migrate. Mark legacy detections as `REMOVED` status on next scan if they're replaced by CSPM equivalents.

#### 4.2 API Routes

**No changes needed** - the scanner feeds into the existing detection storage and compliance calculation pipeline.

### Phase 5: Testing Strategy

#### Unit Tests

```python
# tests/unit/scanners/aws/test_securityhub_scanner.py

def test_scan_consolidated_controls_success():
    """Test scanning with new CSPM API."""

def test_scan_consolidated_controls_fallback_to_legacy():
    """Test fallback when CSPM API returns AccessDenied."""

def test_control_detection_creation():
    """Test RawDetection structure from CSPM control."""
```

#### Integration Tests

```python
# tests/integration/test_securityhub_scan.py

@pytest.mark.integration
async def test_real_account_cspm_scan():
    """Test against real AWS account with Security Hub enabled."""
```

## Migration Path

### For Existing Users

1. **No immediate action required** - scanner falls back to legacy API
2. **To use new features** - update IAM policy with new permissions
3. **Re-scan** - detections will use CSPM format after policy update

### For New Users

1. Default IAM policy includes new permissions
2. Scanner uses CSPM API by default
3. No legacy data to migrate

## Risk Assessment

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| Legacy API removed by AWS | Low (6+ months warning) | High | Graceful fallback implemented |
| IAM permission denied | Medium | Low | Falls back to legacy |
| Detection count mismatch | Medium | Low | Consolidated view = fewer duplicates |
| MITRE mapping changes | Low | Medium | Control descriptions improve mapping |

## Timeline

| Phase | Description | Estimated Effort |
|-------|-------------|------------------|
| 1 | IAM policy update | 1 hour |
| 2 | Scanner enhancement | 4 hours |
| 3 | Data model review | 1 hour |
| 4 | Backward compatibility | 2 hours |
| 5 | Testing | 3 hours |
| **Total** | | **11 hours** |

## Validation Checklist

- [x] IAM policy updated with new permissions (Phase 1)
- [x] `AWS_REQUIRED_PERMISSIONS` list updated for UI (Phase 1)
- [x] Scanner uses CSPM API when available (Phase 2)
- [x] Graceful fallback to legacy API works (Phase 2)
- [x] Existing detections not broken (backward compatible)
- [x] Unit tests pass (78 tests across 3 test files)
- [ ] Integration test with real account passes
- [x] Documentation updated (this file)

## Implementation Status: COMPLETE

**Completed:** 2025-12-27

### Commits:
1. `baa18a7` - Phase 1: IAM policy + 22 tests
2. `189b947` - Phase 2: Scanner + 27 tests
3. `f7328aa` - Phase 3: MITRE mapping + 29 tests

### Test Summary:
- `test_cloud_credential.py`: 22 tests
- `test_securityhub_scanner.py`: 27 tests
- `test_securityhub_mappings.py`: 29 tests
- **Total: 78 tests, all passing**

## Sources

- [ListSecurityControlDefinitions API](https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_ListSecurityControlDefinitions.html)
- [BatchGetSecurityControls API](https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_BatchGetSecurityControls.html)
- [Understanding security controls in Security Hub CSPM](https://docs.aws.amazon.com/securityhub/latest/userguide/controls-view-manage.html)
- [Required IAM permissions for controls](https://docs.aws.amazon.com/securityhub/latest/userguide/iam-permissions-controls-standards.html)

---

**Plan Created:** 2025-12-27
**Author:** Claude Code (API Design Agent Framework)
