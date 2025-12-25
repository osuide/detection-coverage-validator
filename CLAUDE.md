# A13E Detection Coverage Validator - Claude Code Instructions

## Language Requirements

**All text content must use UK English spelling and conventions.** This applies to:
- User-facing content (UI text, documentation, error messages)
- Code comments and docstrings
- Remediation templates and security guidance
- API responses and messages

Common UK English spellings to use:
- colour (not color)
- organisation (not organization)
- authorised (not authorized)
- defence (not defense)
- analyse (not analyze)
- behaviour (not behavior)
- favour (not favor)
- honour (not honor)
- centre (not center)
- licence (noun) / license (verb)
- practise (verb) / practice (noun)
- travelling (not traveling)
- modelling (not modeling)
- catalogue (not catalog)
- cheque (not check, for payments)
- programme (not program, for schedules/events)

## Project Context

This is a **multi-cloud security detection coverage validator** that:
- Scans **AWS and GCP** environments for existing security detections
- Maps detections to MITRE ATT&CK framework
- Identifies coverage gaps and provides remediation guidance
- Provides technique-specific detection strategies with IaC templates

**Cloud Support**: AWS & GCP are included in all subscription plans.

## Remediation Template Requirements

Every MITRE ATT&CK technique template should provide:
- **AWS**: CloudFormation + Terraform templates
- **GCP**: Terraform templates (primary IaC for GCP)
- Both in simplified 3-step format with clear comments
- CloudWatch/Cloud Logging queries where applicable

## Key Components

- **Backend**: FastAPI with PostgreSQL, located in `/backend`
- **Frontend**: React with TypeScript, located in `/frontend`
- **Infrastructure**: Terraform for AWS, located in `/infrastructure/terraform`
- **Documentation**: User guides in `/docs/user-guide`
- **Remediation Templates**: `/backend/app/data/remediation_templates`

## Coding Standards

- Python: Follow PEP 8, use type hints
- TypeScript: Strict mode enabled, use interfaces over types
- All API endpoints should be documented with OpenAPI schemas
- Tests should be placed adjacent to the code they test

## RBAC (Role-Based Access Control)

**IMPORTANT: `require_role()` uses exact match, NOT hierarchical.**

User roles in order of privilege: `OWNER > ADMIN > MEMBER > VIEWER`

When using `require_role()` in API endpoints, you must explicitly list ALL roles that should have access:

```python
# WRONG - Only allows MEMBER, blocks OWNER and ADMIN!
auth: AuthContext = Depends(require_role(UserRole.MEMBER))

# CORRECT - Allows OWNER, ADMIN, and MEMBER
auth: AuthContext = Depends(
    require_role(UserRole.OWNER, UserRole.ADMIN, UserRole.MEMBER)
)

# For read-only endpoints, include VIEWER
auth: AuthContext = Depends(
    require_role(UserRole.OWNER, UserRole.ADMIN, UserRole.MEMBER, UserRole.VIEWER)
)
```

Related dependencies in `app/core/security.py`:
- `require_role(*roles)` - Exact match for specified roles
- `require_org_features()` - Requires Pro/Enterprise subscription with org features
- `require_feature(feature)` - Requires specific subscription feature

## Service-Aware Coverage Implementation (COMPLETE)

### Problem Statement
Control 3.5 "Securely Dispose of Data" showed 100% coverage with only S3 deletion detection, when data exists in many services (RDS, DynamoDB, EBS, etc.). The coverage model was technique-based but ignored service scope.

**Old formula**: `coverage = covered_techniques / total_techniques`
**New formula**: `coverage = (covered_services ∩ in_scope_services) / in_scope_services`

### Implementation Status - ALL COMPLETE

#### Database & Models
- `backend/app/models/detection.py` - Added `target_services` JSONB field (line 150-153)
- `backend/app/models/cloud_account.py` - Added `discovered_services` and `discovered_services_at` fields (line 86-92)
- `backend/alembic/versions/029_add_service_awareness.py` - Migration with GIN indexes

#### Service Mappings & Discovery
- `backend/app/scanners/aws/service_mappings.py` (NEW) - Core 10 services constants:
  - `CORE_SERVICES`: S3, EBS, EFS, RDS, DynamoDB, Redshift, ElastiCache, SecretsManager, CloudWatchLogs, ECR
  - `AWS_RESOURCE_TO_SERVICE`: CloudFormation type → service name
  - `AWS_EVENT_SOURCE_TO_SERVICE`: EventBridge source → service name
  - `extract_services_from_event_pattern()`, `extract_services_from_resource_types()`, `extract_services_from_log_groups()`
- `backend/app/scanners/aws/service_discovery_scanner.py` (NEW) - Discovers which services have resources in account

#### Scanner Updates
- `backend/app/scanners/base.py` - Added `target_services` field to `RawDetection` dataclass (line 30-31)
- `backend/app/scanners/aws/eventbridge_scanner.py` - Extracts target_services from event patterns (line 127)
- `backend/app/scanners/aws/config_scanner.py` - Extracts target_services from compliance_resource_types (line 95-96)
- `backend/app/scanners/aws/cloudwatch_scanner.py` - Extracts target_services from log group names (line 111-112)
- `backend/app/services/scan_service.py` - Persists target_services on detection create/update (lines 603, 624)

#### Coverage Calculator Integration
- `backend/app/analyzers/service_coverage_calculator.py` (NEW) - Core service-aware coverage calculation:
  - `ServiceCoverageResult` dataclass - per-technique coverage
  - `ControlServiceCoverage` dataclass - per-control aggregate coverage
  - `get_account_services()` - gets discovered services for account
  - `get_detection_services()` - gets service → detection mapping
  - `calculate_technique_coverage()` - calculates coverage per technique
  - `calculate_control_coverage()` - calculates aggregate control coverage

- `backend/app/analyzers/compliance_calculator.py` - Updated to use service coverage:
  - `calculate()` method now accepts `cloud_account_id` parameter for service-aware coverage
  - `ControlCoverageInfo` dataclass includes: `service_coverage_percent`, `in_scope_services`, `covered_services`, `uncovered_services`
  - `ServiceCoverageMetrics` dataclass for aggregate service metrics
  - Coverage status adjusted based on combined technique + service coverage

- `backend/app/services/compliance_service.py` - Updated to pass `cloud_account_id` to calculator and store service metrics

#### API Schema Updates
- `backend/app/schemas/compliance.py` - Added service coverage schemas:
  - `ServiceCoverageItem` - overall service coverage metrics
  - `TechniqueServiceCoverageItem` - per-technique service coverage
  - `ControlServiceCoverageItem` - per-control service coverage
  - Added `service_coverage` fields to `TechniqueCoverageDetail`, `ControlCoverageDetailResponse`, `ControlGapItem`, `ControlStatusItem`
  - Added `service_coverage` to `CloudCoverageMetricsResponse`

#### Frontend Updates
- `frontend/src/services/complianceApi.ts` - Added TypeScript interfaces:
  - `ServiceCoverageItem`, `TechniqueServiceCoverage`, `ControlServiceCoverage`
  - Updated all relevant interfaces with service coverage fields

- `frontend/src/components/compliance/TechniqueBreakdown.tsx` - Added `ServiceCoverageIndicator` component:
  - Shows covered/uncovered services with colour-coded badges
  - Displays service coverage percentage

- `frontend/src/components/compliance/CoverageDetailModal.tsx` - Added service coverage display:
  - Service coverage progress bar
  - Missing services badges

### How Service-Aware Coverage Works

1. **Detection Scanning**: When detections are scanned, `target_services` is extracted from:
   - EventBridge event patterns (via `extract_services_from_event_pattern()`)
   - Config rule resource types (via `extract_services_from_resource_types()`)
   - CloudWatch log group names (via `extract_services_from_log_groups()`)

2. **Service Discovery**: `ServiceDiscoveryScanner` checks which services have resources in the account

3. **Coverage Calculation**:
   - For each control, `cloud_context.aws_services` defines required services
   - `ServiceCoverageCalculator` intersects with discovered services to get in-scope services
   - Coverage = services with detections / in-scope services

4. **Status Adjustment**: Control status is adjusted based on combined technique + service coverage:
   - `effective_coverage = (technique_coverage + service_coverage) / 2`
   - Status thresholds: ≥80% = covered, ≥40% = partial, <40% = uncovered

### Testing the Implementation

1. Run the migration (if not already done):
   ```bash
   cd backend
   alembic upgrade head
   ```

2. Re-run a scan to populate `target_services` on detections:
   - This will extract services from EventBridge patterns, Config rules, and CloudWatch log groups

3. Verify target_services is populated:
   ```sql
   SELECT name, target_services FROM detections WHERE target_services IS NOT NULL LIMIT 10;
   ```

4. Check compliance coverage API includes service metrics:
   - The `cloud_metrics` object will include `service_coverage` when available

### Plan File Reference
Full implementation plan: `/Users/austinosuide/.claude/plans/delightful-gathering-platypus.md`

## Terraform Known Issues

### Cognito Google Identity Provider Drift

**Issue**: AWS Cognito auto-populates computed `provider_details` attributes (authorize_url, token_url, oidc_issuer, etc.) that cause perpetual terraform drift.

**Symptoms**: `terraform plan` always shows changes to `aws_cognito_identity_provider.google` even when nothing has changed:
```
~ provider_details = {
  - "attributes_url" = "..." -> null
  - "authorize_url" = "..." -> null
  - "oidc_issuer" = "..." -> null
  - "token_url" = "..." -> null
}
```

**Solution**: Use `ignore_changes` in the lifecycle block:
```hcl
resource "aws_cognito_identity_provider" "google" {
  # ... config ...

  lifecycle {
    create_before_destroy = true
    ignore_changes        = [provider_details]
  }
}
```

**Reference**: https://github.com/hashicorp/terraform-provider-aws/issues/4831

**Location**: `infrastructure/terraform/modules/cognito/main.tf`

## Technical Debt / Backlog

### Remediation Templates

#### LOW: Add `treat_missing_data` to CloudWatch Alarms (152 templates)

**Issue**: 152 remediation templates with CloudWatch metric alarms are missing the `treat_missing_data` setting.

**Impact**: LOW - Alarms show `INSUFFICIENT_DATA` state when no log data is present, instead of staying in `OK` state.

**Fix**: Add to Terraform templates:
```hcl
resource "aws_cloudwatch_metric_alarm" "..." {
  # ... existing config ...
  treat_missing_data = "notBreaching"
}
```

Add to CloudFormation templates:
```yaml
Type: AWS::CloudWatch::Alarm
Properties:
  # ... existing config ...
  TreatMissingData: notBreaching
```

**Templates affected**: Run this to identify:
```bash
cd backend/app/data/remediation_templates
grep -L "treat_missing_data" t*.py | xargs grep -l "aws_cloudwatch_metric_alarm"
```
