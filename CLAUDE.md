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

### Currency Requirements

**All product pricing must use British Pounds (£/GBP).** This applies to:
- Subscription tier pricing (FREE, Individual £29/mo, Pro £250/mo, Enterprise)
- User-facing messages about upgrades and pricing
- Stripe configuration (currency: "gbp")
- API responses for pricing endpoints
- Documentation and marketing content

**Exception**: AWS/GCP infrastructure costs in remediation templates can use $ (USD) since those are vendor prices.

#### Currency Implementation (Completed)

All product pricing uses GBP:
- Stripe checkout sessions use `currency: "gbp"`
- Invoice model uses `default="gbp"`
- API field names use `*_pounds` and `*_pence`
- Frontend uses `Intl.NumberFormat` with `currency: 'GBP'`
- Landing page shows £0, £29, £250 pricing

Stripe products (test mode):
- A13E Individual: `price_1SijVDAB6j5KiVeUwd4QD5uX` (£29/month, 6 accounts)
- A13E Pro: `price_1SijVTAB6j5KiVeUZTSUdnBl` (£250/month, 500 accounts)

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

### ReAct Methodology for Template Review

When reviewing or creating remediation templates, follow this ReAct (Reason-Act-Observe-Act) methodology:

**Step 1 - REASON**: Understand the technique
- What is this MITRE ATT&CK technique?
- What specific behaviours or API calls should we detect?
- What are the cloud-specific manifestations (AWS/GCP)?

**Step 2 - ACT**: Research best practices
- Fetch the MITRE ATT&CK page for the technique
- Search for current AWS/GCP official documentation on detecting this technique
- Look for AWS Security Blog posts, GCP security guides, or vendor best practices

**Step 3 - OBSERVE**: Compare template against research
- Does our template's detection logic match MITRE's recommendations?
- Are we monitoring the correct API calls, log sources, and event patterns?
- Are we missing any key detection strategies that AWS/GCP recommends?
- Are the GuardDuty finding types correct and current?
- Are the CloudWatch/Cloud Logging queries accurate?

**Step 4 - ACT**: Update both detection logic AND infrastructure
- **Detection Logic**: Update event patterns, API calls, log queries based on research
- **Infrastructure Patterns**: Apply EventBridge best practices (DLQ, retry, scoped SNS, input_transformer)
- Verify Python syntax after each edit

**Important**: Do NOT assume the current template is correct. Always research and validate against official sources before making changes. Do NOT make up detection patterns - only use validated approaches from MITRE, AWS, or GCP documentation.

### EventBridge Template Best Practices

When creating EventBridge-based detection templates, follow the optimised pattern:

**Required Components:**
1. **SNS Topic** with `kms_master_key_id = "alias/aws/sns"` for encryption
2. **Dead Letter Queue** (SQS) with `message_retention_seconds = 1209600` (14 days)
3. **Retry Policy** with `maximum_retry_attempts = 8` and `maximum_event_age_in_seconds = 3600`
4. **Scoped SNS Topic Policy** with `AWS:SourceAccount` and `aws:SourceArn` conditions
5. **Input Transformer** for human-readable alert format
6. **`data "aws_caller_identity" "current" {}`** for dynamic account ID

**Example Terraform Pattern:**
```hcl
data "aws_caller_identity" "current" {}

resource "aws_sns_topic" "alerts" {
  name              = "${var.name_prefix}-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sqs_queue" "dlq" {
  name                      = "${var.name_prefix}-dlq"
  message_retention_seconds = 1209600
}

resource "aws_cloudwatch_event_target" "to_sns" {
  rule      = aws_cloudwatch_event_rule.detection.name
  target_id = "SNSTarget"
  arn       = aws_sns_topic.alerts.arn

  retry_policy {
    maximum_event_age_in_seconds = 3600
    maximum_retry_attempts       = 8
  }

  dead_letter_config {
    arn = aws_sqs_queue.dlq.arn
  }

  input_transformer {
    input_paths = { ... }
    input_template = "..."
  }
}

resource "aws_sns_topic_policy" "allow_eventbridge" {
  arn = aws_sns_topic.alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.alerts.arn
      Condition = {
        StringEquals = { "AWS:SourceAccount" = data.aws_caller_identity.current.account_id }
        ArnEquals    = { "aws:SourceArn" = aws_cloudwatch_event_rule.detection.arn }
      }
    }]
  })
}
```

**CloudFormation Equivalent:**
- Add `TopicPolicy` resource with `AWS::SNS::TopicPolicy`
- Use `!Ref AWS::AccountId` for account scoping
- Use `!GetAtt EventRule.Arn` for rule ARN scoping

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

## Database & Migrations

**Migrations run automatically on application startup.**

The `run_migrations()` function in `backend/app/main.py` (lines 113-136) automatically runs `alembic upgrade head` when the application starts. This means:

- No manual `alembic upgrade head` command is needed
- Deploy new code and migrations apply on restart
- In development, restart the FastAPI server to apply migrations
- Migration files are in `backend/alembic/versions/`

```python
# From main.py - migrations run on startup
def run_migrations():
    from alembic import command
    from alembic.config import Config
    alembic_cfg = Config(str(BASE_DIR / "alembic.ini"))
    command.upgrade(alembic_cfg, "head")
```

### Alembic Migration Best Practices with asyncpg

When writing migrations with asyncpg (async PostgreSQL driver), follow these rules:

1. **Revision IDs must be <= 32 characters** - The `alembic_version.version_num` column is `VARCHAR(32)`. Use short names like `038_add_eval_history` not `038_add_detection_evaluation_history`.

2. **For PostgreSQL ENUMs, use `PG_ENUM` not `sa.Enum`** - The `sa.Enum(..., create_type=False)` doesn't work with asyncpg. Use:
   ```python
   from sqlalchemy.dialects.postgresql import ENUM as PG_ENUM

   # WRONG - create_type=False is ignored with asyncpg
   sa.Column("status", sa.Enum("a", "b", name="myenum", create_type=False))

   # CORRECT - use PG_ENUM to reference existing type
   sa.Column("status", PG_ENUM(name="myenum", create_type=False))
   ```

3. **Create ENUMs with raw SQL, not SQLAlchemy** - Use `conn.execute(sa.text("CREATE TYPE ..."))` because `checkfirst=True` doesn't work with asyncpg.

4. **Make migrations idempotent** - Check if tables/types exist before creating. Use `inspector.get_table_names()` (proven to work with asyncpg) to check table existence:
   ```python
   conn = op.get_bind()
   inspector = sa.inspect(conn)
   if "my_table" in inspector.get_table_names():
       return  # Already migrated
   ```

5. **Handle orphaned ENUMs** - If migration fails after creating ENUMs, they persist (CREATE TYPE is auto-committed). Drop orphaned enums before recreating:
   ```python
   conn.execute(sa.text("DROP TYPE IF EXISTS myenum CASCADE"))
   conn.execute(sa.text("CREATE TYPE myenum AS ENUM ('a', 'b')"))
   ```

6. **Adding values to existing ENUMs - use "recreate enum" approach** - `ALTER TYPE ... ADD VALUE` cannot run inside a transaction, and asyncpg has issues with autocommit workarounds. Instead, recreate the enum:
   ```python
   def upgrade() -> None:
       conn = op.get_bind()

       # Check if value already exists (idempotency)
       result = conn.execute(sa.text(
           "SELECT 1 FROM pg_enum WHERE enumtypid = 'myenum'::regtype AND enumlabel = 'newvalue'"
       ))
       if result.fetchone():
           return  # Already exists

       # Step 1: Rename existing type
       conn.execute(sa.text("ALTER TYPE myenum RENAME TO myenum_old"))

       # Step 2: Create new type with all values
       conn.execute(sa.text("CREATE TYPE myenum AS ENUM ('a', 'b', 'newvalue')"))

       # Step 3: Update column to use new type (cast through text)
       conn.execute(sa.text(
           "ALTER TABLE mytable ALTER COLUMN mycolumn TYPE myenum USING mycolumn::text::myenum"
       ))

       # Step 4: Drop old type
       conn.execute(sa.text("DROP TYPE myenum_old"))
   ```
   Reference: https://blog.yo1.dog/updating-enum-values-in-postgresql-the-safe-and-easy-way/

7. **Data deletion migrations must respect FK constraints** - When deleting data from multiple tables, delete from child tables (those with foreign keys pointing TO a table) before deleting from parent tables. Use `\d+ tablename` in psql or check the models to find FK constraints:
   ```python
   def upgrade() -> None:
       conn = op.get_bind()

       # Delete from tables that have FK to 'scans' FIRST
       conn.execute(sa.text("DELETE FROM coverage_snapshots"))  # FK to scans
       conn.execute(sa.text("DELETE FROM coverage_gaps"))        # FK to scans

       # Then delete from tables that have FK to 'detections'
       conn.execute(sa.text("DELETE FROM detection_mappings"))   # FK to detections

       # Now safe to delete parent tables
       conn.execute(sa.text("DELETE FROM detections"))
       conn.execute(sa.text("DELETE FROM scans"))
   ```

   **Key FK relationships in this codebase:**
   - `coverage_snapshots` → `scans.id`
   - `coverage_gaps` → `scans.id`
   - `coverage_history` → `scans.id` (SET NULL)
   - `detection_evaluation_history` → `scans.id` (SET NULL), `detections.id`
   - `detection_mappings` → `detections.id`

References:
- [Alembic asyncpg Discussion #1208](https://github.com/sqlalchemy/alembic/discussions/1208)
- [SQLAlchemy Alembic Issue #1347](https://github.com/sqlalchemy/alembic/issues/1347)
- [Alembic ALTER TYPE ADD VALUE Issue #123](https://github.com/sqlalchemy/alembic/issues/123)

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

## Team Invites Feature Gating

**Team member invitations are a paid feature.** FREE tier users operate in single-user mode.

### Tier Limits

| Tier | Team Members | Can Invite |
|------|--------------|------------|
| FREE | 1 (owner only) | No |
| INDIVIDUAL | Up to 3 | Yes |
| PRO | Up to 10 | Yes |
| ENTERPRISE | Unlimited | Yes |

### User Experience by Tier

**FREE Tier:**
- Can view team members list (shows only themselves)
- "Invite Member" button is replaced with upgrade prompt
- Sees message: "Team member invitations require Individual tier (£29/mo) or higher"
- Link to billing/upgrade page

**INDIVIDUAL Tier:**
- Can invite up to 3 team members total (including owner)
- Sees member count and limit in UI
- Warning shown when approaching limit

**PRO Tier:**
- Can invite up to 10 team members total
- Full team management features

**ENTERPRISE Tier:**
- Unlimited team members
- No limit warnings shown

### Implementation Details

**Backend:**
- Feature flag: `team_invites` in `TIER_LIMITS` (billing.py)
- Endpoint gating: `require_feature("team_invites")` on `POST /api/v1/teams/invites`
- Member limit check before creating invite (includes pending invites in count)

**Frontend:**
- `TeamManagement.tsx` fetches subscription via `billingApi.getSubscription()`
- Uses `isFreeTier()` helper from `billingApi.ts` to check tier
- Shows `UpgradePrompt` component for FREE users instead of invite button

### API Responses

**403 Forbidden (FREE tier attempting to invite):**
```json
{
  "detail": "Team member invitations require Individual tier (£29/mo) or higher. Collaborate with your team by upgrading."
}
```

**403 Forbidden (member limit reached):**
```json
{
  "detail": "Team member limit (3) reached. Upgrade to Pro for more team members."
}
```

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

## Template Review Progress (December 2025)

### Completed ReAct Reviews
Templates reviewed with full MITRE research + AWS/GCP best practice validation:

**Session 1 (Previous):**
- T1007-T1041 (35 templates)

**Session 2 (26 Dec 2025):**
- T1046, T1047, T1048, T1053 (Network/Scheduled Task)
- T1059 (Command Scripting) - Added SSM Run Command detection (T1059.009)
- T1068, T1070 (Priv Esc/Indicator Removal) - Fixed duplicate attributes
- T1071 (Application Layer Protocol) - Added DoH/DoT GuardDuty findings
- T1078.004, T1087.004, T1098.001, T1105, T1110, T1136 (Credential/Persistence)
- T1190 (Exploit Public Facing) - Fixed 4 duplicate treat_missing_data
- T1485, T1486, T1496.001, T1530, T1537 (Impact/Exfiltration)
- T1538, T1550.001, T1552, T1552.005, T1562.008, T1566, T1567, T1610 (Discovery/Lateral Movement)

**Session 3 (26 Dec 2025 continued):**
- T1055 (Process Injection) - Added specific GuardDuty ProcessInjection finding types, DLQ, retry
- T1056 (Input Capture) - Fixed duplicate attributes, added DLQ/retry/scoped SNS
- T1057 (Process Discovery) - Added SNS topic policies
- T1072 (Software Deployment Tools) - Fixed duplicates, added SNS policies
- T1074, T1074.002 (Data Staged) - Added SNS topic policies
- T1082, T1083 (System/File Discovery) - Added SNS topic policies
- T1621 (MFA Request Generation) - Added SNS topic policies
- T1651 (Cloud Admin Command) - Fixed duplicate treat_missing_data, added aws:SourceArn
- T1613 (Container Resource Discovery) - Added SNS topic policies
- T1133 (External Remote Services) - Added SNS topic policies
- T1606 (Forge Web Credentials) - Added SNS topic policies for SAML/Federation detection
- T1609 (Container Admin Command) - Fixed duplicate TreatMissingData, added SNS policies
- T1612 (Build Image on Host) - Already compliant, no fixes needed

### Remaining Templates to Review
Priority order for next session:
1. T1606, T1609 (Forge Credentials, Container Admin)
2. T1088-T1104, T1106-T1135 (Various)
3. T1137-T1189 (Various)
4. All remaining T1xxx templates (~200 remaining)

### Key Fixes Applied (Session 3)
1. Added specific GuardDuty ProcessInjection finding types (T1055)
2. Added SNS topic policies with AWS:SourceAccount to 15+ templates
3. Fixed duplicate attributes in T1056, T1072, T1651
4. Added `data "aws_caller_identity"` declarations where missing

## Technical Debt / Backlog

### Performance Optimisations (Future)

The following optimisations are documented for future implementation when needed:

| Priority | Optimisation | Expected Gain | Cost | Notes |
|----------|--------------|---------------|------|-------|
| 1 | Increase ECS task resources (1024 CPU, 2048 MB) | 5-10ms | +£30/mo | Terraform: `modules/backend/main.tf` |
| 2 | Upgrade RDS instance (db.t3.medium or higher) | 5-15ms | +£25-95/mo | Terraform: `modules/database/main.tf` |
| 3 | Add CloudFront for API caching | 20-30ms | +£10-50/mo | New module needed |

**Already Implemented (December 2025):**
- Database pool size increased to 20 (from 5) with pool_pre_ping and pool_recycle
- N+1 query fixed in `_get_security_function_breakdown()` using SQL GROUP BY
- Redis cache module added (`app/core/cache.py`) with framework ID caching
- HTTP cache headers added to compliance framework endpoints (1 hour TTL)
- In-memory metrics collector (`app/core/metrics.py`) for real-time admin dashboard stats
- ECS task resources doubled to 1024 CPU, 2048 MB (commit `3d6f98f`)

### Async Event Loop & Threading (December 2025)

**Problem Solved**: 504 Gateway Timeouts during scans caused by synchronous boto3 calls blocking the asyncio event loop.

**Root Cause**: boto3 is synchronous. When AWS API calls run in an `async def` function, they block the entire event loop, preventing HTTP requests from being processed. This caused requests to queue up and timeout after 60 seconds.

**Solution Implemented** (commit `775c812`):
- Added `run_sync()` helper method to `BaseScanner` that offloads boto3 calls to a `ThreadPoolExecutor` (8 workers)
- Updated EventBridge and Config scanners to use `run_sync()` for all AWS API calls

**Usage Pattern**:
```python
# BLOCKING - Don't do this in async functions
response = client.list_event_buses()

# NON-BLOCKING - Use this pattern instead
response = await self.run_sync(client.list_event_buses)

# With arguments:
response = await self.run_sync(client.get_rule, Name=rule_name)
```

**Current Threading Configuration**:
| Component | Configuration | Notes |
|-----------|---------------|-------|
| Uvicorn | 2 workers | `--workers 2` in Dockerfile |
| boto3 ThreadPool (scanners) | 8 workers | `_boto3_executor` in `base.py` |
| boto3 ThreadPool (credentials) | 10 workers | `_credential_executor` in `aws_credential_service.py` |
| Database pool | 20 connections | `pool_size=20, max_overflow=30` |
| HTTP clients | Async (httpx) | All use `httpx.AsyncClient` |

**Services Using Thread Pool (Non-Blocking)**:
- ✅ `eventbridge_scanner.py` - `run_sync()` for all boto3 calls
- ✅ `config_scanner.py` - `run_sync()` for all boto3 calls
- ✅ `aws_credential_service.py` - `_run_sync()` for all boto3 calls, 8 permission checks run in parallel
- ✅ `region_discovery_service.py` - Already uses `run_in_executor()` for all boto3 calls

**aws_credential_service.py Optimisation** (December 2025):
- Added dedicated thread pool (`_credential_executor`, 10 workers)
- STS assume_role runs in thread pool via `assume_role_async()`
- All 8 permission checks run IN PARALLEL via `asyncio.gather()`:
  - CloudWatch Logs, CloudWatch Alarms, EventBridge, GuardDuty
  - Security Hub, Config, CloudTrail, Lambda
- Expected speedup: ~8x faster credential validation (was sequential, now parallel)

**Services Still Using Blocking boto3 (Low Priority)**:

| Service | Blocking Calls | Impact | Priority |
|---------|----------------|--------|----------|
| `email_service.py` | `client.send_email()` | Blocks during email sends | Low |
| Other scanners (CloudWatch, GuardDuty, SecurityHub, Lambda) | Various | Already in thread pool via scan context | Low |

**Note**: All medium-priority services have been optimised. Remaining services have minimal impact.

### Observability (Future)

| Priority | Feature | Cost | Notes |
|----------|---------|------|-------|
| 1 | CloudWatch EMF (Embedded Metrics Format) | ~$1.50/mo | Persistent metrics, historical trends, alerting. Upgrade from in-memory metrics when needed. |
| 2 | Database connection pool stats | £0 | Expose SQLAlchemy pool.status() in admin metrics |
| 3 | Prometheus + Grafana | $50-100/mo | Full observability stack. Consider for enterprise customers. |

**Current State (December 2025):**
- In-memory rolling averages for API latency, error rate, cache hit rate
- Metrics reset on application restart (ephemeral)
- Admin dashboard shows real-time stats from `app/core/metrics.py`

### Remediation Templates

#### COMPLETED: Recent Improvements (December 2025)

| Improvement | Templates | Commit | Status |
|-------------|-----------|--------|--------|
| SNS encryption (KMS) | 253 | `cd9f88a` | DONE |
| Alert fatigue fixes | 236 | `ed7080b` | DONE |
| EventBridge pattern upgrades | 7 techniques | `05946ab`, `6385324`, `8cfcc2b` | DONE |
| Missing SNS topic policies | 18 | `c0aa7dd` | DONE |
| Faster detection (period 300s) | 79 | `385a1da` | DONE |
| treat_missing_data on all alarms | 240 | `385a1da` | DONE |

#### COMPLETED: Add `treat_missing_data` to CloudWatch Alarms

**Status**: DONE (commit `385a1da`)

All 240 templates with CloudWatch metric alarms now include:
- Terraform: `treat_missing_data = "notBreaching"`
- CloudFormation: `TreatMissingData: notBreaching`

This prevents alarms from showing `INSUFFICIENT_DATA` state when no log data is present.

## Infrastructure Architecture

### Network Topology (December 2025)

```
┌─────────────────────────────────────────────────────────────────┐
│                         VPC (10.0.0.0/16)                       │
├─────────────────────────────────────────────────────────────────┤
│  PUBLIC SUBNETS (10.0.0.0/24, 10.0.1.0/24)                     │
│  ┌──────────────────┐  ┌──────────────────┐                    │
│  │  ALB (internet)  │  │  ECS Backend     │ ←── Public IP      │
│  └────────┬─────────┘  │  (Fargate)       │     Internet via   │
│           │            └──────────────────┘     IGW            │
│           │                    │                                │
├───────────┼────────────────────┼────────────────────────────────┤
│  PRIVATE SUBNETS (10.0.10.0/24, 10.0.11.0/24)                  │
│           │                    │                                │
│           ▼                    ▼                                │
│  ┌──────────────────┐  ┌──────────────────┐                    │
│  │  RDS PostgreSQL  │  │  ElastiCache     │                    │
│  │  (no internet)   │  │  Redis           │                    │
│  └──────────────────┘  └──────────────────┘                    │
│                                                                 │
│  S3 Gateway Endpoint (FREE) ──────────────────────────────────│
└─────────────────────────────────────────────────────────────────┘
```

### Key Architecture Decisions

| Decision | Rationale |
|----------|-----------|
| **Backend in PUBLIC subnets** | Requires internet access for external APIs (GitHub OAuth, Google APIs, HIBP, Cognito, MITRE sync) |
| **No NAT Gateway** | Backend has public IPs; RDS/Redis don't need internet |
| **No VPC Interface Endpoints** | Backend bypasses them via public subnets; scanner module unused |
| **S3 Gateway Endpoint kept** | Free, optimises S3 traffic from private subnets |

### Cost Savings (December 2025)

| Removed Resource | Monthly Savings |
|------------------|-----------------|
| ECR API VPC Endpoint | ~$14.40 |
| ECR DKR VPC Endpoint | ~$14.40 |
| CloudWatch Logs VPC Endpoint | ~$14.40 |
| Secrets Manager VPC Endpoint | ~$14.40 |
| SSM VPC Endpoint | ~$14.40 |
| **Total** | **~$72/month** |

### External API Dependencies (require internet access)

| Service | URL | Purpose |
|---------|-----|---------|
| Have I Been Pwned | `api.pwnedpasswords.com` | Password breach checking |
| Google APIs | `googleapis.com` | GCP credential validation |
| GitHub OAuth | `github.com`, `api.github.com` | GitHub SSO |
| Cognito OAuth | `*.amazoncognito.com` | Social login token exchange |
| MITRE ATT&CK | `raw.githubusercontent.com` | Threat data sync |

### Security Controls

| Layer | Control |
|-------|---------|
| **Network** | Security groups restrict ingress to ALB only |
| **Application** | WAF with OWASP CRS, rate limiting, anonymous IP blocking |
| **Data** | RDS/Redis in private subnets, no public access |
| **Identity** | IAM roles with least privilege, external ID for cross-account |

### Future Considerations

If dedicated scan workers are needed in private subnets:
1. **NAT Gateway** (~$32/mo + data) - General internet access
2. **VPC Endpoints** (~$7/mo each) - AWS service-specific, better isolation
3. **Lambda** - For short-running scans (<15 min), no VPC config needed
