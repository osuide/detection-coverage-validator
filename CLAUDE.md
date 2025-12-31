# A13E Detection Coverage Validator - Claude Code Instructions

## Language & Currency

**UK English** for all content (colour, organisation, behaviour, centre, analyse, etc.)

**British Pounds (£/GBP)** for product pricing: FREE, Individual £29/mo, Pro £250/mo, Enterprise. Exception: AWS/GCP infrastructure costs in templates can use USD.

Stripe products (test mode):
- A13E Individual: `price_1SijVDAB6j5KiVeUwd4QD5uX` (£29/month, 6 accounts)
- A13E Pro: `price_1SijVTAB6j5KiVeUZTSUdnBl` (£250/month, 500 accounts)

## Project Context

Multi-cloud security detection coverage validator:
- Scans **AWS and GCP** for security detections
- Maps to MITRE ATT&CK framework
- Identifies coverage gaps with remediation guidance
- IaC templates (CloudFormation, Terraform)

## Key Components

| Component | Location |
|-----------|----------|
| Backend (FastAPI) | `/backend` |
| Frontend (React/TS) | `/frontend` |
| Infrastructure (Terraform) | `/infrastructure/terraform` |
| Remediation Templates | `/backend/app/data/remediation_templates` |

## Coding Standards

- **Python**: PEP 8, type hints required
- **TypeScript**: Strict mode, interfaces over types
- **API**: OpenAPI schemas for all endpoints
- **Tests**: Adjacent to code they test

## Database & Migrations

**Migrations run automatically on startup** via `run_migrations()` in `backend/app/main.py`.

### Alembic + asyncpg Rules

| Rule | Correct | Wrong |
|------|---------|-------|
| Revision ID length | ≤32 chars: `038_add_eval` | `038_add_detection_evaluation_history` |
| Reference existing ENUM | `PG_ENUM(name="x", create_type=False)` | `sa.Enum("a", name="x", create_type=False)` |
| Create ENUM | `sa.text("CREATE TYPE x AS ENUM...")` | SQLAlchemy ENUM objects |
| Add ENUM value | Recreate enum (rename→create→alter→drop) | `ALTER TYPE ADD VALUE` |

**Make migrations idempotent:**
```python
inspector = sa.inspect(op.get_bind())
if "my_table" in inspector.get_table_names():
    return  # Already migrated
```

**FK delete order** (child → parent):
```
coverage_snapshots, coverage_gaps → scans
detection_mappings → detections
```

## RBAC

**`require_role()` uses exact match, NOT hierarchical.**

```python
# WRONG - blocks OWNER and ADMIN!
auth = Depends(require_role(UserRole.MEMBER))

# CORRECT
auth = Depends(require_role(UserRole.OWNER, UserRole.ADMIN, UserRole.MEMBER))
```

## Team Invites (Paid Feature)

| Tier | Team Members | Can Invite |
|------|--------------|------------|
| FREE | 1 (owner) | No |
| INDIVIDUAL | 3 | Yes |
| PRO | 10 | Yes |
| ENTERPRISE | Unlimited | Yes |

## Async boto3 Pattern

**boto3 is synchronous and blocks the asyncio event loop.** Always use `run_sync()`:

```python
# WRONG - blocks event loop
response = client.list_event_buses()

# CORRECT - offloads to thread pool
response = await self.run_sync(client.list_event_buses)
response = await self.run_sync(client.get_rule, Name=rule_name)

# Paginator pattern
pages = await self.run_sync(lambda: list(paginator.paginate()))
```

**Threading Configuration:**
| Component | Workers |
|-----------|---------|
| Uvicorn | 2 |
| boto3 ThreadPool (scanners) | 8 |
| boto3 ThreadPool (credentials) | 10 |
| Database pool | 20 (+30 overflow) |

All scanners use `run_sync()`: eventbridge, config, cloudwatch, guardduty, lambda, securityhub.

## Redis Caching

**Cache must SKIP API calls, not merge:**
```python
# WRONG
cached = await get_cached_data(key)
response = await api_call()  # Still slow!

# CORRECT
cached = await get_cached_data(key)
if cached:
    return cached  # Skip API entirely!
response = await api_call()
await cache_data(key, response)
```

**Cache TTLs:**
| Cache | TTL |
|-------|-----|
| SecurityHub controls | 5 min |
| Compliance frameworks | 1 hour |
| Scan status | 30 sec |

## Remediation Templates

### EventBridge Best Practices

Required components:
1. SNS with `kms_master_key_id = "alias/aws/sns"`
2. DLQ (SQS) with 14-day retention
3. Retry policy: 8 attempts, 1 hour max age
4. Scoped SNS topic policy (`AWS:SourceAccount` + `aws:SourceArn`)
5. Input transformer for alerts
6. `data "aws_caller_identity" "current" {}`

```hcl
resource "aws_sns_topic_policy" "allow_eventbridge" {
  arn = aws_sns_topic.alerts.arn
  policy = jsonencode({
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

### ReAct Methodology for Reviews

1. **REASON**: Understand MITRE technique, cloud-specific behaviours
2. **ACT**: Research official AWS/GCP docs, security blogs
3. **OBSERVE**: Compare template against research
4. **ACT**: Update detection logic AND infrastructure

**Never assume templates are correct. Research and validate first.**

## Security Hub API

**DateFilter requires exactly one of:**
- `DateRange` alone: `{"DateRange": {"Unit": "DAYS", "Value": 7}}`
- `Start` AND `End` together

**Don't use UpdatedAt for compliance data** - it misses unchanged failed controls.

## Terraform

### OAuth Credentials (CRITICAL)

**Running Terraform without OAuth credentials destroys SSO resources.**

```bash
# REQUIRED before terraform apply
cd infrastructure/terraform
cp .env.terraform.example .env.terraform
# Fill in values, then:
source .env.terraform && terraform apply -var-file="staging.tfvars"
```

| Variable | Purpose |
|----------|---------|
| `TF_VAR_google_client_id` | Google SSO via Cognito |
| `TF_VAR_google_client_secret` | Google SSO via Cognito |
| `TF_VAR_github_client_id` | GitHub SSO via backend |
| `TF_VAR_github_client_secret` | GitHub SSO via backend |

Check blocks in `main.tf` warn if credentials are missing.

### Known Issues

**Cognito Google IdP Drift**: AWS auto-populates computed attributes. Fix:
```hcl
lifecycle {
  ignore_changes = [provider_details]
}
```

## Infrastructure

```
VPC (10.0.0.0/16)
├── PUBLIC SUBNETS: ALB, ECS Backend (internet via IGW)
└── PRIVATE SUBNETS: RDS PostgreSQL, ElastiCache Redis
    └── S3 Gateway Endpoint (free)
```

**No NAT Gateway** - backend has public IPs for external APIs (HIBP, Google, GitHub, Cognito, MITRE).

**Security**: WAF with OWASP CRS, RDS/Redis private only, IAM least privilege.
