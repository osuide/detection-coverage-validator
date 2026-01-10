# A13E Detection Coverage Validator

## Standards

- **UK English** for all content (colour, organisation, behaviour)
- **£/GBP** for pricing: FREE, Individual £29/mo, Pro £250/mo, Enterprise
- Stripe: Individual `price_1SijVDAB6j5KiVeUwd4QD5uX`, Pro `price_1SijVTAB6j5KiVeUZTSUdnBl`

## Project Structure

| Component | Location |
|-----------|----------|
| Backend (FastAPI) | `/backend` |
| Frontend (React/TS) | `/frontend` |
| Infrastructure | `/infrastructure/terraform` |
| Remediation Templates | `/backend/app/data/remediation_templates` |

**Coding**: Python PEP 8 + type hints, TypeScript strict mode, OpenAPI schemas required.

## Database & Migrations

Migrations run automatically on startup via `run_migrations()`.

**Alembic Rules:**
- Revision ID ≤32 chars
- Reference existing ENUM: `PG_ENUM(name="x", create_type=False)`
- Create ENUM: Use `sa.text("CREATE TYPE...")`
- Make migrations idempotent with `inspector.get_table_names()` checks

## RBAC (CRITICAL)

**`require_role()` uses exact match, NOT hierarchical:**
```python
# WRONG: auth = Depends(require_role(UserRole.MEMBER))
# CORRECT:
auth = Depends(require_role(UserRole.OWNER, UserRole.ADMIN, UserRole.MEMBER))
```

**Team limits:** FREE=1, INDIVIDUAL=3, PRO=10, ENTERPRISE=unlimited

## Async boto3 (CRITICAL)

**boto3 blocks asyncio. Always use `run_sync()`:**
```python
response = await self.run_sync(client.list_event_buses)
pages = await self.run_sync(lambda: list(paginator.paginate()))
```

## Redis Caching

**Cache must SKIP API calls, not merge:**
```python
cached = await get_cached_data(key)
if cached:
    return cached  # Skip API entirely!
```

TTLs: SecurityHub 5min, Default 1hr, Scan status 60sec

## Customer Scanner Roles (CRITICAL)

**ECS task role must allow BOTH naming conventions:**

| Pattern | Used By |
|---------|---------|
| `A13E-ReadOnly` | AWS docs, CloudFormation templates |
| `a13e-scanner-*` | GCP Workload Identity Federation |

```hcl
# CORRECT - allows both conventions
Resource = [
  "arn:aws:iam::*:role/a13e-scanner-*",
  "arn:aws:iam::*:role/A13E-ReadOnly"
]
```

**Location:** `modules/backend/main.tf` → `AssumeCustomerScannerRoles`

## Terraform (CRITICAL)

**OAuth and billing credentials required or features get destroyed/disabled:**
```bash
# Staging
source .env.terraform && terraform apply -var-file="staging.tfvars"

# Production
source .env.terraform.prod && terraform apply -var-file="prod.tfvars"
```

Required vars:
- **SSO**: `TF_VAR_google_client_id`, `TF_VAR_google_client_secret`, `TF_VAR_github_client_id`, `TF_VAR_github_client_secret`
- **Billing**: `TF_VAR_stripe_secret_key`, `TF_VAR_stripe_webhook_secret` (CRITICAL for subscriptions!)
- **Support**: `TF_VAR_support_api_key`

⚠️ **Missing Stripe keys = "Stripe billing is not configured" error** - users cannot purchase subscriptions!

**Known Issues:**
- Cognito Google IdP drift: Use `lifecycle { ignore_changes = [provider_details] }`
- WAFv2 IP Set deletion: Use `lifecycle { create_before_destroy = true }`

## GitHub Secrets (CRITICAL)

All secrets must be configured for deployments to work. Missing secrets cause silent failures.

### Repository-Level Secrets (Shared by All Environments)

| Secret | Purpose | Example/Notes |
|--------|---------|---------------|
| `AWS_ACCESS_KEY_ID` | AWS deployment credentials | IAM user with deployment permissions |
| `AWS_SECRET_ACCESS_KEY` | AWS deployment credentials | Pair with access key ID |
| `GOOGLE_CLIENT_ID` | Google OAuth SSO | From Google Cloud Console |
| `GOOGLE_CLIENT_SECRET` | Google OAuth SSO | From Google Cloud Console |
| `GH_OAUTH_CLIENT_ID` | GitHub OAuth SSO | From GitHub OAuth Apps |
| `GH_OAUTH_CLIENT_SECRET` | GitHub OAuth SSO | From GitHub OAuth Apps |
| `STRIPE_SECRET_KEY` | Stripe billing API | `sk_live_...` or `sk_test_...` |
| `STRIPE_WEBHOOK_SECRET` | Stripe webhook verification | `whsec_...` |
| `TELEMETRY_SHEET_ID` | Google Sheet for telemetry | Sheet ID from URL |
| `SUPPORT_API_KEY` | Support system auth | `uxCVmUkOgnSWCj3v12A0tDL2Rqn72ESUGJ6yOEwEEcc` |
| `S3_BUCKET_NAME` | Default frontend bucket | Should be STAGING bucket as safe default |

### Environment-Specific Secrets

**Staging** (`gh secret set <NAME> --env staging`):

| Secret | Purpose | Value |
|--------|---------|-------|
| `S3_BUCKET_NAME` | Frontend S3 bucket | `a13e-staging-frontend-*` |
| `API_URL` | Backend API URL | `https://api.staging.a13e.com` |
| `CLOUDFRONT_DISTRIBUTION_ID` | CDN invalidation | From Terraform output |
| `COGNITO_USER_POOL_ID` | Auth user pool | From Terraform output |
| `COGNITO_CLIENT_ID` | Auth client | From Terraform output |
| `COGNITO_DOMAIN` | Auth domain | From Terraform output |
| `STRIPE_PUBLISHABLE_KEY` | Stripe public key | `pk_test_...` |

**Production** (`gh secret set <NAME> --env prod`):

| Secret | Purpose | Value |
|--------|---------|-------|
| `S3_BUCKET_NAME` | Frontend S3 bucket | `a13e-prod-frontend-*` |
| `API_URL` | Backend API URL | `https://api.a13e.com` |
| `CLOUDFRONT_DISTRIBUTION_ID` | CDN invalidation | From Terraform output |
| `COGNITO_USER_POOL_ID` | Auth user pool | From Terraform output |
| `COGNITO_CLIENT_ID` | Auth client | From Terraform output |
| `COGNITO_DOMAIN` | Auth domain | From Terraform output |
| `STRIPE_PUBLISHABLE_KEY` | Stripe public key | `pk_live_...` |

### Adding Missing Secrets

```bash
# Repository-level
gh secret set SUPPORT_API_KEY --body "uxCVmUkOgnSWCj3v12A0tDL2Rqn72ESUGJ6yOEwEEcc"

# Environment-specific
gh secret set API_URL --env staging --body "https://api.staging.a13e.com"
gh secret set API_URL --env prod --body "https://api.a13e.com"
```

### Verification

```bash
# List all secrets
gh secret list
gh secret list --env staging
gh secret list --env prod
```

⚠️ **Common Issues:**
- Missing `SUPPORT_API_KEY` → Support system 401 errors
- Wrong `API_URL` per environment → SSO/CORS failures
- Repo-level `S3_BUCKET_NAME` pointing to prod → Staging overwrites production

## Infrastructure

```
VPC (10.0.0.0/16)
├── PUBLIC: ALB
├── PRIVATE: RDS PostgreSQL, ElastiCache Redis
└── ECS Backend: Public subnets (staging) / Private subnets (prod)
```

| Environment | NAT Gateway | ECS Subnets | Why |
|-------------|-------------|-------------|-----|
| Staging | None | Public | Cost savings |
| Production | Multi-AZ (HA) | Private | Security - no public IPs |

## Security Hub API

**DateFilter requires exactly one of:**
- `DateRange` alone: `{"DateRange": {"Unit": "DAYS", "Value": 7}}`
- `Start` AND `End` together

Don't use `UpdatedAt` for compliance - misses unchanged failed controls.

## Remediation Templates

**EventBridge requirements:**
1. SNS with `kms_master_key_id = "alias/aws/sns"`
2. DLQ (SQS) with 14-day retention
3. Retry: 8 attempts, 1 hour max age
4. Scoped SNS policy with `AWS:SourceAccount` + `aws:SourceArn`
5. Input transformer for alerts

## Deployment (CRITICAL)

**NEVER manually build/push Docker images. Deploy via git:**
```bash
git push origin main  # Deploys to STAGING
gh workflow run deploy.yml -f environment=prod  # Production
```

## Google Workspace Integration

Support system uses Gmail, Sheets (CRM), Drive (KB), Chat (alerts), Apps Script (automation).

**Backend endpoints:** `/api/support/customer-context`, `/customers`, `/new-registrations`, `/welcome-email-sent`

**Key fields:**
- `open_gaps`: From `CoverageSnapshot.uncovered_techniques` (NOT CoverageGap table)
- `tier_display`: Human-readable tier name
- `welcome_email_sent_at`: Tracks welcome email status

## Frontend

**URLs:**
| Site | Staging | Production |
|------|---------|------------|
| App | staging.a13e.com | app.a13e.com |
| API | api.staging.a13e.com | api.a13e.com |
| User Docs | staging.a13e.com/docs | app.a13e.com/docs |
| OpenAPI | docs.staging.a13e.com | docs.a13e.com |
| Marketing | staging.a13e.com | a13e.com |

Use `<Link to="/path">` for navigation, relative `/docs` for user docs.
