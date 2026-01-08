# A13E Detection Coverage Validator - Claude Code Instructions

## Language & Currency

**UK English** for all content (colour, organisation, behaviour, centre, analyse, etc.)

**British Pounds (£/GBP)** for product pricing: FREE, Individual £29/mo, Pro £250/mo, Enterprise. Exception: AWS/GCP infrastructure costs in templates can use USD.

Stripe products (test mode):
- A13E Individual: `price_1SijVDAB6j5KiVeUwd4QD5uX` (£29/month, 6 accounts)
- A13E Pro: `price_1SijVTAB6j5KiVeUZTSUdnBl` (£250/month, 500 accounts)

Always use Context7 MCP when I need library/API documentation, code generation, setup or configuration steps without me having to explicitly ask.
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

**WAFv2 IP Set Deletion** ([Issue #17601](https://github.com/hashicorp/terraform-provider-aws/issues/17601)): Terraform tries to delete IP sets before updating the WAF ACL that references them, causing `WAFAssociatedItemException`. Fix already applied to `modules/security/main.tf`:
```hcl
# On both aws_wafv2_ip_set and aws_wafv2_web_acl resources
lifecycle {
  create_before_destroy = true
}
```

### Environment Switching

Staging and production use separate state files. Switch with:
```bash
# Production
terraform init -backend-config=backend-prod.hcl -reconfigure

# Staging
terraform init -backend-config=backend-staging.hcl -reconfigure
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

## Google Workspace Integration

**First point of reference for collaborative work:** emails, customer management, support automation, and notifications.

**Same Google Workspace for staging and production** - environment detection via Script Properties and backend API responses.

### Services Used

| Service | Purpose | Why |
|---------|---------|-----|
| **Gmail** | Support inbox (support@a13e.com), welcome emails, ticket confirmations | Unified customer communication, no third-party email service needed |
| **Google Groups** | Collaborative inbox for support@ | Team-shared inbox with assignment, no per-seat cost |
| **Google Sheets** | CRM (Tickets, Customers, Templates sheets) | Visual dashboard, conditional formatting, no database cost |
| **Google Drive** | Knowledge Base documents for RAG | Free storage, easy content updates, document search |
| **Google Chat** | Automated alerts (SLA breaches, churn risk, renewals) | Real-time team notifications, webhook integration |
| **Google Apps Script** | Automation engine (every 5 min) | No hosting cost, native Workspace integration, time-based triggers |
| **Claude API** | AI classification, draft generation, personalisation | Intelligent ticket routing, response suggestions |

### Architecture

```
┌─────────────────────┐     ┌──────────────────────────────────────────────┐
│   A13E BACKEND      │     │           GOOGLE WORKSPACE                   │
│   (FastAPI/ECS)     │     │                                              │
│                     │     │  ┌────────────────────────────────────────┐  │
│  /api/support/      │◄────│  │  Google Apps Script (Triggers)         │  │
│    customer-context │     │  │  • processNewTickets (5 min)           │  │
│    customers        │     │  │  • syncCustomers (daily 7 AM)          │  │
│    new-registrations│     │  │  • checkSLABreaches (hourly)           │  │
│    welcome-email-   │     │  │  • executeScheduledSend (1 min)        │  │
│      sent           │     │  └────────────────────────────────────────┘  │
│                     │     │           │              │                   │
└─────────────────────┘     │           ▼              ▼                   │
                            │  ┌─────────────┐  ┌─────────────────────┐    │
                            │  │ Gmail       │  │ Google Sheets (CRM) │    │
                            │  │ • Labels    │  │ • Tickets           │    │
                            │  │ • Drafts    │  │ • Customers         │    │
                            │  │ • Filters   │  │ • Templates         │    │
                            │  └─────────────┘  └─────────────────────┘    │
                            │           │              │                   │
                            │           ▼              ▼                   │
                            │  ┌─────────────┐  ┌─────────────────────┐    │
                            │  │ Drive       │  │ Google Chat         │    │
                            │  │ (KB Docs)   │  │ (Alerts Space)      │    │
                            │  └─────────────┘  └─────────────────────┘    │
                            └──────────────────────────────────────────────┘
```

### Environment Configuration

Apps Script uses Script Properties for environment-aware URLs:

| Property | Staging | Production |
|----------|---------|------------|
| `ENVIRONMENT` | staging | production |
| `A13E_API_URL` | api.staging.a13e.com | api.a13e.com |
| `A13E_SUPPORT_API_KEY` | (shared key) | (shared key) |
| `SPREADSHEET_ID` | (shared CRM sheet) | (shared CRM sheet) |
| `CHAT_WEBHOOK_URL` | (shared webhook) | (shared webhook) |

### Apps Script Files

| File | Purpose |
|------|---------|
| `Code.gs` | Main config, Claude API, Gmail helpers |
| `ProcessFromSheet.gs` | Ticket processing from CRM submission |
| `CustomerCRM.gs` | Daily customer sync, churn/upgrade detection |
| `WelcomeEmail.gs` | AI-personalised welcome emails for new users |
| `SLA.gs` | SLA calculation and breach monitoring |
| `Templates.gs` | Canned response matching |
| `KnowledgeBase.gs` | Drive document search for RAG |
| `AutoSend.gs` | Scheduled email sending with confidence threshold |

### Backend Support Endpoints

| Endpoint | Auth | Purpose |
|----------|------|---------|
| `GET /api/support/customer-context` | Support API Key | Single customer context for ticket handling |
| `GET /api/support/customers` | Support API Key | All customers for CRM sync |
| `GET /api/support/new-registrations` | Support API Key | Users needing welcome emails |
| `POST /api/support/welcome-email-sent` | Support API Key | Mark user as welcomed |
| `POST /api/support/tickets` | User JWT | Submit support ticket |
| `GET /api/support/context` | User JWT | User's own context for form pre-fill |

### Key Points

- **SUPPORT_API_KEY**: Stored in AWS Secrets Manager, unconditionally included in ECS task definition
- **open_gaps**: Count of uncovered MITRE techniques from `CoverageSnapshot.uncovered_techniques` (NOT CoverageGap table)
- **tier_display**: Use this field for human-readable tier names
- **environment**: API returns customer's environment (staging/production) for correct docs URLs
- **welcome_email_sent_at**: User field tracking when welcome email was sent

### Terraform Variable

```bash
export TF_VAR_support_api_key="your-key-here"
```

If not set, terraform apply will warn but continue (secret stores "NOT_CONFIGURED").

## Deployment (CRITICAL)

**NEVER manually build or push Docker images.** Always deploy via git:

```bash
# Correct deployment workflow
git add <files>
git commit -m "Description of changes"
git push origin main
```

**Push to main deploys to STAGING only.** Production requires manual trigger:

```bash
# Deploy to production (after staging verified)
gh workflow run deploy.yml -f environment=prod
```

GitHub Actions CI/CD automatically:
1. Builds Docker images for linux/amd64
2. Pushes to ECR
3. Updates ECS service

**Never run `docker build` or `docker push` manually** - the CI pipeline handles this.

## Frontend (React)

### ScrollToTop on Navigation

React Router preserves scroll position between route changes by default. The `ScrollToTop` component in `frontend/src/components/ScrollToTop.tsx` resets scroll position on every navigation:

```tsx
import { useEffect } from 'react'
import { useLocation } from 'react-router'

export default function ScrollToTop() {
  const { pathname } = useLocation()
  useEffect(() => {
    window.scrollTo(0, 0)
  }, [pathname])
  return null
}
```

**Added in App.tsx before `<Routes>`** - applies to all pages including nested admin and protected routes.

### URL Structure

| Site | Staging | Production |
|------|---------|------------|
| **App (Frontend)** | `staging.a13e.com` | `app.a13e.com` |
| **API** | `api.staging.a13e.com` | `api.a13e.com` |
| **User Documentation** | `staging.a13e.com/docs` | `app.a13e.com/docs` |
| **OpenAPI Specs** | `docs.staging.a13e.com` | `docs.a13e.com` |
| **Marketing Site** | `staging.a13e.com` | `a13e.com` |

**Important**: User docs (`/docs`) are part of the React app. OpenAPI specs are a separate static site on the `docs.` subdomain.

- Use `<Link to="/path">` for internal navigation, not `<a href="#">`
- For user docs in components, use relative `/docs` path (works in all environments)
