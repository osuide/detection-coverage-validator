# Detection Coverage Validator - Implementation Roadmap

**Created:** 2025-12-18
**Purpose:** Keep implementation focused on MVP and prevent scope creep

---

## Guiding Principles

1. **MVP First** - Ship core value before nice-to-haves
2. **Monetization Enables Everything** - No revenue = no product
3. **Staging Before Production** - Never test in prod
4. **Detection Features > SaaS Features** - Our differentiator is coverage analysis, not team management

---

## Environment Strategy

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   LOCAL DEV     │     │    STAGING      │     │   PRODUCTION    │
│                 │     │                 │     │                 │
│ docker-compose  │ --> │  AWS (scaled)   │ --> │  AWS (full)     │
│ localhost:8000  │     │  staging.a13e   │     │  app.a13e.io    │
│ localhost:3000  │     │                 │     │                 │
└─────────────────┘     └─────────────────┘     └─────────────────┘
     DEV MODE              REAL AWS               REAL AWS
     Mock scanning         Real scanning          Real scanning
     No Stripe             Stripe TEST mode       Stripe LIVE mode
```

### Staging Environment Requirements
- **Frontend:** S3 + CloudFront (staging.a13e.io or similar)
- **Backend:** ECS Fargate (1 task, small instance)
- **Database:** RDS PostgreSQL (db.t3.micro, single AZ)
- **Cache:** ElastiCache Redis (cache.t3.micro, single node)
- **Cost:** ~$50-100/month

### Production Environment
- **Frontend:** S3 + CloudFront (app.a13e.io)
- **Backend:** ECS Fargate (2+ tasks, auto-scaling)
- **Database:** RDS PostgreSQL (db.t3.small+, Multi-AZ)
- **Cache:** ElastiCache Redis (cache.t3.small+, cluster mode)
- **Cost:** ~$200-500/month depending on scale

---

## Phase 0: MVP Launch Blockers (CURRENT FOCUS)
**Goal:** Get to revenue-generating state
**Timeline:** 1-2 weeks
**Status:** IN PROGRESS

### 0.1 Stripe Integration ⏳
**Priority:** CRITICAL - Can't monetize without it
**Effort:** 2-3 hours

- [ ] Create Stripe account (if not done)
- [ ] Create products in Stripe Dashboard:
  - Free tier (for trial)
  - Starter ($49/mo - 5 accounts)
  - Professional ($149/mo - 25 accounts)
  - Enterprise (custom)
- [ ] Get API keys (test + live)
- [ ] Configure environment variables
- [ ] Test checkout flow locally
- [ ] Test webhook handling
- [ ] Test subscription lifecycle (upgrade/downgrade/cancel)

**Files:**
- `backend/app/api/routes/billing.py`
- `backend/app/core/config.py`
- `frontend/src/pages/Billing.tsx`

### 0.2 Staging Environment ⏳
**Priority:** CRITICAL - Can't test production-like setup
**Effort:** 4-6 hours

- [ ] Create AWS infrastructure (Terraform or manual):
  - VPC + subnets
  - RDS PostgreSQL (db.t3.micro)
  - ElastiCache Redis (cache.t3.micro)
  - ECS Cluster + Service
  - ALB for backend
  - S3 + CloudFront for frontend
- [ ] Configure staging domain (staging.a13e.io or similar)
- [ ] Set up SSL certificates
- [ ] Deploy backend to ECS
- [ ] Deploy frontend to S3/CloudFront
- [ ] Configure staging environment variables
- [ ] Test end-to-end in staging

**Files:**
- `infrastructure/terraform/staging/` (to create)
- `infrastructure/terraform/modules/` (reusable)

### 0.3 Real AWS Scanning ⏳
**Priority:** CRITICAL - Core product value
**Effort:** 2-3 hours

- [ ] Create A13E AWS account for scanning (or use existing)
- [ ] Create IAM role with `sts:AssumeRole` permission
- [ ] Update `A13E_AWS_ACCOUNT_ID` in code:
  - `backend/app/services/aws_credential_service.py`
  - `backend/app/core/config.py`
  - `frontend/src/components/CredentialWizard.tsx`
- [ ] Remove `A13E_DEV_MODE=true` from staging/prod
- [ ] Test with real AWS account
- [ ] Verify permissions are validated correctly

### 0.4 OAuth Providers ⏳
**Priority:** HIGH - Improves conversion
**Effort:** 2-3 hours

- [ ] Set up AWS Cognito User Pool
- [ ] Configure Cognito App Client
- [ ] Register Google OAuth app, add to Cognito
- [ ] Register GitHub OAuth app, add to Cognito
- [ ] (Optional) Register Microsoft OAuth app
- [ ] Configure callback URLs for staging + prod
- [ ] Test OAuth flows

**Files:**
- `backend/app/core/config.py` (Cognito settings)
- `backend/app/api/routes/auth.py`
- `frontend/src/services/cognitoApi.ts`

### 0.5 Email Service ⏳
**Priority:** HIGH - Password reset, invites
**Effort:** 2 hours

- [ ] Choose provider (AWS SES recommended - already in AWS)
- [ ] Verify domain in SES
- [ ] Create email templates:
  - Password reset
  - Team invite
  - Welcome email
  - Subscription confirmation
- [ ] Configure SMTP/API settings
- [ ] Test email delivery

### 0.6 Basic Tests ⏳
**Priority:** MEDIUM - Confidence before launch
**Effort:** 4-6 hours

- [ ] Set up pytest for backend
- [ ] Write critical path tests:
  - Auth flow (signup, login, token refresh)
  - Account creation
  - Scan triggering
  - Coverage calculation
- [ ] Set up Jest for frontend
- [ ] Write component tests for critical flows
- [ ] Set up GitHub Actions CI
- [ ] Run tests on PR

---

## Phase 1: Post-Launch Improvements
**Goal:** Improve core detection features
**Timeline:** 2-4 weeks after launch
**Status:** NOT STARTED

### 1.1 Detection Validation
**Why:** Avoid "false coverage" - detections that exist but don't work
**Effort:** 1-2 days

- [ ] Syntax validation (is config parseable?)
- [ ] Semantic validation (do referenced resources exist?)
- [ ] Add `health_status` to detection model
- [ ] Show validation status in UI
- [ ] Alert on broken detections

### 1.2 Scheduled Scans
**Why:** Continuous monitoring without manual triggers
**Effort:** 1-2 days

- [ ] Add scheduling model (cron expression)
- [ ] Set up background job runner (Celery + Redis or AWS SQS)
- [ ] Create scan scheduler service
- [ ] Add schedule UI to accounts page
- [ ] Send notifications on scan completion

### 1.3 Drift Detection
**Why:** Show value over time ("your coverage dropped 15%")
**Effort:** 2-3 days

- [ ] Store historical snapshots (already have model)
- [ ] Implement comparison logic
- [ ] Calculate coverage deltas
- [ ] Add drift alerts
- [ ] Show trends in dashboard

### 1.4 Production Deployment
**Why:** Scale beyond staging
**Effort:** 4-6 hours

- [ ] Create production Terraform config
- [ ] Set up production domain (app.a13e.io)
- [ ] Configure Multi-AZ database
- [ ] Set up auto-scaling
- [ ] Configure production Stripe (live mode)
- [ ] Set up monitoring (CloudWatch/Datadog)
- [ ] Set up alerting

---

## Phase 2: Advanced Features
**Goal:** Differentiate from competitors
**Timeline:** 1-2 months after launch
**Status:** NOT STARTED

### 2.1 GCP Scanning (Full)
**Why:** Multi-cloud is in our value prop
**Effort:** 3-5 days

- [ ] Implement GCP credential validation (currently dev mode)
- [ ] Test all GCP scanners with real accounts
- [ ] Verify GCP indicator library coverage
- [ ] Add GCP-specific UI elements

### 2.2 NLP-Based Mapping
**Why:** Handle custom/complex detections better
**Effort:** 1-2 weeks

- [ ] Research NLP approaches (embeddings, similarity)
- [ ] Build training dataset from existing mappings
- [ ] Implement NLP mapper
- [ ] Add confidence scoring
- [ ] A/B test against pattern matching

### 2.3 Detection Recommendations
**Why:** Actionable gap remediation
**Effort:** 1 week

- [ ] Build recommendation templates per technique
- [ ] Generate specific recommendations per gap
- [ ] Include effort estimates
- [ ] Link to vendor documentation

### 2.4 MITRE Navigator Export
**Why:** Integration with existing workflows
**Effort:** 2-3 days

- [ ] Implement Navigator JSON export
- [ ] Add export button to coverage page
- [ ] Support layer customization

---

## Phase 3: Enterprise Features
**Goal:** Larger customers, higher ACV
**Timeline:** 3-6 months after launch
**Status:** NOT STARTED

### 3.1 IaC Generation
**Why:** One-click remediation
**Effort:** 2-3 weeks

- [ ] Terraform template generation
- [ ] CloudFormation template generation
- [ ] Pulumi support
- [ ] CDK support

### 3.2 SIEM Integration
**Why:** Fit into existing security stack
**Effort:** 2-3 weeks

- [ ] Splunk integration
- [ ] Elastic/ELK integration
- [ ] Chronicle integration
- [ ] Generic webhook

### 3.3 API Deprecation Monitoring
**Why:** Proactive detection health
**Effort:** 1-2 weeks

- [ ] Track AWS/GCP deprecation announcements
- [ ] Match against detection configs
- [ ] Alert before EOL dates

### 3.4 ML-Based Mapping
**Why:** Handle edge cases, improve accuracy
**Effort:** 2-4 weeks

- [ ] Build classification model
- [ ] Train on validated mappings
- [ ] Implement confidence calibration
- [ ] Deploy as optional enhancement

### 3.5 Custom Compliance Frameworks
**Why:** Enterprise compliance requirements
**Effort:** 2-3 weeks

- [ ] Support NIST CSF mapping
- [ ] Support CIS Controls mapping
- [ ] Support custom frameworks
- [ ] Compliance reporting

---

## Decision Log

| Date | Decision | Rationale |
|------|----------|-----------|
| 2025-12-18 | Pattern matching only for MVP | 80% coverage, high confidence, ships faster |
| 2025-12-18 | Defer detection validation to Phase 1 | Not blocking for initial value |
| 2025-12-18 | Defer scheduled scans to Phase 1 | Manual scans work for beta |
| 2025-12-18 | Defer drift detection to Phase 1 | Need baseline data first |
| 2025-12-18 | Staging required before production | Can't test in prod |
| 2025-12-18 | AWS-only for MVP launch | GCP can follow quickly |

---

## Scope Creep Warnings 🚨

**If you find yourself working on these, STOP and refocus on Phase 0:**

- ❌ Advanced UI animations/polish
- ❌ Additional OAuth providers beyond Google/GitHub
- ❌ Complex team permission hierarchies
- ❌ Multi-region deployment
- ❌ Advanced analytics/reporting
- ❌ Mobile app
- ❌ Browser extension
- ❌ Custom branding per org
- ❌ White-labeling

**Ask yourself:** "Does this help us get paying customers THIS WEEK?"

---

## Success Metrics

### Phase 0 Complete When:
- [ ] Can accept payment via Stripe
- [ ] Staging environment running
- [ ] Real AWS account scanning works
- [ ] At least one OAuth provider works
- [ ] Password reset emails work
- [ ] Basic tests pass in CI

### Phase 1 Complete When:
- [ ] Production environment running
- [ ] Detection validation shows health status
- [ ] Scheduled scans work
- [ ] Drift detection shows trends
- [ ] 10+ paying customers

### Phase 2 Complete When:
- [ ] GCP scanning fully works
- [ ] NLP mapping improves accuracy
- [ ] Recommendations are actionable
- [ ] MITRE Navigator export works
- [ ] 50+ paying customers

---

## Current Focus (Update Weekly)

**Week of 2025-12-18:**
- Phase 0.1: Stripe Integration
- Phase 0.2: Staging Environment
- Phase 0.3: Real AWS Scanning

**DO NOT START Phase 1 until Phase 0 is 100% complete.**

---

*Last Updated: 2025-12-18*
