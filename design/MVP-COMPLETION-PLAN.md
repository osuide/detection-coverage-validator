# MVP Completion Plan - Phase 1 Final

## Overview
Complete the SaaS portal MVP with enterprise-grade authentication, organization security controls, billing/subscription management, and a compelling public landing page.

---

## Task Breakdown

### Task 1: SSO Integrations via AWS Cognito
**Agent**: AUTH-AGENT (09-AUTH-AGENT.md)
**Estimated Effort**: Medium
**Priority**: High

#### Architecture Decision: AWS Cognito
Using AWS Cognito as our identity provider offers:
- Built-in federation with Google, Azure AD, SAML providers
- Managed user pools with MFA support
- OAuth2/OIDC compliant
- Hosted UI option for quick setup
- JWT tokens compatible with our existing auth
- Scales automatically

#### Cognito Setup:
1. **User Pool** - DCV-Users
   - Email as username
   - MFA optional (configurable per org)
   - Custom attributes: organization_id, role

2. **Identity Providers**:
   - Google (Social IdP)
   - Azure AD (OIDC IdP)
   - Okta (OIDC/SAML IdP)

3. **App Client**:
   - DCV-Web-Client
   - Authorization code grant flow
   - Callback URLs for each environment

#### Subtasks:
1.1 **Cognito Infrastructure (Terraform)**
- User pool with email verification
- App client configuration
- Identity provider setup placeholders
- Domain configuration

1.2 **Backend Cognito Integration**
- Verify Cognito JWT tokens
- Sync Cognito users to local database
- Handle Cognito webhooks (user events)
- Federated sign-in handling

1.3 **Frontend Cognito Integration**
- AWS Amplify Auth or custom OIDC flow
- Login/signup with Cognito Hosted UI or custom UI
- Social sign-in buttons
- Token refresh handling

1.4 **Identity Provider Configuration**
- Google OAuth app registration
- Azure AD app registration
- Okta OIDC configuration
- Attribute mapping for each provider

#### Database Changes:
```sql
-- Store Cognito user ID mapping
ALTER TABLE users ADD COLUMN cognito_sub VARCHAR(255) UNIQUE;
ALTER TABLE users ADD COLUMN cognito_username VARCHAR(255);
ALTER TABLE users ADD COLUMN identity_provider VARCHAR(50); -- cognito, google, azure, okta

CREATE TABLE federated_identities (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider VARCHAR(50) NOT NULL, -- google, azure, okta
    provider_user_id VARCHAR(255) NOT NULL,
    provider_email VARCHAR(255),
    linked_at TIMESTAMP DEFAULT NOW(),
    last_login_at TIMESTAMP,
    UNIQUE(provider, provider_user_id)
);

CREATE INDEX idx_users_cognito_sub ON users(cognito_sub);
CREATE INDEX idx_federated_identities_user ON federated_identities(user_id);
```

#### API Endpoints:
```
GET  /api/v1/auth/cognito/config           - Get Cognito configuration for frontend
POST /api/v1/auth/cognito/token            - Exchange Cognito tokens for app tokens
POST /api/v1/auth/cognito/link             - Link federated identity to user
GET  /api/v1/auth/cognito/identities       - List linked identity providers
DELETE /api/v1/auth/cognito/:provider      - Unlink identity provider
```

#### Terraform Resources:
```hcl
# infrastructure/terraform/modules/cognito/main.tf
resource "aws_cognito_user_pool" "main" {
  name = "dcv-users-${var.environment}"

  username_attributes      = ["email"]
  auto_verified_attributes = ["email"]

  password_policy {
    minimum_length    = 12
    require_lowercase = true
    require_numbers   = true
    require_symbols   = true
    require_uppercase = true
  }

  mfa_configuration = "OPTIONAL"

  software_token_mfa_configuration {
    enabled = true
  }

  account_recovery_setting {
    recovery_mechanism {
      name     = "verified_email"
      priority = 1
    }
  }
}

resource "aws_cognito_user_pool_client" "web" {
  name         = "dcv-web-client"
  user_pool_id = aws_cognito_user_pool.main.id

  generate_secret = false

  allowed_oauth_flows                  = ["code"]
  allowed_oauth_scopes                 = ["openid", "email", "profile"]
  allowed_oauth_flows_user_pool_client = true

  callback_urls = var.callback_urls
  logout_urls   = var.logout_urls

  supported_identity_providers = ["COGNITO", "Google"]
}
```

---

### Task 2: Organization Security Settings
**Agent**: AUTH-AGENT + UI-DESIGN-AGENT
**Estimated Effort**: Medium
**Priority**: High

#### Subtasks:
2.1 **MFA Enforcement**
- Organization-level MFA requirement toggle
- Grace period for existing members to enable MFA
- Block access if MFA not configured after grace period

2.2 **Session Management**
- Configurable session timeout (1h, 4h, 8h, 24h, 7d)
- Idle timeout vs absolute timeout
- Force re-authentication for sensitive actions

2.3 **Authentication Policies**
- Allowed authentication methods (password, SSO providers)
- Password complexity requirements
- Account lockout after failed attempts

2.4 **Domain Verification**
- Add and verify organization domains
- Auto-join for verified domain emails
- Domain-based SSO enforcement

2.5 **IP Allowlisting** (Enterprise)
- Restrict access to specific IP ranges
- Separate allowlist for API vs UI access

#### Database Changes:
```sql
CREATE TABLE organization_security_settings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    require_mfa BOOLEAN DEFAULT FALSE,
    mfa_grace_period_days INTEGER DEFAULT 7,
    session_timeout_minutes INTEGER DEFAULT 1440, -- 24 hours
    idle_timeout_minutes INTEGER DEFAULT 60,
    allowed_auth_methods JSONB DEFAULT '["password"]',
    password_min_length INTEGER DEFAULT 12,
    password_require_uppercase BOOLEAN DEFAULT TRUE,
    password_require_lowercase BOOLEAN DEFAULT TRUE,
    password_require_number BOOLEAN DEFAULT TRUE,
    password_require_special BOOLEAN DEFAULT TRUE,
    max_failed_login_attempts INTEGER DEFAULT 5,
    lockout_duration_minutes INTEGER DEFAULT 30,
    ip_allowlist JSONB, -- null = allow all
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(organization_id)
);

CREATE TABLE verified_domains (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    domain VARCHAR(255) NOT NULL,
    verification_token VARCHAR(255),
    verification_method VARCHAR(50), -- dns_txt, dns_cname, meta_tag
    verified_at TIMESTAMP,
    auto_join_enabled BOOLEAN DEFAULT FALSE,
    sso_required BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(domain)
);

CREATE INDEX idx_verified_domains_org ON verified_domains(organization_id);
CREATE INDEX idx_verified_domains_domain ON verified_domains(domain);
```

#### API Endpoints:
```
GET    /api/v1/org/security              - Get security settings
PUT    /api/v1/org/security              - Update security settings
GET    /api/v1/org/domains               - List verified domains
POST   /api/v1/org/domains               - Add domain for verification
GET    /api/v1/org/domains/:id/verify    - Check verification status
DELETE /api/v1/org/domains/:id           - Remove domain
```

---

### Task 3: Billing & Subscription Management
**Agent**: New BILLING-AGENT concepts
**Estimated Effort**: High
**Priority**: High

#### Pricing Model: Free Scan + Simple Subscription
```
FREE SCAN (Lead Generation):
- 1 cloud account
- 1 scan (one-time)
- Results expire in 7 days
- Coverage heatmap
- Basic gap list
- PDF report (watermarked)
- No credit card required

SUBSCRIBER ($29/month):
- 3 cloud accounts included
- Unlimited scans
- Continuous coverage monitoring
- Full gap analysis with recommendations
- Historical trend tracking
- Scheduled scans & alerts
- API access
- PDF reports (branded)
- Email support
- +$9/month per additional account

ENTERPRISE (Custom):
- Unlimited accounts
- SSO/SAML integration
- SLA guarantees
- Dedicated support
```

#### Conversion Funnel:
```
Landing Page → "Run Free Scan" → Sign Up → Connect AWS → View Results → "Expires in 7 days" → Subscribe
```

#### Subtasks:
3.1 **Stripe Integration**
- Products and prices setup in Stripe
- Checkout session creation
- Webhook handling for subscription events
- Customer portal for self-service

3.2 **Subscription Management**
- Plan upgrade/downgrade flows
- Proration handling
- Usage tracking against limits
- Overage handling

3.3 **Usage Metering**
- Track cloud accounts count
- Track scan count per billing period
- Enforce limits with grace period
- Usage dashboard

3.4 **Invoicing & Receipts**
- Stripe-generated invoices
- Invoice history view
- Receipt downloads

3.5 **Billing UI**
- Current plan display
- Usage meters
- Upgrade prompts
- Payment method management
- Billing history

#### Database Changes:
```sql
CREATE TYPE account_tier AS ENUM ('free_scan', 'subscriber', 'enterprise');

CREATE TYPE subscription_status AS ENUM (
    'active', 'past_due', 'canceled', 'unpaid'
);

CREATE TABLE subscriptions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    stripe_customer_id VARCHAR(255),
    stripe_subscription_id VARCHAR(255),
    tier account_tier NOT NULL DEFAULT 'free_scan',
    status subscription_status NOT NULL DEFAULT 'active',
    -- Free scan tracking
    free_scan_used BOOLEAN DEFAULT FALSE,
    free_scan_at TIMESTAMP,
    free_scan_expires_at TIMESTAMP,
    -- Subscription details
    included_accounts INTEGER DEFAULT 1,
    additional_accounts INTEGER DEFAULT 0,
    current_period_start TIMESTAMP,
    current_period_end TIMESTAMP,
    cancel_at_period_end BOOLEAN DEFAULT FALSE,
    canceled_at TIMESTAMP,
    metadata JSONB,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(organization_id)
);

CREATE TABLE invoices (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    stripe_invoice_id VARCHAR(255) NOT NULL,
    amount_cents INTEGER NOT NULL,
    currency VARCHAR(3) DEFAULT 'usd',
    status VARCHAR(50), -- draft, open, paid, void, uncollectible
    invoice_pdf_url TEXT,
    hosted_invoice_url TEXT,
    period_start TIMESTAMP,
    period_end TIMESTAMP,
    paid_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_subscriptions_org ON subscriptions(organization_id);
CREATE INDEX idx_subscriptions_stripe ON subscriptions(stripe_subscription_id);
CREATE INDEX idx_subscriptions_tier ON subscriptions(tier);
CREATE INDEX idx_invoices_org ON invoices(organization_id);
```

#### API Endpoints:
```
GET    /api/v1/billing/subscription       - Get current subscription
POST   /api/v1/billing/checkout           - Create checkout session
POST   /api/v1/billing/portal             - Create customer portal session
GET    /api/v1/billing/usage              - Get current usage
GET    /api/v1/billing/invoices           - List invoices
POST   /api/v1/billing/webhook            - Stripe webhook handler
```

#### Tier Limits:
```python
TIER_LIMITS = {
    'free_scan': {
        'cloud_accounts': 1,
        'scans_allowed': 1,  # One-time only
        'results_retention_days': 7,
        'features': {
            'coverage_heatmap': True,
            'gap_list': True,  # Basic, no recommendations
            'pdf_report': True,  # Watermarked
            'historical_trends': False,
            'scheduled_scans': False,
            'alerts': False,
            'api_access': False,
        }
    },
    'subscriber': {
        'cloud_accounts': 3,  # Included, +$9/additional
        'scans_allowed': -1,  # Unlimited
        'results_retention_days': -1,  # Forever
        'features': {
            'coverage_heatmap': True,
            'gap_list': True,  # Full with recommendations
            'pdf_report': True,  # Branded
            'historical_trends': True,
            'scheduled_scans': True,
            'alerts': True,
            'api_access': True,
        }
    },
    'enterprise': {
        'cloud_accounts': -1,  # Unlimited
        'scans_allowed': -1,
        'results_retention_days': -1,
        'features': {
            'all': True,
            'sso': True,
            'sla': True,
        }
    }
}

# Stripe pricing
STRIPE_PRICES = {
    'subscriber_monthly': 2900,  # $29.00 in cents
    'additional_account_monthly': 900,  # $9.00 in cents
}
```

---

### Task 4: Public Landing Page
**Agent**: UI-DESIGN-AGENT + MARKETING concepts
**Estimated Effort**: Medium
**Priority**: High

#### Value Proposition:
**Headline**: "See Your MITRE ATT&CK Coverage in 5 Minutes"
**Subheadline**: "Connect your AWS account. Get an instant coverage heatmap. Find your security gaps."
**Primary CTA**: "Run Free Scan" (no credit card)

#### Key Differentiators:
1. **Instant Results** - See your actual coverage in 5 minutes, not a demo
2. **Zero Risk** - Read-only access, no agents to install
3. **Automated Discovery** - No manual inventory of detection rules
4. **Gap Prioritization** - Know exactly where to focus
5. **Actionable** - Not just reports, but recommendations

#### Landing Page Sections:

4.1 **Hero Section**
- Headline: "See Your MITRE ATT&CK Coverage in 5 Minutes"
- Subheadline: "One free scan. Real results. No credit card."
- Primary CTA: [Run Free Scan] (bright, prominent)
- Secondary: "See how it works" (video/demo link)
- Hero visual: Animated MITRE heatmap showing gaps being discovered
- Trust signal: "Trusted by 100+ security teams" (update as you grow)

4.2 **Problem Statement**
- "Security teams struggle with detection coverage visibility"
- Statistics: 70% of breaches exploit gaps in coverage
- Pain points: Manual tracking, spreadsheet hell, unknown gaps

4.3 **Solution Overview**
- 3-step process: Connect → Scan → Analyze
- Visual workflow diagram
- Time to value: "See your coverage in 5 minutes"

4.4 **Features Grid**
- Coverage Heatmaps
- Gap Analysis
- Detection Inventory
- Scheduled Scans
- Executive Reports
- API Access

4.5 **How It Works**
- Step 1: Connect cloud accounts (read-only)
- Step 2: Automatic detection discovery
- Step 3: MITRE mapping engine
- Step 4: Coverage dashboard
- Step 5: Gap recommendations

4.6 **Social Proof**
- Customer logos (placeholder for now)
- Testimonials
- Case study summaries
- Metrics: "10,000+ detections mapped"

4.7 **Pricing Section**
- Lead with Free Scan offer (prominent)
- $29/month subscription details
- Enterprise "Contact Us"
- Simple comparison: Free Scan vs Subscriber
- FAQ accordion

4.8 **Final CTA Section**
- "Ready to see your gaps?"
- [Run Free Scan] - Large, prominent button
- "Results in 5 minutes. No credit card required."
- Small print: "Read-only access. Your data stays yours."

4.9 **Footer**
- Product links
- Company links
- Legal links
- Social media
- Newsletter signup

#### Technical Implementation:
- Separate public route (no auth required)
- SEO optimized (meta tags, structured data)
- Performance optimized (lazy loading, image optimization)
- Mobile responsive
- Analytics integration (placeholder)

---

## Implementation Order

### Phase 1A: Foundation (Days 1-2)
1. Database migrations for all new tables
2. AWS Cognito Terraform module
3. Basic Stripe setup

### Phase 1B: SSO Implementation via Cognito (Days 3-5)
1. Cognito User Pool setup
2. Backend Cognito JWT verification
3. Google IdP configuration in Cognito
4. Frontend Cognito integration (Amplify or custom)
5. **Git commit & push**

### Phase 1C: Organization Security (Days 6-8)
1. Security settings backend
2. MFA enforcement logic
3. Domain verification
4. Security settings UI
5. **Git commit & push**

### Phase 1D: Billing (Days 9-12)
1. Stripe integration backend
2. Subscription management
3. Usage tracking
4. Billing UI
5. **Git commit & push**

### Phase 1E: Landing Page (Days 13-15)
1. Landing page design
2. React components
3. Responsive styling
4. SEO optimization
5. **Git commit & push**

### Phase 1F: Testing & Polish (Days 16-17)
1. E2E testing all flows
2. Security audit
3. Performance testing
4. Bug fixes
5. **Final git commit & push**

---

## Environment Variables Required

```bash
# AWS Cognito
AWS_COGNITO_USER_POOL_ID=
AWS_COGNITO_CLIENT_ID=
AWS_COGNITO_REGION=eu-west-2
AWS_COGNITO_DOMAIN=  # e.g., dcv-auth.auth.eu-west-2.amazoncognito.com

# SSO Providers (configured in Cognito, but may need for backend)
GOOGLE_CLIENT_ID=      # For Cognito Google IdP
GOOGLE_CLIENT_SECRET=

# Stripe
STRIPE_SECRET_KEY=
STRIPE_PUBLISHABLE_KEY=
STRIPE_WEBHOOK_SECRET=
STRIPE_PRICE_ID_PRO=

# General
FRONTEND_URL=http://localhost:3001
```

---

## Success Criteria

- [ ] Users can sign in with Google via Cognito
- [ ] Organizations can enforce MFA for all members
- [ ] Session timeout is configurable
- [ ] Free scan users get 1 scan, results expire in 7 days
- [ ] Free scan results show upgrade prompt after 7 days
- [ ] Users can subscribe for $29/month via Stripe
- [ ] Subscribers can add accounts for $9/month each
- [ ] Invoices are accessible in billing settings
- [ ] Landing page has "Run Free Scan" as primary CTA
- [ ] Landing page clearly explains value proposition
- [ ] Full conversion funnel works: Landing → Signup → Connect → Scan → Results → Subscribe
- [ ] All features have E2E tests
- [ ] Each feature is committed and pushed to git

---

## Files to Create/Modify

### Backend:
- `backend/app/api/routes/cognito.py` (NEW)
- `backend/app/api/routes/org_security.py` (NEW)
- `backend/app/api/routes/billing.py` (NEW)
- `backend/app/services/cognito_service.py` (NEW)
- `backend/app/services/billing_service.py` (NEW)
- `backend/app/models/billing.py` (NEW)
- `backend/app/models/security.py` (NEW)
- `backend/alembic/versions/006_cognito_fields.py` (NEW)
- `backend/alembic/versions/007_security_settings.py` (NEW)
- `backend/alembic/versions/008_billing_tables.py` (NEW)

### Frontend:
- `frontend/src/pages/Landing.tsx` (NEW)
- `frontend/src/pages/Pricing.tsx` (NEW)
- `frontend/src/pages/CognitoCallback.tsx` (NEW)
- `frontend/src/pages/OrgSecurity.tsx` (NEW)
- `frontend/src/pages/Billing.tsx` (NEW)
- `frontend/src/components/SocialLoginButtons.tsx` (NEW)
- `frontend/src/components/PricingTable.tsx` (NEW)
- `frontend/src/services/billingApi.ts` (NEW)
- `frontend/src/services/cognitoApi.ts` (NEW)

### Infrastructure:
- `infrastructure/terraform/modules/cognito/main.tf` (NEW)
- `infrastructure/terraform/modules/cognito/variables.tf` (NEW)
- `infrastructure/terraform/modules/cognito/outputs.tf` (NEW)

---

**END OF MVP COMPLETION PLAN**
