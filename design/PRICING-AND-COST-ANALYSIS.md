# Pricing & Cost Analysis - Detection Coverage Validator

## Executive Summary

This document analyzes AWS infrastructure costs and proposes a pricing model optimized for profitability with the insight that most customers will only have 1 cloud account.

---

## AWS Monthly Cost Analysis

### Current Architecture Costs (Production)

| Service | Instance/Config | Monthly Cost | Notes |
|---------|-----------------|--------------|-------|
| **RDS PostgreSQL** | db.t3.micro (20GB) | ~$15 | Single AZ, can scale |
| **ElastiCache Redis** | cache.t3.micro | ~$12 | For session/caching |
| **Lambda (API)** | Pay-per-request | ~$5-20 | Depends on traffic |
| **API Gateway** | Pay-per-request | ~$3-10 | HTTP API cheaper |
| **Fargate (Scanner)** | 0.25 vCPU, 0.5GB | ~$5-15 | Only runs during scans |
| **S3 (Frontend)** | Static hosting | ~$1 | CloudFront caching |
| **CloudFront** | CDN | ~$5 | Data transfer |
| **Cognito** | User Pool | ~$3-10 | First 50K MAU free |
| **Secrets Manager** | 2-3 secrets | ~$2 | API keys, DB creds |
| **CloudWatch** | Logs/Metrics | ~$5 | Basic monitoring |
| **NAT Gateway** | Per AZ | ~$32 | **Biggest cost!** |
| **Route 53** | Hosted zone | ~$0.50 | DNS |
| **ACM** | SSL Cert | Free | Certificate |

### Cost Scenarios

#### Minimal Production (Start Here)
```
RDS db.t3.micro (single AZ)     $15
Redis cache.t3.micro            $12
Lambda (light usage)            $5
API Gateway                     $3
Fargate (10 scans/day)          $5
S3 + CloudFront                 $5
Cognito (< 50K MAU)             $0  (free tier)
Secrets Manager                 $2
CloudWatch                      $5
NAT Gateway (1 AZ)              $32
Route 53                        $1
─────────────────────────────────
TOTAL                           ~$85/month
```

#### Optimized Production (Remove NAT Gateway)
Use VPC Endpoints instead of NAT Gateway for AWS services:
```
VPC Endpoints (S3, DynamoDB)    $7/month each
Replace NAT with endpoints      -$32, +$21
─────────────────────────────────
TOTAL                           ~$74/month
```

#### Budget Production (Maximum Savings)
```
RDS db.t3.micro                 $15
Remove Redis (use in-memory)    $0
Lambda (free tier: 1M req)      $0
API Gateway HTTP API            $1
Fargate Spot                    $3
S3 + CloudFront                 $5
Cognito free tier               $0
CloudWatch basics               $3
VPC Endpoints                   $14
Route 53                        $1
─────────────────────────────────
TOTAL                           ~$42/month
```

---

## Variable Costs Per Customer

### Per Scan Cost
Each scan involves:
- **Fargate Task**: 0.25 vCPU × 0.5GB × ~5 min = ~$0.01
- **Lambda Invocations**: ~100 calls = ~$0.0002
- **API Gateway**: ~100 requests = ~$0.0001
- **Data Transfer**: Minimal (metadata only)

**Cost per scan: ~$0.01-0.02**

### Per Customer Monthly Cost (1 account, 4 scans/month)
- Storage (detection data): ~$0.01
- Scans: 4 × $0.02 = $0.08
- API requests: ~$0.05
- **Total: ~$0.15/month per customer**

### Per Customer Monthly Cost (Power user, 10 accounts, daily scans)
- Storage: ~$0.10
- Scans: 30 × 10 × $0.02 = $6.00
- API requests: ~$0.50
- **Total: ~$6.60/month per customer**

---

## Pricing Model Analysis

### Key Insight
> "Very few people have more than one account"

This means:
1. **Fixed costs dominate** - Infrastructure costs are mostly fixed
2. **Per-customer marginal cost is tiny** (~$0.15/month)
3. **Each customer is nearly pure profit** after breakeven
4. **Simplify pricing** - Don't overcomplicate tiers

### Recommended Pricing Strategy: Simple & Profitable

#### Option A: Single Tier + Usage (Recommended)
```
STARTER: $29/month
├── 3 cloud accounts included
├── Unlimited scans
├── Full coverage analytics
├── API access
├── Email support
└── Additional accounts: $9/account/month
```

**Why this works:**
- Low entry point attracts customers
- 3 accounts covers 90%+ of users
- Simple to understand
- $29 is "expense it without approval" territory
- Additional accounts create upsell path

#### Option B: Freemium + Pro
```
FREE: $0/month
├── 1 cloud account
├── 2 scans/month
├── Basic coverage view
└── Community support

PRO: $39/month
├── 5 cloud accounts
├── Unlimited scans
├── Full analytics + recommendations
├── API access
├── Priority support
└── Additional accounts: $7/account/month
```

**Why this works:**
- Free tier for viral growth
- Clear upgrade path
- Higher conversion rate from engaged free users

#### Option C: Per-Account Pricing (Simpler)
```
$19/account/month
├── Unlimited scans
├── Full features
├── API access
└── Volume discounts: 5+ accounts = $15/ea, 10+ = $12/ea
```

**Why this works:**
- Dead simple to understand
- Scales linearly with value
- Easy to predict revenue
- No tier confusion

---

## Profitability Analysis

### Break-Even Calculation

**Fixed Monthly Costs**: ~$85 (production)
**Cost Per Customer**: ~$0.15

#### Option A: Starter @ $29/month
```
Gross Margin per customer: $29 - $0.15 = $28.85 (99.5%)
Break-even customers: $85 / $28.85 = 3 customers
```

#### Option B: Pro @ $39/month
```
Gross Margin per customer: $39 - $0.15 = $38.85 (99.6%)
Break-even customers: $85 / $38.85 = 3 customers
```

#### Option C: Per-Account @ $19/month
```
Gross Margin per account: $19 - $0.05 = $18.95 (99.7%)
Break-even accounts: $85 / $18.95 = 5 accounts
```

### Revenue Projections

| Customers | Option A ($29) | Option B ($39) | Option C ($19) |
|-----------|----------------|----------------|----------------|
| 5 | $145 | $195 | $95 |
| 10 | $290 | $390 | $190 |
| 25 | $725 | $975 | $475 |
| 50 | $1,450 | $1,950 | $950 |
| 100 | $2,900 | $3,900 | $1,900 |
| 250 | $7,250 | $9,750 | $4,750 |
| 500 | $14,500 | $19,500 | $9,500 |

### Net Profit (After AWS Costs)

| Customers | Monthly Revenue | AWS Costs | Net Profit | Margin |
|-----------|-----------------|-----------|------------|--------|
| 10 | $290 | $90 | $200 | 69% |
| 25 | $725 | $95 | $630 | 87% |
| 50 | $1,450 | $100 | $1,350 | 93% |
| 100 | $2,900 | $110 | $2,790 | 96% |
| 250 | $7,250 | $130 | $7,120 | 98% |

---

## Recommended Pricing Structure

Based on analysis, **Option A (Starter @ $29)** is recommended:

### Final Pricing

```
┌─────────────────────────────────────────────────────────────┐
│                    FREE SCAN OFFER                          │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│   🎯 See Your Coverage in 5 Minutes - FREE                  │
│   ─────────────────────────────────────────────────         │
│                                                             │
│   ✓ Connect your AWS account (read-only)                   │
│   ✓ Get instant MITRE ATT&CK coverage heatmap              │
│   ✓ See your detection gaps                                 │
│   ✓ Download executive PDF report                           │
│                                                             │
│   [Run Free Scan] - No credit card required                 │
│                                                             │
│   ⚠️ Free scan results expire in 7 days                     │
│                                                             │
├─────────────────────────────────────────────────────────────┤
│                      SUBSCRIBE                              │
│                                                             │
│   $29/month                                                 │
│   ─────────────────                                         │
│   ✓ 3 cloud accounts                                        │
│   ✓ Unlimited scans                                         │
│   ✓ Continuous coverage monitoring                          │
│   ✓ Gap analysis & recommendations                          │
│   ✓ Historical trend tracking                               │
│   ✓ Scheduled scans & alerts                                │
│   ✓ API access                                              │
│   ✓ Email support                                           │
│                                                             │
│   Need more?                                                │
│   +$9/month per additional cloud account                    │
│                                                             │
├─────────────────────────────────────────────────────────────┤
│                     ENTERPRISE                              │
│                                                             │
│   Custom pricing for:                                       │
│   • Unlimited accounts                                      │
│   • SSO/SAML integration                                    │
│   • Dedicated support                                       │
│   • SLA guarantees                                          │
│                                                             │
│   [Contact Sales]                                           │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Why "One Free Scan" is Genius

1. **Immediate Value Demonstration**
   - User sees their actual coverage in 5 minutes
   - No guessing if the tool works for them
   - Real data creates emotional investment

2. **Low Friction, High Intent**
   - No credit card = anyone can try
   - But connecting AWS = serious intent
   - Self-qualifies leads

3. **Creates Urgency**
   - "Results expire in 7 days" drives action
   - They've seen the gaps, now they need to track them
   - Natural progression to paid

4. **Viral Potential**
   - "I just found 47 gaps in our coverage" - shareable moment
   - Security teams will share with peers
   - PDF report can be forwarded to leadership

5. **Cost is Negligible**
   - One scan costs us ~$0.02
   - Even 1000 free scans = $20
   - Conversion rate of 5% = 50 paying customers = $1,450 MRR

### Conversion Funnel

```
Landing Page Visit
       ↓
  "Run Free Scan"
       ↓
 Sign Up (email)        ← Capture lead
       ↓
Connect AWS Account     ← High-intent signal
       ↓
  View Results          ← "Wow" moment
       ↓
 Download Report        ← Shareable artifact
       ↓
"Results expire in 7 days"
       ↓
   Subscribe $29        ← Conversion
```

### Free Scan Limitations (to drive conversion)

| Feature | Free Scan | Paid ($29/mo) |
|---------|-----------|---------------|
| Scans | 1 | Unlimited |
| Results retention | 7 days | Forever |
| Cloud accounts | 1 | 3 included |
| Coverage heatmap | ✓ | ✓ |
| Gap analysis | Basic list | Full with recommendations |
| PDF report | ✓ (watermarked) | ✓ (branded) |
| Historical trends | ✗ | ✓ |
| Scheduled scans | ✗ | ✓ |
| Alerts | ✗ | ✓ |
| API access | ✗ | ✓ |

### Implementation Notes

```python
# User tiers
class AccountTier(Enum):
    FREE_SCAN = "free_scan"      # One-time free scan
    SUBSCRIBER = "subscriber"     # $29/month
    ENTERPRISE = "enterprise"     # Custom

# Free scan logic
FREE_SCAN_LIMITS = {
    'scans_allowed': 1,
    'results_retention_days': 7,
    'cloud_accounts': 1,
    'features': {
        'coverage_heatmap': True,
        'gap_list': True,  # Basic, no recommendations
        'pdf_report': True,  # Watermarked
        'historical_trends': False,
        'scheduled_scans': False,
        'alerts': False,
        'api_access': False,
    }
}

# After free scan expires
def check_free_scan_expiry(user):
    if user.tier == AccountTier.FREE_SCAN:
        if user.free_scan_at + timedelta(days=7) < now():
            # Results expired - show upgrade prompt
            return "upgrade_required"
    return "active"
```

---

## Implementation in Stripe

```python
# Stripe Products & Prices

PRODUCTS = {
    'starter': {
        'name': 'DCV Starter',
        'description': '3 cloud accounts, unlimited scans',
        'price_monthly': 2900,  # cents
        'price_yearly': 29000,  # ~17% discount
    },
    'additional_account': {
        'name': 'Additional Cloud Account',
        'description': 'Add-on account',
        'price_monthly': 900,   # cents
    }
}

# Usage limits
PLAN_LIMITS = {
    'starter': {
        'included_accounts': 3,
        'scans_per_month': -1,  # unlimited
        'api_access': True,
        'reports': True,
    },
    'trial': {
        'included_accounts': 3,
        'scans_per_month': -1,
        'api_access': True,
        'reports': True,
        'duration_days': 14,
    }
}
```

---

## Cost Optimization Strategies

### Phase 1: Launch (< 50 customers)
- Use minimal production setup (~$85/month)
- Single AZ database (acceptable for early stage)
- Monitor usage closely

### Phase 2: Growth (50-500 customers)
- Add Redis for better performance
- Consider Multi-AZ for reliability
- Budget: ~$150/month

### Phase 3: Scale (500+ customers)
- Right-size RDS (db.t3.small or medium)
- Add read replicas if needed
- Consider Reserved Instances (1-year commit = 30% savings)
- Budget: ~$300-500/month

### Reserved Instance Savings
| Service | On-Demand | 1-Year RI | Savings |
|---------|-----------|-----------|---------|
| RDS db.t3.micro | $15/mo | $10/mo | 33% |
| Redis cache.t3.micro | $12/mo | $8/mo | 33% |

---

## Key Metrics to Track

1. **Customer Acquisition Cost (CAC)**: Target < $100
2. **Monthly Recurring Revenue (MRR)**: Growth rate
3. **Customer Lifetime Value (LTV)**: Target > 12 months × $29 = $348
4. **LTV:CAC Ratio**: Target > 3:1
5. **Gross Margin**: Target > 90%
6. **Churn Rate**: Target < 5% monthly

---

## Summary

| Metric | Value |
|--------|-------|
| **Recommended Price** | $29/month (3 accounts) |
| **Add-on Price** | $9/account/month |
| **Fixed AWS Costs** | ~$85/month |
| **Variable Cost/Customer** | ~$0.15/month |
| **Gross Margin** | 99%+ |
| **Break-even** | 3 customers |
| **Target MRR @ 100 customers** | $2,900 |
| **Net Profit @ 100 customers** | ~$2,790/month |

**Bottom line**: This is an extremely high-margin SaaS business. At just 10 paying customers, you're profitable. At 100 customers, you're making ~$33K/year in profit with minimal operational overhead.

---

**END OF PRICING & COST ANALYSIS**
