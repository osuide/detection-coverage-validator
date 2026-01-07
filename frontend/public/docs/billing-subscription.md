# Billing & Subscription

Understand A13E's subscription plans, pricing, and how to manage your account.

## TL;DR

- **Four plans**: Free (£0), Individual (£29/mo), Pro (£250/mo), Enterprise (custom)
- **Cloud accounts** and **team seats** scale with your plan
- **Upgrade anytime** with pro-rated billing
- **Payment** via credit card (Stripe) or invoice (Enterprise)

---

## Subscription Plans

### Free

**£0** — Perfect for evaluation

| Feature | Included |
|---------|----------|
| Cloud accounts | 1 |
| Team members | 1 (Owner only) |
| Scans | 1 per week |
| Data retention | 30 days |
| Coverage heatmap | ✓ |
| Gap analysis | ✓ |
| Remediation templates | ✓ |
| Support | Documentation |

**Best for**: Evaluating A13E before committing, one-time assessments.

---

### Individual

**£29/month** — For small security teams

| Feature | Included |
|---------|----------|
| Cloud accounts | 6 |
| Team members | 3 |
| Scans | Unlimited |
| Data retention | 90 days |
| Scheduled scans | ✓ |
| Email alerts | ✓ |
| API access | ✓ |
| CSV exports | ✓ |
| Historical trends | ✓ |
| Code analysis | ✓ |
| Support | Priority email |

**Best for**: Small to medium security teams with a few cloud accounts.

---

### Pro

**£250/month** — For growing organisations

| Feature | Included |
|---------|----------|
| Cloud accounts | 500 |
| Team members | 10 |
| Scans | Unlimited |
| Data retention | 1 year (365 days) |
| Organisation scanning | ✓ |
| Auto-discovery | ✓ |
| Unified dashboard | ✓ |
| Delegated scanning | ✓ |
| Everything in Individual | ✓ |
| Support | Priority email |

**Best for**: Organisations with many AWS accounts or GCP projects.

---

### Enterprise

**Custom pricing** — For large organisations

Everything in Pro, plus:

| Feature | Included |
|---------|----------|
| Cloud accounts | Unlimited |
| Team members | Unlimited |
| SSO integration | ✓ (SAML, Okta, Azure AD) |
| Custom integrations | ✓ (SIEM, ticketing, Slack) |
| Dedicated success manager | ✓ |
| Custom SLA | ✓ (up to 99.9%) |
| On-boarding assistance | ✓ |
| Phone support | ✓ |

**Best for**: Enterprises with 100+ cloud accounts, compliance requirements, or need dedicated support.

Contact sales@a13e.com or click **Contact Sales** in Settings → Billing.

---

## Feature Comparison

| Feature | Free | Individual | Pro | Enterprise |
|---------|:----:|:----------:|:---:|:----------:|
| **Accounts & Scanning** |
| Cloud accounts | 1 | 6 | 500 | Unlimited |
| Scans | Limited | Unlimited | Unlimited | Unlimited |
| Scheduled scans | ✗ | ✓ | ✓ | ✓ |
| Auto-discovery | ✗ | ✗ | ✓ | ✓ |
| Data retention | 30 days | 90 days | 1 year | Unlimited |
| **Coverage Analysis** |
| MITRE heatmap | ✓ | ✓ | ✓ | ✓ |
| Gap analysis | ✓ | ✓ | ✓ | ✓ |
| Remediation templates | ✓ | ✓ | ✓ | ✓ |
| Historical trends | ✗ | ✓ | ✓ | ✓ |
| Custom benchmarking | ✗ | ✗ | ✗ | ✓ |
| **Compliance** |
| CIS Controls mapping | ✗ | ✓ | ✓ | ✓ |
| NIST 800-53 mapping | ✗ | ✓ | ✓ | ✓ |
| Compliance history | ✗ | ✓ | ✓ | ✓ |
| Custom frameworks | ✗ | ✗ | ✗ | ✓ |
| **Collaboration** |
| Team members | 1 | 3 | 10 | Unlimited |
| Role-based access | ✗ | ✓ | ✓ | ✓ |
| Audit logs | ✗ | ✓ | ✓ | ✓ |
| SSO integration | ✗ | ✗ | ✗ | ✓ |
| **Reporting & Integration** |
| PDF reports | ✗ | ✓ | ✓ | ✓ |
| CSV exports | ✗ | ✓ | ✓ | ✓ |
| Email alerts | ✗ | ✓ | ✓ | ✓ |
| Webhooks | ✗ | ✗ | ✓ | ✓ |
| API access | ✗ | ✓ | ✓ | ✓ |
| SIEM integration | ✗ | ✗ | ✗ | ✓ |
| **Support** |
| Documentation | ✓ | ✓ | ✓ | ✓ |
| Email support | Basic | Priority | Priority | 24/7 |
| Phone support | ✗ | ✗ | ✗ | ✓ |
| Success manager | ✗ | ✗ | ✗ | ✓ |

---

## Upgrading Your Plan

### Free to Individual or Pro

1. Navigate to **Settings** → **Billing**
2. Click **Upgrade Plan**
3. Select **Individual** or **Pro**
4. Enter payment details (credit card via Stripe)
5. Complete checkout

**What happens**:
- Immediate access to all features
- Your scan data is preserved
- First month is charged immediately
- Future billing on the same day each month

### Individual to Pro

1. Navigate to **Settings** → **Billing**
2. Click **Change Plan**
3. Select **Pro**
4. Confirm the upgrade

**Billing**: You're credited for unused days on Individual and charged pro-rated amount for Pro.

### Any Plan to Enterprise

1. Click **Contact Sales** in Settings → Billing
2. Our team will schedule a call to discuss your needs
3. Receive a custom proposal
4. Sign agreement and onboard

Typical timeline: 3-5 business days.

---

## Downgrading Your Plan

### Pro to Individual

1. Navigate to **Settings** → **Billing**
2. Click **Change Plan**
3. Select **Individual**
4. Review what you'll lose:
   - Accounts over 6 will be deactivated
   - Team members over 3 will lose access
   - Pro-only features will be disabled
5. Confirm the downgrade

**When it takes effect**: At the end of your current billing period.

### Cancelling Your Subscription

1. Navigate to **Settings** → **Billing**
2. Click **Manage Billing** (opens Stripe portal)
3. Click **Cancel Subscription**
4. Choose:
   - **Cancel at end of period** (recommended): Keep access until billing cycle ends
   - **Cancel immediately**: Lose access now

**What happens after cancellation**:
- Scheduled scans stop immediately
- API access revoked
- Team invitations disabled
- After 90 days, all data permanently deleted

**Before cancelling**: Export your data in Settings → Data Export.

---

## Managing Cloud Accounts

### Account Limits

| Plan | Accounts Included |
|------|-------------------|
| Free | 1 |
| Individual | 6 |
| Pro | 500 |
| Enterprise | Unlimited |

### Adding Accounts

If you're within your limit, adding accounts is free.

If you need more than your plan allows:
- **Individual**: Upgrade to Pro (£250/mo) for 500 accounts
- **Pro**: Contact sales for Enterprise pricing

### Removing Accounts

1. Navigate to **Accounts**
2. Click the **Delete** button on the account
3. Confirm deletion

Scan data for deleted accounts is retained for 90 days, then permanently removed.

---

## Managing Team Members

### Seat Limits

| Plan | Team Members |
|------|--------------|
| Free | 1 |
| Individual | 3 |
| Pro | 10 |
| Enterprise | Unlimited |

### Adding Team Members

If you're within your limit, adding members is free. See [Team Management](./team-management.md).

### Over Seat Limit

If you need more seats than your plan allows:
- **Individual**: Upgrade to Pro for 10 seats
- **Pro**: Contact sales for Enterprise

---

## Payment Methods

### Accepted Payment

- **Credit/Debit cards**: Visa, Mastercard, American Express, Discover
- **ACH bank transfer**: Available for US organisations (Pro and Enterprise)
- **Invoice**: Enterprise customers only (annual billing)

### Managing Payment

1. Navigate to **Settings** → **Billing**
2. Click **Manage Billing**
3. In the Stripe portal:
   - Update card details
   - Add backup payment method
   - View upcoming charges

### Failed Payments

If a payment fails:

1. Stripe automatically retries 3 times over 7 days
2. You receive email notifications for each attempt
3. After 3 failures, your subscription is suspended
4. Update payment method to restore access

---

## Invoices & Billing History

### Viewing Invoices

1. Navigate to **Settings** → **Billing**
2. Click **Invoice History** or **Manage Billing**
3. View and download PDF invoices

### Invoice Details

Each invoice includes:

- Invoice number and date
- Billing period
- Line items (plan, any add-ons)
- VAT/sales tax (where applicable)
- Payment method used

### Email Notifications

You'll receive emails for:

- **7 days before renewal**: Upcoming charge reminder
- **Payment successful**: Receipt confirmation
- **Payment failed**: Retry notification
- **Card expiring**: Update reminder

Manage notification settings in **Settings** → **Notifications**.

---

## Common Questions

**Q: How does billing work?**

A: Monthly billing on the same calendar day each month. Annual billing available for Enterprise (contact sales).

**Q: What counts as a "cloud account"?**

A: Each AWS account ID or GCP project ID = 1 cloud account. Multi-region scanning is included at no extra cost.

**Q: Are team member seats limited?**

A: Free: 1 user. Individual: 3 users. Pro: 10 users. Enterprise: Unlimited.

**Q: What happens to my data after 30 days on the Free plan?**

A: Scan data older than 30 days is automatically deleted. Upgrade to retain longer history.

**Q: Can I upgrade mid-month?**

A: Yes. You're charged a pro-rated amount for the remainder of the month, then the full price on renewal.

**Q: Do you charge VAT/sales tax?**

A: Yes, based on your billing address. UK customers pay VAT. EU customers may have VAT added (unless VAT registered). US customers pay applicable sales tax.

**Q: What currency do you charge in?**

A: British Pounds (GBP). All prices shown are in £.

**Q: Can I get a refund?**

A: Monthly plans: No refunds for partial months. Annual plans: Pro-rated refund within 30 days of purchase.

**Q: How do I reactivate after cancellation?**

A: Within 90 days, go to Settings → Billing and resubscribe. Your data is restored. After 90 days, data is permanently deleted.

---

## Enterprise Enquiries

For Enterprise pricing and custom requirements:

- **Email**: sales@a13e.com
- **Schedule a demo**: Click **Contact Sales** in Settings → Billing
- **Typical response**: 1 business day

**Common Enterprise requests**:

| Request | Availability |
|---------|--------------|
| Annual billing | ✓ |
| Custom contract terms | ✓ |
| SLA guarantees | Up to 99.9% |
| Pilot programme | 30 days |
| Volume discounts | 100+ accounts |
| Dedicated infrastructure | Custom |

---

## Getting Help

- **Billing questions**: billing@a13e.com (1 business day response)
- **Sales enquiries**: sales@a13e.com
- **Technical support**: support@a13e.com
- **Self-service**: Settings → Billing → Manage Billing

---

## Next Steps

- [Getting Started](./getting-started.md) - Set up your account
- [Team Management](./team-management.md) - Invite your team
- [Connecting AWS Accounts](./connecting-aws-accounts.md) - Add AWS accounts
- [Connecting GCP Accounts](./connecting-gcp-accounts.md) - Add GCP projects
