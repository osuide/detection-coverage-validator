# Billing and Subscription

Understand A13E's subscription plans, billing, and how to manage your account.

## Subscription Plans

A13E offers three subscription tiers to meet different organisation needs.

### Free Scan

**Price**: $0 (one-time scan)

Perfect for teams evaluating A13E or conducting one-time security assessments.

**What's included**:
- 1 cloud account, 1 scan
- 7-day data retention
- Coverage heatmap and gap analysis
- PDF report export
- Basic email support
- Single user only

Sign up at [app.a13e.com](https://app.a13e.com) and upgrade before 7 days to retain data.

---

### Subscriber

**Price**: Starting at $29/month

Ideal for small to medium security teams with 1-10 cloud accounts.

**What's included**:
- 3 cloud accounts (+$9/mo per additional)
- Unlimited scans, data retention, and team members
- Scheduled scans and historical trends
- Email/webhook alerts
- API access and CSV exports
- Priority email support
- 99.5% uptime SLA

**Pricing examples**: 3 accounts = $29/mo | 5 accounts = $47/mo | 10 accounts = $92/mo

---

### Enterprise

**Price**: Starting at $499/month

For large organisations (100+ accounts) with compliance and advanced support needs.

**Everything in Subscriber, plus**:
- Unlimited cloud accounts
- SSO integration (SAML, Okta, Azure AD)
- Compliance mapping (SOC 2, ISO 27001, PCI-DSS, NIST)
- Custom integrations (SIEM, ticketing, Slack)
- Dedicated customer success manager
- 24/7 phone and chat support
- 99.9% uptime SLA
- Custom security controls and multi-organisation management

Contact sales@a13e.com or click **Contact Sales** in the app.

## Plan Comparison

### Feature Matrix

| Feature | Free Scan | Subscriber | Enterprise |
|---------|-----------|------------|------------|
| **Scanning** |
| Cloud accounts | 1 | 3 (+$9/mo each) | Unlimited |
| Scans per month | 1 (total) | Unlimited | Unlimited |
| Scan scheduling | ✗ | ✓ | ✓ |
| Data retention | 7 days | Forever | Forever |
| Regions | All | All | All |
| **Coverage Analysis** |
| MITRE ATT&CK heatmap | ✓ | ✓ | ✓ |
| Gap analysis | ✓ | ✓ | ✓ |
| Confidence scoring | ✓ | ✓ | ✓ |
| Historical trends | ✗ | ✓ | ✓ |
| Custom benchmarking | ✗ | ✗ | ✓ |
| **Collaboration** |
| Team members | 1 | Unlimited | Unlimited |
| Role-based access | ✗ | ✓ | ✓ |
| SSO integration | ✗ | ✗ | ✓ |
| Audit logs | ✗ | ✓ | ✓ |
| **Alerts & Reporting** |
| Email alerts | ✗ | ✓ | ✓ |
| Webhook notifications | ✗ | ✓ | ✓ |
| PDF reports | ✓ | ✓ | ✓ |
| CSV exports | ✗ | ✓ | ✓ |
| Custom report templates | ✗ | ✗ | ✓ |
| Scheduled reports | ✗ | ✗ | ✓ |
| **API & Integrations** |
| REST API access | ✗ | ✓ | ✓ |
| Slack integration | ✗ | ✗ | ✓ |
| SIEM integration | ✗ | ✗ | ✓ |
| Ticketing integration | ✗ | ✗ | ✓ |
| **Compliance** |
| SOC 2 mapping | ✗ | ✗ | ✓ |
| ISO 27001 mapping | ✗ | ✗ | ✓ |
| PCI-DSS mapping | ✗ | ✗ | ✓ |
| Custom frameworks | ✗ | ✗ | ✓ |
| **Support** |
| Documentation | ✓ | ✓ | ✓ |
| Email support | Basic | Priority | 24/7 |
| Chat support | ✗ | ✗ | ✓ |
| Phone support | ✗ | ✗ | ✓ |
| Customer success manager | ✗ | ✗ | ✓ |
| Uptime SLA | None | 99.5% | 99.9% |

## Upgrading Your Plan

### Free to Subscriber

1. Go to **Settings** → **Billing**
2. Configure cloud accounts (3 included, +$9/mo each additional)
3. Click **Subscribe Now** and enter payment details
4. Complete checkout (powered by Stripe)

You're immediately upgraded with unlimited scans, data retention, and all Subscriber features. First month is pro-rated.

**Important**: Data deleted after 7 days cannot be recovered. Upgrade before expiration to retain scan results.

### Subscriber to Enterprise

Contact sales@a13e.com or click **Contact Sales** in Settings → Billing. Ideal when you have 20+ accounts or need SSO, compliance mapping, or dedicated support. All data migrates seamlessly with no downtime.

## Managing Cloud Accounts

**Account limits**: Free (1) | Subscriber (3 + $9/mo each additional) | Enterprise (unlimited)

### Adding Accounts (Subscriber)

Go to **Accounts** → **Add Account**. If adding beyond your 3 included accounts, billing increases by $9/month (pro-rated for first month).

### Removing Accounts

Click **Delete** on account card. Billing adjusts on next invoice if over included limit. Scan data retained for 90 days, then permanently deleted.

## Payment Methods

**Accepted**: Credit/debit cards (Visa, Mastercard, Amex, Discover) via Stripe. ACH available for US organisations. Enterprise customers can pay via wire transfer (annual only).

### Managing Payment

**Add/update**: Settings → Billing → **Manage Billing** (Stripe portal)

**Failed payments**: Stripe retries 3 times over 7 days. After 3 failures, subscription suspends. You'll receive email notifications before card expiration and after payment failures.

## Invoices and Billing History

Access invoices at Settings → Billing → **Invoice History**. Download individual PDFs or all invoices via **Manage Billing** (Stripe portal).

Each invoice includes invoice number, billing period, line items (base fee, additional accounts, taxes), and payment details.

**Email notifications**: You'll receive emails for upcoming renewals (7 days before), successful payments, and failed payments. Manage recipients in Settings → Notifications.

## Downgrading or Canceling

### Downgrading

**Enterprise to Subscriber**: Contact your customer success manager or support@a13e.com. Takes effect at end of billing period. Enterprise features disabled, but data retained for accounts within your new limit.

**Subscriber to Free**: Not available (Free Scan is one-time only). Cancel subscription instead.

### Canceling Subscription

Organisation Owners can cancel via Settings → Billing → **Manage Billing** → **Cancel Subscription**. Choose to cancel at end of billing period (recommended) or immediately.

**What happens**: Scheduled scans, API access, and team invitations stop immediately. After 90 days, all data is permanently deleted.

**Before canceling**: Export your data at Settings → Data Export (CSV/JSON format).

**Refunds**: No refunds for monthly plans. Annual plans get pro-rated refunds within 30 days.

**Reactivation**: Within 90 days, reactivate at Settings → Billing to restore all data. After 90 days, data is permanently deleted.

## FAQ

**Q: How does billing work?**
A: Monthly billing on the same day each month. Annual payment available (15% discount for Subscriber). All prices in USD.

**Q: What counts as a "cloud account"?**
A: Each AWS account or GCP project = 1 cloud account. Multi-region scanning included at no extra cost.

**Q: Are team members limited?**
A: Free Scan: 1 user. Subscriber and Enterprise: unlimited users at no extra cost.

**Q: What happens after my 7-day Free Scan?**
A: Scan data is permanently deleted. Upgrade before expiration to retain results. Free Scan is one-time per organisation.

**Q: Can I upgrade mid-month?**
A: Yes. You're charged a pro-rated amount for the remainder of the month, then full monthly price.

**Q: Do you charge sales tax?**
A: Yes, based on billing address. US customers pay sales tax, EU customers may have VAT added.

**Q: What's the minimum for Enterprise?**
A: Typically 20+ cloud accounts. 30-day pilots available. Contact sales@a13e.com for custom pricing.

## Getting Help

**Billing Support**: billing@a13e.com (1 business day response)

**Sales**: sales@a13e.com | Schedule demo via Settings → Contact Sales

**Technical Support**: support@a13e.com | In-app help (? icon)

---

**Next Steps**: [Team Management](./team-management.md) | [Running Scans](./running-scans.md) | [Getting Started](./getting-started.md)

**Last updated**: December 2025 | Pricing subject to change. See [a13e.com/pricing](https://a13e.com/pricing)
