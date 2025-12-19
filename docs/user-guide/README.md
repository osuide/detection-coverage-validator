# A13E User Guide

Welcome to the comprehensive user documentation for **A13E Detection Coverage Validator** - the cloud security platform that helps you understand and improve your MITRE ATT&CK detection coverage.

## Documentation Overview

This user guide provides everything you need to effectively use A13E to analyze and improve your cloud security detection coverage.

### Quick Links

| Guide | Description | Time to Read |
|-------|-------------|--------------|
| [Getting Started](./getting-started.md) | New to A13E? Start here for account creation, login, and first steps | 10 min |
| [Connecting AWS Accounts](./connecting-aws-accounts.md) | Detailed guide for securely connecting your AWS accounts | 15 min |
| [Running Scans](./running-scans.md) | Learn how to scan your cloud accounts for security detections | 12 min |
| [Understanding Coverage](./understanding-coverage.md) | Deep dive into MITRE ATT&CK coverage analysis and interpretation | 20 min |
| [Team Management](./team-management.md) | Manage users, roles, and permissions for your organization | 15 min |
| [Billing & Subscription](./billing-subscription.md) | Understand plans, pricing, and manage your subscription | 12 min |

---

## What is A13E?

**A13E Detection Coverage Validator** is a cloud-native security platform that:

1. **Scans** your AWS and GCP cloud accounts to discover existing security detections
2. **Maps** those detections to the MITRE ATT&CK framework
3. **Analyzes** your coverage to identify gaps and prioritize improvements
4. **Tracks** your security posture over time with historical trending

### Key Features

- **MITRE ATT&CK Mapping**: Automatically maps cloud detections to 200+ ATT&CK techniques
- **Multi-Cloud Support**: Works with AWS and GCP (Azure coming soon)
- **Coverage Heatmap**: Visual representation of your detection coverage across all tactics
- **Gap Analysis**: Prioritized list of coverage gaps with remediation guidance
- **Team Collaboration**: Role-based access for security teams
- **Automated Scanning**: Schedule regular scans to track improvements
- **Compliance Reporting**: Export coverage reports for compliance documentation

### Who Uses A13E?

- **Security Engineers**: Improve detection coverage and close gaps
- **Cloud Security Architects**: Validate security controls across cloud environments
- **Security Operations Centers (SOCs)**: Measure and report on detection effectiveness
- **Compliance Teams**: Document security controls for audit requirements
- **CISOs**: Track security posture improvements over time

---

## Getting Started Guides

### For First-Time Users

**Step 1**: [Getting Started](./getting-started.md)
- Create your account (email/password or SSO with Google/GitHub)
- Understand the dashboard
- Navigate the interface

**Step 2**: [Connecting AWS Accounts](./connecting-aws-accounts.md)
- Set up AWS IAM permissions
- Connect your first cloud account
- Validate credentials

**Step 3**: [Running Scans](./running-scans.md)
- Run your first scan
- Monitor scan progress
- Review results

**Step 4**: [Understanding Coverage](./understanding-coverage.md)
- Interpret the coverage heatmap
- Understand confidence scores
- Analyze gaps and prioritize improvements

**Estimated time**: 1-2 hours for complete setup and first scan

### For Team Administrators

**Step 1**: [Getting Started](./getting-started.md)
- Set up your organization
- Configure organization settings

**Step 2**: [Team Management](./team-management.md)
- Invite team members
- Assign appropriate roles
- Configure security policies

**Step 3**: [Billing & Subscription](./billing-subscription.md)
- Choose the right plan
- Manage payment methods
- Monitor usage and costs

**Estimated time**: 30-45 minutes for team setup

---

## Core Concepts

### MITRE ATT&CK Framework

A13E uses the **MITRE ATT&CK** knowledge base to standardize detection coverage analysis. ATT&CK provides:

- **Tactics**: The "why" - adversary goals (e.g., Initial Access, Persistence)
- **Techniques**: The "how" - methods to achieve those goals (e.g., Valid Accounts, Phishing)
- **Sub-techniques**: Specific implementations (e.g., Cloud Accounts, Spearphishing Link)

**Learn more**: [Understanding Coverage](./understanding-coverage.md)

### Cloud Detection Sources

A13E discovers security detections from:

- **AWS GuardDuty**: Managed threat detection findings
- **AWS Security Hub**: Security standard controls and findings
- **Amazon EventBridge**: Custom rules monitoring CloudTrail events
- **Amazon CloudWatch Logs**: Log Insights queries and metric filters
- **AWS Config**: Compliance rules and evaluations

**Learn more**: [Running Scans](./running-scans.md#detection-types)

### Coverage Metrics

A13E calculates coverage using:

- **Coverage Percentage**: Percentage of MITRE ATT&CK techniques covered
- **Confidence Scores**: Quality assessment of each detection (0-100%)
- **Coverage Categories**: Covered (≥60%), Partial (40-59%), Uncovered (<40%)

**Learn more**: [Understanding Coverage](./understanding-coverage.md#coverage-calculation)

---

## Common Workflows

### Daily Operations

**Security Analyst**:
1. Check dashboard for coverage summary
2. Review recent scan results
3. Investigate new gaps or changes
4. Export reports for team meetings

**Recommended reading**: [Understanding Coverage](./understanding-coverage.md)

---

### Weekly Reviews

**Security Engineer**:
1. Run manual scan to get latest coverage
2. Compare with previous week's results
3. Prioritize and address top gaps
4. Implement new detections
5. Re-scan to verify improvements

**Recommended reading**: [Running Scans](./running-scans.md), [Understanding Coverage](./understanding-coverage.md)

---

### Monthly Planning

**Security Lead/CISO**:
1. Review overall coverage trends
2. Identify tactics needing attention
3. Allocate resources to close critical gaps
4. Export reports for executive briefings
5. Plan next month's detection improvements

**Recommended reading**: [Understanding Coverage](./understanding-coverage.md#interpreting-results)

---

### Quarterly Audits

**Compliance Team**:
1. Generate coverage reports for all accounts
2. Document detection coverage for audit
3. Map coverage to compliance frameworks (SOC 2, ISO 27001)
4. Review and update detection policies
5. Archive reports for compliance documentation

**Recommended reading**: [Billing & Subscription](./billing-subscription.md) (Enterprise features)

---

## FAQs

### Getting Started

**Q: Do I need AWS administrator access to use A13E?**
A: No, but you need permissions to create IAM roles (or someone who can create them for you).

**Q: How long does the first scan take?**
A: Typically 5-15 minutes, depending on your account size and number of detections.

**Q: Can I try A13E for free?**
A: Yes! Sign up for a free scan (no credit card required). You get one scan with 7-day data retention.

### Cloud Accounts

**Q: Can I scan multiple AWS accounts?**
A: Yes, add each AWS account separately. Subscriber plan includes 3 accounts, with $9/month per additional account.

**Q: Does A13E work with AWS Organizations?**
A: Yes, add each member account individually. Or use CloudFormation StackSets to deploy IAM roles across all accounts at once.

**Q: What about GCP support?**
A: Yes, A13E supports both AWS and GCP. Azure support is coming soon.

### Security & Privacy

**Q: What permissions does A13E need?**
A: Read-only permissions for GuardDuty, Security Hub, EventBridge, CloudWatch Logs, and Config. No write access, no billing access, no data access.

**Q: Can A13E see my cloud data or logs?**
A: No, A13E only reads detection configurations and metadata, not actual log data or application data.

**Q: Where is my data stored?**
A: Scan results are stored in A13E's cloud infrastructure (US region). Enterprise customers can choose regions or on-premise deployment.

### Coverage & Results

**Q: What's a good coverage percentage?**
A: Industry average is 55-65%. Mature programs achieve 70-80%+. Focus on covering critical techniques first, not just maximizing percentage.

**Q: Why are some techniques showing 0% coverage?**
A: Either you don't have detections for those techniques, or A13E hasn't mapped your detections yet. Review the gaps page for recommendations.

**Q: How often should I scan?**
A: Weekly for active detection development, monthly for stable environments. Use scheduled scans to automate.

### Billing

**Q: Can I cancel anytime?**
A: Yes, cancel anytime. Subscription ends at the end of your billing period. Data retained for 90 days.

**Q: Do you offer discounts?**
A: Annual subscriptions get 15% off. Enterprise customers can negotiate custom pricing. Contact sales@a13e.io.

**Q: What payment methods do you accept?**
A: Credit cards (Visa, MC, Amex, Discover) and ACH bank transfer. Enterprise customers can use wire transfer.

---

## Support & Resources

### Documentation

- **User Guides**: You're reading them!
- **API Documentation**: [docs.a13e.io/api](https://docs.a13e.io/api) (Subscriber+)
- **Knowledge Base**: [help.a13e.io](https://help.a13e.io)

### Support Channels

- **Email**: support@a13e.io
  - **Response time**: 24 hours (Free Scan), 8 hours (Subscriber), 4 hours (Enterprise)
- **In-App Help**: Click the ? icon anywhere in the app
- **Community Forum**: [community.a13e.io](https://community.a13e.io)
- **Status Page**: [status.a13e.io](https://status.a13e.io)

### Additional Resources

- **MITRE ATT&CK**: [attack.mitre.org](https://attack.mitre.org)
- **AWS Security Blog**: [aws.amazon.com/blogs/security](https://aws.amazon.com/blogs/security)
- **A13E Blog**: [blog.a13e.io](https://blog.a13e.io)
- **Webinars**: Register at [a13e.io/webinars](https://a13e.io/webinars)

---

## Release Notes & Updates

A13E is continuously improved with new features and enhancements.

**Current Version**: 0.1.0 (December 2025)

**Recent Updates**:
- MITRE ATT&CK v13.1 support
- GCP Workload Identity authentication
- Enhanced gap prioritization algorithm
- Improved CloudWatch Logs detection mapping

**Upcoming Features**:
- Azure cloud support (Q1 2026)
- Automated remediation workflows (Q2 2026)
- Threat intelligence integration (Q2 2026)

Subscribe to release notes: [a13e.io/releases](https://a13e.io/releases)

---

## Contributing & Feedback

We value your input to improve A13E!

**Feedback Channels**:
- **Feature Requests**: Vote on features at [feedback.a13e.io](https://feedback.a13e.io)
- **Bug Reports**: Email support@a13e.io
- **Documentation**: Suggest improvements via support@a13e.io

**Enterprise Customers**:
- Quarterly business reviews with your customer success manager
- Direct input on roadmap priorities
- Early access to beta features

---

## Quick Reference

### Keyboard Shortcuts

| Action | Shortcut |
|--------|----------|
| Open command palette | `Cmd/Ctrl + K` |
| Go to Dashboard | `G` then `D` |
| Go to Coverage | `G` then `C` |
| Go to Detections | `G` then `T` |
| Go to Gaps | `G` then `G` |
| Go to Accounts | `G` then `A` |
| Search | `/` or `Cmd/Ctrl + /` |
| Help | `?` |

### User Roles

| Role | Can View | Can Edit | Can Manage Team | Can Manage Billing |
|------|----------|----------|-----------------|-------------------|
| Owner | ✓ | ✓ | ✓ | ✓ |
| Admin | ✓ | ✓ | ✓ | ✗ |
| Member | ✓ | ✓ | ✗ | ✗ |
| Viewer | ✓ | ✗ | ✗ | ✗ |

**Learn more**: [Team Management](./team-management.md#user-roles)

### Subscription Plans

| Feature | Free Scan | Subscriber | Enterprise |
|---------|-----------|------------|------------|
| Cloud Accounts | 1 | 3+ | Unlimited |
| Scans | 1 | Unlimited | Unlimited |
| Team Members | 1 | 5+ | Unlimited |
| Data Retention | 7 days | Forever | Forever |
| Pricing | Free | $29/mo | $499/mo |

**Learn more**: [Billing & Subscription](./billing-subscription.md#subscription-plans)

---

## Document Version

**Last Updated**: December 19, 2025
**Documentation Version**: 1.0.0
**A13E Version**: 0.1.0

---

**Ready to get started?** Begin with [Getting Started](./getting-started.md) or jump straight to [Connecting AWS Accounts](./connecting-aws-accounts.md).

For questions or support, contact us at support@a13e.io or visit [help.a13e.io](https://help.a13e.io).
