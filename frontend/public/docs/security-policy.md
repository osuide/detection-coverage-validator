# Security Vulnerability Disclosure Policy

A13E is committed to the security of our customers and their data. We value the contributions of security researchers who help us identify and remediate vulnerabilities responsibly.

## TL;DR

- **Scope**: All A13E-owned systems (app.a13e.com, api.a13e.com, staging.a13e.com)
- **Contact**: security@a13e.com ([PGP key available](/.well-known/pgp-key.txt))
- **Safe harbour**: We won't pursue legal action for good-faith research
- **Response**: Acknowledgement within 24 hours, assessment within 72 hours
- **Recognition**: Hall of Thanks listing for valid reports

---

## Scope

### In Scope

The following systems and assets are covered by this policy:

| Asset | Domain |
|-------|--------|
| Production Application | `app.a13e.com` |
| Production API | `api.a13e.com` |
| Documentation Site | `docs.a13e.com` |
| Marketing Site | `a13e.com` |

### Out of Scope

The following are **not** covered by this policy:

- Staging environments (not publicly accessible)
- Third-party services (AWS, GCP, Stripe, Auth0)
- Physical security testing
- Social engineering attacks against A13E staff
- Denial of service (DoS/DDoS) testing
- Automated vulnerability scanning that generates excessive traffic

---

## How to Report

### Contact Information

| Method | Details |
|--------|---------|
| **Email** | security@a13e.com |
| **PGP Key** | [Download public key](/.well-known/pgp-key.txt) |
| **Key Fingerprint** | `5192 5BF3 40A7 24C1 0D58 E9E0 E40D 5C52 FA6E 469E` |

We strongly encourage encrypting sensitive reports using our PGP key.

### What to Include

To help us triage and respond effectively, please include:

1. **Description**: Clear explanation of the vulnerability
2. **Impact**: What could an attacker achieve?
3. **Steps to reproduce**: Detailed instructions to replicate the issue
4. **Proof of concept**: Screenshots, videos, or code snippets
5. **Affected systems**: URLs, endpoints, or components involved
6. **Your contact details**: How we can reach you for follow-up

### What NOT to Do

When testing, please **do not**:

- Access, modify, or delete data belonging to other users
- Perform actions that could degrade service availability
- Use automated tools that generate excessive traffic
- Publicly disclose vulnerabilities before remediation
- Attempt physical intrusion or social engineering
- Test against accounts you don't own (without explicit permission)

---

## Safe Harbour

A13E supports security research conducted in good faith. If you comply with this policy:

> **We will not pursue legal action** against you for security research activities conducted in accordance with this policy. We consider such research to be authorised under applicable computer access laws.
>
> If legal action is initiated by a third party against you for activities conducted in compliance with this policy, we will make it known that your actions were authorised by A13E.

### Conditions

Safe harbour protections apply when you:

- Act in good faith and avoid privacy violations
- Avoid actions that could harm our users or services
- Do not exploit vulnerabilities beyond demonstrating proof of concept
- Report vulnerabilities promptly without public disclosure
- Comply with all applicable laws

---

## Our Commitment

### Response Timeline

| Stage | Timeframe |
|-------|-----------|
| **Acknowledgement** | Within 24 hours |
| **Initial assessment** | Within 72 hours |
| **Status update** | Every 7 days until resolution |
| **Resolution** | Dependent on severity and complexity |

### Severity Assessment

We assess vulnerabilities using CVSS v3.1 and consider:

| Severity | Description | Target Resolution |
|----------|-------------|-------------------|
| **Critical** | Remote code execution, authentication bypass, data breach | 7 days |
| **High** | Privilege escalation, significant data exposure | 14 days |
| **Medium** | Cross-site scripting, CSRF, limited data exposure | 30 days |
| **Low** | Information disclosure, best practice deviations | 90 days |

Complex issues may require longer remediation periods. We'll keep you informed throughout.

### What We Will Do

- Acknowledge your report promptly
- Keep you informed of our progress
- Work with you to understand and validate the issue
- Credit you in our [Hall of Thanks](/docs/security-thanks) (unless you prefer anonymity)
- Not disclose your identity without permission

---

## Recognition

We believe in recognising those who help improve our security:

### Hall of Thanks

Valid vulnerability reporters are eligible for inclusion in our [Security Researcher Hall of Thanks](/docs/security-thanks), which includes:

- Your name (or chosen alias)
- Link to your profile (LinkedIn, Twitter/X, personal site)
- Date of disclosure
- General category of finding (without sensitive details)

### Eligibility Criteria

To qualify for recognition:

- Report must be valid, unique, and not previously known
- Vulnerability must be within scope
- Reporter must comply with this disclosure policy
- Finding must have genuine security impact

We do not currently offer monetary rewards, but may consider bug bounty programmes in future.

---

## Qualifying Vulnerabilities

### Examples of Valid Reports

- Remote code execution
- SQL injection
- Cross-site scripting (XSS)
- Cross-site request forgery (CSRF)
- Authentication or authorisation flaws
- Server-side request forgery (SSRF)
- Insecure direct object references (IDOR)
- Sensitive data exposure
- Security misconfigurations with demonstrable impact

### Examples of Non-Qualifying Reports

- Missing HTTP security headers without demonstrated exploit
- SSL/TLS configuration issues (unless exploitable)
- Clickjacking on non-sensitive pages
- Lack of rate limiting (without demonstrated abuse scenario)
- Software version disclosure
- SPF/DKIM/DMARC configuration suggestions
- Self-XSS or issues requiring unlikely user interaction
- Theoretical vulnerabilities without proof of concept

---

## Legal Framework

This policy is designed to be consistent with:

- **ISO/IEC 29147:2018** - Vulnerability disclosure
- **ISO/IEC 30111:2019** - Vulnerability handling processes
- **NIST Cybersecurity Framework** - Identify, Protect, Detect, Respond, Recover
- **UK Computer Misuse Act 1990** - We authorise good-faith security testing within scope

Nothing in this policy should be interpreted as authorising activities that violate applicable law.

---

## Contact

For security matters: **security@a13e.com**

For general enquiries: **support@a13e.com**

---

## Policy Version

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | January 2026 | Initial policy |

This policy is reviewed annually. Last updated: January 2026.

---

## Further Resources

- [security.txt](/.well-known/security.txt) - Machine-readable security contact information
- [PGP Public Key](/.well-known/pgp-key.txt) - For encrypted communications
- [Hall of Thanks](/docs/security-thanks) - Recognised security researchers
