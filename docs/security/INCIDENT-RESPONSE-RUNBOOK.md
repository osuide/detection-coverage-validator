# A13E Incident Response Runbook

**Version:** 1.0
**Last Updated:** 2025-12-20
**Classification:** Internal - Security Team
**Review Cycle:** Quarterly

---

## 1. Purpose and Scope

This runbook provides step-by-step procedures for responding to security incidents affecting the A13E Detection Coverage Validator platform. It covers identification, containment, eradication, recovery, and post-incident activities.

### 1.1 Scope

This runbook applies to:
- All security incidents affecting A13E infrastructure
- Data breaches involving customer information
- Compromise of cloud credentials
- Service availability incidents with security implications
- Third-party security incidents affecting A13E

### 1.2 Incident Severity Levels

| Severity | Description | Response Time | Examples |
|----------|-------------|---------------|----------|
| **P1 - Critical** | Active breach, data exfiltration, service down | 15 minutes | Database breach, credential theft, ransomware |
| **P2 - High** | Confirmed attack, partial service impact | 1 hour | Successful phishing, unauthorised access |
| **P3 - Medium** | Attempted attack, no confirmed impact | 4 hours | Failed login attacks, vulnerability discovered |
| **P4 - Low** | Security policy violation, minor issue | 24 hours | Configuration drift, access review findings |

---

## 2. Incident Response Team

### 2.1 Core Team

| Role | Responsibility | Contact |
|------|---------------|---------|
| **Incident Commander** | Overall coordination, decisions | On-call rotation |
| **Security Lead** | Technical investigation, forensics | security@a13e.com |
| **Engineering Lead** | System changes, containment | engineering@a13e.com |
| **Communications Lead** | Customer/stakeholder comms | comms@a13e.com |

### 2.2 Escalation Path

```
┌─────────────────┐
│  Alert Trigger  │
└────────┬────────┘
         │
         ▼
┌─────────────────┐     No      ┌─────────────────┐
│  On-Call Engr   │ ──────────► │  Monitor/Log    │
│  (15 min SLA)   │   Security? │                 │
└────────┬────────┘             └─────────────────┘
         │ Yes
         ▼
┌─────────────────┐
│  Security Lead  │
│  (Assess Sev.)  │
└────────┬────────┘
         │
    ┌────┴────┐
    │         │
    ▼         ▼
┌───────┐ ┌───────┐
│  P1   │ │ P2-P4 │
└───┬───┘ └───┬───┘
    │         │
    ▼         ▼
┌─────────────────┐  ┌─────────────────┐
│  All Hands      │  │  Standard       │
│  War Room       │  │  Response       │
│  Exec Notified  │  │                 │
└─────────────────┘  └─────────────────┘
```

---

## 3. Incident Response Procedures

### 3.1 Phase 1: Detection and Identification

#### 3.1.1 Alert Sources

- **CloudWatch Alarms** - Automated threshold alerts
- **GuardDuty Findings** - AWS threat detection
- **WAF Logs** - Attack pattern detection
- **Application Logs** - Authentication failures, errors
- **Customer Reports** - security@a13e.com
- **Security Researchers** - Via security.txt

#### 3.1.2 Initial Assessment Checklist

```markdown
## Initial Assessment (Complete within 15 minutes for P1)

- [ ] What triggered the alert/report?
- [ ] When did the incident start (date and time in UTC)?
- [ ] What systems are affected (AWS region: eu-west-2)?
- [ ] Is there ongoing malicious activity?
- [ ] Is customer data at risk?
- [ ] What is the initial severity assessment (P1-P4)?
- [ ] Who needs to be notified immediately?
```

#### 3.1.3 Evidence Collection

```bash
# Preserve logs immediately
# CloudWatch Logs (ensure --region is set to eu-west-2)
aws logs describe-log-streams \
  --log-group-name /aws/ecs/a13e-production-backend \
  --order-by LastEventTime --descending \
  --region eu-west-2

# Export relevant time range
aws logs filter-log-events \
  --log-group-name /aws/ecs/a13e-production-backend \
  --start-time $(date -d '1 hour ago' +%s)000 \
  --end-time $(date +%s)000 \
  --region eu-west-2 \
  --output json > incident-logs-$(date +%Y%m%d-%H%M).json

# CloudTrail events
aws cloudtrail lookup-events \
  --start-time $(date -d '24 hours ago' --iso-8601=seconds) \
  --end-time $(date --iso-8601=seconds) \
  --region eu-west-2 \
  --output json > cloudtrail-$(date +%Y%m%d-%H%M).json
```

---

### 3.2 Phase 2: Containment

#### 3.2.1 Immediate Containment Actions

**For Compromised User Account:**
```bash
# 1. Disable user account
# Via admin panel or database
UPDATE users SET is_active = false WHERE id = '<user_id>';

# 2. Invalidate all sessions
DELETE FROM user_sessions WHERE user_id = '<user_id>';

# 3. Revoke API keys
UPDATE api_keys SET is_active = false WHERE user_id = '<user_id>';
```

**For Compromised API Key:**
```bash
# 1. Identify key usage
grep '<api_key_prefix>' /var/log/application/*.log

# 2. Revoke the key
UPDATE api_keys SET is_active = false WHERE id = '<key_id>';

# 3. Notify affected organisation
# Document and send notification
```

**For Infrastructure Compromise:**
```bash
# 1. Isolate affected ECS tasks (stop and drain connections)
aws ecs update-service \
  --cluster a13e-production \
  --service backend \
  --desired-count 0 \
  --region eu-west-2

# 2. Create forensic snapshot of RDS if database compromise suspected
aws rds create-db-cluster-snapshot \
  --db-cluster-identifier a13e-production \
  --db-cluster-snapshot-identifier incident-$(date +%Y%m%d-%H%M) \
  --region eu-west-2

# 3. Rotate credentials
aws secretsmanager rotate-secret \
  --secret-id a13e-production-database-url \
  --region eu-west-2
```

#### 3.2.2 Customer Cloud Credential Compromise

If customer cloud credentials stored in A13E are compromised:

1. **Identify affected credentials**
   ```sql
   SELECT c.id, c.cloud_provider, o.name as org_name
   FROM cloud_credentials c
   JOIN organisations o ON c.organisation_id = o.id
   WHERE c.created_at < '<breach_time>';
   ```

2. **Notify affected customers immediately**
   - Use template: `templates/incident-notification-credentials.md`
   - Include: affected accounts, recommended actions, timeline

3. **Revoke stored credentials**
   ```sql
   UPDATE cloud_credentials
   SET is_active = false, revoked_at = NOW(), revoked_reason = 'Security incident'
   WHERE id IN (<affected_ids>);
   ```

4. **Guide customers to rotate**
   - AWS: New IAM role, update External ID
   - GCP: New service account, revoke old one

---

### 3.3 Phase 3: Eradication

#### 3.3.1 Root Cause Analysis

```markdown
## Root Cause Analysis Template

### Timeline
- [Time] Initial compromise vector
- [Time] Attacker actions
- [Time] Detection
- [Time] Containment

### Attack Vector
- How did the attacker gain access?
- What vulnerability was exploited?
- What credentials/tokens were used?

### Impact Assessment
- What data was accessed?
- What systems were modified?
- What is the blast radius?

### Evidence
- Log files preserved
- Forensic images
- Network captures
```

#### 3.3.2 Remediation Actions

| Issue | Remediation | Verification |
|-------|-------------|--------------|
| Compromised password | Force reset + MFA | Verify new credentials work |
| Stolen API key | Revoke + issue new | Verify new key in customer systems |
| Vulnerable code | Deploy patch | Security scan passes |
| Misconfiguration | Correct config | Config audit passes |
| Malware | Rebuild from clean image | Integrity verification |

---

### 3.4 Phase 4: Recovery

#### 3.4.1 Service Restoration Checklist

```markdown
## Recovery Checklist

### Pre-Recovery
- [ ] Root cause identified and addressed
- [ ] All malicious artefacts removed
- [ ] Credentials rotated
- [ ] Patches applied

### Recovery Steps
- [ ] Restore services in staging first
- [ ] Verify security controls functioning
- [ ] Gradual production restoration
- [ ] Monitor for recurrence

### Post-Recovery Verification
- [ ] All services healthy
- [ ] Security scans pass
- [ ] Logs showing normal activity
- [ ] Customer-facing functionality verified
```

#### 3.4.2 Credential Rotation Procedures

**Database Credentials:**
```bash
# NOTE: A13E uses IAM database authentication in production.
# Only rotate if using password-based auth in development/staging.

# 1. Generate new password
NEW_PASS=$(openssl rand -base64 32)

# 2. Update in RDS (if using password auth)
aws rds modify-db-cluster \
  --db-cluster-identifier a13e-production \
  --master-user-password "$NEW_PASS" \
  --region eu-west-2

# 3. Update in Secrets Manager
aws secretsmanager update-secret \
  --secret-id a13e-production-database-url \
  --secret-string "postgresql://user:$NEW_PASS@host/db"

# 4. Restart application
aws ecs update-service \
  --cluster a13e-production \
  --service backend \
  --force-new-deployment
```

**Encryption Keys:**
```bash
# 1. Generate new Fernet key
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"

# 2. Update in Secrets Manager
aws secretsmanager update-secret \
  --secret-id a13e-production-encryption-key \
  --secret-string "<new-key>"

# 3. Re-encrypt affected data
# WARNING: This requires a background job to decrypt with old key
# and re-encrypt with new key. Alternatively, invalidate all stored
# credentials and require customers to re-enter them.
```

---

### 3.5 Phase 5: Post-Incident Activities

#### 3.5.1 Customer Notification

**Notification Timeline:**
- P1 incidents: Within 24 hours of discovery
- P2 incidents: Within 72 hours
- P3/P4: As appropriate

**Notification Template:**
```markdown
Subject: Security Incident Notification - A13E

Dear [Customer Name],

We are writing to inform you of a security incident affecting the A13E
Detection Coverage Validator platform.

**What Happened:**
[Brief description of incident]

**When It Happened:**
[Date/time range]

**What Information Was Involved:**
[Types of data affected]

**What We Are Doing:**
[Actions taken and ongoing]

**What You Can Do:**
[Recommended customer actions]

**For More Information:**
Contact our security team at security@a13e.com

Sincerely,
The A13E Security Team
```

#### 3.5.2 Post-Incident Review

**Schedule:** Within 5 business days of incident closure

**Attendees:** Incident response team + relevant stakeholders

**Agenda:**
1. Incident timeline review
2. What went well
3. What could be improved
4. Action items and owners
5. Update to runbooks/processes

**Review Template:**
```markdown
## Post-Incident Review: [Incident ID]

### Summary
- Incident type:
- Severity:
- Duration:
- Impact:

### Timeline
[Detailed timeline]

### Root Cause
[Detailed root cause]

### What Went Well
-

### Areas for Improvement
-

### Action Items
| Action | Owner | Due Date |
|--------|-------|----------|
|        |       |          |

### Runbook Updates Needed
-
```

#### 3.5.3 Regulatory Reporting

| Regulation | Reporting Requirement | Timeline |
|------------|----------------------|----------|
| GDPR | ICO notification if personal data breach | 72 hours |
| UK DPA 2018 | ICO notification | 72 hours |
| Customer contracts | Per SLA requirements | As specified |

---

## 4. Specific Incident Playbooks

### 4.1 Playbook: Credential Stuffing Attack

**Indicators:**
- High volume of failed login attempts
- Logins from unusual geographic locations
- Multiple accounts targeted from same IP range

**Response:**
1. Enable enhanced WAF rules
2. Temporarily increase rate limiting
3. Force password reset for affected accounts
4. Analyse attack patterns
5. Block malicious IP ranges
6. Notify affected users

### 4.2 Playbook: Data Breach

**Indicators:**
- Unusual database queries
- Large data exports
- Access from compromised account

**Response:**
1. **Immediate:** Isolate affected systems
2. **15 min:** Assess scope of breach
3. **1 hour:** Notify legal and executive team
4. **4 hours:** Determine notification requirements
5. **24 hours:** Customer notification (if required)
6. **72 hours:** Regulatory notification (if required)

### 4.3 Playbook: Ransomware

**Indicators:**
- Encrypted files
- Ransom notes
- Unusual process activity

**Response:**
1. **DO NOT** pay ransom
2. Isolate all affected systems
3. Preserve evidence before any recovery
4. Identify infection vector
5. Restore from clean backups
6. Report to law enforcement (National Crime Agency)

### 4.4 Playbook: DDoS Attack

**Indicators:**
- Service degradation
- Unusual traffic patterns
- CloudFront/WAF alerts

**Response:**
1. Confirm attack via CloudWatch metrics
2. Enable AWS Shield Advanced (if not active)
3. Engage AWS DDoS Response Team (DRT)
4. Implement rate limiting
5. Scale resources if needed
6. Document attack patterns

---

## 5. Tools and Access

### 5.1 Required Access

| Tool | Access Level | Purpose |
|------|--------------|---------|
| AWS Console | Admin | Infrastructure investigation |
| CloudWatch | Read | Log analysis |
| Database | Read (prod) / Admin (staging) | Query investigation |
| GitHub | Admin | Code review, deployment |

### 5.2 Forensic Tools

- **AWS CloudTrail** - API activity history
- **VPC Flow Logs** - Network traffic analysis
- **CloudWatch Logs Insights** - Log querying
- **AWS GuardDuty** - Threat detection
- **Database audit logs** - Query history

---

## 6. Communication Templates

### 6.1 Internal Status Update

```markdown
## Incident Update: [ID] - [Time]

**Status:** [Investigating/Contained/Resolved]
**Severity:** [P1/P2/P3/P4]

**Current Situation:**
[Brief description]

**Actions Taken:**
-

**Next Steps:**
-

**ETA to Resolution:** [Time estimate or "Investigating"]
```

### 6.2 Customer Status Page Update

```markdown
**[Service] - Investigating Increased Error Rates**
Posted: [Time]

We are currently investigating reports of [issue description].
Our team is actively working on the issue.

We will provide an update within [time].

---
Update [Time]: [Progress update]
```

---

## 7. Document Control

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2025-12-20 | Security Team | Initial runbook |

**Next Review Date:** 2026-03-20
**Testing Schedule:** Quarterly tabletop exercises

---

## 8. Appendices

### Appendix A: Contact List

| Role | Name | Phone | Email |
|------|------|-------|-------|
| Security Lead | [TO BE FILLED] | [TO BE FILLED] | security@a13e.com |
| Engineering Lead | [TO BE FILLED] | [TO BE FILLED] | engineering@a13e.com |
| CEO | [TO BE FILLED] | [TO BE FILLED] | [TO BE FILLED] |
| Legal | [TO BE FILLED] | [TO BE FILLED] | legal@a13e.com |
| AWS Support | - | - | AWS Support Console (Account: 123080274263, Region: eu-west-2) |

### Appendix B: External Contacts

| Organisation | Purpose | Contact |
|--------------|---------|---------|
| AWS Support | Infrastructure issues | Support Console |
| National Crime Agency | Cybercrime reporting | https://www.ncsc.gov.uk/report |
| ICO | Data breach reporting | https://ico.org.uk/report |

---

*This document is confidential and intended for the incident response team only.*
