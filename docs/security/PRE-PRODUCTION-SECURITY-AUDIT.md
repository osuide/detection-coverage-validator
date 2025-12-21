# Pre-Production Security Audit Plan

## A13E Detection Coverage Validator

**Document Version:** 1.0
**Last Updated:** 2025-12-21
**Classification:** Internal - Security Team
**Target Audience:** Security Team, Engineering Leadership, Compliance Officers

---

## 1. Executive Summary

The A13E Detection Coverage Validator is a multi-cloud security platform (AWS and GCP) with a FastAPI backend (~424 Python files), React/TypeScript frontend (~70 files), and AWS infrastructure (Lambda, Fargate, RDS, ElastiCache, CloudFront). This audit plan covers all security domains required before production deployment at https://app.a13e.com.

### Previous Security Work Completed

| Severity | Count | Status |
|----------|-------|--------|
| Critical | 5 | ✅ All fixed (C1-C5) |
| High | 12 | ✅ All fixed (H1-H12) |
| Medium | 19 | ✅ All fixed (M1-M19) |
| Low | 8 | ✅ Documented in backlog |

**Infrastructure Location:** AWS Account 123080274263, Region eu-west-2 (London)

---

## 2. Audit Scope and Objectives

### 2.1 In-Scope Systems

| System | Description | Priority |
|--------|-------------|----------|
| Backend API | FastAPI on ECS Fargate (port 8000) | Critical |
| Frontend | React SPA on CloudFront/S3 | High |
| Database | PostgreSQL on RDS (encrypted) | Critical |
| Cache | Redis on ElastiCache | High |
| Authentication | Cognito + Custom JWT + MFA | Critical |
| Billing | Stripe integration (4-tier model) | Critical |
| Cloud Integrations | AWS AssumeRole, GCP Workload Identity | High |
| Infrastructure | Terraform-managed AWS resources | High |

### 2.2 Audit Objectives

1. **Validate security controls** implemented during the security backlog remediation
2. **Identify residual vulnerabilities** not addressed in previous fixes
3. **Verify compliance readiness** for future SOC 2 Type II certification
4. **Confirm production readiness** with clear Go/No-Go criteria
5. **Document security posture** for stakeholders and customers

---

## 3. Audit Categories and Checklists

### 3.1 Authentication and Authorisation Review

**Key Files:**
- `backend/app/core/security.py`
- `backend/app/api/routes/auth.py`
- `backend/app/services/auth_service.py`
- `backend/app/api/deps/rate_limit.py`

**Checklist:**

| ID | Check | Expected Result | Tools |
|----|-------|-----------------|-------|
| AUTH-01 | JWT algorithm restriction | Only HS256 accepted | Code review |
| AUTH-02 | Token type validation | Admin tokens rejected in user context | Manual test |
| AUTH-03 | Redis-backed rate limiting | Login: 10/min, Signup: 5/5min, MFA: 5/min | Burp Suite |
| AUTH-04 | Password hashing | BCrypt with 12 rounds | Code review |
| AUTH-05 | MFA implementation | TOTP with bcrypt-hashed backup codes | Manual test |
| AUTH-06 | Session management | httpOnly cookies, CSRF double-submit | Browser DevTools |
| AUTH-07 | Token refresh rotation | Refresh tokens rotated on each use | Burp Suite |
| AUTH-08 | Token theft detection | Reused old tokens revoke all sessions | Manual test |
| AUTH-09 | Account lockout | 5 failed attempts triggers exponential lockout | Automated test |
| AUTH-10 | HIBP integration | Breached passwords blocked | Manual test |
| AUTH-11 | OAuth state validation | State parameter validated for GitHub/Google | Manual test |
| AUTH-12 | PKCE for Cognito | Code verifier in sessionStorage | Browser DevTools |
| AUTH-13 | Access token storage | Memory only (Zustand), not localStorage | Browser DevTools |
| AUTH-14 | RBAC role hierarchy | OWNER > ADMIN > MEMBER > VIEWER enforced | Manual test |
| AUTH-15 | Organisation isolation | All queries filtered by org_id | SQL injection test |
| AUTH-16 | Membership verification | JWT org claims verified against DB | Code review |

**Test Scenarios:**

1. **JWT Algorithm Confusion Attack**
   - Attempt login with `alg: none` in token header
   - Expected: Rejected with 401

2. **Token Theft Detection**
   - Obtain refresh token, use it once (rotation)
   - Attempt to use the original token again
   - Expected: All sessions for user revoked

3. **Rate Limiter Multi-Instance**
   - Send 15 login requests within 1 minute from same IP
   - Expected: Requests 11-15 return 429

---

### 3.2 API Security Testing

**Key Files:**
- `backend/app/main.py` (CORS, middleware)
- `backend/app/api/routes/*.py` (all endpoints)

**Checklist:**

| ID | Check | Expected Result | Tools |
|----|-------|-----------------|-------|
| API-01 | CORS origin validation | Only allowed origins, no wildcards | Burp Suite |
| API-02 | Input validation | All endpoints use Pydantic models | Code review |
| API-03 | SQL injection resistance | SQLAlchemy ORM throughout | sqlmap |
| API-04 | Path traversal | Filenames sanitised | Burp Suite |
| API-05 | Error message sanitisation | No stack traces in prod | Manual test |
| API-06 | API key rate limiting | 100 req/min per IP | Burp Suite |
| API-07 | IP allowlist with CIDR | IPv4/IPv6 and CIDR ranges | Manual test |
| API-08 | Webhook signature verification | Stripe webhooks validated | Manual test |
| API-09 | Webhook replay protection | Duplicate event IDs rejected | Burp Suite |
| API-10 | Subscription limits | Account limits enforced | Manual test |
| API-11 | Scan limit atomicity | Concurrent requests don't bypass | Load test |

**Endpoints Requiring Special Attention:**

| Endpoint | Security Concern | Test Required |
|----------|-----------------|---------------|
| `POST /api/v1/auth/login` | Brute force | Rate limit verification |
| `POST /api/v1/billing/webhook` | Replay attacks | Signature + idempotency |
| `POST /api/v1/credentials` | Credential encryption | Verify Fernet |
| `POST /api/v1/accounts` | Subscription limits | Limit bypass attempt |
| `POST /api/v1/scans` | Resource exhaustion | Scan limit enforcement |

---

### 3.3 Infrastructure Security Assessment

**Key Files:**
- `infrastructure/terraform/modules/vpc/main.tf`
- `infrastructure/terraform/modules/database/main.tf`
- `infrastructure/terraform/modules/backend/main.tf`
- `infrastructure/terraform/modules/security/main.tf`

**Checklist:**

| ID | Check | Expected Result | Tools |
|----|-------|-----------------|-------|
| INFRA-01 | Security group restrictions | ECS SG allows only ALB; RDS/Redis allow only ECS | AWS Console |
| INFRA-02 | RDS encryption at rest | storage_encrypted = true | AWS CLI |
| INFRA-03 | RDS in private subnets | No public accessibility | AWS Console |
| INFRA-04 | Redis encryption in transit | transit_encryption_enabled = true | AWS CLI |
| INFRA-05 | Secrets Manager IAM | Scoped to environment prefix | AWS CLI |
| INFRA-06 | VPC Flow Logs | Enabled with 30-day retention | AWS Console |
| INFRA-07 | WAF effectiveness | OWASP CRS, SQLi, rate limiting active | WAF console |
| INFRA-08 | Security headers | CSP, HSTS, X-Frame-Options | curl/Browser |
| INFRA-09 | TLS configuration | TLS 1.2+ on ALB, Grade A | SSL Labs |
| INFRA-10 | CloudTrail enabled | API activity logging active | AWS Console |
| INFRA-11 | GuardDuty enabled | Threat detection active | AWS Console |
| INFRA-12 | Container security | Non-root user, read-only filesystem | Docker inspect |
| INFRA-13 | Deletion protection | Enabled for prod RDS and ALB | Terraform state |
| INFRA-14 | Backup configuration | 7-day retention | AWS Console |

**AWS Security Assessment Commands:**

```bash
# Check security group rules
aws ec2 describe-security-groups --region eu-west-2 \
  --filters "Name=group-name,Values=*a13e*" \
  --query 'SecurityGroups[*].{Name:GroupName,Rules:IpPermissions}'

# Verify RDS encryption
aws rds describe-db-instances --region eu-west-2 \
  --query 'DBInstances[*].{ID:DBInstanceIdentifier,Encrypted:StorageEncrypted}'

# Check VPC Flow Logs
aws ec2 describe-flow-logs --region eu-west-2

# Verify WAF rules
aws wafv2 list-web-acls --region eu-west-2 --scope REGIONAL

# Check GuardDuty status
aws guardduty list-detectors --region eu-west-2
```

---

### 3.4 Data Protection and Encryption Verification

**Key Files:**
- `backend/app/models/cloud_credential.py`
- `backend/app/core/config.py`
- `backend/app/services/auth_service.py`

**Checklist:**

| ID | Check | Expected Result | Tools |
|----|-------|-----------------|-------|
| DATA-01 | Cloud credential encryption | Fernet (AES-128-CBC + HMAC-SHA256) | Code review |
| DATA-02 | Encryption key storage | AWS Secrets Manager | AWS Console |
| DATA-03 | Password hashing | BCrypt 12 rounds | Code review |
| DATA-04 | API key hashing | SHA-256 before storage | Code review |
| DATA-05 | Secret key protection | SecretStr type, not in logs | Code review |
| DATA-06 | TLS in transit | All connections use TLS 1.2+ | Wireshark |
| DATA-07 | Database encryption | RDS AES-256 at rest | AWS Console |
| DATA-08 | Sensitive data in logs | Redacted by middleware | Log review |
| DATA-09 | External ID for AWS | Confused deputy protection | Code review |
| DATA-10 | Key rotation tracking | Rotation count and timestamp tracked | DB check |

**Data Classification:**

| Data Type | Storage | Protection | Verified |
|-----------|---------|------------|----------|
| Passwords | PostgreSQL | BCrypt hash (12 rounds) | [ ] |
| Refresh tokens | PostgreSQL | SHA-256 hash + rotation detection | [ ] |
| API keys | PostgreSQL | SHA-256 hash | [ ] |
| AWS credentials | PostgreSQL | Fernet encryption | [ ] |
| GCP service keys | PostgreSQL | Fernet encryption | [ ] |
| SECRET_KEY | Secrets Manager | SecretStr type | [ ] |
| Audit logs | CloudWatch | Encrypted | [ ] |

---

### 3.5 Dependency Vulnerability Scanning

**Scanning Commands:**

```bash
# Python dependencies
pip-audit --requirement backend/requirements.txt
safety check -r backend/requirements.txt

# Node.js dependencies
cd frontend && npm audit

# Container image
trivy image <ecr-repository-url>:latest

# Cloud security posture
prowler aws -r eu-west-2 -M json-asff
```

**Acceptance Criteria:**
- Zero critical CVEs
- Zero high CVEs (or documented mitigation)
- < 5 medium CVEs with mitigation plan

---

### 3.6 Penetration Testing Scope

**Methodology:** OWASP Testing Guide v4.2, PTES

**Scope:**

| Area | In Scope | Out of Scope |
|------|----------|--------------|
| Web Application | https://staging.a13e.com | Customer cloud accounts |
| API | /api/v1/* endpoints | Third-party APIs |
| Infrastructure | AWS Account 123080274263 | Other AWS accounts |
| Authentication | All auth flows | Cognito internals |

**OWASP Top 10 2021 Testing:**
- A01: Broken Access Control - BOLA/BFLA tests
- A02: Cryptographic Failures - TLS, encryption review
- A03: Injection - SQL, command injection
- A07: Authentication Failures - Session management
- A09: Logging/Monitoring - Audit log coverage

**Tools:**

| Category | Tools |
|----------|-------|
| Web scanning | Burp Suite Pro, OWASP ZAP |
| SQL injection | sqlmap |
| Cloud | ScoutSuite, Prowler |
| Container | Trivy, Grype |
| TLS | testssl.sh, SSL Labs |

---

### 3.7 Compliance Readiness (SOC 2 Preparation)

**Relevant Controls:**

| SOC 2 Criteria | Implementation | Status |
|----------------|----------------|--------|
| CC6.1 Logical Access | RBAC, MFA, sessions | ✅ Implemented |
| CC6.2 Authentication | JWT + cookies, BCrypt | ✅ Implemented |
| CC6.3 Authorisation | Role hierarchy, org isolation | ✅ Implemented |
| CC6.6 Encryption | TLS 1.2+, AES-256, Fernet | ✅ Implemented |
| CC7.2 Vulnerability Mgmt | Dependabot, scanning | ✅ Implemented |
| CC7.4 Incident Response | Runbook documented | ✅ Documented |

**Documentation Required:**

- [x] Security Architecture Document
- [x] Threat Model
- [x] Incident Response Runbook
- [x] Security Audit Report
- [x] Pre-Production Audit Plan (this document)
- [ ] Privacy Policy
- [ ] Terms of Service

---

### 3.8 Incident Response Preparation

**Verification Checklist:**

| ID | Check | Status |
|----|-------|--------|
| IR-01 | Contact list populated | [ ] Verify |
| IR-02 | AWS Support access | [ ] Verify |
| IR-03 | Log retention (1 year) | [ ] Verify |
| IR-04 | RDS snapshot tested | [ ] Verify |
| IR-05 | Credential rotation tested | [ ] Verify |
| IR-06 | Customer notification template | [ ] Verify |

**Tabletop Exercise Scenarios:**

1. **Credential Stuffing Attack** - Rate limiting, user notification
2. **Customer Credential Compromise** - API pattern detection, revocation
3. **Database Breach** - Forensic snapshot, GDPR notification

---

## 4. Timeline and Schedule

| Phase | Duration | Activities |
|-------|----------|------------|
| **Phase 1: Automated Scanning** | 2 days | Dependency scan, infrastructure scan, TLS |
| **Phase 2: Manual Testing** | 5 days | Auth testing, API security, OWASP Top 10 |
| **Phase 3: Penetration Testing** | 3 days | Full-scope pentest on staging |
| **Phase 4: Remediation** | 3-5 days | Fix findings, retest critical |
| **Phase 5: Documentation** | 2 days | Final report, evidence |

**Total Duration:** 15-17 business days

---

## 5. Go/No-Go Criteria

### 5.1 Must-Pass (Blockers)

| Criteria | Requirement |
|----------|-------------|
| Critical CVEs | Zero |
| High CVEs | Zero (or mitigated) |
| Authentication Bypass | None found |
| SQL Injection | None found |
| Authorisation Bypass | None found |
| Data Encryption | All sensitive data encrypted |
| TLS Grade | A on SSL Labs |
| Rate Limiting | Functional across instances |
| Audit Logging | All security events logged |

### 5.2 Should-Pass (Warnings)

| Criteria | Acceptable Risk |
|----------|-----------------|
| Medium CVEs | < 5 with mitigation plan |
| VPC Flow Logs | Can enable post-launch |
| Cognito Advanced Security | AUDIT mode acceptable initially |

### 5.3 Decision Matrix

| Result | Criteria | Action |
|--------|----------|--------|
| **GO** | All Must-Pass ✅ | Proceed to production |
| **CONDITIONAL GO** | All Must-Pass ✅, some Should-Pass ⚠️ | Proceed with documented risks |
| **NO-GO** | Any Must-Pass ❌ | Remediate before production |

---

## 6. Risk Register

### Accepted Risks

| ID | Description | Mitigation |
|----|-------------|------------|
| AR-01 | CSP 'unsafe-inline' for Stripe.js | Required for Stripe compliance |
| AR-02 | ECS in public subnets | WAF + Security Groups protection |
| AR-03 | AWS-managed KMS for RDS | Acceptable for current compliance |

### Residual Risks Requiring Monitoring

| ID | Description | Monitoring | Alert |
|----|-------------|------------|-------|
| RR-01 | DDoS attacks | WAF metrics | >500 blocks/hour |
| RR-02 | Credential stuffing | Failed login metrics | >50 failures/5min |
| RR-03 | Insider threat | Audit log review | Weekly |

---

## 7. Sign-Off

| Role | Name | Date | Signature |
|------|------|------|-----------|
| Security Lead | | | |
| Engineering Lead | | | |
| Product Owner | | | |

---

## Appendix A: Security Contacts

| Role | Contact |
|------|---------|
| Security Lead | security@a13e.com |
| Engineering Lead | engineering@a13e.com |
| AWS Support | AWS Console |
| ICO (GDPR) | https://ico.org.uk/report |
| NCSC | https://www.ncsc.gov.uk/report |

---

## Appendix B: Audit Tools

| Tool | Version | Purpose |
|------|---------|---------|
| Burp Suite Pro | 2024.x | Web/API testing |
| OWASP ZAP | 2.14+ | Web scanning |
| sqlmap | 1.8+ | SQL injection |
| Trivy | 0.50+ | Container scanning |
| Prowler | 4.0+ | AWS security |
| pip-audit | Latest | Python CVE scan |
| npm audit | Latest | Node.js CVE scan |
| SSL Labs | Online | TLS configuration |

---

**Document Control:**
- Created: 2025-12-21
- Author: Security Team
- Review: Before each production deployment
