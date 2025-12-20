# A13E Detection Coverage Validator - Threat Model

**Version:** 1.0
**Last Updated:** 2025-12-20
**Classification:** Internal
**Review Cycle:** Quarterly

---

## Executive Summary

This document provides a comprehensive threat model for the A13E Detection Coverage Validator platform. It identifies potential threats, attack vectors, and mitigations using the STRIDE methodology. This threat model supports SOC 2 Type II compliance and ongoing security risk management.

---

## 1. System Overview

### 1.1 Purpose

A13E is a multi-cloud security detection coverage validator that:
- Scans AWS and GCP environments for existing security detections
- Maps detections to the MITRE ATT&CK framework
- Identifies coverage gaps and provides remediation guidance
- Provides technique-specific detection strategies with IaC templates

### 1.2 Architecture Summary

```
┌─────────────────────────────────────────────────────────────────────┐
│                         INTERNET                                     │
└─────────────────────────────────────────────────────────────────────┘
                                │
                    ┌───────────┴───────────┐
                    │      CloudFront       │
                    │   (CDN + WAF + CSP)   │
                    └───────────┬───────────┘
                                │
          ┌─────────────────────┼─────────────────────┐
          │                     │                     │
          ▼                     ▼                     ▼
┌─────────────────┐   ┌─────────────────┐   ┌─────────────────┐
│  S3 (Frontend)  │   │   ALB + WAF     │   │    Cognito      │
│  Static Assets  │   │   (API Gateway) │   │   (SSO/OAuth)   │
└─────────────────┘   └────────┬────────┘   └─────────────────┘
                               │
                    ┌──────────┴──────────┐
                    │    ECS Fargate      │
                    │   (Backend API)     │
                    └──────────┬──────────┘
                               │
          ┌────────────────────┼────────────────────┐
          │                    │                    │
          ▼                    ▼                    ▼
┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐
│   RDS Postgres  │  │  ElastiCache    │  │  Secrets Mgr    │
│   (Database)    │  │  (Redis Cache)  │  │  (Credentials)  │
└─────────────────┘  └─────────────────┘  └─────────────────┘
                               │
          ┌────────────────────┴────────────────────┐
          │              CUSTOMER CLOUDS            │
          ▼                                         ▼
┌─────────────────┐                      ┌─────────────────┐
│   AWS Accounts  │                      │   GCP Projects  │
│  (via AssumeRole)                      │  (via WIF/SA)   │
└─────────────────┘                      └─────────────────┘
```

### 1.3 Trust Boundaries

| Boundary | Description |
|----------|-------------|
| **TB-1** | Internet to CloudFront/WAF |
| **TB-2** | CloudFront to Application Load Balancer |
| **TB-3** | ALB to ECS Fargate containers |
| **TB-4** | Application to Database/Cache |
| **TB-5** | Application to Customer Cloud Accounts (via AssumeRole/WIF) |
| **TB-6** | Application to Third-party Services (Stripe, OAuth providers) |

**Note:** A13E infrastructure runs in AWS Account 123080274263, Region eu-west-2.

### 1.4 Data Classification

| Classification | Examples | Protection Required |
|----------------|----------|---------------------|
| **Critical** | Cloud credentials, API keys, encryption keys | Encrypted at rest + transit, audit logged, MFA required |
| **Confidential** | User PII, scan results, detection mappings | Encrypted at rest + transit, access controlled |
| **Internal** | Audit logs, system metrics, configuration | Access controlled, retained per policy |
| **Public** | Marketing content, documentation | Integrity protection only |

---

## 2. STRIDE Threat Analysis

### 2.1 Spoofing Identity

#### T-S1: Credential Stuffing Attack
- **Target:** Authentication endpoints (`/auth/login`)
- **Attack Vector:** Automated attempts using breached credential lists
- **Impact:** Unauthorised account access
- **Likelihood:** High
- **Mitigations:**
  - ✅ Rate limiting (10 req/min per IP)
  - ✅ Account lockout after 5 failed attempts
  - ✅ MFA support (TOTP)
  - ✅ Breached password checking (HaveIBeenPwned k-anonymity API)
- **Residual Risk:** Low

#### T-S2: Session Hijacking via XSS
- **Target:** User sessions
- **Attack Vector:** XSS to steal tokens from localStorage
- **Impact:** Full account takeover
- **Likelihood:** Medium
- **Mitigations:**
  - ✅ Refresh tokens in httpOnly cookies
  - ✅ Access tokens in memory only (Zustand)
  - ✅ CSP headers (with documented exceptions)
  - ✅ Input sanitisation throughout
- **Residual Risk:** Low

#### T-S3: OAuth Account Linking Attack
- **Target:** SSO integration (GitHub, Google)
- **Attack Vector:** CSRF to link attacker's OAuth account
- **Impact:** Persistent unauthorised access
- **Likelihood:** Medium
- **Mitigations:**
  - ✅ State parameter validation
  - ✅ PKCE for Cognito flows
  - ✅ Email verification required
- **Residual Risk:** Low

#### T-S4: API Key Impersonation
- **Target:** API key authentication
- **Attack Vector:** Stolen or guessed API keys
- **Impact:** Unauthorised API access
- **Likelihood:** Medium
- **Mitigations:**
  - ✅ High-entropy key generation (24 bytes, rendered as 48 hex characters)
  - ✅ Key hashing before storage (SHA-256)
  - ✅ Scope-based permissions
  - ✅ IP allowlist support
  - ✅ Key rotation capability
- **Residual Risk:** Low

### 2.2 Tampering

#### T-T1: SQL Injection
- **Target:** Database queries
- **Attack Vector:** Malicious input in API parameters
- **Impact:** Data breach, data manipulation
- **Likelihood:** Low (ORM usage)
- **Mitigations:**
  - ✅ SQLAlchemy ORM (parameterised queries)
  - ✅ Pydantic input validation
  - ✅ No raw SQL queries
- **Residual Risk:** Very Low

#### T-T2: Request Tampering
- **Target:** API requests
- **Attack Vector:** MITM modification of requests
- **Impact:** Unauthorised actions
- **Likelihood:** Low
- **Mitigations:**
  - ✅ TLS 1.2+ everywhere
  - ✅ HSTS headers
  - ✅ Certificate pinning (CloudFront)
- **Residual Risk:** Very Low

#### T-T3: Cloud Credential Manipulation
- **Target:** Stored cloud credentials
- **Attack Vector:** Database compromise leading to credential theft
- **Impact:** Customer cloud account compromise
- **Likelihood:** Low
- **Mitigations:**
  - ✅ Credentials encrypted at rest (Fernet: AES-128-CBC + HMAC-SHA256)
  - ✅ Encryption key in Secrets Manager
  - ✅ Prefer AssumeRole/WIF over long-lived credentials
  - ✅ External ID for confused deputy prevention
- **Residual Risk:** Low

### 2.3 Repudiation

#### T-R1: Action Denial
- **Target:** Security-relevant actions
- **Attack Vector:** User denies performing action
- **Impact:** Accountability loss, compliance failure
- **Likelihood:** Medium
- **Mitigations:**
  - ✅ Comprehensive audit logging
  - ✅ Immutable log storage (CloudWatch)
  - ✅ IP address and user-agent capture
  - ✅ Timestamp with timezone
- **Residual Risk:** Low

#### T-R2: Log Tampering
- **Target:** Audit logs
- **Attack Vector:** Privileged user modifies logs
- **Impact:** Evidence destruction
- **Likelihood:** Low
- **Mitigations:**
  - ✅ Logs written to CloudWatch (append-only)
  - ✅ Log retention policies
  - ✅ Separate log access permissions
- **Residual Risk:** Low

### 2.4 Information Disclosure

#### T-I1: Database Breach
- **Target:** PostgreSQL database
- **Attack Vector:** SQL injection, credential theft, insider threat
- **Impact:** Mass data breach
- **Likelihood:** Low
- **Mitigations:**
  - ✅ Encryption at rest (AES-256)
  - ✅ VPC isolation (private subnets)
  - ✅ IAM database authentication
  - ✅ Automated backups with encryption
- **Residual Risk:** Low

#### T-I2: Credential Exposure in Logs
- **Target:** Application logs
- **Attack Vector:** Sensitive data written to logs
- **Impact:** Credential theft
- **Likelihood:** Medium
- **Mitigations:**
  - ✅ SecureLoggingMiddleware excludes sensitive endpoints
  - ✅ Structured logging with field filtering
  - ✅ No credential logging policy
- **Residual Risk:** Low

#### T-I3: Error Message Information Leakage
- **Target:** API error responses
- **Attack Vector:** Detailed errors reveal system internals
- **Impact:** Attack surface discovery
- **Likelihood:** Medium
- **Mitigations:**
  - ✅ Generic error messages in production
  - ✅ Detailed errors only in development
  - ✅ Stack traces never exposed
- **Residual Risk:** Low

#### T-I4: Scan Results Cross-Tenant Access
- **Target:** Multi-tenant scan data
- **Attack Vector:** IDOR or tenant isolation failure
- **Impact:** Cross-customer data breach
- **Likelihood:** Low
- **Mitigations:**
  - ✅ Organisation ID filtering on all queries
  - ✅ Authorisation checks on every endpoint
  - ✅ Row-level security patterns
- **Residual Risk:** Low

### 2.5 Denial of Service

#### T-D1: Application-Layer DDoS
- **Target:** API endpoints
- **Attack Vector:** High-volume API requests
- **Impact:** Service unavailability
- **Likelihood:** Medium
- **Mitigations:**
  - ✅ AWS WAF rate limiting (2000 req/5min)
  - ✅ CloudFront caching
  - ✅ Auto-scaling ECS tasks
  - ✅ Endpoint-specific rate limits
- **Residual Risk:** Medium

#### T-D2: Resource Exhaustion via Scanning
- **Target:** Scan processing
- **Attack Vector:** Triggering excessive scans
- **Impact:** Service degradation, cost escalation
- **Likelihood:** Medium
- **Mitigations:**
  - ✅ Scan rate limits per organisation
  - ✅ Subscription tier quotas
  - ✅ Background job queuing (SQS)
  - ✅ Scan timeout limits
- **Residual Risk:** Low

#### T-D3: Account Lockout Abuse
- **Target:** User accounts
- **Attack Vector:** Triggering lockouts for legitimate users
- **Impact:** Targeted user denial of service
- **Likelihood:** Low
- **Mitigations:**
  - ✅ Rate limiting by IP, not just account
  - ✅ Lockout duration limited (30 minutes)
  - ✅ Admin unlock capability
- **Residual Risk:** Low

### 2.6 Elevation of Privilege

#### T-E1: Vertical Privilege Escalation
- **Target:** Role-based access control
- **Attack Vector:** Exploiting RBAC bugs to gain admin access
- **Impact:** Full system compromise
- **Likelihood:** Low
- **Mitigations:**
  - ✅ Hierarchical role model (OWNER > ADMIN > MEMBER > VIEWER)
  - ✅ Role checks on every endpoint
  - ✅ Principle of least privilege
  - ✅ Separate admin authentication
- **Residual Risk:** Low

#### T-E2: Horizontal Privilege Escalation (Tenant Escape)
- **Target:** Organisation boundaries
- **Attack Vector:** Accessing another organisation's resources
- **Impact:** Cross-tenant data breach
- **Likelihood:** Low
- **Mitigations:**
  - ✅ Organisation context in JWT claims
  - ✅ Organisation ID validated on all requests
  - ✅ Database queries filtered by organisation
- **Residual Risk:** Low

#### T-E3: JWT Token Manipulation
- **Target:** Authentication tokens
- **Attack Vector:** Forging or modifying JWT claims
- **Impact:** Identity spoofing, privilege escalation
- **Likelihood:** Very Low
- **Mitigations:**
  - ✅ Strong secret key validation on startup
  - ✅ HS256 signature verification
  - ✅ Short token expiry (30 minutes)
  - ✅ Refresh token rotation
- **Residual Risk:** Very Low

---

## 3. Third-Party Risk Assessment

### 3.1 AWS Services

| Service | Data Handled | Risk Level | Mitigations |
|---------|--------------|------------|-------------|
| RDS PostgreSQL | All application data | High | Encryption, VPC isolation, IAM auth |
| Secrets Manager | Encryption keys, credentials | Critical | IAM policies, audit logging |
| Cognito | User identities | High | MFA, secure configuration |
| S3 | Frontend assets, backups | Medium | Encryption, versioning, access logging |
| CloudFront | Request routing | Low | WAF, TLS, access logging |

### 3.2 External Services

| Service | Purpose | Data Shared | Risk Level | Mitigations |
|---------|---------|-------------|------------|-------------|
| Stripe | Payment processing | Billing info, email | High | PCI DSS compliance, tokenisation |
| GitHub | OAuth authentication | Email, profile | Medium | Verified emails only, state validation |
| Google | OAuth authentication | Email, profile | Medium | Verified emails only, PKCE |

---

## 4. Attack Scenarios

### 4.1 Scenario: Compromised Developer Workstation

**Narrative:** An attacker compromises a developer's laptop containing AWS credentials.

**Attack Path:**
1. Phishing email delivers malware
2. Attacker extracts AWS credentials from `~/.aws/credentials`
3. Attacker attempts to access production infrastructure

**Mitigations:**
- ✅ Production secrets in Secrets Manager, not on workstations
- ✅ IAM roles with MFA requirement
- ✅ CloudTrail monitoring for unusual access
- ✅ Separate production AWS account
- ⚠️ Consider: Hardware security keys for privileged access

### 4.2 Scenario: Customer Cloud Credential Theft

**Narrative:** Attacker gains access to stored customer cloud credentials.

**Attack Path:**
1. Attacker exploits application vulnerability
2. Gains database read access
3. Extracts encrypted credentials
4. Attempts to decrypt credentials

**Mitigations:**
- ✅ Credentials encrypted with Fernet (AES-128-CBC + HMAC-SHA256)
- ✅ Encryption key stored in AWS Secrets Manager (separate from database)
- ✅ Prefer AWS IAM AssumeRole with External ID (confused deputy protection)
- ✅ Prefer GCP Workload Identity Federation (no long-lived keys)
- ✅ Limited credential permissions (read-only scanning)
- ✅ Audit logging of credential access

### 4.3 Scenario: Insider Threat - Malicious Administrator

**Narrative:** A privileged employee attempts to access customer data.

**Attack Path:**
1. Admin uses legitimate access to view customer scans
2. Exports data for personal gain
3. Attempts to cover tracks

**Mitigations:**
- ✅ Audit logging of all data access
- ✅ Logs stored in immutable CloudWatch
- ✅ Admin session re-authentication for sensitive actions
- ⚠️ Consider: Additional monitoring for bulk data exports
- ⚠️ Consider: Data Loss Prevention (DLP) tooling

---

## 5. Risk Matrix

| Risk ID | Threat | Likelihood | Impact | Risk Level | Status |
|---------|--------|------------|--------|------------|--------|
| T-S1 | Credential stuffing | High | High | High | Mitigated |
| T-S2 | Session hijacking | Medium | High | High | Mitigated |
| T-S3 | OAuth account linking | Medium | High | High | Mitigated |
| T-S4 | API key impersonation | Medium | Medium | Medium | Mitigated |
| T-T1 | SQL injection | Low | Critical | Medium | Mitigated |
| T-T3 | Credential manipulation | Low | Critical | High | Mitigated |
| T-I1 | Database breach | Low | Critical | High | Mitigated |
| T-I4 | Cross-tenant access | Low | Critical | High | Mitigated |
| T-D1 | Application DDoS | Medium | Medium | Medium | Partially Mitigated |
| T-E1 | Privilege escalation | Low | Critical | Medium | Mitigated |

---

## 6. Recommendations

### 6.1 Immediate Actions (Next Sprint)
- [x] Implement breached password checking (HaveIBeenPwned API) ✅ COMPLETED
- [ ] Add bulk export monitoring alerts

### 6.2 Short-Term (Next Quarter)
- [ ] Hardware security key support (WebAuthn/FIDO2)
- [ ] Data Loss Prevention (DLP) for scan exports
- [ ] Enhanced anomaly detection for authentication

### 6.3 Long-Term (Next Year)
- [ ] Zero-trust network architecture
- [ ] Customer-managed encryption keys (BYOK)
- [ ] SOC 2 Type II certification

---

## 7. Document Control

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2025-12-20 | Security Team | Initial threat model |

**Next Review Date:** 2026-03-20

---

*This document is confidential and intended for internal use only.*
