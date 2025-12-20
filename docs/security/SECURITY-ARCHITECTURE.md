# A13E Security Architecture

**Version:** 1.0
**Last Updated:** 2025-12-20
**Classification:** Internal

---

## 1. Overview

This document describes the security architecture of the A13E Detection Coverage Validator platform. It covers defence-in-depth layers, data protection, identity management, and security controls.

**Infrastructure Location:** AWS Account 123080274263, Region eu-west-2 (London)

---

## 2. High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              INTERNET                                        │
│                                                                              │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐        │
│  │   Users     │  │  API Keys   │  │ OAuth IdPs  │  │  Attackers  │        │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘        │
└─────────┼────────────────┼────────────────┼────────────────┼────────────────┘
          │                │                │                │
          ▼                ▼                ▼                ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         EDGE SECURITY LAYER                                  │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                      AWS CloudFront                                  │   │
│  │  • Global CDN with edge locations                                    │   │
│  │  • TLS 1.2+ termination                                             │   │
│  │  • DDoS protection (Shield Standard)                                │   │
│  │  • Geographic restrictions                                          │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                    │                                         │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                      AWS WAF                                         │   │
│  │  • OWASP Top 10 managed rules                                       │   │
│  │  • Rate limiting (2000 req/5min)                                    │   │
│  │  • SQL injection protection                                         │   │
│  │  • XSS protection                                                   │   │
│  │  • IP reputation blocking                                           │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                    │                                         │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                  Lambda@Edge (Security Headers)                      │   │
│  │  • Content-Security-Policy                                          │   │
│  │  • Strict-Transport-Security                                        │   │
│  │  • X-Frame-Options: DENY                                            │   │
│  │  • X-Content-Type-Options: nosniff                                  │   │
│  │  • Referrer-Policy                                                  │   │
│  │  • Permissions-Policy                                               │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
                                     │
                    ┌────────────────┴────────────────┐
                    ▼                                 ▼
┌─────────────────────────────────┐   ┌─────────────────────────────────────┐
│        FRONTEND (Static)        │   │         BACKEND (API)                │
│  ┌───────────────────────────┐  │   │  ┌─────────────────────────────────┐│
│  │      S3 Bucket            │  │   │  │     Application Load Balancer   ││
│  │  • Static hosting         │  │   │  │  • SSL termination              ││
│  │  • Versioning enabled     │  │   │  │  • Health checks                ││
│  │  • Access logging         │  │   │  │  • Target group routing         ││
│  │  • Public access blocked  │  │   │  └───────────────┬─────────────────┘│
│  └───────────────────────────┘  │   │                  │                  │
│                                  │   │  ┌───────────────▼─────────────────┐│
│  React SPA with:                │   │  │     ECS Fargate Cluster         ││
│  • Zustand (in-memory auth)    │   │  │  • Private subnet only           ││
│  • No localStorage tokens      │   │  │  • IAM task roles                ││
│  • CSRF token handling         │   │  │  • Secrets injection             ││
│                                  │   │  │  • Auto-scaling                 ││
│                                  │   │  │  • Container insights           ││
│                                  │   │  └───────────────┬─────────────────┘│
└─────────────────────────────────┘   │                  │                  │
                                       └──────────────────┼──────────────────┘
                                                          │
┌─────────────────────────────────────────────────────────┼───────────────────┐
│                         APPLICATION LAYER               │                    │
│                                                          │                    │
│  ┌──────────────────────────────────────────────────────▼────────────────┐  │
│  │                      FastAPI Application                               │  │
│  │                                                                        │  │
│  │  ┌────────────────┐  ┌────────────────┐  ┌────────────────┐          │  │
│  │  │  Rate Limiter  │  │  Auth Middleware│  │ CORS Middleware│          │  │
│  │  │  (per-endpoint)│  │  (JWT + Cookie) │  │ (strict origins)│         │  │
│  │  └────────────────┘  └────────────────┘  └────────────────┘          │  │
│  │                                                                        │  │
│  │  ┌────────────────┐  ┌────────────────┐  ┌────────────────┐          │  │
│  │  │ Secure Logging │  │  Input Valid.  │  │  RBAC Checks   │          │  │
│  │  │  (redaction)   │  │  (Pydantic)    │  │  (per-route)   │          │  │
│  │  └────────────────┘  └────────────────┘  └────────────────┘          │  │
│  │                                                                        │  │
│  └────────────────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────────────────┘
                                     │
┌────────────────────────────────────┼─────────────────────────────────────────┐
│                      DATA LAYER    │                                          │
│                                    │                                          │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │                        VPC (Private Subnets)                          │   │
│  │                                                                        │   │
│  │  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐       │   │
│  │  │  RDS PostgreSQL │  │   ElastiCache   │  │  Secrets Manager│       │   │
│  │  │                 │  │     (Redis)     │  │                 │       │   │
│  │  │  • Encrypted    │  │  • Encrypted    │  │  • Encryption   │       │   │
│  │  │    at rest      │  │    in transit   │  │    keys         │       │   │
│  │  │  • Multi-AZ     │  │  • Auth tokens  │  │  • DB creds     │       │   │
│  │  │  • IAM auth     │  │  • Session      │  │  • API keys     │       │   │
│  │  │  • Auto backup  │  │    cache        │  │  • OAuth secrets│       │   │
│  │  └─────────────────┘  └─────────────────┘  └─────────────────┘       │   │
│  │                                                                        │   │
│  └────────────────────────────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────────────────────────┘
                                     │
┌────────────────────────────────────┼─────────────────────────────────────────┐
│               EXTERNAL INTEGRATIONS│                                          │
│                                    │                                          │
│  ┌─────────────────┐  ┌────────────┴────────┐  ┌─────────────────┐          │
│  │  Customer AWS   │  │  Customer GCP       │  │  OAuth Providers │          │
│  │                 │  │                     │  │                  │          │
│  │  • AssumeRole   │  │  • Workload ID Fed  │  │  • GitHub        │          │
│  │  • External ID  │  │  • Service Account  │  │  • Google        │          │
│  │  • Read-only    │  │  • Limited scope    │  │                  │          │
│  └─────────────────┘  └─────────────────────┘  └─────────────────┘          │
│                                                                               │
│  ┌─────────────────┐  ┌─────────────────────┐                               │
│  │     Stripe      │  │     Email (SES)     │                               │
│  │                 │  │                     │                               │
│  │  • PCI DSS      │  │  • Verified domain  │                               │
│  │  • Tokenisation │  │  • DKIM/SPF         │                               │
│  └─────────────────┘  └─────────────────────┘                               │
└──────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Authentication Architecture

### 3.1 Authentication Flow

```
┌─────────┐                  ┌─────────┐                  ┌─────────┐
│ Browser │                  │ Backend │                  │   DB    │
└────┬────┘                  └────┬────┘                  └────┬────┘
     │                            │                            │
     │  1. POST /auth/login       │                            │
     │  {email, password}         │                            │
     │ ─────────────────────────► │                            │
     │                            │  2. Verify credentials     │
     │                            │ ─────────────────────────► │
     │                            │                            │
     │                            │  3. User + hash            │
     │                            │ ◄───────────────────────── │
     │                            │                            │
     │                            │  4. bcrypt.verify()        │
     │                            │                            │
     │  5. Set-Cookie:            │                            │
     │     dcv_refresh_token      │                            │
     │     (httpOnly, Secure)     │                            │
     │                            │                            │
     │  6. Set-Cookie:            │                            │
     │     dcv_csrf_token         │                            │
     │     (JS readable)          │                            │
     │                            │                            │
     │  7. Response:              │                            │
     │     {access_token, user}   │                            │
     │ ◄───────────────────────── │                            │
     │                            │                            │
     │  8. Store access_token     │                            │
     │     in Zustand (memory)    │                            │
     │                            │                            │
```

### 3.2 Token Refresh Flow

```
┌─────────┐                  ┌─────────┐                  ┌─────────┐
│ Browser │                  │ Backend │                  │   DB    │
└────┬────┘                  └────┬────┘                  └────┬────┘
     │                            │                            │
     │  1. Access token expired   │                            │
     │                            │                            │
     │  2. POST /auth/refresh-session                          │
     │     Cookie: dcv_refresh_token (automatic)               │
     │     Header: X-CSRF-Token (from JS)                      │
     │ ─────────────────────────► │                            │
     │                            │                            │
     │                            │  3. Validate CSRF          │
     │                            │     (header == cookie)     │
     │                            │                            │
     │                            │  4. Validate refresh token │
     │                            │ ─────────────────────────► │
     │                            │                            │
     │                            │  5. Rotate refresh token   │
     │                            │ ─────────────────────────► │
     │                            │                            │
     │  6. New cookies set        │                            │
     │  7. New access_token       │                            │
     │ ◄───────────────────────── │                            │
     │                            │                            │
```

### 3.3 Token Security Properties

| Token Type | Storage | Lifetime | XSS Protected | CSRF Protected |
|------------|---------|----------|---------------|----------------|
| Access Token | Memory (Zustand) | 30 min | Partially (not in localStorage) | N/A |
| Refresh Token | httpOnly Cookie | 7 days (configurable) | Yes | Yes (double-submit) |
| CSRF Token | JS-readable Cookie | Same as refresh | No (by design) | N/A |
| MFA Token | Memory | 5 min | Yes | N/A |

---

## 4. Authorisation Architecture

### 4.1 Role-Based Access Control (RBAC)

```
┌─────────────────────────────────────────────────────────────────┐
│                      PERMISSION HIERARCHY                        │
│                                                                  │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │                       OWNER                              │    │
│  │  • All permissions                                       │    │
│  │  • Transfer ownership                                    │    │
│  │  • Delete organisation                                   │    │
│  │  • Manage billing                                        │    │
│  │  ┌─────────────────────────────────────────────────┐    │    │
│  │  │                    ADMIN                         │    │    │
│  │  │  • Manage members                               │    │    │
│  │  │  • Manage cloud accounts                        │    │    │
│  │  │  • Configure organisation settings              │    │    │
│  │  │  • View all data                                │    │    │
│  │  │  ┌─────────────────────────────────────────┐   │    │    │
│  │  │  │               MEMBER                     │   │    │    │
│  │  │  │  • Run scans                            │   │    │    │
│  │  │  │  • View scan results                    │   │    │    │
│  │  │  │  • Manage assigned accounts             │   │    │    │
│  │  │  │  ┌─────────────────────────────────┐   │   │    │    │
│  │  │  │  │            VIEWER               │   │   │    │    │
│  │  │  │  │  • View scan results            │   │   │    │    │
│  │  │  │  │  • View dashboards              │   │   │    │    │
│  │  │  │  │  • Read-only access             │   │   │    │    │
│  │  │  │  └─────────────────────────────────┘   │   │    │    │
│  │  │  └─────────────────────────────────────────┘   │    │    │
│  │  └─────────────────────────────────────────────────┘    │    │
│  └─────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────┘
```

### 4.2 Authorisation Check Flow

```python
# Every API endpoint follows this pattern:

@router.get("/accounts")
async def list_accounts(
    auth: AuthContext = Depends(get_auth_context),  # 1. Extract auth
    db: AsyncSession = Depends(get_db),
):
    # 2. Verify authentication
    if not auth.user:
        raise HTTPException(401, "Not authenticated")

    # 3. Verify organisation membership
    if not auth.membership:
        raise HTTPException(403, "No organisation access")

    # 4. Verify role permission
    if auth.membership.role not in [UserRole.OWNER, UserRole.ADMIN, UserRole.MEMBER]:
        raise HTTPException(403, "Insufficient permissions")

    # 5. Query with organisation filter (tenant isolation)
    accounts = await db.execute(
        select(CloudAccount).where(
            CloudAccount.organisation_id == auth.membership.organisation_id
        )
    )

    return accounts.scalars().all()
```

---

## 5. Data Protection

### 5.1 Encryption Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                    DATA ENCRYPTION LAYERS                        │
│                                                                  │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │                  IN TRANSIT (TLS 1.2+)                   │    │
│  │                                                          │    │
│  │  Internet ←──TLS──→ CloudFront ←──TLS──→ ALB ←──TLS──→ App   │
│  │                                                          │    │
│  │  App ←──TLS──→ RDS    App ←──TLS──→ Redis                │    │
│  │                                                          │    │
│  └─────────────────────────────────────────────────────────┘    │
│                                                                  │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │                   AT REST (AES-256)                      │    │
│  │                                                          │    │
│  │  RDS: AWS-managed encryption (KMS)                       │    │
│  │  S3:  AWS-managed encryption (KMS)                       │    │
│  │  EBS: AWS-managed encryption (KMS)                       │    │
│  │                                                          │    │
│  └─────────────────────────────────────────────────────────┘    │
│                                                                  │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │              APPLICATION-LEVEL ENCRYPTION                │    │
│  │                                                          │    │
│  │  Cloud Credentials: Fernet (AES-128-CBC + HMAC-SHA256)  │    │
│  │  Key stored in: AWS Secrets Manager                      │    │
│  │                                                          │    │
│  │  Passwords: bcrypt with 12 rounds (cost factor)          │    │
│  │  MFA Backup Codes: bcrypt with 12 rounds                │    │
│  │  API Keys: SHA-256 hash (24-byte high-entropy keys)      │    │
│  │                                                          │    │
│  └─────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────┘
```

### 5.2 Sensitive Data Handling

| Data Type | Storage | Encryption | Access Control | Retention |
|-----------|---------|------------|----------------|-----------|
| Passwords | PostgreSQL | bcrypt hash (12 rounds) | N/A (hashed) | Until deletion |
| Refresh Tokens | PostgreSQL | SHA-256 hash | User session | 7 days (configurable) |
| API Keys | PostgreSQL | SHA-256 hash | Organisation | Until revoked |
| AWS Credentials | PostgreSQL | Fernet (AES) | Organisation | Until deleted |
| GCP Service Keys | PostgreSQL | Fernet (AES) | Organisation | Until deleted |
| Scan Results | PostgreSQL | RDS encryption | Organisation | Per policy |
| Audit Logs | CloudWatch | CloudWatch encryption | Admin only | 1 year |

---

## 6. Network Security

### 6.1 Network Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                              AWS VPC                                     │
│                           (10.0.0.0/16)                                 │
│                                                                          │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │                    PUBLIC SUBNETS                                │   │
│  │                  (10.0.1.0/24, 10.0.2.0/24)                     │   │
│  │                                                                  │   │
│  │  ┌─────────────────┐  ┌─────────────────┐  ┌───────────────┐   │   │
│  │  │  NAT Gateway    │  │  NAT Gateway    │  │  ALB          │   │   │
│  │  │  (AZ-1)         │  │  (AZ-2)         │  │               │   │   │
│  │  └─────────────────┘  └─────────────────┘  └───────────────┘   │   │
│  │                                                                  │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                          │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │                   PRIVATE SUBNETS                                │   │
│  │                 (10.0.10.0/24, 10.0.11.0/24)                    │   │
│  │                                                                  │   │
│  │  ┌─────────────────┐  ┌─────────────────┐  ┌───────────────┐   │   │
│  │  │  ECS Fargate    │  │  RDS Primary    │  │  RDS Standby  │   │   │
│  │  │  Tasks          │  │  (AZ-1)         │  │  (AZ-2)       │   │   │
│  │  └─────────────────┘  └─────────────────┘  └───────────────┘   │   │
│  │                                                                  │   │
│  │  ┌─────────────────┐  ┌─────────────────┐                       │   │
│  │  │  ElastiCache    │  │  ElastiCache    │                       │   │
│  │  │  (AZ-1)         │  │  (AZ-2)         │                       │   │
│  │  └─────────────────┘  └─────────────────┘                       │   │
│  │                                                                  │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

### 6.2 Security Groups

| Security Group | Inbound | Outbound | Purpose |
|----------------|---------|----------|---------|
| ALB SG | 443 from 0.0.0.0/0 | All to ECS SG | Load balancer |
| ECS SG | 8000 from ALB SG | All (NAT) | Application containers |
| RDS SG | 5432 from ECS SG | None | Database |
| Redis SG | 6379 from ECS SG | None | Cache |

---

## 7. Monitoring and Detection

### 7.1 Security Monitoring Stack

```
┌─────────────────────────────────────────────────────────────────┐
│                    SECURITY MONITORING                           │
│                                                                  │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │                   DATA SOURCES                           │    │
│  │                                                          │    │
│  │  • CloudTrail (API activity)                            │    │
│  │  • VPC Flow Logs (network traffic)                      │    │
│  │  • ALB Access Logs                                      │    │
│  │  • WAF Logs                                             │    │
│  │  • Application Logs (structlog)                         │    │
│  │  • RDS Audit Logs                                       │    │
│  │                                                          │    │
│  └─────────────────────────────────────────────────────────┘    │
│                            │                                     │
│                            ▼                                     │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │                  CLOUDWATCH LOGS                         │    │
│  │                                                          │    │
│  │  • Centralised log aggregation                          │    │
│  │  • Log retention (1 year)                               │    │
│  │  • Metric filters                                       │    │
│  │  • Log Insights queries                                 │    │
│  │                                                          │    │
│  └─────────────────────────────────────────────────────────┘    │
│                            │                                     │
│                            ▼                                     │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │                  ALERTING                                │    │
│  │                                                          │    │
│  │  • CloudWatch Alarms                                    │    │
│  │  • SNS Notifications                                    │    │
│  │  • GuardDuty findings                                   │    │
│  │  • Security Hub aggregation                             │    │
│  │                                                          │    │
│  └─────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────┘
```

### 7.2 Key Security Alerts

| Alert | Trigger | Severity | Response |
|-------|---------|----------|----------|
| Failed login spike | >50 failed logins/5min | High | Investigate source IPs |
| WAF block rate | >100 blocks/min | Medium | Review WAF rules |
| Unusual API key usage | New IP for API key | Medium | Verify with customer |
| Database connection spike | >100 connections | High | Check for attacks |
| Admin action | Any admin panel action | Info | Audit log review |

---

## 8. Compliance Controls

### 8.1 SOC 2 Control Mapping

| Control Area | Control | Implementation |
|--------------|---------|----------------|
| CC6.1 | Logical access | RBAC, MFA, session management |
| CC6.2 | Authentication | JWT + httpOnly cookies, bcrypt |
| CC6.3 | Authorisation | Role hierarchy, organisation isolation |
| CC6.6 | Encryption | TLS 1.2+, AES-256, Fernet |
| CC6.7 | Transmission security | TLS everywhere, HSTS |
| CC7.1 | Change management | GitHub PRs, CI/CD pipeline |
| CC7.2 | Vulnerability management | Dependabot, security scanning |

---

## 9. Document Control

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2025-12-20 | Security Team | Initial architecture |

---

*This document is confidential and intended for internal use only.*
