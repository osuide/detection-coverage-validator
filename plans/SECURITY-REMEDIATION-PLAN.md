# Security Remediation Plan

**Created:** 2025-12-21
**Updated:** 2025-12-21
**Framework:** Master Orchestrator Chain-of-Thought Methodology
**Source:** SECURITY-AUDIT-REPORT.md
**Status:** Ready for Implementation

---

## Executive Summary

This plan addresses **6 Critical**, **11 High**, and **14 Medium** security findings from the security audit. Each remediation follows the Chain-of-Thought process: validate the issue, reason through solutions, implement with validation criteria.

### Risk Acceptance Decisions

| Item | Decision | Rationale |
|------|----------|-----------|
| H3: NAT Gateway | **Deferred to Backlog** | ~$40-50/month cost; ECS in public subnets acceptable with existing security groups + WAF |
| M6: Customer-Managed KMS | **Risk Accepted** | AWS managed keys provide adequate encryption; CMK adds minimal security value for ~$1/month |

### Priority Matrix

| Priority | Category | Items | Estimated Effort | Monthly Cost |
|----------|----------|-------|------------------|--------------|
| P0 | Critical - Must fix before production | 6 | ~8 hours | $0 |
| P1 | High - Fix within sprint | 11 | ~10 hours | ~$6-18 (VPC Flow Logs) |
| P2 | Medium - Fix within release | 14 | ~8 hours | $0 |
| P3 | Low - Track and plan | 8 | Deferred | - |
| P4 | Info - Best practices | 5 | Deferred | - |
| **Backlog** | Deferred | 2 | When revenue justifies | ~$40-50 (NAT Gateway) |

**Total Estimated Cost:** ~$6-18/month (VPC Flow Logs only)

---

## Phase 1: Critical Fixes (P0)

### C1: In-Memory Rate Limiter
**Location:** `backend/app/api/routes/auth.py:52-77`
**Validation:** ✅ Confirmed - RateLimiter class uses in-memory defaultdict

#### Chain-of-Thought

**Reasoning:**
- Current implementation uses `defaultdict` to store request timestamps
- Each ECS container instance maintains separate state
- In load-balanced deployment, attackers can bypass by hitting different instances
- Rate limiting warning already exists (line 63-73) but doesn't solve the problem

**Solution Options:**
1. Redis-backed rate limiting with `fastapi-limiter` ← **Recommended**
2. AWS WAF rate limiting rules (coarser, per-IP only)
3. API Gateway throttling (requires architecture change)

**Decision:** Option 1 - Redis-backed with `fastapi-limiter`

#### Implementation

```python
# backend/app/api/deps/rate_limit.py (new file)
from fastapi import Request, HTTPException
from fastapi_limiter import FastAPILimiter
from fastapi_limiter.depends import RateLimiter
import aioredis

async def init_rate_limiter(redis_url: str):
    """Initialise Redis-backed rate limiter."""
    redis = await aioredis.from_url(redis_url, encoding="utf-8", decode_responses=True)
    await FastAPILimiter.init(redis)

# Create reusable dependencies
auth_rate_limit = RateLimiter(times=10, seconds=60)  # 10 requests per minute
signup_rate_limit = RateLimiter(times=5, seconds=300)  # 5 per 5 minutes
password_reset_rate_limit = RateLimiter(times=3, seconds=3600)  # 3 per hour
```

```python
# Update backend/app/main.py startup
@app.on_event("startup")
async def startup():
    from app.api.deps.rate_limit import init_rate_limiter
    await init_rate_limiter(settings.redis_url)
```

```python
# Update backend/app/api/routes/auth.py
from app.api.deps.rate_limit import auth_rate_limit, signup_rate_limit

@router.post("/login", dependencies=[Depends(auth_rate_limit)])
async def login(...):
    ...

@router.post("/signup", dependencies=[Depends(signup_rate_limit)])
async def signup(...):
    ...
```

#### Validation Criteria
- [ ] `fastapi-limiter` added to requirements.txt
- [ ] Rate limiter initialised on startup
- [ ] Login endpoint limited to 10/minute
- [ ] Signup endpoint limited to 5/5-minutes
- [ ] Test: Multiple rapid requests from same IP get 429
- [ ] Test: Rate limits persist across container restarts
- [ ] Remove old in-memory RateLimiter class

---

### C2: Hardcoded Admin Password
**Location:** `backend/app/main.py:271-272`
**Validation:** ✅ Confirmed - Password hash for 'A13eSecurePwd2025S' in source code

#### Chain-of-Thought

**Reasoning:**
- Current implementation has bcrypt hash of known password
- Password visible in version control history forever
- `requires_password_change=true` mitigates but doesn't eliminate risk
- Only runs in staging/production (not dev) - reduces exposure

**Solution Options:**
1. Generate random password on first seed, log once ← **Recommended**
2. Use environment variable for initial password
3. Require manual admin creation via CLI

**Decision:** Option 1 + Option 2 hybrid - check env var first, generate if not set

#### Implementation

```python
# backend/app/main.py - Replace lines 267-305
def _seed_admin_user():
    """Seed initial admin user with secure password generation."""
    import secrets
    import bcrypt

    settings = get_settings()
    if settings.environment == "development":
        logger.info("skip_admin_seed", reason="development environment")
        return

    try:
        database_url = settings.database_url.replace("+asyncpg", "")
        engine = create_engine(database_url)

        with engine.connect() as conn:
            result = conn.execute(
                text("SELECT id FROM admin_users WHERE email = :email"),
                {"email": "admin@a13e.com"},
            )
            existing = result.fetchone()

            if existing:
                logger.info("admin_user_exists", email="admin@a13e.com")
                return

            # Check for environment variable first
            admin_password = os.environ.get("INITIAL_ADMIN_PASSWORD")

            if not admin_password:
                # Generate cryptographically secure password
                admin_password = secrets.token_urlsafe(16)
                logger.critical(
                    "generated_initial_admin_password",
                    password=admin_password,
                    message="SAVE THIS PASSWORD - it will not be shown again"
                )

            password_hash = bcrypt.hashpw(
                admin_password.encode(),
                bcrypt.gensalt(12)
            ).decode()

            from uuid import uuid4
            admin_id = uuid4()

            conn.execute(
                text("""
                    INSERT INTO admin_users (
                        id, email, password_hash, role, full_name,
                        mfa_enabled, is_active, failed_login_attempts,
                        requires_password_change
                    ) VALUES (
                        :id, :email, :password_hash, 'super_admin', 'System Administrator',
                        false, true, 0, true
                    )
                """),
                {
                    "id": str(admin_id),
                    "email": "admin@a13e.com",
                    "password_hash": password_hash,
                },
            )
            conn.commit()
            logger.info("admin_user_seeded", email="admin@a13e.com", id=str(admin_id))

    except Exception as e:
        logger.error("admin_seed_error", error=str(e))
```

#### Validation Criteria
- [ ] No hardcoded password hash in source code
- [ ] Password generated randomly if env var not set
- [ ] Password logged once on first seed only
- [ ] `requires_password_change=true` still enforced
- [ ] Test: Fresh deployment generates unique password
- [ ] Test: INITIAL_ADMIN_PASSWORD env var is respected

---

### C3: Overly Permissive Database Security Group
**Location:** `infrastructure/terraform/modules/database/main.tf:34`
**Validation:** ✅ Confirmed - `cidr_blocks = ["10.0.0.0/8"]`

#### Chain-of-Thought

**Reasoning:**
- Current: Any resource in 10.0.0.0/8 can access PostgreSQL
- VPC CIDR is 10.0.0.0/16, so this is 256x too permissive
- Attacker with foothold in VPC can access database directly
- Should restrict to only ECS security group

**Solution:** Use `source_security_group_id` instead of CIDR

#### Implementation

```hcl
# infrastructure/terraform/modules/database/main.tf

variable "ecs_security_group_id" {
  description = "Security group ID of ECS tasks that need database access"
  type        = string
}

resource "aws_security_group" "rds" {
  name        = "dcv-${var.environment}-rds-sg"
  description = "Security group for RDS database"
  vpc_id      = var.vpc_id

  # Only allow access from ECS containers
  ingress {
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [var.ecs_security_group_id]
    description     = "PostgreSQL from ECS tasks only"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "dcv-${var.environment}-db-sg"
  }
}
```

```hcl
# infrastructure/terraform/main.tf - Update module call
module "database" {
  source = "./modules/database"
  # ... existing vars
  ecs_security_group_id = module.backend.ecs_security_group_id
}
```

#### Validation Criteria
- [ ] Security group uses `security_groups` not `cidr_blocks`
- [ ] Only ECS security group can access RDS
- [ ] Terraform plan shows security group update
- [ ] Test: ECS can still connect to database
- [ ] Test: Other VPC resources cannot connect to RDS on port 5432

---

### C4: Overly Permissive Redis Security Group
**Location:** `infrastructure/terraform/modules/cache/main.tf:25`
**Validation:** ✅ Confirmed - `cidr_blocks = ["10.0.0.0/8"]`

#### Chain-of-Thought

**Reasoning:**
- Same issue as database security group
- Redis contains session data, rate limit state, cached responses
- Attacker with VPC access could read/modify sessions
- Should restrict to only ECS security group

**Solution:** Use `source_security_group_id` instead of CIDR

#### Implementation

```hcl
# infrastructure/terraform/modules/cache/main.tf

variable "ecs_security_group_id" {
  description = "Security group ID of ECS tasks that need Redis access"
  type        = string
}

resource "aws_security_group" "redis" {
  name        = "dcv-${var.environment}-redis-sg"
  description = "Security group for Redis cache"
  vpc_id      = var.vpc_id

  ingress {
    from_port       = 6379
    to_port         = 6379
    protocol        = "tcp"
    security_groups = [var.ecs_security_group_id]
    description     = "Redis from ECS tasks only"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "dcv-${var.environment}-redis-sg"
  }
}
```

#### Validation Criteria
- [ ] Security group uses `security_groups` not `cidr_blocks`
- [ ] Only ECS security group can access Redis
- [ ] Terraform plan shows security group update
- [ ] Test: ECS can still connect to Redis
- [ ] Test: Rate limiting still works

---

### C5: Missing Security Headers
**Location:** `backend/app/main.py:44-95`
**Validation:** ✅ Confirmed - Only SecureLoggingMiddleware exists, no security headers

#### Chain-of-Thought

**Reasoning:**
- Lambda@Edge adds headers for CloudFront (frontend)
- API responses do NOT have security headers
- Missing: X-Frame-Options, X-Content-Type-Options, X-XSS-Protection, HSTS
- FastAPI/Starlette needs middleware for this

**Solution:** Add SecurityHeadersMiddleware to FastAPI

#### Implementation

```python
# backend/app/middleware/security_headers.py (new file)
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add security headers to all responses."""

    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)

        # Prevent clickjacking
        response.headers["X-Frame-Options"] = "DENY"

        # Prevent MIME-type sniffing
        response.headers["X-Content-Type-Options"] = "nosniff"

        # XSS protection (legacy but still useful)
        response.headers["X-XSS-Protection"] = "1; mode=block"

        # HSTS - enforce HTTPS
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains; preload"
        )

        # Content Security Policy for API
        response.headers["Content-Security-Policy"] = (
            "default-src 'none'; frame-ancestors 'none'"
        )

        # Referrer policy
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

        # Permissions policy
        response.headers["Permissions-Policy"] = (
            "accelerometer=(), camera=(), geolocation=(), gyroscope=(), "
            "magnetometer=(), microphone=(), payment=(), usb=()"
        )

        return response
```

```python
# backend/app/main.py - Add after SecureLoggingMiddleware
from app.middleware.security_headers import SecurityHeadersMiddleware

app.add_middleware(SecurityHeadersMiddleware)
```

#### Validation Criteria
- [ ] SecurityHeadersMiddleware created
- [ ] Middleware added to FastAPI app
- [ ] Test: Response includes X-Frame-Options: DENY
- [ ] Test: Response includes X-Content-Type-Options: nosniff
- [ ] Test: Response includes Strict-Transport-Security header
- [ ] Test: CSP header present on API responses

---

### C6: Secrets Manager Wildcard Access
**Location:** `infrastructure/terraform/modules/backend/main.tf:411-413`
**Validation:** ✅ Confirmed - `Resource = "*"` for secretsmanager:GetSecretValue

#### Chain-of-Thought

**Reasoning:**
- Current: ECS task role can read ANY secret in AWS account
- Should only need access to A13E-specific secrets
- Pattern: `arn:aws:secretsmanager:*:*:secret:a13e/${environment}/*`
- Attacker compromising container can exfiltrate all secrets

**Solution:** Restrict to environment-specific secret prefix

#### Implementation

```hcl
# infrastructure/terraform/modules/backend/main.tf

# Replace the secretsmanager statement (around line 408-414)
{
  Sid    = "ReadA13ESecrets"
  Effect = "Allow"
  Action = [
    "secretsmanager:GetSecretValue"
  ]
  Resource = [
    "arn:aws:secretsmanager:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:secret:a13e/${var.environment}/*"
  ]
}
```

```hcl
# Also need to ensure secrets use this prefix
# infrastructure/terraform/modules/backend/main.tf (secrets section)

resource "aws_secretsmanager_secret" "database_url" {
  name = "a13e/${var.environment}/database-url"  # Use prefix
  # ...
}
```

#### Validation Criteria
- [ ] IAM policy restricts to `a13e/${environment}/*` prefix
- [ ] All A13E secrets use the correct naming prefix
- [ ] Terraform plan shows IAM policy update
- [ ] Test: ECS can still read required secrets
- [ ] Test: ECS cannot read secrets outside prefix (if any exist)

---

## Phase 2: High Priority Fixes (P1)

### H1: VPC Flow Logs Not Enabled
**Location:** `infrastructure/terraform/modules/vpc/main.tf:18-26`
**Validation:** ✅ Confirmed - No flow log resource exists
**Cost:** ~$6-18/month (CloudWatch Logs)

#### Implementation

```hcl
# infrastructure/terraform/modules/vpc/main.tf

# CloudWatch log group for VPC flow logs
resource "aws_cloudwatch_log_group" "vpc_flow_logs" {
  name              = "/aws/vpc/a13e-${var.environment}-flow-logs"
  retention_in_days = 30

  tags = {
    Name = "a13e-${var.environment}-vpc-flow-logs"
  }
}

# IAM role for VPC flow logs
resource "aws_iam_role" "vpc_flow_logs" {
  name = "a13e-${var.environment}-vpc-flow-logs-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "vpc-flow-logs.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy" "vpc_flow_logs" {
  name = "a13e-${var.environment}-vpc-flow-logs-policy"
  role = aws_iam_role.vpc_flow_logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogGroups",
          "logs:DescribeLogStreams"
        ]
        Effect   = "Allow"
        Resource = "*"
      }
    ]
  })
}

# VPC Flow Logs
resource "aws_flow_log" "main" {
  vpc_id                   = aws_vpc.main.id
  traffic_type             = "ALL"
  log_destination_type     = "cloud-watch-logs"
  log_destination          = aws_cloudwatch_log_group.vpc_flow_logs.arn
  iam_role_arn             = aws_iam_role.vpc_flow_logs.arn

  tags = {
    Name = "a13e-${var.environment}-vpc-flow-logs"
  }
}
```

#### Validation Criteria
- [ ] Flow logs CloudWatch log group created
- [ ] IAM role for flow logs created
- [ ] VPC flow log resource created
- [ ] Terraform apply succeeds
- [ ] Test: Flow logs appear in CloudWatch within 5 minutes

---

### H2: Redis Encryption Not Enabled
**Location:** `infrastructure/terraform/modules/cache/main.tf:45-60`
**Validation:** ✅ Confirmed - No encryption settings
**Cost:** $0 (included in ElastiCache)

#### Implementation

```hcl
# infrastructure/terraform/modules/cache/main.tf

resource "aws_elasticache_cluster" "main" {
  cluster_id           = "dcv-${var.environment}-redis"
  engine               = "redis"
  engine_version       = "7.0"
  node_type            = var.node_type
  num_cache_nodes      = 1
  parameter_group_name = "default.redis7"
  port                 = 6379

  subnet_group_name  = aws_elasticache_subnet_group.main.name
  security_group_ids = [aws_security_group.redis.id]

  # Enable encryption at rest
  at_rest_encryption_enabled = true

  # Enable encryption in transit
  transit_encryption_enabled = true

  tags = {
    Name = "dcv-${var.environment}-redis"
  }
}
```

**Note:** Enabling encryption may require cluster replacement. Plan accordingly.

#### Validation Criteria
- [ ] `at_rest_encryption_enabled = true` added
- [ ] `transit_encryption_enabled = true` added
- [ ] Terraform plan reviewed for replacement
- [ ] Cluster recreated with encryption (if required)
- [ ] Test: Application can still connect to Redis
- [ ] Test: Connection uses TLS (verify with redis-cli --tls)

---

### H3: JWT Algorithm Not Explicitly Restricted
**Location:** `backend/app/core/security.py:42`

#### Implementation

```python
# backend/app/core/security.py

# When decoding JWT, explicitly specify algorithms
payload = jwt.decode(
    token,
    settings.secret_key,
    algorithms=["HS256"],  # Explicitly restrict to HS256
    options={"verify_exp": True}
)
```

#### Validation Criteria
- [ ] `algorithms=["HS256"]` added to jwt.decode()
- [ ] Test: Valid HS256 tokens work
- [ ] Test: Tokens with algorithm=none are rejected
- [ ] Test: Tokens with algorithm=HS512 are rejected

---

### H4: Inconsistent CSRF Validation
**Location:** `backend/app/api/routes/auth.py:629-689` vs `auth.py:692`

#### Implementation

Create a CSRF validation dependency and apply consistently:

```python
# backend/app/api/deps/csrf.py

from fastapi import Request, HTTPException
import hmac

async def validate_csrf(request: Request):
    """Validate CSRF token for cookie-authenticated requests."""
    # Only validate for state-changing methods
    if request.method in ("GET", "HEAD", "OPTIONS"):
        return

    # Get tokens
    cookie_token = request.cookies.get("csrf_token")
    header_token = request.headers.get("X-CSRF-Token")

    if not cookie_token or not header_token:
        raise HTTPException(status_code=403, detail="CSRF token missing")

    # Constant-time comparison
    if not hmac.compare_digest(cookie_token, header_token):
        raise HTTPException(status_code=403, detail="CSRF token mismatch")
```

Apply to all cookie-authenticated endpoints.

#### Validation Criteria
- [ ] CSRF dependency created with constant-time comparison
- [ ] All POST/PUT/DELETE endpoints with cookies have CSRF
- [ ] Test: Request without CSRF token returns 403
- [ ] Test: Request with mismatched token returns 403
- [ ] Test: Request with valid token succeeds

---

### H5: No Exponential Backoff on Lockout
**Location:** `backend/app/services/auth_service.py:212-213`

#### Implementation

```python
# backend/app/services/auth_service.py

def calculate_lockout_duration(failed_attempts: int) -> int:
    """Calculate lockout duration with exponential backoff.

    Returns lockout duration in seconds.
    - 5 failures: 1 minute
    - 10 failures: 4 minutes
    - 15 failures: 16 minutes
    - ...capped at 24 hours
    """
    if failed_attempts < 5:
        return 0

    # 2^((attempts - 5) / 5) minutes, capped at 1440 minutes (24 hours)
    exponent = (failed_attempts - 5) // 5
    minutes = min(2 ** exponent, 1440)
    return minutes * 60
```

#### Validation Criteria
- [ ] Exponential backoff implemented
- [ ] Maximum lockout capped at 24 hours
- [ ] Lockout duration stored in database
- [ ] Test: 5 failures = 1 minute lockout
- [ ] Test: 15 failures = 16 minute lockout
- [ ] Test: Lockout resets after successful login

---

### H6: Raw SQL in Seeding Functions
**Location:** `backend/app/main.py:145, 169, 209, 220, 276, 289`
**Validation:** ✅ Confirmed - Uses `text()` queries

#### Implementation

Replace raw SQL with SQLAlchemy ORM operations where possible:

```python
# Example - Replace raw SQL admin check
# Before:
result = conn.execute(
    text("SELECT id FROM admin_users WHERE email = :email"),
    {"email": "admin@a13e.com"},
)

# After:
from app.models.admin_user import AdminUser
result = db.query(AdminUser).filter(AdminUser.email == "admin@a13e.com").first()
```

For seeding that runs before models are available, keep parameterised queries but ensure no user input is interpolated.

#### Validation Criteria
- [ ] All seeding uses parameterised queries only
- [ ] No string interpolation in SQL
- [ ] ORM used where possible
- [ ] Test: Seeding still works after changes

---

### H7: File Upload Size Check After Reading
**Location:** `backend/app/api/routes/custom_detections.py:169-183`

#### Implementation

```python
# backend/app/api/routes/custom_detections.py

from fastapi import UploadFile, HTTPException

MAX_UPLOAD_SIZE = 1 * 1024 * 1024  # 1MB

async def validate_file_size(file: UploadFile) -> bytes:
    """Read file with size validation to prevent memory exhaustion."""
    contents = b""
    chunk_size = 8192

    while True:
        chunk = await file.read(chunk_size)
        if not chunk:
            break
        contents += chunk
        if len(contents) > MAX_UPLOAD_SIZE:
            raise HTTPException(
                status_code=413,
                detail=f"File too large. Maximum size is {MAX_UPLOAD_SIZE // 1024}KB"
            )

    return contents
```

#### Validation Criteria
- [ ] Streaming read with size check implemented
- [ ] Size check happens during read, not after
- [ ] 413 returned for oversized files
- [ ] Test: 500KB file uploads successfully
- [ ] Test: 2MB file returns 413 without consuming full memory

---

### H8: Path Traversal in Report Filenames
**Location:** `backend/app/api/routes/reports.py:56, 86, 114, 160, 205`

#### Implementation

```python
# backend/app/api/routes/reports.py

import re

def sanitise_filename(name: str) -> str:
    """Sanitise filename to prevent header injection and path traversal."""
    # Remove any characters that aren't alphanumeric, underscore, or hyphen
    safe_name = re.sub(r'[^a-zA-Z0-9_-]', '_', name)
    # Collapse multiple underscores
    safe_name = re.sub(r'_+', '_', safe_name)
    # Limit length
    return safe_name[:100]

# Usage in Content-Disposition header:
filename = sanitise_filename(account.name)
response.headers["Content-Disposition"] = f'attachment; filename="{filename}_report.csv"'
```

#### Validation Criteria
- [ ] `sanitise_filename()` function created
- [ ] Applied to all report filename generation
- [ ] Test: Account name with special chars is sanitised
- [ ] Test: Account name with path traversal (`../`) is sanitised
- [ ] Test: Account name with newlines is sanitised

---

### H9: CORS Origins Not Validated
**Location:** `backend/app/main.py:382-402`

#### Implementation

```python
# backend/app/main.py

def validate_cors_origins(origins: list[str]) -> list[str]:
    """Validate CORS origins on startup."""
    from urllib.parse import urlparse

    settings = get_settings()
    validated = []

    for origin in origins:
        parsed = urlparse(origin)

        # Must have scheme and netloc
        if not parsed.scheme or not parsed.netloc:
            raise ValueError(f"Invalid CORS origin format: {origin}")

        # Production must use HTTPS (except localhost)
        if settings.environment == "production":
            if parsed.scheme != "https" and "localhost" not in parsed.netloc:
                raise ValueError(f"CORS origin must use HTTPS in production: {origin}")

        validated.append(origin)

    return validated

# On startup:
cors_origins = validate_cors_origins(settings.cors_origins.split(","))
```

#### Validation Criteria
- [ ] CORS origins validated on startup
- [ ] HTTP origins rejected in production (except localhost)
- [ ] Malformed URLs rejected
- [ ] Test: Valid HTTPS origin accepted
- [ ] Test: HTTP origin rejected in production mode

---

### H10: SECRET_KEY No Entropy Validation
**Location:** `backend/app/core/config.py:32-35`

#### Implementation

```python
# backend/app/core/config.py

import math
from collections import Counter

def calculate_shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not s:
        return 0.0

    length = len(s)
    counter = Counter(s)
    entropy = -sum(
        (count / length) * math.log2(count / length)
        for count in counter.values()
    )
    return entropy

class Settings(BaseSettings):
    secret_key: str

    @validator("secret_key")
    def validate_secret_key(cls, v):
        if len(v) < 32:
            raise ValueError("SECRET_KEY must be at least 32 characters")

        entropy = calculate_shannon_entropy(v)
        if entropy < 3.0:  # Reasonable threshold for random strings
            raise ValueError(
                f"SECRET_KEY has insufficient entropy ({entropy:.2f}). "
                "Use a cryptographically random value."
            )

        return v
```

#### Validation Criteria
- [ ] Shannon entropy calculation implemented
- [ ] Minimum entropy threshold of 3.0
- [ ] Minimum length of 32 characters
- [ ] Test: "aaaa...aaaa" (32 a's) rejected for low entropy
- [ ] Test: Random 32-char string accepted

---

### H11: HIBP Check Fails Open
**Location:** `backend/app/services/hibp_service.py:104, 126, 131`

#### Implementation

Add configurable fail-closed mode:

```python
# backend/app/core/config.py
hibp_fail_closed: bool = True  # Fail closed by default in production

# backend/app/services/hibp_service.py
async def check_password_breach(self, password: str) -> tuple[bool, int]:
    """Check if password appears in HIBP database.

    Returns:
        (is_breached, breach_count)

    If HIBP API is unavailable:
    - In fail-closed mode: Returns (True, 0) - treat as breached
    - In fail-open mode: Returns (False, 0) - allow password
    """
    try:
        # ... existing HIBP check logic ...
    except Exception as e:
        logger.warning("hibp_check_failed", error=str(e))

        if settings.hibp_fail_closed:
            # Fail closed - reject password when we can't verify
            return (True, 0)
        else:
            # Fail open - allow password (legacy behaviour)
            return (False, 0)
```

#### Validation Criteria
- [ ] `hibp_fail_closed` setting added
- [ ] Default to fail-closed in production
- [ ] Behaviour documented in logs
- [ ] Test: API failure in fail-closed mode returns breached=True
- [ ] Test: API failure in fail-open mode returns breached=False

---

## Phase 3: Medium Priority Fixes (P2)

### M1-M14: Summary Table

| ID | Issue | Location | Fix Summary |
|----|-------|----------|-------------|
| M1 | CSRF Token Timing Attack | auth.py:649-663 | Use `hmac.compare_digest()` |
| M2 | IP Allowlist Lacks CIDR | security.py:296-303 | Use `ipaddress` module |
| M3 | Information Disclosure | cloud_organizations.py:207,224 | Log full, return generic |
| M4 | CREDENTIAL_ENCRYPTION_KEY Optional | config.py:108-109 | Make mandatory in production |
| M5 | MFA Secrets Plain Text | user.py:68-69 | Encrypt with Fernet |
| M6 | Cognito Advanced Security Audit | cognito/main.tf:67-69 | Change to ENFORCED |
| M7-M14 | Various | Various | See detailed implementations below |

### M1: CSRF Token Timing Attack

```python
# Replace string comparison with constant-time comparison
import hmac

# Before:
if csrf_cookie != csrf_header:
    raise HTTPException(403, "CSRF mismatch")

# After:
if not hmac.compare_digest(csrf_cookie, csrf_header):
    raise HTTPException(403, "CSRF mismatch")
```

### M2: IP Allowlist CIDR Support

```python
import ipaddress

def ip_in_allowlist(client_ip: str, allowlist: list[str]) -> bool:
    """Check if IP is in allowlist, supporting both IPs and CIDRs."""
    try:
        client = ipaddress.ip_address(client_ip)
        for entry in allowlist:
            if "/" in entry:
                # CIDR notation
                network = ipaddress.ip_network(entry, strict=False)
                if client in network:
                    return True
            else:
                # Single IP
                if client == ipaddress.ip_address(entry):
                    return True
        return False
    except ValueError:
        return False
```

### M3: Information Disclosure Fix

```python
# Before:
raise HTTPException(400, detail=f"AWS Error: {e}")

# After:
logger.error("aws_api_error", error=str(e), account_id=str(account.id))
raise HTTPException(400, detail="Failed to connect to cloud provider")
```

### M4: Encryption Key Mandatory

```python
@validator("credential_encryption_key")
def validate_encryption_key(cls, v, values):
    env = values.get("environment", "development")
    if env == "production" and not v:
        raise ValueError("CREDENTIAL_ENCRYPTION_KEY is required in production")
    return v
```

### M5: Encrypt MFA Secrets

```python
# app/models/user.py
from app.core.encryption import encrypt_field, decrypt_field

class User(Base):
    # Store encrypted TOTP secret
    _totp_secret_encrypted = Column("totp_secret", String, nullable=True)

    @property
    def totp_secret(self) -> Optional[str]:
        if self._totp_secret_encrypted:
            return decrypt_field(self._totp_secret_encrypted)
        return None

    @totp_secret.setter
    def totp_secret(self, value: str):
        self._totp_secret_encrypted = encrypt_field(value)
```

### M6: Cognito Advanced Security

```hcl
resource "aws_cognito_user_pool" "main" {
  # ...

  user_pool_add_ons {
    advanced_security_mode = "ENFORCED"  # Changed from AUDIT
  }

  # ...
}
```

---

## Backlog (Deferred Items)

### BACKLOG-1: ECS Tasks in Public Subnets (NAT Gateway)
**Original ID:** H3
**Location:** `infrastructure/terraform/modules/backend/main.tf:547-549`
**Status:** ⏸️ Deferred
**Cost Impact:** ~$40-50/month

#### Rationale for Deferral
- Current setup: ECS tasks in public subnets with public IPs
- Mitigations in place: Security groups, WAF, ALB
- Cost: NAT Gateway adds ~$40-50/month recurring
- Decision: Revisit when monthly revenue exceeds $500

#### Implementation (When Ready)
```hcl
# Add NAT Gateway and move ECS to private subnets
# See original H3 section for full implementation
```

#### Trigger for Implementation
- [ ] Monthly revenue > $500
- [ ] Security compliance requirement (SOC 2, ISO 27001)
- [ ] Enterprise customer requirement

---

### BACKLOG-2: Customer-Managed KMS Keys
**Original ID:** M6
**Location:** `infrastructure/terraform/modules/database/main.tf:67`
**Status:** ❌ Risk Accepted
**Cost Impact:** ~$1/month

#### Rationale for Risk Acceptance
- AWS managed keys provide AES-256 encryption
- Customer-managed keys add:
  - Manual key rotation management
  - Additional IAM complexity
  - Minimal security improvement
- Decision: AWS managed keys acceptable for current risk profile

#### Re-evaluation Triggers
- [ ] Compliance requirement mandates CMK
- [ ] Need for custom key rotation policy
- [ ] Cross-account key sharing requirement

---

## Implementation Schedule

### Week 1: Critical Fixes (P0) - $0/month
1. Day 1-2: C1 (Redis rate limiter), C5 (Security headers)
2. Day 2-3: C2 (Admin password), C6 (Secrets Manager)
3. Day 3-4: C3, C4 (Security groups)
4. Day 4-5: Testing and validation

### Week 2: High Priority (P1) - ~$6-18/month
1. Day 1-2: H1 (VPC Flow Logs), H2 (Redis encryption)
2. Day 2-3: H3-H5 (JWT, CSRF, Lockout)
3. Day 3-4: H6-H8 (SQL, File Upload, Filenames)
4. Day 4-5: H9-H11 (CORS, SECRET_KEY, HIBP)

### Week 3: Medium Priority (P2) - $0/month
1. Day 1-3: M1-M6
2. Day 3-5: M7-M14, comprehensive testing

---

## Cost Summary

| Phase | Items | Monthly Cost |
|-------|-------|--------------|
| P0 Critical | C1-C6 | $0 |
| P1 High | H1-H11 | ~$6-18 (VPC Flow Logs) |
| P2 Medium | M1-M14 | $0 |
| **Total (Implemented)** | **31 fixes** | **~$6-18/month** |
| Backlog | 2 items | ~$41-51 (when implemented) |

---

## Validation Checklist

### Pre-Deployment
- [ ] All critical fixes (C1-C6) implemented
- [ ] Unit tests pass
- [ ] Integration tests pass
- [ ] Security scan (OWASP ZAP or equivalent)
- [ ] Terraform plan reviewed

### Post-Deployment
- [ ] VPC Flow Logs appearing in CloudWatch
- [ ] Rate limiting working across instances
- [ ] Security headers present in responses
- [ ] No security group allows 10.0.0.0/8
- [ ] Redis encryption enabled
- [ ] All tests pass in staging

---

## Rollback Plan

If issues arise after deployment:

1. **Rate Limiter Issues:** Fall back to in-memory limiter temporarily
2. **Security Group Issues:** Temporarily widen to VPC CIDR (not 10.0.0.0/8)
3. **Redis Encryption Issues:** May require cluster recreation - have backup

---

**Document Version:** 1.1
**Last Updated:** 2025-12-21
**Next Review:** After implementation begins
**Owner:** Security Team
