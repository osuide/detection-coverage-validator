# A13E Development Backlog

## Features

### Heatmap Enhancements

- [x] **Display detection names in heatmap tooltip** *(Completed 2025-12-19)*
  - Shows associated detection names when hovering over technique cells
  - Backend updated to include detection names in `/coverage/{id}/techniques` endpoint
  - Tooltip shows up to 5 detection names, click for full list

## Documentation

- [ ] **Create GCP connection guide**
  - Product supports GCP but all connection guides are AWS-focused
  - Create `connecting-gcp-projects.md` documentation
  - Priority: Medium

- [ ] **Apply UK English corrections**
  - Fix remaining US English spellings in documentation
  - See docs review notes for specific instances
  - Priority: Low

## Security Backlog

*From Security Audit Report (2025-12-21)*

### H4: Replace Raw SQL in Seeding Functions with ORM

- **Location:** `backend/app/main.py:146, 168, 190, 211, 220, 276, 308`
- **Priority:** Low
- **Risk:** Maintenance risk, not immediate vulnerability

**Current State:**
The `seed_mitre_data()` and `seed_admin_user()` functions use raw SQL via SQLAlchemy's `text()`:
```python
conn.execute(text("SELECT COUNT(*) FROM techniques"))
conn.execute(text("""INSERT INTO tactics (...) VALUES (:id, :name, ...)"""), params)
```

**Why Backlogged:**
| Factor | Assessment |
|--------|------------|
| User input? | No - all values are hardcoded constants |
| Parameterised? | Yes - uses `:named` parameters (safe from injection) |
| When does it run? | Only on app startup, seeding static data |
| Who can trigger it? | Only the system (not user-accessible) |
| Attack vector? | None - attacker can't influence the inputs |

**Fix (when prioritised):**
1. Create/use SQLAlchemy ORM models for `Tactic` and `Technique`
2. Replace ~100 lines of raw SQL with ORM operations
3. Test that seeding still works correctly
4. Estimated effort: 4 hours

---

### H8: Enable VPC Flow Logs

- **Location:** `infrastructure/terraform/modules/vpc/main.tf`
- **Priority:** Low
- **Cost:** ~$5-15/month (CloudWatch Logs storage)

**Why Backlogged:**
- Primarily useful for forensic analysis after incidents
- Not an active prevention mechanism
- Adds ongoing cost with limited immediate value for current scale

**Fix (when prioritised):**
```hcl
resource "aws_flow_log" "main" {
  vpc_id          = aws_vpc.main.id
  traffic_type    = "ALL"
  log_destination = aws_cloudwatch_log_group.flow_logs.arn
}
```

---

### H9: Move ECS Tasks to Private Subnets (NAT Gateway)

- **Location:** `infrastructure/terraform/modules/backend/main.tf:547-549`
- **Priority:** Low
- **Cost:** ~$40-50/month (NAT Gateway)

**Why Backlogged:**
- Current mitigation: WAF, security groups, ALB (no direct public access to containers)
- NAT Gateway adds significant monthly cost
- Recommend implementing when scaling to production with higher security requirements

**Fix (when prioritised):**
1. Create NAT Gateway in public subnets
2. Update ECS service to use private subnets
3. Update route tables for private subnet internet access via NAT

---

### M6: Customer-Managed KMS Keys for RDS

- **Location:** `infrastructure/terraform/modules/database/main.tf:67`
- **Priority:** Low (Risk Accepted)
- **Cost:** ~$1/month per key

**Why Risk Accepted:**
- AWS-managed keys provide adequate encryption
- Customer-managed keys add complexity without significant security benefit for current threat model
- Revisit if compliance requirements (SOC 2, HIPAA) mandate key rotation control

---

### M3: Account Access Type Conversion Safety

- **Location:** `backend/app/core/security.py:98-112`
- **Priority:** Low
- **Risk:** Type safety issue in access control

**Current State:**
The `can_access_account()` method compares UUID to string list:
```python
return str(account_id) in self.membership.allowed_account_ids
```

**Why Backlogged:**
- Current implementation works correctly (explicit string conversion)
- No immediate vulnerability - just a defensive coding improvement
- Would benefit from explicit type validation on `allowed_account_ids`

**Fix (when prioritised):**
Add type validation when loading `allowed_account_ids` to ensure consistent UUID string format.

---

### M6b: Credential Update Organisation Context Validation

- **Location:** `backend/app/api/routes/credentials.py:238-304`
- **Priority:** Low
- **Risk:** Theoretical org context mismatch

**Why Backlogged:**
- Credential updates already require auth context with org
- Cloud account ownership is validated
- Low likelihood of exploitation

**Fix (when prioritised):**
Add explicit organisation ID validation in credential update endpoints.

---

### M7: GCP Key Logging Risk

- **Location:** `backend/app/api/routes/credentials.py:67-77`
- **Priority:** Low
- **Risk:** Potential key exposure in error logs

**Current State:**
GCP service account key validation may expose key fragments in error messages.

**Why Backlogged:**
- Keys are encrypted before storage
- Error messages don't currently log the full key
- Would require custom exception handling

**Fix (when prioritised):**
Wrap key validation in try/except that sanitises error messages before logging.

---

### M8: API Key Stats Transaction Isolation

- **Location:** `backend/app/core/security.py:352-355`
- **Priority:** Low
- **Risk:** Usage stats may be lost on concurrent requests

**Current State:**
API key usage stats (`last_used_at`, `usage_count`) are updated without explicit transaction:
```python
api_key.last_used_at = datetime.now(timezone.utc)
api_key.usage_count += 1
```

**Why Backlogged:**
- Usage stats are informational, not security-critical
- Lost updates have minimal impact
- Would add latency to every API key request

**Fix (when prioritised):**
Use `SELECT FOR UPDATE` or atomic increment for `usage_count`.

---

### M14: GCP Key Rotation Tracking

- **Location:** `backend/app/models/cloud_credential.py:184-185`
- **Priority:** Low
- **Risk:** No audit trail for key rotation

**Why Backlogged:**
- Key rotation is a manual process currently
- Encryption key changes are tracked via timestamps
- Would require additional schema changes

**Fix (when prioritised):**
Add `rotated_at` and `rotation_count` fields to track key lifecycle.

---

### M15: API Key IPv6 Allowlist Support

- **Location:** `backend/app/core/security.py:333-339`
- **Priority:** Low
- **Risk:** IPv6 addresses may not match allowlist correctly

**Current State:**
IP allowlist checking uses `ipaddress` module which supports IPv6, but allowlist entries are typically IPv4.

**Why Backlogged:**
- Most deployments use IPv4
- The `ipaddress` module handles IPv6 correctly when specified
- Would require UI updates to support IPv6 entry

**Fix (when prioritised):**
Add documentation and UI support for IPv6 CIDR notation in allowlists.

---

### M16: SECRET_KEY Pydantic Field Marking

- **Location:** `backend/app/core/config.py:32-35`
- **Priority:** Low
- **Risk:** Secret key visible in settings repr

**Current State:**
`secret_key` field is not marked with `SecretStr` type.

**Why Backlogged:**
- Settings object is not exposed to users
- No logging of full settings object
- Would require updating all usages

**Fix (when prioritised):**
```python
from pydantic import SecretStr
secret_key: SecretStr
# Update all usages to call .get_secret_value()
```

---

## Technical Debt

- [ ] **Code splitting for frontend bundle**
  - Bundle currently exceeds 500KB warning threshold
  - Implement dynamic imports for route-based splitting
  - Priority: Low
