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

## Technical Debt

- [ ] **Code splitting for frontend bundle**
  - Bundle currently exceeds 500KB warning threshold
  - Implement dynamic imports for route-based splitting
  - Priority: Low
