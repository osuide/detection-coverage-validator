# A13E Production Deployment Plan

**Created:** 2025-12-19
**Status:** PLANNING (Not Yet Executed)
**Target Environment:** AWS eu-west-2
**Production Domain:** app.a13e.io / api.a13e.io

---

## Executive Summary

This document outlines the complete plan for deploying the A13E Detection Coverage Validator to production. The staging environment (staging.a13e.com) is fully operational and serves as the blueprint for production infrastructure.

**Current State:**
- Staging: 100% operational at https://staging.a13e.com
- Production: Not deployed

**Estimated Effort:** 4-6 hours
**Estimated Monthly Cost:** ~$250/month

---

## 1. Prerequisites Checklist

Before starting production deployment, ensure:

- [ ] Domain `a13e.io` is registered and accessible
- [ ] AWS CLI configured with appropriate IAM permissions
- [ ] Terraform v1.0+ installed
- [ ] Stripe account ready for live mode activation
- [ ] SES production access approved (exit sandbox mode)
- [ ] OAuth provider apps updated with production callback URLs

---

## 2. Infrastructure Comparison: Staging vs Production

| Component | Staging | Production | Change |
|-----------|---------|------------|--------|
| **ECS Tasks** | 1 task | 2 tasks min + auto-scaling | Scale up |
| **ECS CPU/Memory** | 512/1024 | 1024/2048 | Double |
| **RDS Instance** | db.t3.micro | db.t3.small | Upgrade |
| **RDS Multi-AZ** | No | Yes | Enable HA |
| **RDS Backup** | 7 days | 30 days | Extend |
| **ElastiCache** | 1 node | 2 nodes + replication | Add failover |
| **ElastiCache Type** | cache.t3.micro | cache.t3.small | Upgrade |
| **CloudFront Price Class** | 100 (US/EU) | 100 (US/EU) | Same |
| **WAF** | Enabled | Enabled | Same |
| **Deletion Protection** | No | Yes | Enable |
| **Domain** | staging.a13e.com | app.a13e.io | Change |
| **Stripe Mode** | Test | Live | Switch |

---

## 3. Production Cost Estimate

| Component | Specification | Monthly Cost |
|-----------|---------------|--------------|
| ECS Fargate | 2 tasks × 1 vCPU × 2GB | ~$100 |
| RDS PostgreSQL | db.t3.small Multi-AZ | ~$50 |
| ElastiCache Redis | cache.t3.small × 2 nodes | ~$30 |
| S3 + CloudFront | 100GB transfer | ~$10 |
| ALB | 1 load balancer | ~$20 |
| Route 53 | Hosted zone + queries | ~$1 |
| ACM Certificates | Free | $0 |
| CloudWatch | Logs + metrics + alarms | ~$20 |
| WAF | Web ACL + rules | ~$10 |
| Secrets Manager | 5 secrets | ~$3 |
| **TOTAL** | | **~$244/month** |

---

## 4. Deployment Phases

### Phase 1: Create Production Terraform Configuration (30 min)

**Task 1.1: Create production.tfvars**

Create file: `infrastructure/terraform/production.tfvars`

```hcl
# =============================================================================
# A13E Production Environment Configuration
# =============================================================================

aws_region  = "eu-west-2"
environment = "production"

# VPC Configuration (different CIDR to avoid conflicts if peering needed)
vpc_cidr = "10.1.0.0/16"

# Production-grade instance sizing
db_instance_class    = "db.t3.small"
db_multi_az          = true
db_backup_retention  = 30
db_deletion_protection = true

redis_node_type      = "cache.t3.small"
redis_num_cache_nodes = 2
redis_automatic_failover = true

ecs_task_cpu    = 1024
ecs_task_memory = 2048
ecs_desired_count = 2
ecs_min_capacity  = 2
ecs_max_capacity  = 6

# Domain Configuration
domain_name  = "a13e.io"
subdomain    = "app"
api_subdomain = "api"
enable_https = true

# Stripe LIVE Mode Price IDs (replace with actual live IDs)
stripe_price_ids = {
  subscriber         = "price_LIVE_SUBSCRIBER_REPLACE_ME"
  enterprise         = "price_LIVE_ENTERPRISE_REPLACE_ME"
  additional_account = "price_LIVE_ADDITIONAL_REPLACE_ME"
}

# OAuth/SSO (Google and GitHub only)
enable_cognito = true

# Email
enable_ses = true

# Monitoring
enable_enhanced_monitoring = true
alarm_email = "alerts@a13e.io"

# Tags
tags = {
  Environment = "production"
  Project     = "a13e"
  ManagedBy   = "terraform"
}
```

**Task 1.2: Update Terraform variables.tf**

Add any missing variables for production-specific settings:

```hcl
variable "db_multi_az" {
  description = "Enable Multi-AZ for RDS"
  type        = bool
  default     = false
}

variable "db_deletion_protection" {
  description = "Enable deletion protection for RDS"
  type        = bool
  default     = false
}

variable "ecs_min_capacity" {
  description = "Minimum ECS task count for auto-scaling"
  type        = number
  default     = 1
}

variable "ecs_max_capacity" {
  description = "Maximum ECS task count for auto-scaling"
  type        = number
  default     = 4
}

variable "enable_enhanced_monitoring" {
  description = "Enable enhanced monitoring and alarms"
  type        = bool
  default     = false
}

variable "alarm_email" {
  description = "Email address for CloudWatch alarms"
  type        = string
  default     = ""
}
```

---

### Phase 2: Domain & SSL Setup (30 min)

**Task 2.1: Create Route 53 Hosted Zone for a13e.io**

If not already done:
```bash
aws route53 create-hosted-zone --name a13e.io --caller-reference $(date +%s)
```

**Task 2.2: Update Domain Registrar**

Point nameservers from your registrar to Route 53:
1. Get NS records from Route 53 hosted zone
2. Update nameservers at domain registrar (wait up to 48h for propagation)

**Task 2.3: ACM Certificates Will Be Created by Terraform**

Certificates needed:
- `app.a13e.io` (CloudFront - us-east-1)
- `api.a13e.io` (ALB - eu-west-2)

---

### Phase 3: Stripe Live Mode Configuration (30 min)

**Task 3.1: Create Live Mode Products in Stripe Dashboard**

1. Log into Stripe Dashboard
2. Switch to **Live Mode** (toggle in left sidebar)
3. Create products matching staging:

| Product | Price | Stripe Price ID |
|---------|-------|-----------------|
| A13E Subscriber | $29/month | price_LIVE_xxx |
| A13E Enterprise | $499/month | price_LIVE_xxx |
| Additional Account | $9/month | price_LIVE_xxx |

**Task 3.2: Get Live API Keys**

1. Go to Developers > API Keys
2. Copy:
   - Publishable key: `pk_live_xxx`
   - Secret key: `sk_live_xxx`

**Task 3.3: Create Live Webhook Endpoint**

1. Go to Developers > Webhooks
2. Add endpoint: `https://api.a13e.io/api/v1/billing/webhook`
3. Select events:
   - `checkout.session.completed`
   - `customer.subscription.created`
   - `customer.subscription.updated`
   - `customer.subscription.deleted`
   - `invoice.paid`
   - `invoice.payment_failed`
4. Copy webhook signing secret: `whsec_xxx`

**Task 3.4: Store Secrets in AWS Secrets Manager**

```bash
# Create production secrets
aws secretsmanager create-secret \
  --name "a13e/production/stripe" \
  --secret-string '{
    "secret_key": "sk_live_xxx",
    "webhook_secret": "whsec_xxx",
    "publishable_key": "pk_live_xxx"
  }' \
  --region eu-west-2
```

---

### Phase 4: OAuth Provider Updates (20 min)

**Task 4.1: Update Google OAuth App**

1. Go to Google Cloud Console > APIs & Services > Credentials
2. Edit OAuth 2.0 Client
3. Add Authorized redirect URI:
   - `https://app.a13e.io/auth/callback`
   - `https://dcv-production-xxx.auth.eu-west-2.amazoncognito.com/oauth2/idpresponse`

**Task 4.2: Update GitHub OAuth App**

1. Go to GitHub > Settings > Developer settings > OAuth Apps
2. Edit application
3. Update Authorization callback URL:
   - `https://api.a13e.io/api/v1/auth/github/callback`

---

### Phase 5: Deploy Infrastructure (1-2 hours)

**Task 5.1: Initialize Terraform Workspace**

```bash
cd infrastructure/terraform

# Create production workspace
terraform workspace new production

# Or select if exists
terraform workspace select production
```

**Task 5.2: Plan Infrastructure**

```bash
# Set OAuth secrets as environment variables
export TF_VAR_google_client_id="xxx"
export TF_VAR_google_client_secret="xxx"
export TF_VAR_github_client_id="xxx"
export TF_VAR_github_client_secret="xxx"

# Plan with production config
terraform plan -var-file=production.tfvars -out=production.tfplan
```

**Task 5.3: Review Plan Carefully**

Verify:
- [ ] RDS is db.t3.small with Multi-AZ
- [ ] ECS has 2 desired tasks
- [ ] Domain names are correct (app.a13e.io, api.a13e.io)
- [ ] Deletion protection is enabled
- [ ] No resources from staging will be affected

**Task 5.4: Apply Infrastructure**

```bash
terraform apply production.tfplan
```

**Task 5.5: Wait for Resources**

- ACM certificate validation: 5-30 minutes
- RDS creation: 10-15 minutes
- ElastiCache creation: 5-10 minutes
- CloudFront distribution: 15-30 minutes

---

### Phase 6: Database Setup (30 min)

**Task 6.1: Run Database Migrations**

```bash
# Get RDS endpoint from Terraform output
terraform output rds_endpoint

# Run migrations via ECS Exec or bastion
aws ecs execute-command \
  --cluster a13e-production-backend \
  --task <task-id> \
  --container backend \
  --interactive \
  --command "alembic upgrade head"
```

**Task 6.2: Seed MITRE ATT&CK Data**

```bash
aws ecs execute-command \
  --cluster a13e-production-backend \
  --task <task-id> \
  --container backend \
  --interactive \
  --command "python scripts/seed_mitre.py"
```

**Task 6.3: Create Initial Admin User (if needed)**

```bash
aws ecs execute-command \
  --cluster a13e-production-backend \
  --task <task-id> \
  --container backend \
  --interactive \
  --command "python scripts/create_admin.py --email admin@a13e.io"
```

---

### Phase 7: Deploy Application (30 min)

**Task 7.1: Build and Push Backend Image**

```bash
# Login to ECR
aws ecr get-login-password --region eu-west-2 | \
  docker login --username AWS --password-stdin \
  <account-id>.dkr.ecr.eu-west-2.amazonaws.com

# Build for production
docker build -t a13e-production-backend:latest \
  --platform linux/amd64 \
  -f backend/Dockerfile \
  ./backend

# Tag and push
docker tag a13e-production-backend:latest \
  <account-id>.dkr.ecr.eu-west-2.amazonaws.com/a13e-production-backend:latest

docker push <account-id>.dkr.ecr.eu-west-2.amazonaws.com/a13e-production-backend:latest
```

**Task 7.2: Build and Deploy Frontend**

```bash
cd frontend

# Update environment for production
echo "VITE_API_BASE_URL=https://api.a13e.io" > .env.production

# Build
npm run build

# Deploy to S3
aws s3 sync dist/ s3://a13e-production-frontend-xxx/ --delete

# Invalidate CloudFront cache
aws cloudfront create-invalidation \
  --distribution-id <distribution-id> \
  --paths "/*"
```

**Task 7.3: Force ECS Service Update**

```bash
aws ecs update-service \
  --cluster a13e-production-backend \
  --service a13e-production-backend \
  --force-new-deployment
```

---

### Phase 8: Verification & Testing (1 hour)

**Task 8.1: Health Checks**

```bash
# API health
curl https://api.a13e.io/health
# Expected: {"status":"healthy","version":"0.1.0"}

# Frontend loads
curl -I https://app.a13e.io
# Expected: HTTP/2 200
```

**Task 8.2: Functional Testing**

- [ ] User signup with email
- [ ] User login
- [ ] Google OAuth login
- [ ] GitHub OAuth login
- [ ] Password reset email sends
- [ ] Create cloud account
- [ ] Connect AWS credentials
- [ ] Trigger scan (dev mode initially)
- [ ] View coverage heatmap
- [ ] View detections
- [ ] View gaps
- [ ] Stripe checkout flow
- [ ] Team invite
- [ ] API key creation

**Task 8.3: Admin Portal Testing**

- [ ] Admin login at https://admin.a13e.io
- [ ] View organizations
- [ ] View users
- [ ] View metrics dashboard
- [ ] Audit logs visible

---

### Phase 9: Monitoring Setup (30 min)

**Task 9.1: Create CloudWatch Alarms**

The following alarms should be created (via Terraform or manually):

| Alarm | Metric | Threshold | Action |
|-------|--------|-----------|--------|
| RDS CPU High | CPUUtilization | > 80% for 5 min | SNS Alert |
| RDS Storage Low | FreeStorageSpace | < 10 GB | SNS Alert |
| RDS Connections High | DatabaseConnections | > 80% max | SNS Alert |
| ECS CPU High | CPUUtilization | > 85% for 5 min | SNS Alert |
| ECS Memory High | MemoryUtilization | > 85% for 5 min | SNS Alert |
| ALB 5xx Errors | HTTPCode_Target_5XX_Count | > 10/min | SNS Alert |
| ALB Latency High | TargetResponseTime | > 2s p99 | SNS Alert |
| ElastiCache CPU | CPUUtilization | > 80% | SNS Alert |

**Task 9.2: Create SNS Topic for Alerts**

```bash
aws sns create-topic --name a13e-production-alerts --region eu-west-2

aws sns subscribe \
  --topic-arn arn:aws:sns:eu-west-2:<account-id>:a13e-production-alerts \
  --protocol email \
  --notification-endpoint alerts@a13e.io
```

**Task 9.3: Create CloudWatch Dashboard**

Create dashboard with widgets for:
- ECS task count and health
- RDS CPU, connections, storage
- ElastiCache hit rate, CPU
- ALB request count, latency, errors
- API error rate (from application logs)

---

### Phase 10: SES Production Access (Variable time)

**Task 10.1: Request Production Access**

1. Go to AWS SES Console > Account dashboard
2. Click "Request production access"
3. Fill out:
   - Mail type: Transactional
   - Website URL: https://app.a13e.io
   - Use case description: "Password reset, team invitations, subscription confirmations"
   - Expected send volume: < 1000/day initially

**Task 10.2: Wait for Approval**

AWS typically responds within 24-48 hours.

**Task 10.3: Verify Production Domain**

If using different domain than staging:
```bash
aws ses verify-domain-identity --domain a13e.io --region eu-west-2
```

Add DNS records:
- TXT record for domain verification
- 3 CNAME records for DKIM

---

## 5. Post-Deployment Checklist

### Immediate (Day 1)

- [ ] All health endpoints return 200
- [ ] Users can sign up and log in
- [ ] OAuth providers work
- [ ] Emails send successfully
- [ ] Stripe payments process
- [ ] No errors in CloudWatch logs
- [ ] Alarms are not firing

### Week 1

- [ ] Monitor error rates daily
- [ ] Check CloudWatch costs
- [ ] Review security group rules
- [ ] Test backup restore procedure
- [ ] Document any manual changes made
- [ ] Update runbook with production details

### Ongoing

- [ ] Weekly review of CloudWatch metrics
- [ ] Monthly security review
- [ ] Quarterly disaster recovery test
- [ ] Regular dependency updates

---

## 6. Rollback Procedure

If critical issues arise:

### Application Rollback

```bash
# Revert to previous ECS task definition
aws ecs update-service \
  --cluster a13e-production-backend \
  --service a13e-production-backend \
  --task-definition a13e-production-backend:<previous-revision>

# Revert frontend
aws s3 sync s3://a13e-production-frontend-backup/ s3://a13e-production-frontend-xxx/
aws cloudfront create-invalidation --distribution-id <id> --paths "/*"
```

### Database Rollback

```bash
# Restore from snapshot
aws rds restore-db-instance-from-db-snapshot \
  --db-instance-identifier a13e-production-db-restored \
  --db-snapshot-identifier <snapshot-id>
```

### Full Infrastructure Rollback

```bash
# Destroy production and redeploy staging config
terraform workspace select production
terraform destroy -var-file=production.tfvars

# Point DNS back to staging temporarily
```

---

## 7. Security Considerations

### Production-Only Security Measures

1. **Admin Portal IP Allowlist**
   - Restrict to VPN/office IPs only
   - Configure in WAF rules

2. **Enhanced Logging**
   - Enable CloudTrail for all API calls
   - Enable VPC Flow Logs
   - Enable ALB access logs to S3

3. **Secrets Rotation**
   - JWT secret: Rotate every 90 days
   - Database password: Rotate every 90 days
   - API keys: User-managed rotation

4. **Network Security**
   - Review security group rules
   - Ensure RDS not publicly accessible
   - Verify ECS tasks in private subnets

---

## 8. Contacts & Escalation

| Role | Contact | Responsibility |
|------|---------|----------------|
| Platform Lead | austin@a13e.io | Infrastructure decisions |
| On-Call | alerts@a13e.io | Incident response |
| AWS Support | AWS Console | Infrastructure issues |
| Stripe Support | dashboard.stripe.com | Payment issues |

---

## 9. Reference Commands

### Terraform Commands

```bash
# Select workspace
terraform workspace select production

# Plan changes
terraform plan -var-file=production.tfvars

# Apply changes
terraform apply -var-file=production.tfvars

# Show outputs
terraform output

# Destroy (DANGEROUS)
terraform destroy -var-file=production.tfvars
```

### AWS CLI Commands

```bash
# ECS service status
aws ecs describe-services --cluster a13e-production-backend --services a13e-production-backend

# ECS task logs
aws logs tail /ecs/a13e-production-backend --follow

# RDS status
aws rds describe-db-instances --db-instance-identifier a13e-production-db

# Force ECS deployment
aws ecs update-service --cluster a13e-production-backend --service a13e-production-backend --force-new-deployment

# Invalidate CloudFront
aws cloudfront create-invalidation --distribution-id <id> --paths "/*"
```

### Database Commands

```bash
# Connect via ECS Exec
aws ecs execute-command \
  --cluster a13e-production-backend \
  --task <task-id> \
  --container backend \
  --interactive \
  --command "/bin/bash"

# Run migrations
alembic upgrade head

# Check migration status
alembic current
```

---

## 10. Document History

| Date | Author | Changes |
|------|--------|---------|
| 2025-12-19 | Claude | Initial production deployment plan |

---

**Next Step:** When ready to execute, follow phases 1-10 in order. Estimated total time: 4-6 hours.
