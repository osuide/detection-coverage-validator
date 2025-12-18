# Production Deployment Checklist

This document tracks critical configuration changes required when deploying A13E to production.

## Environment Variables

### Development vs Production

| Variable | Development | Production | Notes |
|----------|------------|------------|-------|
| `A13E_DEV_MODE` | `true` | **REMOVE or `false`** | See [AWS Credentials](#aws-credentials-critical) |
| `DEBUG` | `true` | `false` | Disable debug mode |
| `DATABASE_URL` | Local PostgreSQL | RDS endpoint | Use secrets manager |
| `JWT_SECRET` | Dev value | **Strong random secret** | Generate with `openssl rand -hex 32` |

---

## AWS Credentials (CRITICAL)

### The Problem

In development, `A13E_DEV_MODE=true` skips real AWS API calls for credential validation. This allows testing the UI flow without actual cross-account access.

In production, A13E's backend must be able to **assume IAM roles in customer AWS accounts**.

### Production Requirements

1. **Remove `A13E_DEV_MODE`** from production environment (or set to `false`)

2. **A13E Infrastructure Account**: The backend must run with IAM credentials from A13E's designated AWS account (currently configured as `123456789012` - update this to actual account ID)

3. **Required IAM Permissions for A13E Backend**:
   ```json
   {
     "Version": "2012-10-17",
     "Statement": [
       {
         "Effect": "Allow",
         "Action": "sts:AssumeRole",
         "Resource": "arn:aws:iam::*:role/A13E-*"
       }
     ]
   }
   ```
   This allows A13E to assume any customer role that follows the naming convention.

4. **Update A13E Account ID**:
   - File: `backend/app/services/aws_credential_service.py`
   - Line: `A13E_AWS_ACCOUNT_ID = "123456789012"`
   - Also update: `backend/app/core/config.py` → `a13e_aws_account_id`
   - Also update: `frontend/src/components/CredentialWizard.tsx` → `A13E_AWS_ACCOUNT_ID`

### How Cross-Account Access Works

```
Customer Account (123080274263)          A13E Account (123456789012)
┌─────────────────────────────┐         ┌─────────────────────────────┐
│                             │         │                             │
│  IAM Role: A13E-ReadOnly    │ ←─────  │  A13E Backend Service       │
│  - Trust: 123456789012      │  STS    │  - Has sts:AssumeRole       │
│  - ExternalID: a13e-xxx     │ Assume  │  - Calls customer role      │
│  - Policy: Read-only        │  Role   │                             │
│                             │         │                             │
└─────────────────────────────┘         └─────────────────────────────┘
```

### Deployment Steps for AWS Integration

1. Create an IAM role for the A13E backend service in A13E's AWS account
2. Attach the `sts:AssumeRole` policy (see above)
3. Configure ECS/Lambda/EC2 to use this role
4. Update the `A13E_AWS_ACCOUNT_ID` constant to match your actual account
5. Remove `A13E_DEV_MODE` from production docker-compose/ECS task definition
6. Test with a real customer account

---

## GCP Credentials

Similar to AWS, GCP credential validation is mocked in dev mode.

### Production Requirements

1. Set up Workload Identity Federation between A13E's GCP project and customer projects
2. Or use a GCP service account with domain-wide delegation

---

## Security Checklist

- [ ] `A13E_DEV_MODE` removed from production
- [ ] Strong `JWT_SECRET` configured via secrets manager
- [ ] Database credentials in secrets manager (not env vars)
- [ ] HTTPS enforced on all endpoints
- [ ] CORS configured for production domain only
- [ ] Rate limiting enabled
- [ ] Audit logging enabled
- [ ] Encryption keys rotated

---

## Files to Update Before Production

| File | What to Change |
|------|----------------|
| `docker-compose.yml` | Remove `A13E_DEV_MODE`, update all dev credentials |
| `backend/app/services/aws_credential_service.py` | Update `A13E_AWS_ACCOUNT_ID` |
| `backend/app/core/config.py` | Update `a13e_aws_account_id` default |
| `frontend/src/components/CredentialWizard.tsx` | Update `A13E_AWS_ACCOUNT_ID` constant |
| `infrastructure/terraform/` | Configure actual AWS/GCP resources |
