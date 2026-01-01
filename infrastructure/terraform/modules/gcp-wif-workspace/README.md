# A13E Google Workspace WIF Module

This Terraform module configures Workload Identity Federation (WIF) to allow a13e's AWS infrastructure to access Google Workspace APIs without service account keys.

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                              AWS                                         │
│                                                                          │
│   ┌─────────────┐         ┌─────────────────┐                           │
│   │ ECS Task    │────────►│ IAM Task Role   │                           │
│   │ (Backend)   │         │                 │                           │
│   └─────────────┘         └────────┬────────┘                           │
│                                    │                                     │
│                                    │ AssumeRoleWithWebIdentity          │
│                                    │ (via AWS STS)                      │
└────────────────────────────────────┼────────────────────────────────────┘
                                     │
                                     │ OIDC Token
                                     ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                           Google Cloud                                   │
│                                                                          │
│   ┌─────────────────────────────────────────────────────────────────┐   │
│   │              Workload Identity Federation                        │   │
│   │                                                                  │   │
│   │   ┌─────────────────┐         ┌─────────────────────────────┐  │   │
│   │   │ Identity Pool   │────────►│ AWS OIDC Provider           │  │   │
│   │   │ a13e-internal   │         │ (validates AWS credentials) │  │   │
│   │   └─────────────────┘         └──────────────┬──────────────┘  │   │
│   │                                              │                  │   │
│   └──────────────────────────────────────────────┼──────────────────┘   │
│                                                  │                       │
│                                                  │ Impersonates          │
│                                                  ▼                       │
│   ┌─────────────────────────────────────────────────────────────────┐   │
│   │              Service Account                                     │   │
│   │              a13e-workspace@project.iam.gserviceaccount.com     │   │
│   │                                                                  │   │
│   │              [Domain-Wide Delegation Enabled]                    │   │
│   └──────────────────────────────────────────────┬──────────────────┘   │
│                                                  │                       │
└──────────────────────────────────────────────────┼──────────────────────┘
                                                   │
                                                   │ Impersonates User
                                                   ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                        Google Workspace                                  │
│                                                                          │
│   ┌─────────────────────────────────────────────────────────────────┐   │
│   │              austin@a13e.com (delegated access)                  │   │
│   │                                                                  │   │
│   │   ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────────────┐   │   │
│   │   │ Gmail   │  │ Drive   │  │ Sheets  │  │ Admin Directory │   │   │
│   │   │ API     │  │ API     │  │ API     │  │ API             │   │   │
│   │   └─────────┘  └─────────┘  └─────────┘  └─────────────────┘   │   │
│   │                                                                  │   │
│   └─────────────────────────────────────────────────────────────────┘   │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

## Usage

```hcl
module "workspace_wif" {
  source = "./modules/gcp-wif-workspace"

  gcp_project_id        = "a13e-internal"
  aws_account_id        = "123456789012"
  environment           = "production"
  workspace_domain      = "a13e.com"
  workspace_admin_email = "austin@a13e.com"

  allowed_aws_roles = [
    "a13e-backend-task-role",
    "a13e-automation-role"
  ]
}
```

## Manual Steps Required

After applying this Terraform module, you must manually configure domain-wide delegation:

1. Go to [admin.google.com](https://admin.google.com)
2. Navigate to: **Security → Access and data control → API controls**
3. Click: **Manage Domain Wide Delegation**
4. Click: **Add new**
5. Enter the **Client ID** from Terraform output: `service_account_unique_id`
6. Add the OAuth Scopes (see output `domain_wide_delegation_instructions`)
7. Click **Authorize**

## Outputs

| Output | Description |
|--------|-------------|
| `workload_identity_pool_id` | Pool ID for WIF configuration |
| `provider_resource_name` | Full provider resource name |
| `service_account_email` | Email of the Workspace service account |
| `service_account_unique_id` | Client ID for domain-wide delegation |
| `configuration` | All values needed for application config |

## Security Benefits

| Aspect | Service Account Key | WIF |
|--------|---------------------|-----|
| Credential lifetime | Permanent until rotated | 1 hour max |
| Key management | Manual rotation required | No keys to manage |
| Audit trail | Limited | Full audit in both AWS and GCP |
| Blast radius | Key compromise = full access | Role-scoped, time-limited |
| Revocation | Must delete/rotate key | Disable pool or provider |

## Python Usage

```python
from google.auth import identity_pool
from google.auth.transport.requests import Request
from googleapiclient.discovery import build

# WIF credentials from AWS
credentials = identity_pool.Credentials.from_info({
    "type": "external_account",
    "audience": "//iam.googleapis.com/projects/PROJECT_NUMBER/locations/global/workloadIdentityPools/POOL_ID/providers/PROVIDER_ID",
    "subject_token_type": "urn:ietf:params:aws:token-type:aws4_request",
    "token_url": "https://sts.googleapis.com/v1/token",
    "credential_source": {
        "environment_id": "aws1",
        "regional_cred_verification_url": "https://sts.{region}.amazonaws.com?Action=GetCallerIdentity&Version=2011-06-15"
    },
    "service_account_impersonation_url": "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/SA_EMAIL:generateAccessToken"
})

# For Workspace APIs, create delegated credentials
from google.auth import impersonated_credentials

delegated_credentials = impersonated_credentials.Credentials(
    source_credentials=credentials,
    target_principal="sa@project.iam.gserviceaccount.com",
    target_scopes=["https://www.googleapis.com/auth/gmail.modify"],
    delegates=[],
    subject="austin@a13e.com"  # Workspace user to impersonate
)

# Use with Workspace APIs
gmail_service = build('gmail', 'v1', credentials=delegated_credentials)
```
