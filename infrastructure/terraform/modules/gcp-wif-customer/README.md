# A13E GCP Workload Identity Federation Setup

This Terraform module configures your GCP project to allow A13E Detection Coverage Validator to scan for security detections using Workload Identity Federation (WIF).

## Why Workload Identity Federation?

A13E is a security tool that helps you identify gaps in your detection coverage. **We practice what we preach** - using JSON service account keys would contradict our security mission.

### Benefits of WIF

| Feature | WIF | Service Account Keys |
|---------|-----|---------------------|
| Credential Storage | None - keyless | Keys must be stored |
| Credential Rotation | Automatic (1h tokens) | Manual rotation required |
| Blast Radius | Limited by conditions | Full SA access if leaked |
| Audit Trail | Full attribution | Hard to trace |
| Compliance | MITRE T1528 mitigated | T1528 risk |

### Security Architecture

```
+-------------------+     +-------------------+     +-------------------+
| A13E on AWS ECS   |     | GCP WIF Pool      |     | Your GCP Project  |
|                   |     |                   |     |                   |
| 1. Get OIDC token |---->| 2. Validate token |---->| 3. Impersonate SA |
|    from ECS       |     |    Exchange for   |     |    Get temp creds |
|                   |     |    GCP cred       |     |                   |
+-------------------+     +-------------------+     +-------------------+
```

## Prerequisites

1. GCP project with billing enabled
2. `Owner` or `IAM Admin` role to create resources
3. A13E AWS account ID (shown in the A13E app during setup: `123080274263`)
4. Terraform >= 1.0.0

## Quick Start

### 1. Add the Module

```hcl
module "a13e_wif" {
  source = "github.com/a13e/terraform-gcp-wif-customer"

  project_id          = "your-gcp-project-id"
  a13e_aws_account_id = "123080274263"  # A13E's AWS account ID
}

output "a13e_config" {
  value = module.a13e_wif.a13e_configuration
}
```

### 2. Apply the Configuration

```bash
terraform init
terraform plan
terraform apply
```

### 3. Provide Configuration to A13E

After applying, copy the output values to your A13E dashboard:

```
project_id:            your-gcp-project-id
pool_id:               a13e-pool
provider_id:           aws
service_account_email: a13e-scanner@your-project.iam.gserviceaccount.com
pool_location:         global
```

## What This Module Creates

| Resource | Purpose |
|----------|---------|
| Workload Identity Pool | Container for federated identities |
| AWS OIDC Provider | Trusts A13E's AWS account |
| Service Account | `a13e-scanner@project.iam.gserviceaccount.com` |
| Custom IAM Role | Minimum read-only permissions |
| IAM Bindings | Allow WIF to impersonate SA |

## Permissions Granted

The custom role grants **read-only** access to:

- **Cloud Logging**: Log-based metrics and sinks
- **Cloud Monitoring**: Alerting policies and notification channels
- **Security Command Center**: Findings and sources
- **Google SecOps (Chronicle)**: Detection rules and alerts
- **Eventarc**: Event triggers
- **Cloud Functions**: Function configurations
- **Cloud Run**: Service configurations
- **Resource Manager**: Project metadata

**We do NOT access:**
- Cloud Storage contents
- BigQuery/Cloud SQL data
- Secret Manager values
- IAM service account keys
- Compute instance data
- VPC flow log contents
- KMS key material

## Customisation

### Custom Pool ID

```hcl
module "a13e_wif" {
  source = "github.com/a13e/terraform-gcp-wif-customer"

  project_id          = "your-gcp-project-id"
  a13e_aws_account_id = "123080274263"
  pool_id             = "my-custom-pool-id"
  provider_id         = "a13e-aws"
}
```

### Organisation-Level Setup

For scanning multiple projects, create the WIF pool at organisation level:

```hcl
# In organisation-level Terraform
module "a13e_wif_org" {
  source = "github.com/a13e/terraform-gcp-wif-customer"

  project_id          = "your-org-admin-project"
  a13e_aws_account_id = "123080274263"
}

# Grant SA access to child projects
resource "google_project_iam_member" "a13e_child_project" {
  project = "child-project-id"
  role    = module.a13e_wif_org.custom_role_id
  member  = "serviceAccount:${module.a13e_wif_org.service_account_email}"
}
```

## Troubleshooting

### Token Exchange Fails

**Error**: `PERMISSION_DENIED: Permission denied on resource...`

**Solution**: Ensure the AWS account ID is correct and the A13E IAM role name matches.

### Impersonation Fails

**Error**: `Request had insufficient authentication scopes`

**Solution**: Verify the `iam.workloadIdentityUser` binding exists on the service account.

### Missing Permissions

**Error**: `PERMISSION_DENIED` on specific API call

**Solution**: Check the custom role includes the required permission. Some services (Chronicle) may require additional organisation-level setup.

## Security Considerations

1. **Attribute Conditions**: The provider has an attribute condition that only allows A13E's specific IAM role to federate.

2. **No Key Storage**: WIF eliminates the need to store or rotate service account keys.

3. **Short-Lived Tokens**: All credentials expire within 1 hour.

4. **Audit Logging**: All API calls are logged in Cloud Audit Logs with the federated identity.

5. **Least Privilege**: Custom role grants minimum read-only permissions.

## Outputs

| Output | Description |
|--------|-------------|
| `workload_identity_pool_id` | Pool ID for A13E configuration |
| `provider_id` | AWS provider ID |
| `service_account_email` | SA email for A13E configuration |
| `a13e_configuration` | All values needed for A13E dashboard |

## Support

If you encounter issues:

1. Check [A13E Documentation](https://docs.a13e.io/gcp-setup)
2. Contact support@a13e.io
3. Open an issue on GitHub

## Licence

MIT Licence - see [LICENCE](LICENCE) for details.
