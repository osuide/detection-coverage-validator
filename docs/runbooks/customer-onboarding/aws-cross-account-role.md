# AWS Cross-Account Role Setup Runbook

**Document Type:** Customer Onboarding Runbook
**Version:** 1.1
**Last Updated:** 2026-01-28
**Author:** A13E Documentation Team
**Classification:** Internal / Customer-Facing

---

## Purpose

This runbook provides step-by-step guidance for A13E customers to configure AWS cross-account IAM roles, enabling the A13E Detection Coverage Validator to scan their AWS security detection configurations.

---

## Scope

This document covers:

- Overview of cross-account access architecture
- CloudFormation template deployment (recommended)
- Manual IAM role creation procedure
- Connection validation via the A13E backend API
- Troubleshooting common connection issues
- Security considerations and best practices

This document does **not** cover:

- GCP Workload Identity Federation setup (see separate runbook)
- A13E platform administration
- Detection rule remediation

---

## Prerequisites

Before beginning, ensure you have:

| Requirement | Details |
|-------------|---------|
| **AWS Console Access** | IAM permissions to create roles and policies |
| **AWS Account ID** | Your 12-digit AWS account number |
| **A13E Account** | An active A13E organisation with the target AWS account added |
| **External ID** | Generated automatically when you start the connection wizard |

**Estimated Time:** 5-20 minutes (depending on method chosen)

---

## Overview of Cross-Account Access

### Architecture

A13E uses AWS Security Token Service (STS) `AssumeRole` to obtain temporary credentials for scanning your AWS account. This architecture follows AWS best practices:

```{.dot}
digraph CrossAccountArchitecture {
    rankdir=TB
    splines=ortho
    nodesep=0.5
    ranksep=0.4
    compound=true

    graph [fontname="Arial", bgcolor="white"]
    node [fontname="Arial", fontsize=10, shape=box, style="rounded,filled", penwidth=1.2]
    edge [fontname="Arial", fontsize=9, color="#455a64", penwidth=1.2]

    subgraph cluster_customer {
        label=<<B>CUSTOMER AWS ACCOUNT</B>>
        labeljust=l
        style="rounded,filled"
        fillcolor="#e3f2fd"
        color="#1565c0"
        penwidth=1.5
        fontname="Arial"
        fontsize=11

        customer_role [label=<<TABLE BORDER="0" CELLBORDER="0" CELLSPACING="2">
            <TR><TD><B>IAM Role: A13E-DetectionScanner</B></TD></TR>
            <TR><TD> </TD></TR>
            <TR><TD ALIGN="LEFT"><B><FONT POINT-SIZE="9">Trust Policy:</FONT></B></TD></TR>
            <TR><TD ALIGN="LEFT"><FONT POINT-SIZE="8">- Principal: arn:aws:iam::123080274263:root</FONT></TD></TR>
            <TR><TD ALIGN="LEFT"><FONT POINT-SIZE="8">- Condition: sts:ExternalId = a13e-{customer_id}</FONT></TD></TR>
            <TR><TD> </TD></TR>
            <TR><TD ALIGN="LEFT"><B><FONT POINT-SIZE="9">Permissions Policy:</FONT></B></TD></TR>
            <TR><TD ALIGN="LEFT"><FONT POINT-SIZE="8">- Read-only access to security services</FONT></TD></TR>
            <TR><TD ALIGN="LEFT"><FONT POINT-SIZE="8">- CloudWatch, EventBridge, GuardDuty, Security Hub, etc.</FONT></TD></TR>
        </TABLE>>, fillcolor="#ffffff", color="#1565c0"]
    }

    subgraph cluster_a13e {
        label=<<B>A13E AWS ACCOUNT (123080274263)</B>>
        labeljust=l
        style="rounded,filled"
        fillcolor="#e8f5e9"
        color="#2e7d32"
        penwidth=1.5
        fontname="Arial"
        fontsize=11

        a13e_role [label=<<TABLE BORDER="0" CELLBORDER="0" CELLSPACING="2">
            <TR><TD><B>ECS Task Role</B></TD></TR>
            <TR><TD><FONT POINT-SIZE="9">(A13E scanning infrastructure)</FONT></TD></TR>
            <TR><TD> </TD></TR>
            <TR><TD ALIGN="LEFT"><B><FONT POINT-SIZE="9">Actions:</FONT></B></TD></TR>
            <TR><TD ALIGN="LEFT"><FONT POINT-SIZE="8">1. Call sts:AssumeRole with ExternalId</FONT></TD></TR>
            <TR><TD ALIGN="LEFT"><FONT POINT-SIZE="8">2. Receive temporary credentials (1 hour max)</FONT></TD></TR>
            <TR><TD ALIGN="LEFT"><FONT POINT-SIZE="8">3. Scan security detection configurations</FONT></TD></TR>
            <TR><TD ALIGN="LEFT"><FONT POINT-SIZE="8">4. Return coverage analysis results</FONT></TD></TR>
        </TABLE>>, fillcolor="#ffffff", color="#2e7d32"]
    }

    a13e_role -> customer_role [label="sts:AssumeRole", fontsize=9, color="#e65100", fontcolor="#e65100", penwidth=1.5, dir=both, arrowtail=none]
}
```

### Key Security Features

1. **No Long-Lived Credentials**: A13E never stores AWS access keys. All access uses temporary STS credentials valid for a maximum of 1 hour.

2. **External ID Protection**: The External ID (format: `a13e-{32 hex characters}`) prevents confused deputy attacks by ensuring only A13E can assume the role.

3. **Read-Only Permissions**: The IAM policy grants only `Describe*`, `List*`, and `Get*` permissions. A13E cannot modify any resources.

4. **Audit Trail**: All A13E API calls appear in your CloudTrail logs, identified by the session name `A13E-{timestamp}-{unique_suffix}`.

---

## IAM Role Naming Conventions

A13E supports two naming conventions:

| Convention | Role Name | Use Case |
|------------|-----------|----------|
| **Current** | `a13e-scanner-{customer_id}` | New deployments, multi-tenant environments |
| **Legacy** | `A13E-ReadOnly` | Existing deployments, backward compatibility |

Both conventions are fully supported. Choose whichever best fits your organisation's naming standards.

---

## Trust Policy Requirements

The IAM role must have the following trust policy:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::123080274263:root"
      },
      "Action": "sts:AssumeRole",
      "Condition": {
        "StringEquals": {
          "sts:ExternalId": "a13e-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
        }
      }
    }
  ]
}
```

**Critical Points:**

- The Principal **must** be `arn:aws:iam::123080274263:root` (A13E's AWS account)
- The External ID **must** start with `a13e-` followed by exactly 32 hexadecimal characters
- The External ID is unique per customer connection and provided in the A13E dashboard

---

## Required Permissions (Read-Only)

The following permissions are required for A13E to scan security detection configurations:

### CloudWatch Logs

| Permission | Purpose |
|------------|---------|
| `logs:DescribeQueryDefinitions` | Find saved CloudWatch Logs Insights queries |
| `logs:DescribeLogGroups` | List log groups to find metric filters |
| `logs:DescribeMetricFilters` | Discover detection rules based on log patterns |
| `logs:DescribeSubscriptionFilters` | Identify log forwarding configurations |

### EventBridge

| Permission | Purpose |
|------------|---------|
| `events:ListRules` | List event-driven detection rules |
| `events:DescribeRule` | Get rule details and event patterns |
| `events:ListEventBuses` | Discover custom event buses |
| `events:ListTargetsByRule` | Identify what actions rules trigger |

### CloudWatch Alarms

| Permission | Purpose |
|------------|---------|
| `cloudwatch:DescribeAlarms` | List alerting rules |
| `cloudwatch:DescribeAlarmsForMetric` | Find alarms for specific metrics |

### GuardDuty

| Permission | Purpose |
|------------|---------|
| `guardduty:ListDetectors` | Check if GuardDuty is enabled |
| `guardduty:GetDetector` | Get detector configuration |
| `guardduty:ListFindings` | List finding types (not contents) |

### AWS Config

| Permission | Purpose |
|------------|---------|
| `config:DescribeConfigRules` | List compliance rules |
| `config:DescribeComplianceByConfigRule` | Get rule compliance status |

### Security Hub

| Permission | Purpose |
|------------|---------|
| `securityhub:DescribeHub` | Check if Security Hub is enabled |
| `securityhub:GetEnabledStandards` | List enabled compliance standards |
| `securityhub:DescribeStandardsControls` | Get control details |
| `securityhub:ListSecurityControlDefinitions` | List security control definitions (CSPM) |
| `securityhub:BatchGetSecurityControls` | Get control details and status (CSPM) |

### CloudTrail

| Permission | Purpose |
|------------|---------|
| `cloudtrail:DescribeTrails` | Check audit logging configuration |
| `cloudtrail:GetTrailStatus` | Verify trails are active |
| `cloudtrail:GetEventSelectors` | Check what events are logged |

### Lambda

| Permission | Purpose |
|------------|---------|
| `lambda:ListFunctions` | Find serverless detection functions |
| `lambda:GetFunction` | Get function configuration |
| `lambda:GetFunctionConfiguration` | Get runtime settings |
| `lambda:ListEventSourceMappings` | Identify function triggers |

### STS

| Permission | Purpose |
|------------|---------|
| `sts:GetCallerIdentity` | Validate connection during setup |

### AWS Organizations (Optional)

| Permission | Purpose |
|------------|---------|
| `organizations:DescribeOrganization` | Check if account is in an Organisation |
| `organizations:ListRoots` | Get Organisation root ID |
| `organizations:ListParents` | Walk account's parent hierarchy |
| `organizations:DescribeOrganizationalUnit` | Get OU names for hierarchy path |

**Note:** These permissions are optional. Without them:
- Accounts in AWS Organizations will show `null` for hierarchy path
- Standalone accounts will correctly show "Standalone"
- All other A13E features work normally

---

## Step-by-Step Instructions

### Method 1: CloudFormation Deployment (Recommended)

**Time Required:** 5 minutes

#### Step 1: Add Your Account in A13E

1. Navigate to **Accounts** in the A13E dashboard
2. Click **Add Account**
3. Enter:
   - **Account Name**: Descriptive name (e.g., "Production AWS")
   - **Provider**: AWS
   - **Account ID**: Your 12-digit AWS account ID
   - **Regions**: Select regions to scan
4. Click **Add Account**

#### Step 2: Start the Connection Wizard

1. Click the **Connect** button (link icon) on your new account
2. Review the permissions A13E will request
3. Click **Continue**

#### Step 3: Download the Template

1. Ensure **Use Template** is selected
2. Click **CloudFormation** to download `a13e-iam-role.yaml`
3. Note the **A13E AWS Account ID** (`123080274263`) and **External ID** displayed

#### Step 4: Deploy in AWS Console

1. Sign in to the AWS Console for the target account
2. Navigate to **CloudFormation** > **Stacks**
3. Click **Create stack** > **With new resources (standard)**
4. Select **Upload a template file**
5. Upload the downloaded `a13e-iam-role.yaml`
6. Click **Next**

#### Step 5: Configure Stack Parameters

| Parameter | Value |
|-----------|-------|
| **Stack name** | `A13E-DetectionScanner` |
| **A13ETrustAccountId** | `123080274263` (default) |
| **ExternalId** | Paste from A13E wizard (format: `a13e-{32 hex chars}`) |
| **RoleName** | `A13E-DetectionScanner` (or your preferred name) |

> **Warning:** The External ID must match exactly. Copy it directly from the A13E wizard to avoid errors.

Click **Next** and accept defaults on subsequent pages.

#### Step 6: Create the Stack

1. Review the configuration
2. **Check the acknowledgement box**: "I acknowledge that AWS CloudFormation might create IAM resources"
3. Click **Submit**
4. Wait for status: **CREATE_COMPLETE** (1-2 minutes)

#### Step 7: Copy the Role ARN

1. Go to the **Outputs** tab of your stack
2. Copy the **RoleArn** value

Format: `arn:aws:iam::{your-account-id}:role/A13E-DetectionScanner`

#### Step 8: Complete Connection in A13E

1. Return to the A13E connection wizard
2. Click **I've Created the Role**
3. Paste the **Role ARN**
4. Click **Validate Connection**
5. Wait for validation (green checkmarks indicate success)
6. Click **Done**

---

### Method 2: Manual IAM Role Creation

**Time Required:** 15-20 minutes

Use this method if your organisation requires manual change control or does not permit CloudFormation.

#### Step 1: Create the IAM Policy

1. In AWS Console, navigate to **IAM** > **Policies**
2. Click **Create policy**
3. Select the **JSON** tab
4. Paste the following policy:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "CloudWatchLogsAccess",
      "Effect": "Allow",
      "Action": [
        "logs:DescribeLogGroups",
        "logs:DescribeMetricFilters",
        "logs:DescribeSubscriptionFilters",
        "logs:DescribeQueryDefinitions"
      ],
      "Resource": "*"
    },
    {
      "Sid": "CloudWatchAlarmsAccess",
      "Effect": "Allow",
      "Action": [
        "cloudwatch:DescribeAlarms",
        "cloudwatch:DescribeAlarmsForMetric"
      ],
      "Resource": "*"
    },
    {
      "Sid": "EventBridgeAccess",
      "Effect": "Allow",
      "Action": [
        "events:ListRules",
        "events:DescribeRule",
        "events:ListTargetsByRule",
        "events:ListEventBuses"
      ],
      "Resource": "*"
    },
    {
      "Sid": "GuardDutyAccess",
      "Effect": "Allow",
      "Action": [
        "guardduty:ListDetectors",
        "guardduty:GetDetector",
        "guardduty:ListFindings",
        "guardduty:GetFindings"
      ],
      "Resource": "*"
    },
    {
      "Sid": "SecurityHubAccess",
      "Effect": "Allow",
      "Action": [
        "securityhub:DescribeHub",
        "securityhub:GetEnabledStandards",
        "securityhub:DescribeStandards",
        "securityhub:DescribeStandardsControls",
        "securityhub:GetInsights",
        "securityhub:ListEnabledProductsForImport",
        "securityhub:ListSecurityControlDefinitions",
        "securityhub:BatchGetSecurityControls",
        "securityhub:ListStandardsControlAssociations"
      ],
      "Resource": "*"
    },
    {
      "Sid": "ConfigAccess",
      "Effect": "Allow",
      "Action": [
        "config:DescribeConfigRules",
        "config:DescribeComplianceByConfigRule"
      ],
      "Resource": "*"
    },
    {
      "Sid": "CloudTrailAccess",
      "Effect": "Allow",
      "Action": [
        "cloudtrail:DescribeTrails",
        "cloudtrail:GetTrailStatus",
        "cloudtrail:GetEventSelectors"
      ],
      "Resource": "*"
    },
    {
      "Sid": "LambdaAccess",
      "Effect": "Allow",
      "Action": [
        "lambda:ListFunctions",
        "lambda:ListEventSourceMappings",
        "lambda:GetFunction",
        "lambda:GetFunctionConfiguration"
      ],
      "Resource": "*"
    },
    {
      "Sid": "InspectorAccess",
      "Effect": "Allow",
      "Action": [
        "inspector2:BatchGetAccountStatus",
        "inspector2:ListCoverage",
        "inspector2:ListCoverageStatistics",
        "inspector2:ListFindingAggregations"
      ],
      "Resource": "*"
    },
    {
      "Sid": "MacieAccess",
      "Effect": "Allow",
      "Action": [
        "macie2:GetMacieSession",
        "macie2:GetAutomatedDiscoveryConfiguration",
        "macie2:ListClassificationJobs",
        "macie2:GetFindingStatistics",
        "macie2:GetBucketStatistics"
      ],
      "Resource": "*"
    },
    {
      "Sid": "OrganizationsAccess",
      "Effect": "Allow",
      "Action": [
        "organizations:DescribeOrganization",
        "organizations:ListRoots",
        "organizations:ListParents",
        "organizations:DescribeOrganizationalUnit"
      ],
      "Resource": "*"
    }
  ]
}
```

5. Click **Next**
6. Enter:
   - **Name**: `A13E-DetectionScanner-Policy`
   - **Description**: "Read-only access for A13E detection coverage scanning"
7. Click **Create policy**

#### Step 2: Create the IAM Role

1. Navigate to **IAM** > **Roles**
2. Click **Create role**
3. Select **AWS account** as the trusted entity type
4. Choose **Another AWS account**
5. Enter **Account ID**: `123080274263`
6. **Check**: Require external ID
7. Enter the **External ID** from the A13E wizard
8. Click **Next**

#### Step 3: Attach the Policy

1. Search for `A13E-DetectionScanner-Policy`
2. Select it
3. Click **Next**

#### Step 4: Name and Create the Role

1. Enter:
   - **Role name**: `A13E-DetectionScanner` (or `A13E-ReadOnly` for legacy compatibility)
   - **Description**: "Cross-account role for A13E detection coverage scanning"
2. Review the trust policy and permissions
3. Click **Create role**

#### Step 5: Copy the Role ARN

1. Click on your newly created role
2. Copy the **ARN** from the role summary

#### Step 6: Complete Connection in A13E

Follow Step 8 from the CloudFormation method above.

---

## Connection Validation

When you click **Validate Connection** in A13E, the backend performs the following checks:

### Validation Process

1. **Role Assumption Test**
   - A13E calls `sts:AssumeRole` with the provided Role ARN and External ID
   - Verifies the trust policy is correctly configured
   - Obtains temporary credentials

2. **Permission Checks (Parallel)**
   - CloudWatch Logs: `describe_log_groups` (limit 1)
   - CloudWatch: `describe_alarms` (max 1)
   - EventBridge: `list_rules` (limit 1)
   - GuardDuty: `list_detectors`
   - Security Hub: `describe_hub`
   - Config: `describe_config_rules`
   - CloudTrail: `describe_trails`
   - Lambda: `list_functions` (max 1)

3. **Result Determination**
   - **VALID**: All permission checks pass
   - **PERMISSION_ERROR**: Role assumption succeeded but some permissions are missing
   - **INVALID**: Role assumption failed (trust policy or External ID issue)

### Validation Response Example

```json
{
  "status": "valid",
  "message": "All 24 required permissions verified.",
  "granted_permissions": [
    "logs:DescribeLogGroups",
    "logs:DescribeMetricFilters",
    "cloudwatch:DescribeAlarms",
    "..."
  ],
  "missing_permissions": []
}
```

---

## Troubleshooting

### Error: "Access Denied when assuming role"

**Cause:** Trust policy misconfiguration

**Resolution:**

1. In AWS Console, go to **IAM** > **Roles** > your A13E role
2. Click the **Trust relationships** tab
3. Verify:
   - Principal is `arn:aws:iam::123080274263:root`
   - External ID matches exactly (including the `a13e-` prefix)

### Error: "External ID mismatch"

**Cause:** The External ID in the role does not match A13E's records

**Resolution:**

1. Check the External ID in the A13E connection wizard
2. Update the role's trust policy with the correct External ID
3. Re-validate the connection

### Error: "Role not found"

**Cause:** Incorrect Role ARN or role does not exist

**Resolution:**

1. Verify the Role ARN format: `arn:aws:iam::{account-id}:role/{role-name}`
2. Ensure you are using the correct AWS account ID
3. Copy the ARN directly from the AWS Console

### Error: "Missing permissions"

**Cause:** IAM policy is incomplete or outdated

**Resolution:**

1. Download the latest policy from the A13E connection wizard
2. Update the IAM policy attached to the role
3. Re-validate the connection

### Error: "MalformedPolicyDocument"

**Cause:** Trust policy has syntax errors

**Resolution:**

1. Re-create the role using the CloudFormation template
2. Ensure no manual edits introduced JSON syntax errors

### Connection Shows "Pending Validation"

**Cause:** Validation has not been run or previous validation expired

**Resolution:**

1. Click the **Settings** icon on the account card
2. Select **Validate Connection**
3. Wait for validation to complete

### Account hierarchy not showing

**Cause:** Missing Organizations permissions (optional feature)

**Resolution:**

1. Verify the IAM role has the following permissions:
   - `organizations:DescribeOrganization`
   - `organizations:ListRoots`
   - `organizations:ListParents`
   - `organizations:DescribeOrganizationalUnit`
2. Update the IAM policy using the latest template from A13E
3. Wait up to 24 hours for cache to expire, or clear cache via support

**Note:** If the account is not in an AWS Organization, it will show "Standalone" which is correct behaviour.

---

## Best Practices and Tips

### Security Recommendations

1. **Use CloudFormation or Terraform**: Infrastructure-as-Code ensures consistent, auditable deployments

2. **Never Share External IDs**: Treat the External ID as sensitive information specific to your A13E connection

3. **Enable CloudTrail**: Monitor A13E's access by filtering CloudTrail logs for the role name

4. **Periodic Review**: Review the role's permissions quarterly to ensure they match A13E's documented requirements

5. **Separate Roles per Account**: Create individual roles for each AWS account rather than reusing credentials

### Operational Tips

1. **Use Descriptive Names**: Include environment identifiers in account names (e.g., "Prod-EU-West", "Dev-US-East")

2. **Document External IDs**: Store External IDs securely in your organisation's credential management system

3. **Test in Non-Production First**: Validate the setup in a development or staging account before production

4. **StackSets for Multi-Account**: Use CloudFormation StackSets to deploy the role across multiple accounts in AWS Organisations

---

## Security Considerations

### What A13E Can Access

| Category | Access Level |
|----------|--------------|
| Security detection configurations | Read-only |
| Alarm and rule metadata | Read-only |
| Service enablement status | Read-only |
| Finding types and counts | Read-only |

### What A13E Cannot Access

| Category | Access Level |
|----------|--------------|
| Log contents or log data | No access |
| S3 bucket contents | No access |
| Database data | No access |
| Secrets or credentials | No access |
| IAM user access keys | No access |
| Any write/modify operations | No access |

### Credential Security

- **No Stored Secrets**: A13E uses STS temporary credentials, not long-lived access keys
- **1-Hour Maximum Session**: Credentials automatically expire after 1 hour
- **Automatic Rotation**: New credentials are obtained for each scan
- **Audit Trail**: All access is logged in your CloudTrail with session name `A13E-{timestamp}-{suffix}`

---

## Glossary

| Term | Definition |
|------|------------|
| **Cross-Account Access** | AWS mechanism allowing one account to access resources in another account |
| **External ID** | A unique identifier used in trust policies to prevent confused deputy attacks |
| **STS** | AWS Security Token Service, used to obtain temporary credentials |
| **AssumeRole** | STS API call to obtain temporary credentials for a specified IAM role |
| **Confused Deputy Attack** | A security vulnerability where an attacker tricks a trusted service into accessing resources on their behalf |
| **Trust Policy** | IAM policy defining which principals can assume a role |
| **CSPM** | Cloud Security Posture Management, Security Hub's consolidated controls feature |

---

## Related Documentation

- [Connecting AWS Accounts (User Guide)](../../../frontend/public/docs/connecting-aws-accounts.md)
- [Running Scans](../../../frontend/public/docs/running-scans.md)
- [Understanding Coverage](../../../frontend/public/docs/understanding-coverage.md)
- [GCP Workload Identity Federation Setup](./gcp-workload-identity-federation.md) (separate runbook)

---

## Document Metadata

| Field | Value |
|-------|-------|
| **Document ID** | RB-ONBOARD-AWS-001 |
| **Version** | 1.1 |
| **Status** | Published |
| **Owner** | A13E Platform Team |
| **Review Cycle** | Quarterly |
| **Next Review** | 2026-04-28 |
| **A13E AWS Account ID** | 123080274263 |
| **CloudFormation Template Version** | 2010-09-09 |

---

## Revision History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2026-01-09 | A13E Documentation Team | Initial release |
| 1.1 | 2026-01-28 | A13E Platform Team | Added AWS Organizations permissions for hierarchy feature |
