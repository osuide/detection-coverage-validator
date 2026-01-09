# Connecting AWS Accounts

Connect your AWS accounts to A13E for security detection scanning using a read-only IAM role.

## TL;DR

- A13E uses a **read-only IAM role** with cross-account access
- Choose **CloudFormation** (5 minutes), **Terraform** (10 minutes), or **Manual** (15-20 minutes)
- The IAM role uses an **External ID** to prevent confused deputy attacks
- A13E **cannot** modify resources, read log contents, or access secrets

---

## Before You Start

You'll need:

- **AWS Console access**: Permission to create IAM roles and policies
- **AWS Account ID**: Your 12-digit account number
- **About 10 minutes**: For the complete setup process

During setup, A13E provides an **External ID**—a unique security token that ensures only A13E can assume the role.

---

## Understanding Permissions

A13E uses **read-only permissions** following the principle of least privilege.

### What A13E Can Access

| Service | Permissions | Purpose |
|---------|-------------|---------|
| GuardDuty | Read detector configuration | Discover threat detection rules |
| Security Hub | Read findings and controls | Map compliance to MITRE |
| EventBridge | Read rules and targets | Discover custom detection rules |
| CloudWatch Logs | Read log groups, queries | Find Insights queries and filters |
| CloudWatch | Read alarms and metrics | Discover alarm configurations |
| Config | Read rules and compliance | Find compliance rules |
| CloudTrail | Read trail configuration | Verify logging is enabled |
| Inspector | Read findings | Discover vulnerability detections |
| Macie | Read findings | Discover data protection detections |
| Lambda | List functions (metadata only) | Identify custom detections |
| IAM | Read role info (self only) | Validate connection |

### What A13E Cannot Access

- ❌ Billing or cost data
- ❌ Modify any resources
- ❌ Read actual log contents
- ❌ Access secrets or credentials
- ❌ Launch or terminate compute resources
- ❌ Access S3 object contents

---

## Connection Methods

Choose the method that best fits your workflow:

| Method | Best For | Time |
|--------|----------|------|
| **CloudFormation** | Quick setup, AWS Console users | 5 minutes |
| **Terraform** | Infrastructure-as-Code workflows | 10 minutes |
| **Manual** | Custom setups, strict change control | 15-20 minutes |

---

## Method 1: CloudFormation (Recommended)

The fastest way to connect your AWS account.

### Step 1: Add Your Account in A13E

1. Navigate to **Accounts** in A13E
2. Click **Add Account**
3. Enter:
   - **Account Name**: Descriptive name (e.g., "Production AWS")
   - **Provider**: AWS
   - **Account ID**: Your 12-digit AWS account ID
   - **Regions**: Select which regions to scan
4. Click **Add Account**

### Step 2: Start the Connection Wizard

1. Click the **Connect** button (link icon) on your new account
2. Review the permissions A13E will request
3. Click **Continue**

### Step 3: Download the Template

1. Ensure **Use Template** is selected
2. Click **CloudFormation** to download `a13e-iam-role.yaml`
3. Note the **A13E AWS Account ID** and **External ID** shown at the top

### Step 4: Deploy in AWS Console

1. Sign in to the **AWS Console** for the account you're connecting
2. Navigate to **CloudFormation** → **Stacks**
3. Click **Create stack** → **With new resources (standard)**
4. Select **Upload a template file**
5. Upload the downloaded `a13e-iam-role.yaml`
6. Click **Next**

### Step 5: Configure Stack Parameters

> ⚠️ **Important**: You **must** update the ExternalId parameter before deploying. The template will fail validation if you leave it as the placeholder value. Copy the External ID exactly as shown in the A13E wizard.

1. **Stack name**: `A13E-ReadOnlyRole`
2. **Parameters**:
   - **A13EAccountId**: Leave as default (`123080274263`) unless instructed otherwise
   - **ExternalId**: Paste the External ID from the A13E wizard (format: `a13e-` followed by 32 hex characters)
3. Click **Next**
4. Accept defaults on the Configure stack options page
5. Click **Next**

### Step 6: Create the Stack

1. Review the configuration
2. **Check the acknowledgement box**: "I acknowledge that AWS CloudFormation might create IAM resources"
3. Click **Submit**
4. Wait for status to show **CREATE_COMPLETE** (1-2 minutes)

### Step 7: Copy the Role ARN

1. Go to the **Outputs** tab of your stack
2. Copy the **RoleArn** value
   - Format: `arn:aws:iam::123456789012:role/A13E-ReadOnly`

### Step 8: Complete Connection in A13E

1. Return to the A13E connection wizard
2. Click **I've Created the Role**
3. Paste the **Role ARN**
4. Click **Continue**
5. Click **Validate Connection**
6. Wait for validation to complete (shows green checkmarks for each permission)
7. Click **Done**

Your account now shows "Connected" status and you can run scans.

---

## Method 2: Terraform

For teams using Infrastructure-as-Code.

### Step 1: Start the Wizard

Follow Steps 1-2 from the CloudFormation method to add your account and start the connection wizard.

### Step 2: Download Terraform Module

1. Click **Terraform** to download the Terraform configuration
2. Note the **A13E AWS Account ID** and **External ID**

### Step 3: Apply the Configuration

```bash
# Navigate to where you saved the file
cd path/to/a13e-terraform

# Update variables in the .tf file or create a terraform.tfvars:
# a13e_account_id = "FROM_WIZARD"
# external_id = "FROM_WIZARD"

# Initialise and apply
terraform init
terraform plan
terraform apply

# Get the role ARN
terraform output role_arn
```

### Step 4: Complete Connection

1. Copy the role ARN from the Terraform output
2. Return to A13E and complete the connection wizard (Step 8 from CloudFormation method)

---

## Method 3: Manual Setup

For organisations with strict change control processes.

### Step 1: Create the IAM Policy

1. In AWS Console, go to **IAM** → **Policies**
2. Click **Create policy**
3. Switch to **JSON** tab
4. Paste the policy JSON from the A13E connection wizard
5. Click **Next**
6. **Name**: `A13E-DetectionScanner`
7. **Description**: "Read-only access for A13E detection scanning"
8. Click **Create policy**

### Step 2: Create the IAM Role

1. Go to **IAM** → **Roles**
2. Click **Create role**
3. **Trusted entity type**: AWS account
4. Select **Another AWS account**
5. Enter the **A13E AWS Account ID** from the wizard
6. **Check**: Require external ID
7. Enter the **External ID** from the wizard
8. Click **Next**

### Step 3: Attach the Policy

1. Search for `A13E-DetectionScanner`
2. Check the box to select it
3. Click **Next**

### Step 4: Name and Create

1. **Role name**: `A13E-ReadOnly`
2. **Description**: "Cross-account role for A13E detection coverage scanning"
3. Review the trusted entities and permissions
4. Click **Create role**

### Step 5: Copy the Role ARN

1. Click on your new role
2. Copy the **ARN** from the role summary

### Step 6: Complete Connection

Return to A13E and complete the connection wizard (Step 8 from CloudFormation method).

---

## Validating Your Connection

When you click **Validate Connection**, A13E:

1. Assumes the IAM role using the External ID
2. Tests each required permission
3. Reports success or failure for each service

### Successful Validation

You'll see green checkmarks for:
- ✓ GuardDuty access
- ✓ Security Hub access
- ✓ EventBridge access
- ✓ CloudWatch access
- ✓ Config access
- ✓ CloudTrail access

### Failed Validation

If validation fails, check the specific error:

| Error | Cause | Solution |
|-------|-------|----------|
| **Trust relationship error** | External ID mismatch | Verify External ID matches exactly |
| **Role not found** | Typo in Role ARN | Copy ARN directly from AWS Console |
| **Access denied** | Missing permissions | Ensure policy is attached to role |
| **Missing permissions** | Incomplete policy | Update policy with latest from wizard |

---

## Troubleshooting

### "Access Denied" Error

The IAM role's trust relationship may be incorrect.

1. In AWS Console, go to **IAM** → **Roles** → your A13E role
2. Click the **Trust relationships** tab
3. Verify the Principal matches the A13E Account ID
4. Verify the `sts:ExternalId` condition matches exactly

### "Missing Permissions" Error

The policy may be incomplete or outdated.

1. Download the latest policy JSON from the A13E wizard
2. Update your IAM policy in AWS Console
3. Re-validate the connection in A13E

### "Invalid Role ARN Format" Error

Role ARN format: `arn:aws:iam::ACCOUNT_ID:role/ROLE_NAME`

- Ensure no extra spaces
- Copy directly from AWS Console
- Don't include any angle brackets or placeholders

### Connection Shows "Pending Validation"

Click the **Settings** icon on the account card and select **Validate Connection** to retry.

---

## Updating Permissions

When A13E adds new features requiring additional permissions:

1. Download the latest template from the A13E wizard
2. **Update** your existing stack or policy (don't create new resources)
   - CloudFormation: Update stack with new template
   - Terraform: Update module and run `terraform apply`
   - Manual: Update the IAM policy JSON
3. Re-validate the connection in A13E

---

## Multi-Account Setup

### AWS Organisations

Use CloudFormation StackSets to deploy the IAM role to multiple accounts:

1. In CloudFormation, go to **StackSets**
2. Create a new StackSet with the A13E template
3. Target your desired accounts or organisational units (OUs)
4. Deploy to all accounts

Then add each account in A13E and complete the connection using the Role ARN.

### Separate AWS Accounts

Add each account individually in A13E:

1. Add account with unique name
2. Complete connection wizard
3. Validate credentials
4. Repeat for each account

Coverage analysis will aggregate results across all connected accounts.

---

## Security Considerations

### External ID

The External ID prevents confused deputy attacks. Never share your External ID publicly.

### Read-Only Access

A13E's IAM policy grants only read permissions. The role cannot:
- Create, modify, or delete resources
- Access customer data in S3, databases, or logs
- Assume other roles or escalate privileges

### Credential Rotation

The IAM role uses AWS STS for temporary credentials that automatically rotate. No long-term credentials are stored.

### Audit Trail

All A13E API calls to your account are logged in CloudTrail. You can filter for the role name to see exactly what A13E accesses.

---

## Next Steps

- [Running Scans](./running-scans.md) - Start scanning for detection coverage
- [Understanding Coverage](./understanding-coverage.md) - Interpret your results
- [Using the Dashboards](./using-dashboards.md) - Navigate your coverage data
