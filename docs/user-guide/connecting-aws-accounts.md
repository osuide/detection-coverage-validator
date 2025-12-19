# Connecting AWS Accounts

This guide walks you through connecting your AWS accounts to A13E for security detection scanning.

## Prerequisites

Before connecting an AWS account, ensure you have:

- **AWS Permissions**: Administrator access or IAM creation permissions (`iam:CreateRole`, `iam:CreatePolicy`, `cloudformation:CreateStack`)
- **AWS Account ID**: Your 12-digit AWS account number
- **A13E Account**: Access to the A13E dashboard

During setup, you'll receive an **External ID** from A13E—a unique security token that prevents confused deputy attacks.

## Understanding Permissions

A13E uses **read-only permissions** following the principle of least privilege. The IAM role grants access to:

- GuardDuty, Security Hub, EventBridge findings
- CloudWatch Logs metadata (log groups, metric filters)
- AWS Config rules and CloudTrail trail configurations
- IAM role validation (self-inspection only)

A13E **cannot** access billing data, modify resources, read log contents, access secrets, or control compute resources

## Connection Methods

A13E offers three methods to connect your AWS account. Choose the one that best fits your workflow:

| Method | Best For | Time Required |
|--------|----------|---------------|
| **CloudFormation** | Quick setup, AWS Console users | 5 minutes |
| **Terraform** | Infrastructure-as-Code workflows | 10 minutes |
| **Manual** | Custom setups, strict change control | 15-20 minutes |

## Method 1: CloudFormation (Recommended)

CloudFormation provides one-click deployment of the required IAM role and policy.

### Step 1: Add Your Account

1. Navigate to **Accounts** in the A13E dashboard
2. Click **Add Account**
3. Enter account details:
   - **Account Name**: `Production AWS` (or your preferred name)
   - **Provider**: Select **AWS**
   - **Account ID**: Your 12-digit AWS account ID
4. Click **Add Account**

### Step 2: Start Connection Wizard

1. Click the **Connect** button (link icon) next to your new account
2. Review the required permissions page
3. Click **Continue**

### Step 3: Download CloudFormation Template

1. On the **Setup Access** screen, ensure **Use Template** is selected
2. Click the **CloudFormation** card to download `a13e-iam-role.yaml`
3. Note the **A13E AWS Account ID** and **External ID** displayed at the top

### Step 4: Deploy in AWS Console

1. Sign in to the **AWS Console** for the account you're connecting
2. Navigate to **CloudFormation** → **Stacks**
3. Click **Create stack** → **With new resources**
4. Select **Upload a template file**
5. Upload the `a13e-iam-role.yaml` file
6. Click **Next**

### Step 5: Configure Stack

1. **Stack name**: `A13E-ReadOnlyRole` (or your preferred name)
2. **Parameters**:
   - **A13EAccountId**: Paste the A13E AWS Account ID from the wizard
   - **ExternalId**: Paste the External ID from the wizard
3. Click **Next**

### Step 6: Review and Create

1. Review the stack configuration
2. Check the box: **"I acknowledge that AWS CloudFormation might create IAM resources"**
3. Click **Create stack**
4. Wait for stack status to show **CREATE_COMPLETE** (usually 1-2 minutes)

### Step 7: Copy Role ARN

1. In the CloudFormation stack, go to **Outputs** tab
2. Copy the **RoleArn** value (e.g., `arn:aws:iam::123456789012:role/A13E-ReadOnly`)

### Step 8: Complete Connection

1. Return to the A13E connection wizard
2. Click **I've Created the Role** to proceed to credentials step
3. Paste the **Role ARN** into the input field
4. Click **Continue**
5. Click **Validate Connection**
6. Wait for validation to complete
7. Click **Done** when validation succeeds

## Method 2: Terraform

For infrastructure-as-code workflows:

1. Follow the initial account setup from Method 1 (Steps 1-2)
2. Download the Terraform module (`a13e-aws-role.tf`) from the connection wizard
3. Update variables with the A13E Account ID and External ID from the wizard
4. Apply the configuration:
   ```bash
   terraform init
   terraform apply
   terraform output role_arn
   ```
5. Copy the Role ARN and complete connection in the A13E wizard (same as CloudFormation Step 8)

## Method 3: Manual IAM Setup

For organisations with strict change control processes:

1. Follow the initial account setup from Method 1 (Steps 1-2)
2. In AWS Console, create an IAM policy:
   - Copy the policy JSON from the A13E connection wizard
   - Create policy named `A13E-DetectionScanner`
3. Create an IAM role:
   - Trusted entity: **Another AWS account**
   - Enter A13E Account ID and External ID from wizard
   - Attach the `A13E-DetectionScanner` policy
   - Name the role `A13E-ReadOnly`
4. Copy the Role ARN from the role summary
5. Complete connection in the A13E wizard (same as CloudFormation Step 8)

## Validating Your Connection

After entering the Role ARN, A13E validates by:
1. Assuming the role with the external ID
2. Testing each required permission
3. Verifying access to GuardDuty, Security Hub, and other services

**Successful validation** shows a green "Valid" badge with granted permissions listed.

**Failed validation** shows error details. Common issues:
- **Trust relationship error**: Verify External ID and A13E Account ID match exactly
- **Missing permissions**: Ensure the IAM policy is attached to the role
- **Role not found**: Check the Role ARN for typos

## Troubleshooting

### "Access Denied" or "Not Authorized"
Check the IAM role's **Trust relationships** tab. Verify the Principal account and external ID condition match exactly what's shown in the A13E wizard.

### "Missing Permissions"
In IAM, verify the `A13E-DetectionScanner` policy is attached to the role. Compare the policy JSON with the latest version in the connection wizard.

### "Invalid Role ARN Format"
Verify format: `arn:aws:iam::ACCOUNT_ID:role/ROLE_NAME`. Copy directly from AWS Console to avoid typos.

### Connection Shows "Pending Validation"
Click the Settings button (gear icon) on the account card and select **Validate Connection**.

### Updating Permissions
When A13E adds new features requiring additional permissions:
1. Download the latest template from A13E
2. **Update** your existing CloudFormation stack or run `terraform apply` (don't create new resources)
3. Re-validate the connection in A13E

## Multi-Account Setup

**For AWS Organisations**: Use CloudFormation StackSets to deploy the IAM role to multiple accounts simultaneously. Upload the A13E template to StackSets and target your desired accounts or OUs.

**For separate accounts**: Add each account individually in A13E and complete the connection process. Coverage analysis will aggregate results across all connected accounts.

## Next Steps

After connecting your AWS account:
- [Running Scans](./running-scans.md) - Start scanning for detection coverage
- [Understanding Coverage](./understanding-coverage.md) - Interpret your results
- [Team Management](./team-management.md) - Share access with your team

Need help? Check AWS CloudTrail for AssumeRole errors, test permissions using the IAM Policy Simulator, or contact support@a13e.io with your Role ARN and error details
