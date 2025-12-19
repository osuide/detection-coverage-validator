# Getting Started with A13E Detection Coverage Validator

Welcome to A13E! This guide will help you get started with analysing your cloud security detection coverage using the MITRE ATT&CK framework.

## Table of Contents

- [What is A13E?](#what-is-a13e)
- [Creating Your Account](#creating-your-account)
- [Signing In](#signing-in)
- [Dashboard Overview](#dashboard-overview)
- [First Steps](#first-steps)

## What is A13E?

A13E Detection Coverage Validator helps security teams understand and improve their cloud security detection coverage by:

- **Scanning** your AWS and GCP cloud accounts for existing security detections
- **Mapping** those detections to the MITRE ATT&CK framework
- **Analysing** coverage gaps and providing prioritised recommendations
- **Tracking** coverage improvements over time

## Creating Your Account

### Option 1: Email/Password Registration

1. Navigate to the A13E signup page
2. Fill in the required information:
   - **Full Name**: Your name (e.g., "John Doe")
   - **Work Email**: Your professional email address
   - **Password**: Create a strong password that meets these requirements:
     - At least 12 characters long
     - Contains at least one lowercase letter (a-z)
     - Contains at least one uppercase letter (A-Z)
     - Contains at least one number (0-9)
     - Contains at least one special character (@$!%*?&)
   - **Organisation Name**: Your company or team name
3. Check the box to accept the Terms of Service and Privacy Policy
4. Click **Create Account**

### Option 2: Single Sign-On (SSO)

A13E supports SSO for faster, more secure authentication:

#### Google SSO
1. Click **Continue with Google** on the login page
2. Select your Google account
3. Grant permissions when prompted
4. Complete your profile if this is your first login

#### GitHub SSO
1. Click **Continue with GitHub** on the login page
2. Authorize the A13E application
3. Grant permissions to access your basic profile
4. Complete your profile if this is your first login

> **Note**: When signing up with SSO, you'll be prompted to create or join an organisation on your first login.

## Signing In

### Email/Password Sign In

1. Navigate to the login page
2. Enter your **email address** and **password**
3. (Optional) Check **Remember me** to stay signed in
4. Click **Sign in**

### Multi-Factor Authentication (MFA)

If your organisation has MFA enabled:

1. Enter your email and password as usual
2. You'll be redirected to the MFA verification page
3. Enter the 6-digit code from your authenticator app
4. Click **Verify**

### Forgot Password

If you've forgotten your password:

1. Click **Forgot your password?** on the login page
2. Enter your email address
3. Check your email for a password reset link
4. Follow the link and create a new password
5. Sign in with your new password

## Dashboard Overview

After signing in, you'll see the main dashboard with several key sections:

### Summary Statistics

Four metric cards display your current coverage status:

- **Covered**: Number of MITRE ATT&CK techniques with strong detection coverage (≥60% confidence)
- **Partial**: Techniques with moderate coverage (40-60% confidence)
- **Gaps**: Techniques with little to no coverage (<40% confidence)
- **Detections**: Total number of security detections discovered across your accounts

### Coverage Visualisation

#### Overall Coverage Gauge
Shows your overall detection coverage percentage and average confidence score. This gives you a quick snapshot of your security posture.

#### Tactic Coverage Heatmap
Displays coverage across the 14 MITRE ATT&CK tactics:
- Initial Access
- Execution
- Persistence
- Privilege Escalation
- Defense Evasion
- Credential Access
- Discovery
- Lateral Movement
- Collection
- Command and Control
- Exfiltration
- Impact
- Reconnaissance
- Resource Development

Colours indicate coverage level:
- **Green**: Well covered (≥60% confidence)
- **Yellow**: Partially covered (40-60% confidence)
- **Gray**: Uncovered or minimal coverage (<40% confidence)

### Detection Sources

This section shows detections discovered from various AWS services:

- **GuardDuty**: Amazon GuardDuty findings and threat detections
- **Security Hub**: AWS Security Hub controls and findings
- **EventBridge**: Custom EventBridge rules monitoring CloudTrail events
- **CloudWatch Logs**: Log Insights queries and metric filters
- **Config Rules**: AWS Config compliance rules

Each card shows:
- Number of detections from that source
- Status indicator (configured/not configured)

### Top Coverage Gaps

A preview of your most critical coverage gaps, showing:
- Technique ID and name
- Associated MITRE ATT&CK tactic
- Priority level (Critical, High, Medium, Low)

Click **View all gaps →** to see the complete gap analysis.

## First Steps

To get the most value from A13E, follow these steps:

### 1. Add Your First Cloud Account

1. Click **Add Cloud Account** from the dashboard or navigate to the **Accounts** page
2. Enter your cloud account details:
   - **Account Name**: A descriptive name (e.g., "Production AWS")
   - **Provider**: AWS or GCP
   - **Account ID**: Your 12-digit AWS account ID or GCP project ID
3. Click **Add Account**

See [Connecting AWS Accounts](./connecting-aws-accounts.md) for detailed setup instructions.

### 2. Connect Account Credentials

1. After adding an account, click the **Connect** button (link icon)
2. Follow the guided wizard to:
   - Review required permissions
   - Download CloudFormation/Terraform templates OR follow manual setup steps
   - Enter the IAM role ARN or service account credentials
   - Validate the connection
3. Click **Done** when validation succeeds

### 3. Run Your First Scan

1. Navigate to the **Accounts** page
2. Find your connected account
3. Click the **Play** button (▶) to start a scan
4. Monitor scan progress in the status indicator
5. Scan duration varies based on account size (typically 5-15 minutes)

### 4. Explore Your Results

Once the scan completes:

- **Dashboard**: View overall coverage metrics and top gaps
- **Coverage**: Explore the detailed MITRE ATT&CK heatmap
- **Detections**: Review all discovered security detections
- **Gaps**: Analyse prioritised coverage gaps with remediation guidance

### 5. Invite Your Team

1. Navigate to **Settings** → **Team Management**
2. Click **Invite Member**
3. Enter their email address and select a role:
   - **Viewer**: Read-only access
   - **Member**: Can view and edit resources
   - **Admin**: Can manage team members (requires Owner to grant)
4. Add an optional personal message
5. Click **Send Invite**

## Navigation

The main navigation menu includes:

- **Dashboard**: Overview of coverage and key metrics
- **Coverage**: Detailed MITRE ATT&CK heatmap visualisation
- **Detections**: List of all discovered security detections
- **Gaps**: Prioritised coverage gap analysis
- **Accounts**: Manage cloud accounts and run scans
- **Settings**: Organisation, team, billing, and security settings

## Getting Help

- **Documentation**: Access comprehensive guides in the Help section
- **Support**: Contact support@a13e.io for assistance
- **Community**: Join our community forum for best practices and discussions

## Next Steps

- [Connecting AWS Accounts](./connecting-aws-accounts.md) - Detailed guide for AWS integration
- [Running Scans](./running-scans.md) - Learn about scanning options and schedules
- [Understanding Coverage](./understanding-coverage.md) - Deep dive into MITRE ATT&CK coverage analysis
- [Team Management](./team-management.md) - Collaborate with your security team
- [Billing & Subscription](./billing-subscription.md) - Understand plans and upgrade options
