# Getting Started with A13E

Get up and running with A13E Detection Coverage Validator in under 15 minutes.

## TL;DR

- **Create an account** using email/password, Google, or GitHub SSO
- **Add your AWS or GCP account** with read-only credentials
- **Run your first scan** to discover existing security detections
- **View your coverage** on the MITRE ATT&CK heatmap to identify gaps

---

## What is A13E?

A13E Detection Coverage Validator helps security teams understand how well their cloud environment can detect attacks. It:

- **Scans** your AWS and GCP accounts for security detections (GuardDuty, Security Hub, EventBridge rules, CloudWatch alarms, Config rules)
- **Maps** those detections to the MITRE ATT&CK framework
- **Identifies gaps** where you lack detection capability
- **Provides remediation** with ready-to-deploy Infrastructure-as-Code templates

---

## Creating Your Account

### Option 1: Email and Password

1. Navigate to the A13E signup page
2. Fill in your details:
   - **Full Name**: Your name as you'd like it displayed
   - **Work Email**: Your professional email address
   - **Password**: Must meet all requirements:
     - At least 12 characters
     - One lowercase letter (a-z)
     - One uppercase letter (A-Z)
     - One number (0-9)
     - One special character (@$!%*?&)
   - **Organisation Name**: Your company or team name
3. Accept the Terms of Service and Privacy Policy
4. Click **Create Account**

### Option 2: Google SSO

1. Click **Continue with Google** on the login page
2. Select your Google account
3. Grant the requested permissions
4. You'll be signed in and taken to the dashboard

### Option 3: GitHub SSO

1. Click **Continue with GitHub** on the login page
2. Authorise the A13E application
3. You'll be signed in and taken to the dashboard

> **Note**: When signing up with SSO, an organisation is automatically created for you (e.g., "John's Organization"). You can rename it later in your organisation settings.

---

## Signing In

### Standard Sign In

1. Go to the login page
2. Enter your **email address** and **password**
3. Click **Sign in**

### Multi-Factor Authentication (MFA)

If you've enabled MFA:

1. Enter your email and password as usual
2. You'll be redirected to the MFA verification page
3. Enter the 6-digit code from your authenticator app
4. Click **Verify**

### Forgot Password

1. Click **Forgot your password?** on the login page
2. Enter your email address
3. Check your inbox for a reset link
4. Follow the link to create a new password

---

## Setting Up MFA

We strongly recommend enabling MFA for all accounts, especially Admin and Owner roles.

1. Navigate to **Profile** (click your avatar in the bottom-left sidebar)
2. Find the **Security** section
3. Click **Enable MFA**
4. Scan the QR code with your authenticator app (Google Authenticator, Authy, 1Password, etc.)
5. Enter the 6-digit verification code
6. Save your backup codes in a secure location

> **Tip**: Store backup codes somewhere safe. If you lose access to your authenticator app, you'll need these to recover your account.

---

## Your First Steps

After signing in, follow these steps to see your first coverage report:

### Step 1: Add Your First Cloud Account

1. From the Dashboard, click **Add Cloud Account** (or navigate to **Accounts**)
2. Enter account details:
   - **Account Name**: A descriptive name (e.g., "Production AWS")
   - **Provider**: AWS or GCP
   - **Account ID**: Your 12-digit AWS account ID or GCP project ID
   - **Regions**: Select which regions to scan (eu-west-2 is selected by default)
3. Click **Add Account**

### Step 2: Connect Credentials

1. Click the **Connect** button (link icon) on your new account
2. Review the required permissions
3. Choose your setup method:
   - **CloudFormation** (recommended for AWS): One-click deployment
   - **Terraform**: For Infrastructure-as-Code workflows
   - **Manual**: Step-by-step IAM role creation
4. Follow the guided wizard to create the IAM role
5. Enter the Role ARN and click **Validate Connection**
6. Click **Done** when validation succeeds

See [Connecting AWS Accounts](./connecting-aws-accounts.md) or [Connecting GCP Accounts](./connecting-gcp-accounts.md) for detailed instructions.

### Step 3: Run Your First Scan

1. Navigate to **Accounts**
2. Find your connected account (shows "Connected" status)
3. Click the **Play** button (▶) to start scanning
4. Watch the progress bar as A13E discovers your detections
5. Typical scan time: 5-15 minutes depending on account size

### Step 4: Explore Your Results

Once the scan completes, explore your coverage:

| Page | What You'll See |
|------|-----------------|
| **Dashboard** | Coverage percentage, tactic heatmap, detection sources, top gaps |
| **Coverage** | Full MITRE ATT&CK heatmap with 168 cloud techniques |
| **Detections** | All discovered security detections with MITRE mappings |
| **Gaps** | Prioritised coverage gaps with remediation guidance |
| **Compliance** | Framework coverage (CIS Controls, NIST 800-53) |

### Step 5: Invite Your Team

1. Navigate to **Settings** → **Team Management**
2. Click **Invite Member**
3. Enter their email and select a role:
   - **Viewer**: Read-only access to dashboards and reports
   - **Member**: Can run scans and view all data
   - **Admin**: Can manage team members and settings
4. Click **Send Invite**

---

## Navigation Overview

The main navigation menu includes:

| Menu Item | Description |
|-----------|-------------|
| **Dashboard** | High-level coverage metrics and key insights |
| **Coverage** | Detailed MITRE ATT&CK heatmap visualisation |
| **Detections** | Browse all discovered security detections |
| **Gaps** | Prioritised coverage gaps with remediation |
| **Compliance** | CIS Controls and NIST 800-53 framework coverage |
| **Accounts** | Manage cloud accounts and run scans |

Settings (via your avatar) include:
- **Profile**: Personal settings and MFA
- **Team Management**: Invite and manage team members
- **API Keys**: Generate keys for programmatic access
- **Billing**: Manage subscription and payment

---

## Subscription Plans

A13E offers flexible plans for teams of all sizes:

| Plan | Price | Cloud Accounts | Team Members |
|------|-------|----------------|--------------|
| **Free** | £0 | 1 | 1 |
| **Individual** | £29/month | 6 | 3 |
| **Pro** | £250/month | 500 | 10 |
| **Enterprise** | Custom | Unlimited | Unlimited |

See [Billing & Subscription](./billing-subscription.md) for full details.

---

## Getting Help

- **Documentation**: You're reading it! Browse the docs for detailed guides.
- **Support**: Contact support@a13e.com for assistance
- **In-app help**: Click the **?** icon for contextual guidance

---

## Next Steps

- [Connecting AWS Accounts](./connecting-aws-accounts.md) - Detailed AWS integration guide
- [Connecting GCP Accounts](./connecting-gcp-accounts.md) - Detailed GCP integration guide
- [Running Scans](./running-scans.md) - Learn about scanning options and schedules
- [Using the Dashboards](./using-dashboards.md) - Navigate and interpret your results
- [Understanding Coverage](./understanding-coverage.md) - Deep dive into MITRE ATT&CK coverage
- [API Keys](./api-keys.md) - Set up programmatic access
