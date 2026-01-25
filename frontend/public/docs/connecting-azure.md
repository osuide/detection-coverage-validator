# Connecting Azure Accounts

Connect your Azure subscriptions to A13E using Workload Identity Federation (WIF) for secure, keyless authentication.

## TL;DR

- **No client secrets required** - A13E uses Workload Identity Federation for keyless authentication
- **Two setup methods**: Automated script (recommended) or manual Azure Portal configuration
- **Read-only access** - A13E only requires Reader and Security Reader roles
- **Required info**: Tenant ID, Client ID, and Subscription ID

---

## Overview

A13E connects to Azure using Workload Identity Federation (WIF), a modern authentication method that eliminates the need for client secrets or certificates.

### How It Works

1. A13E's AWS infrastructure requests an OIDC token from AWS Cognito
2. Azure AD validates the token via a federated identity credential trust
3. Azure issues short-lived (1 hour) credentials for scanning
4. No secrets are stored - authentication is completely keyless

### Security Benefits

| Benefit | Description |
|---------|-------------|
| **No secrets to manage** | No client secrets or certificates to rotate |
| **Short-lived credentials** | Tokens expire after 1 hour |
| **Least privilege** | Only Reader and Security Reader roles required |
| **Audit trail** | All access logged in Azure AD sign-in logs |

---

## What A13E Scans

A13E discovers security detections from the following Azure services:

| Service | What A13E Discovers |
|---------|---------------------|
| **Microsoft Defender for Cloud** | Security assessments, recommendations, and secure score |
| **Azure Policy** | Policy compliance state and assignments |
| **Regulatory Compliance** | Framework compliance status (CIS, NIST, etc.) |
| **Security Center** | Security posture findings and alerts |

### What A13E Can Access

- Microsoft Defender for Cloud security assessments
- Azure Policy compliance state
- Security Center recommendations
- Resource configurations (read-only)

### What A13E Cannot Access

- Key Vault secrets or certificates
- Storage account data
- Database contents
- Any write operations

---

## Prerequisites

Before connecting your Azure subscription, ensure you have:

- **Azure CLI** installed and authenticated (`az login`)
- **Owner** or **User Access Administrator** role on the Azure subscription
- **Global Administrator** or **Application Administrator** role in Microsoft Entra ID
- **jq** installed (for the automated script method)

---

## Required Azure Roles

A13E requires two built-in Azure roles:

| Role | Purpose |
|------|---------|
| **Reader** | View all resources in the subscription |
| **Security Reader** | Access Microsoft Defender for Cloud data |

These are read-only roles with no write permissions.

---

## Setup Method 1: Automated Script (Recommended)

The automated script handles all Azure configuration in one command.

### Step 1: Add Your Azure Subscription

1. Navigate to **Accounts** in A13E
2. Click **Add Cloud Account**
3. Select **Azure** as the provider
4. Enter your **Subscription ID** (found in Azure Portal → Subscriptions)
5. Click **Add Account**

### Step 2: Generate Your Identity ID

1. Click the **Connect** button on your new Azure account
2. Review the required permissions
3. Click **Continue** to proceed to the setup step
4. Click **Generate Identity ID**
5. Copy the generated Identity ID (format: `eu-west-2:xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`)

> **Important**: Save this Identity ID - you'll need it for the setup script.

### Step 3: Run the Setup Script

Open Azure Cloud Shell (Bash) or a terminal with Azure CLI installed:

```bash
# Download the setup script
curl -sL https://app.a13e.com/api/v1/credentials/templates/entra/wif-setup -o azure_wif_setup.sh

# Make it executable
chmod +x azure_wif_setup.sh

# Run the script with your details
./azure_wif_setup.sh \
  --subscription YOUR_SUBSCRIPTION_ID \
  --cognito-identity-id YOUR_IDENTITY_ID
```

Replace:
- `YOUR_SUBSCRIPTION_ID` with your Azure subscription GUID
- `YOUR_IDENTITY_ID` with the Identity ID from Step 2

### Step 4: Complete the Connection

The script outputs your Tenant ID and Client ID. Return to A13E:

1. Enter the **Tenant ID** from the script output
2. Enter the **Client ID** from the script output
3. Click **Save & Connect**
4. Click **Validate Connection**

Once validation succeeds, your Azure subscription is connected and ready to scan.

---

## Setup Method 2: Manual Portal Setup

If you prefer to configure Azure manually, follow these steps.

### Step 1: Generate Your Identity ID

1. In A13E, add your Azure subscription and click **Connect**
2. Click **Generate Identity ID**
3. Copy the Identity ID for use in Step 3

### Step 2: Create App Registration

1. Go to **Azure Portal → Microsoft Entra ID → App registrations**
2. Click **New registration**
3. Configure:
   - **Name**: `A13E-DetectionScanner`
   - **Supported account types**: Single tenant (this organisation only)
   - **Redirect URI**: Leave blank
4. Click **Register**
5. Note the **Application (client) ID** from the Overview page

### Step 3: Configure Federated Identity Credential

1. In your app registration, go to **Certificates & secrets**
2. Click **Federated credentials** → **Add credential**
3. Select **Other issuer** as the scenario
4. Configure:
   - **Issuer**: `https://cognito-identity.amazonaws.com`
   - **Subject identifier**: Your Identity ID from Step 1
   - **Audience**: The Identity Pool ID shown in the A13E wizard
   - **Name**: `A13E-Cognito-Federation`
   - **Description**: `A13E Detection Coverage Validator - Cognito WIF to Azure federation`
5. Click **Add**

### Step 4: Assign Roles

1. Go to **Subscriptions → Your Subscription → Access control (IAM)**
2. Click **Add → Add role assignment**
3. Assign the **Reader** role:
   - Role: Reader
   - Assign access to: User, group, or service principal
   - Select: `A13E-DetectionScanner`
   - Click **Review + assign**
4. Repeat for the **Security Reader** role

### Step 5: Complete the Connection

1. Return to the A13E Azure Setup wizard
2. Enter your **Tenant ID** (found in Microsoft Entra ID → Overview)
3. Enter your **Client ID** (Application ID from the app registration)
4. Click **Save & Connect**
5. Click **Validate Connection**

---

## Validation

After entering your credentials, A13E validates the connection by:

1. Obtaining an OIDC token from AWS Cognito
2. Exchanging it for Azure credentials via the federated trust
3. Verifying access to your subscription
4. Confirming Reader and Security Reader permissions

### Successful Validation

When validation succeeds, you'll see:
- Green "Valid" status badge
- "Azure WIF configuration is valid" message
- Your account is ready to scan

### Validation Errors

| Error | Solution |
|-------|----------|
| "Failed to get Cognito identity token" | Regenerate your Identity ID and update the federated credential |
| "Failed to create Azure credential" | Verify the federated credential configuration matches exactly |
| "Cannot access subscription" | Ensure Reader and Security Reader roles are assigned |
| "Azure credential returned empty token" | Check the federated credential issuer and audience values |

---

## Troubleshooting

### Script Errors

**"jq is not installed"**
```bash
# macOS
brew install jq

# Ubuntu/Debian
sudo apt-get install jq

# RHEL/CentOS
sudo yum install jq
```

**"Not logged in to Azure CLI"**
```bash
az login
```

**"Cannot access subscription"**
- Verify you have Owner or User Access Administrator role
- Ensure you're logged in to the correct tenant: `az account show`

### Connection Errors

**"Invalid Tenant ID or Client ID"**
- Tenant ID format: `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`
- Client ID format: `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`
- Find Tenant ID: Azure Portal → Microsoft Entra ID → Overview
- Find Client ID: App registrations → Your app → Overview

**"Federated credential validation failed"**
- Verify the Subject in your federated credential matches your Identity ID exactly
- Ensure the Issuer is `https://cognito-identity.amazonaws.com`
- Check the Audience matches the Identity Pool ID shown in A13E

### Permissions Errors

**"Access denied" or "Insufficient permissions"**
- Verify both Reader and Security Reader roles are assigned at the subscription level
- Check the role assignments are for the correct service principal
- Wait 5 minutes for role assignments to propagate

---

## Running Your First Scan

Once connected:

1. Navigate to **Accounts**
2. Find your Azure subscription (shows "Connected" status)
3. Click the **Play** button to start scanning
4. View results on the **Dashboard** and **Coverage** pages

Azure scans typically complete in 5-10 minutes depending on subscription size.

---

## Next Steps

- [Running Scans](./running-scans.md) - Learn about scanning options and schedules
- [Using the Dashboards](./using-dashboards.md) - Navigate and interpret your results
- [Understanding Coverage](./understanding-coverage.md) - Deep dive into MITRE ATT&CK coverage
- [Connecting AWS Accounts](./connecting-aws-accounts.md) - Add AWS accounts
- [Connecting GCP Accounts](./connecting-gcp-accounts.md) - Add GCP projects
