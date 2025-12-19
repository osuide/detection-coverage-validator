# Running Scans

Learn how to scan your cloud accounts for security detections and analyse MITRE ATT&CK coverage.

## Table of Contents

- [What is a Scan?](#what-is-a-scan)
- [Starting a Scan](#starting-a-scan)
- [Monitoring Scan Progress](#monitoring-scan-progress)
- [Understanding Scan Results](#understanding-scan-results)
- [Detection Types](#detection-types)
- [Scheduled Scans](#scheduled-scans)
- [Scan History](#scan-history)
- [Best Practices](#best-practices)

## What is a Scan?

A scan is the process where A13E:

1. **Connects** to your cloud account using the configured IAM role
2. **Discovers** security detections across various AWS services
3. **Maps** those detections to MITRE ATT&CK techniques
4. **Calculates** coverage metrics and identifies gaps
5. **Generates** reports and recommendations

### What Gets Scanned?

A13E scans the following AWS services for security detections:

- **AWS GuardDuty**: Threat detection findings and configurations
- **AWS Security Hub**: Security standards, controls, and findings
- **Amazon EventBridge**: Custom rules monitoring CloudTrail events
- **Amazon CloudWatch Logs**: Log Insights queries and metric filters with alarms
- **AWS Config**: Compliance rules and evaluations

### Scan Duration

Typical scan times:
- **Small accounts** (1-50 detections): 2-5 minutes
- **Medium accounts** (50-200 detections): 5-10 minutes
- **Large accounts** (200+ detections): 10-20 minutes

Factors affecting duration:
- Number of enabled AWS regions
- Volume of detection rules and configurations
- API rate limits and throttling

## Starting a Scan

### Prerequisites

Before running a scan, ensure:

1. ✓ Cloud account is added to A13E
2. ✓ Credentials are connected and validated
3. ✓ Account status shows "Connected" (green badge)

### Manual Scan

#### From the Accounts Page

1. Navigate to **Accounts** in the main menu
2. Find the account you want to scan
3. Click the **Play button** (▶) on the account card
4. Scan starts immediately and status changes to "Running"

#### From the Dashboard

1. If you have no recent scans, you'll see a prompt to run a scan
2. Click **Run Scan** or **Add Cloud Account**
3. Select the account to scan

### Scan Configuration

When starting a scan, you can configure:

#### Regions (Optional)

By default, scans cover all regions configured for the account. To scan specific regions:

```
Note: Region selection is currently set during account creation.
To change regions, edit the account settings.
```

Commonly scanned regions:
- `us-east-1` (N. Virginia)
- `us-west-2` (Oregon)
- `eu-west-1` (Ireland)
- `ap-southeast-1` (Singapore)

#### Detection Types (Optional)

Choose which detection sources to scan:

- **GuardDuty Findings**: Threat detection rules
- **Security Hub Controls**: Security standard controls
- **EventBridge Rules**: Custom CloudTrail monitoring rules
- **CloudWatch Logs Insights**: Log analysis queries
- **Config Rules**: Compliance and configuration rules

> **Tip**: Leave all detection types selected for comprehensive coverage analysis.

## Monitoring Scan Progress

### Real-Time Status

While a scan is running, you'll see:

#### Account Card Status

- **Status Badge**: Changes from "Connected" to "Scanning..."
- **Progress Indicator**: Spinning icon on the Play button
- **Last Scan**: Shows "In progress"

#### Scan Status Values

| Status | Description |
|--------|-------------|
| **Pending** | Scan queued, waiting to start |
| **Running** | Currently scanning cloud account |
| **Completed** | Scan finished successfully |
| **Failed** | Scan encountered an error |
| **Cancelled** | Scan was manually stopped |

### Cancelling a Scan

To cancel a running scan:

1. Click the account card while scan is running
2. Click **Cancel Scan** (if available)
3. Scan will stop and status changes to "Cancelled"

> **Note**: Partial results from cancelled scans are not saved.

## Understanding Scan Results

### Scan Summary

After completion, the account card shows:

- **Last Scan**: Timestamp of most recent scan
- **Status**: "Connected" with green badge
- **Detections Found**: Count of discovered detections

### Viewing Results

Click on the account name or navigate to:

1. **Dashboard**: See high-level coverage metrics
2. **Coverage**: Explore MITRE ATT&CK heatmap
3. **Detections**: Browse all discovered detections
4. **Gaps**: Review prioritized coverage gaps

### Coverage Metrics

After each scan, A13E calculates:

- **Coverage Percentage**: Percentage of MITRE ATT&CK techniques covered
- **Covered Techniques**: Techniques with strong detection (≥60% confidence)
- **Partial Techniques**: Techniques with moderate coverage (40-60% confidence)
- **Uncovered Techniques**: Techniques with little/no coverage (<40% confidence)
- **Total Detections**: Number of security detections discovered
- **Mapped Detections**: Detections successfully mapped to ATT&CK
- **Average Confidence**: Mean confidence score across all techniques

## Detection Types

A13E discovers and analyses various types of security detections:

### 1. GuardDuty Findings

**What it scans**:
- Active GuardDuty detectors
- Finding types and severity levels
- Detection coverage per finding type

**Example detections**:
- `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration`
- `Backdoor:EC2/C2ActivityB.DNS`
- `CryptoCurrency:EC2/BitcoinTool.B!DNS`

**MITRE mapping**:
- GuardDuty findings map to techniques like Credential Access, Command & Control, Impact

### 2. Security Hub Controls

**What it scans**:
- Enabled security standards (AWS Foundational, CIS, PCI-DSS)
- Active control checks
- Compliance status

**Example detections**:
- `CloudTrail.1 - CloudTrail should be enabled`
- `IAM.1 - IAM policies should not allow full "*:*" administrative privileges`
- `S3.1 - S3 Block Public Access setting should be enabled`

**MITRE mapping**:
- Security Hub controls map to Defense Evasion, Persistence, Privilege Escalation techniques

### 3. EventBridge Rules

**What it scans**:
- Custom EventBridge rules
- CloudTrail event patterns
- Rule targets and actions

**Example detections**:
- Rules monitoring `CreateUser`, `DeleteUser` IAM events
- Rules tracking EC2 instance state changes
- Rules detecting S3 bucket policy modifications

**MITRE mapping**:
- EventBridge rules map based on monitored CloudTrail events (e.g., IAM changes → Persistence)

### 4. CloudWatch Logs Insights

**What it scans**:
- CloudWatch Insights queries
- Log groups and metric filters
- Alarms connected to filters

**Example detections**:
- Queries searching for failed authentication attempts
- Filters detecting unauthorized API calls
- Queries identifying unusual network traffic patterns

**MITRE mapping**:
- Log queries map based on detection logic (e.g., failed auth → Credential Access)

### 5. AWS Config Rules

**What it scans**:
- Custom and managed Config rules
- Compliance evaluation status
- Remediation configurations

**Example detections**:
- `encrypted-volumes` - Check if EBS volumes are encrypted
- `root-account-mfa-enabled` - Verify MFA on root account
- `s3-bucket-logging-enabled` - Ensure S3 logging is active

**MITRE mapping**:
- Config rules map to Defense Evasion and Collection techniques

## Scheduled Scans

> **Available in**: Subscriber and Enterprise plans

Automate regular scans to track coverage over time.

### Creating a Schedule

1. Navigate to **Settings** → **Scheduled Scans** (or similar location)
2. Click **Create Schedule**
3. Configure:
   - **Frequency**: Daily, Weekly, Monthly
   - **Time**: Preferred scan time (UTC)
   - **Accounts**: Select which accounts to scan
   - **Notifications**: Email alerts on completion or failures
4. Click **Save Schedule**

### Schedule Options

| Frequency | Best For |
|-----------|----------|
| **Daily** | Production environments, active detection development |
| **Weekly** | Standard monitoring, most organisations |
| **Monthly** | Quarterly reviews, stable environments |

### Managing Schedules

- **Edit**: Change frequency or accounts
- **Pause**: Temporarily disable without deleting
- **Delete**: Permanently remove the schedule
- **Run Now**: Trigger an immediate scan regardless of schedule

## Scan History

### Viewing Past Scans

1. Navigate to **Accounts**
2. Click on an account name
3. View the **Scan History** section

### History Details

For each scan, you can see:

- **Timestamp**: When the scan completed
- **Status**: Success, failed, or cancelled
- **Duration**: How long the scan took
- **Detections Found**: Count of discoveries
- **Changes**: New or removed detections since last scan

### Comparing Scans

Compare two scans to see:
- Newly added detections
- Removed or disabled detections
- Coverage percentage changes
- Gap improvements or regressions

> **Available in**: Subscriber and Enterprise plans

## Best Practices

### Scanning Frequency

**Recommended**:
- **Initial Setup**: Run 1-2 scans to verify connectivity and baseline coverage
- **Active Development**: Weekly or bi-weekly scans when actively improving detections
- **Steady State**: Monthly scans for monitoring and compliance

**Avoid**:
- Hourly or very frequent scans (adds load, results don't change that often)
- Scanning during active configuration changes (wait for changes to complete)

### Regional Coverage

**Best Practices**:
- Scan all regions where you have resources
- Include regions even with minimal resources (for complete coverage)
- Exclude regions with no resources to reduce scan time

**Common Region Sets**:
- **US Only**: `us-east-1`, `us-west-1`, `us-west-2`
- **Global**: All commercial regions
- **Compliance**: Regions required by regulatory standards (e.g., EU regions for GDPR)

### Error Handling

If a scan fails:

1. **Check Credentials**: Verify connection is still valid (credentials may have expired)
2. **Review Permissions**: Ensure IAM role still has required permissions
3. **Check AWS Status**: Verify no AWS service outages in your regions
4. **Retry**: Click **Run Scan** again after resolving issues
5. **Contact Support**: If issues persist, email support@a13e.io with scan ID

### Managing Results

After each scan:

- ✓ Review coverage changes from previous scan
- ✓ Prioritize new gaps based on severity
- ✓ Investigate any removed detections (were they disabled?)
- ✓ Export reports for compliance documentation
- ✓ Share results with your security team

## Scan Notifications

### Email Alerts

Configure email notifications for:

- **Scan Completion**: Receive email when scan finishes
- **Scan Failures**: Alert on errors or failures
- **Coverage Changes**: Notify when coverage increases or decreases significantly
- **New Critical Gaps**: Alert on newly discovered critical coverage gaps

To configure:
1. Go to **Settings** → **Notifications**
2. Select alert types
3. Add recipient email addresses
4. Click **Save Preferences**

### Integration Webhooks

> **Available in**: Enterprise plan

Send scan results to external systems:

- Slack notifications
- PagerDuty alerts
- Custom webhooks
- SIEM integrations

## Next Steps

- [Understanding Coverage](./understanding-coverage.md) - Interpret MITRE ATT&CK coverage results
- [Connecting AWS Accounts](./connecting-aws-accounts.md) - Add more accounts to scan
- [Team Management](./team-management.md) - Share results with your team

## Getting Help

For scan-related issues:

- **Check Account Connection**: Ensure "Connected" status before scanning
- **Review Permissions**: Verify IAM role has all required permissions
- **Check Logs**: Navigate to Settings → Audit Logs for detailed error messages
- **Contact Support**: Email support@a13e.io with scan ID and error details
