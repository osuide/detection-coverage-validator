"""
T1217 - Browser Information Discovery

Adversaries enumerate browser data to gather intelligence about compromised systems
and users. This technique exploits browsers' storage of sensitive information including
bookmarks, cached credentials, browsing history, and account details. Browser data
reveals personal interests, banking activities, internal network resources, and
infrastructure details.
"""

from .template_loader import (
    RemediationTemplate,
    ThreatContext,
    DetectionStrategy,
    DetectionImplementation,
    Campaign,
    DetectionType,
    EffortLevel,
    FalsePositiveRate,
    CloudProvider,
)

TEMPLATE = RemediationTemplate(
    technique_id="T1217",
    technique_name="Browser Information Discovery",
    tactic_ids=["TA0007"],
    mitre_url="https://attack.mitre.org/techniques/T1217/",
    threat_context=ThreatContext(
        description=(
            "Adversaries enumerate browser data to gather intelligence about compromised "
            "systems and users. Attackers target browser artefacts including bookmarks, "
            "cached credentials, browsing history, and account details stored in local files "
            "and databases (e.g., %APPDATA%/Google/Chrome, ~/.config/google-chrome/). "
            "This data reveals personal interests, banking activities, internal network "
            "resources, and infrastructure details that aid in lateral movement and "
            "credential theft."
        ),
        attacker_goal="Enumerate browser data to discover credentials, internal resources, and user intelligence",
        why_technique=[
            "Reveals internal network resources via bookmarks",
            "Exposes banking and financial activity",
            "Provides cached credentials and session tokens",
            "Identifies cryptocurrency wallet extensions",
            "Discovers two-factor authentication extensions",
            "Maps user interests and behaviour patterns",
            "Uncovers cloud service accounts and portals",
        ],
        known_threat_actors=[],
        recent_campaigns=[
            Campaign(
                name="OilRig Juicy Mix Campaign",
                year=2023,
                description="Deployed specialised tools (CDumper for Chrome, EDumper for Edge, MKG) to harvest cookies, history, and credentials from browsers",
                reference_url="https://attack.mitre.org/campaigns/C0044/",
            ),
            Campaign(
                name="Volt Typhoon Infrastructure Reconnaissance",
                year=2024,
                description="Targeted network administrators' browsing histories to map critical infrastructure and internal systems",
                reference_url="https://attack.mitre.org/groups/G1017/",
            ),
            Campaign(
                name="Scattered Spider Infostealer Campaign",
                year=2024,
                description="Utilised infostealer malware like Raccoon Stealer to extract browser histories and credentials from compromised endpoints",
                reference_url="https://attack.mitre.org/groups/G1015/",
            ),
        ],
        prevalence="common",
        trend="increasing",
        severity_score=6,
        severity_reasoning=(
            "Browser information discovery is a high-value reconnaissance technique "
            "that often yields credentials, session tokens, and internal resource mappings. "
            "Infostealers targeting browser data have proliferated in recent years. "
            "Cannot be prevented through configuration—requires detection and response. "
            "Commonly precedes credential theft and lateral movement."
        ),
        business_impact=[
            "Exposure of cached credentials and session tokens",
            "Unauthorised access to banking and financial accounts",
            "Discovery of internal network topology",
            "Theft of cryptocurrency wallet credentials",
            "Compromise of two-factor authentication secrets",
            "Data exfiltration of sensitive browsing history",
        ],
        typical_attack_phase="discovery",
        often_precedes=["T1555", "T1539", "T1078"],
        often_follows=["T1059", "T1204.002"],
    ),
    detection_strategies=[
        # Strategy 1: AWS - Windows Browser File Access
        DetectionStrategy(
            strategy_id="t1217-aws-windows",
            name="Windows Browser Artefact Access Detection (AWS)",
            description="Detect unauthorised access to browser data files on Windows EC2 instances.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query=r"""fields @timestamp, @message
| filter @logStream like /windows-file-access/
| filter @message like /Chrome\\User Data|Firefox\\Profiles|Edge\\User Data|Safari\\LocalStorage/
| filter @message like /\.sqlite|\.db|Bookmarks|History|Cookies|Login Data|Web Data/
| parse @message "* * *" as timestamp, hostname, file_path
| stats count(*) as access_count by hostname, bin(5m)
| filter access_count > 10
| sort access_count desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect Windows browser information discovery on EC2

Parameters:
  AlertEmail:
    Type: String
    Description: Email for security alerts

Resources:
  # Step 1: SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      TopicName: browser-discovery-alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: CloudWatch Log Group for file access logging
  FileAccessLogGroup:
    Type: AWS::Logs::LogGroup
    Properties:
      LogGroupName: /aws/ec2/windows/file-access
      RetentionInDays: 90

  # Step 3: Metric filter for browser file access
  BrowserAccessFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref FileAccessLogGroup
      FilterPattern: '[time, host, path="*Chrome*" || path="*Firefox*" || path="*Edge*" || path="*Safari*", file="*.sqlite" || file="*Bookmarks*" || file="*History*" || file="*Cookies*"]'
      MetricTransformations:
        - MetricName: BrowserFileAccess
          MetricNamespace: Security/Discovery
          MetricValue: "1"
          DefaultValue: 0

  # Step 4: CloudWatch Alarm
  BrowserDiscoveryAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: WindowsBrowserDiscovery
      AlarmDescription: Detects bulk browser file access indicating information discovery
      MetricName: BrowserFileAccess
      Namespace: Security/Discovery
      Statistic: Sum
      Period: 300
      EvaluationPeriods: 1
      Threshold: 10
      ComparisonOperator: GreaterThanThreshold
      AlarmActions:
        - !Ref AlertTopic
      TreatMissingData: notBreaching""",
                terraform_template="""# AWS: Detect Windows browser information discovery

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

# Step 1: SNS topic for alerts
resource "aws_sns_topic" "alerts" {
  name = "browser-discovery-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: CloudWatch Log Group
resource "aws_cloudwatch_log_group" "file_access" {
  name              = "/aws/ec2/windows/file-access"
  retention_in_days = 90
}

# Step 3: Metric filter for browser file access
resource "aws_cloudwatch_log_metric_filter" "browser_access" {
  name           = "windows-browser-discovery"
  log_group_name = aws_cloudwatch_log_group.file_access.name
  pattern        = "[time, host, path=\"*Chrome*\" || path=\"*Firefox*\" || path=\"*Edge*\" || path=\"*Safari*\", file=\"*.sqlite\" || file=\"*Bookmarks*\" || file=\"*History*\" || file=\"*Cookies*\"]"

  metric_transformation {
    name      = "BrowserFileAccess"
    namespace = "Security/Discovery"
    value     = "1"
  }
}

# Step 4: CloudWatch Alarm
resource "aws_cloudwatch_metric_alarm" "browser_discovery" {
  alarm_name          = "WindowsBrowserDiscovery"
  alarm_description   = "Detects bulk browser file access indicating information discovery"
  metric_name         = "BrowserFileAccess"
  namespace           = "Security/Discovery"
  statistic           = "Sum"
  period              = 300
  threshold           = 10
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  alarm_actions       = [aws_sns_topic.alerts.arn]
  treat_missing_data  = "notBreaching"
}""",
                alert_severity="high",
                alert_title="Windows Browser Information Discovery Detected",
                alert_description_template="Bulk browser file access detected on {hostname}, indicating potential browser data enumeration.",
                investigation_steps=[
                    "Identify which user account accessed browser files",
                    "Determine if activity is authorised (e.g., backup software, forensics)",
                    "Review file access timeline and specific files accessed",
                    "Check for infostealer malware signatures (RedLine, Lumma, Raccoon)",
                    "Examine process ancestry to identify execution source",
                    "Search for data exfiltration attempts (network connections, file uploads)",
                    "Review CloudTrail for related API calls and S3 uploads",
                ],
                containment_actions=[
                    "Isolate the instance to prevent credential use and lateral movement",
                    "Force password resets for users on compromised systems",
                    "Invalidate browser session tokens and cookies",
                    "Scan for malware using EDR or antivirus solutions",
                    "Review and rotate credentials for discovered accounts",
                    "Enable credential guard on Windows systems",
                    "Implement application allow-listing to prevent infostealers",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning=(
                "Whitelist authorised backup software, forensic tools, and browser sync services. "
                "Exclude antivirus and EDR agents that scan browser files. "
                "Filter legitimate browser processes accessing their own data directories. "
                "Consider time-based exceptions for scheduled backup windows."
            ),
            detection_coverage="65% - requires object access auditing enabled",
            evasion_considerations=(
                "Attackers may use volume shadow copies to access browser files. "
                "Direct disk access bypasses file system auditing. "
                "Low-and-slow enumeration may evade rate-based detection. "
                "Encrypted archives can hide exfiltrated browser data."
            ),
            implementation_effort=EffortLevel.HIGH,
            implementation_time="3-4 hours",
            estimated_monthly_cost="$15-40 (depends on log volume)",
            prerequisites=[
                "CloudWatch Agent installed on EC2 instances",
                "Windows Object Access Auditing enabled",
                "File system audit logs forwarded to CloudWatch",
                "SACL configured for browser profile directories",
            ],
        ),
        # Strategy 2: AWS - Linux Browser File Access
        DetectionStrategy(
            strategy_id="t1217-aws-linux",
            name="Linux Browser Artefact Access Detection (AWS)",
            description="Detect unauthorised access to browser data files on Linux EC2 instances.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, @message
| filter @logStream like /linux-file-access/
| filter @message like /.config\\/google-chrome|.mozilla\\/firefox|.config\\/chromium|Library\\/Application Support\\/Google\\/Chrome/
| filter @message like /\\.sqlite|\\.db|Bookmarks|History|Cookies|Login Data/
| parse @message "* * *" as timestamp, hostname, file_path
| stats count(*) as access_count by hostname, bin(5m)
| filter access_count > 8
| sort access_count desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect Linux browser information discovery on EC2

Parameters:
  AlertEmail:
    Type: String
    Description: Email for security alerts

Resources:
  # Step 1: SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      TopicName: linux-browser-discovery-alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: CloudWatch Log Group
  FileAccessLogGroup:
    Type: AWS::Logs::LogGroup
    Properties:
      LogGroupName: /aws/ec2/linux/file-access
      RetentionInDays: 90

  # Step 3: Metric filter for Linux browser file access
  LinuxBrowserFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref FileAccessLogGroup
      FilterPattern: '[time, host, path="*.config/google-chrome*" || path="*.mozilla*" || path="*.config/chromium*" || path="*Library/Application Support*"]'
      MetricTransformations:
        - MetricName: LinuxBrowserFileAccess
          MetricNamespace: Security/Discovery
          MetricValue: "1"
          DefaultValue: 0

  # Step 4: CloudWatch Alarm
  LinuxBrowserAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: LinuxBrowserDiscovery
      AlarmDescription: Detects bulk browser file access on Linux instances
      MetricName: LinuxBrowserFileAccess
      Namespace: Security/Discovery
      Statistic: Sum
      Period: 300
      EvaluationPeriods: 1
      Threshold: 8
      ComparisonOperator: GreaterThanThreshold
      AlarmActions:
        - !Ref AlertTopic
      TreatMissingData: notBreaching""",
                terraform_template="""# AWS: Detect Linux browser information discovery

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

# Step 1: SNS topic for alerts
resource "aws_sns_topic" "alerts" {
  name = "linux-browser-discovery-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: CloudWatch Log Group
resource "aws_cloudwatch_log_group" "file_access" {
  name              = "/aws/ec2/linux/file-access"
  retention_in_days = 90
}

# Step 3: Metric filter for browser file access
resource "aws_cloudwatch_log_metric_filter" "browser_access" {
  name           = "linux-browser-discovery"
  log_group_name = aws_cloudwatch_log_group.file_access.name
  pattern        = "[time, host, path=\"*.config/google-chrome*\" || path=\"*.mozilla*\" || path=\"*.config/chromium*\" || path=\"*Library/Application Support*\"]"

  metric_transformation {
    name      = "LinuxBrowserFileAccess"
    namespace = "Security/Discovery"
    value     = "1"
  }
}

# Step 4: CloudWatch Alarm
resource "aws_cloudwatch_metric_alarm" "browser_discovery" {
  alarm_name          = "LinuxBrowserDiscovery"
  alarm_description   = "Detects bulk browser file access on Linux instances"
  metric_name         = "LinuxBrowserFileAccess"
  namespace           = "Security/Discovery"
  statistic           = "Sum"
  period              = 300
  threshold           = 8
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  alarm_actions       = [aws_sns_topic.alerts.arn]
  treat_missing_data  = "notBreaching"
}""",
                alert_severity="high",
                alert_title="Linux Browser Information Discovery Detected",
                alert_description_template="Bulk browser file access detected on {hostname}, indicating potential browser data enumeration.",
                investigation_steps=[
                    "Identify which user account accessed browser files",
                    "Check if access is authorised (backup tools, user migration)",
                    "Review auditd logs for file access details",
                    "Examine process details via ps and /proc inspection",
                    "Search for known infostealer indicators",
                    "Check network connections for data exfiltration",
                    "Review bash history for suspicious commands",
                ],
                containment_actions=[
                    "Isolate the instance to prevent credential misuse",
                    "Force password resets for affected users",
                    "Invalidate session tokens and cookies",
                    "Scan for malware and rootkits",
                    "Review SSH keys and authorised_keys files",
                    "Enable SELinux or AppArmor policies for browser directories",
                    "Implement file integrity monitoring for browser profiles",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning=(
                "Whitelist backup software and browser sync services. "
                "Exclude browser processes accessing their own profile directories. "
                "Filter configuration management tools and user migration scripts. "
                "Consider excluding system monitoring agents."
            ),
            detection_coverage="60% - requires auditd configuration",
            evasion_considerations=(
                "Direct memory access or dumping /proc can bypass file auditing. "
                "Attackers may copy files to /tmp before reading to evade detection. "
                "Use of tar or zip with low read frequency can bypass rate thresholds. "
                "Rootkits can hide file access from audit logs."
            ),
            implementation_effort=EffortLevel.HIGH,
            implementation_time="3-4 hours",
            estimated_monthly_cost="$15-40 (depends on log volume)",
            prerequisites=[
                "CloudWatch Agent installed on EC2 instances",
                "auditd configured with file watch rules",
                "File access events forwarded to CloudWatch",
                "Audit rules for ~/.config and ~/.mozilla directories",
            ],
        ),
        # Strategy 3: AWS - Process-Based Browser Discovery
        DetectionStrategy(
            strategy_id="t1217-aws-process",
            name="Browser Data Enumeration Process Detection (AWS)",
            description="Detect processes accessing multiple browser artefacts across different browsers.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query=r"""fields @timestamp, @message
| filter @logStream like /process-monitoring/
| filter @message like /powershell.exe|cmd.exe|python|perl|bash|sh/
| filter @message like /Chrome.*History|Firefox.*cookies.sqlite|Edge.*Bookmarks|sqlite3.*Login Data/
| parse @message "* * * *" as timestamp, hostname, process, cmdline
| stats count(*) as browser_access by hostname, process, bin(10m)
| filter browser_access > 5
| sort browser_access desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect browser discovery via process monitoring

Parameters:
  AlertEmail:
    Type: String
    Description: Email for security alerts

Resources:
  # Step 1: SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      TopicName: browser-process-discovery-alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: CloudWatch Log Group for process monitoring
  ProcessLogGroup:
    Type: AWS::Logs::LogGroup
    Properties:
      LogGroupName: /aws/ec2/process-monitoring
      RetentionInDays: 90

  # Step 3: Metric filter for browser enumeration processes
  BrowserEnumFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref ProcessLogGroup
      FilterPattern: '[time, host, proc="*powershell*" || proc="*cmd.exe*" || proc="*python*" || proc="*bash*", args="*Chrome*" || args="*Firefox*" || args="*sqlite*"]'
      MetricTransformations:
        - MetricName: BrowserEnumerationProcess
          MetricNamespace: Security/Discovery
          MetricValue: "1"
          DefaultValue: 0

  # Step 4: CloudWatch Alarm
  ProcessDiscoveryAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: BrowserProcessDiscovery
      AlarmDescription: Detects processes enumerating browser data
      MetricName: BrowserEnumerationProcess
      Namespace: Security/Discovery
      Statistic: Sum
      Period: 600
      EvaluationPeriods: 1
      Threshold: 5
      ComparisonOperator: GreaterThanThreshold
      AlarmActions:
        - !Ref AlertTopic
      TreatMissingData: notBreaching""",
                terraform_template="""# AWS: Detect browser discovery via process monitoring

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

# Step 1: SNS topic for alerts
resource "aws_sns_topic" "alerts" {
  name = "browser-process-discovery-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: CloudWatch Log Group
resource "aws_cloudwatch_log_group" "processes" {
  name              = "/aws/ec2/process-monitoring"
  retention_in_days = 90
}

# Step 3: Metric filter for browser enumeration
resource "aws_cloudwatch_log_metric_filter" "browser_enum" {
  name           = "browser-enumeration-process"
  log_group_name = aws_cloudwatch_log_group.processes.name
  pattern        = "[time, host, proc=\"*powershell*\" || proc=\"*cmd.exe*\" || proc=\"*python*\" || proc=\"*bash*\", args=\"*Chrome*\" || args=\"*Firefox*\" || args=\"*sqlite*\"]"

  metric_transformation {
    name      = "BrowserEnumerationProcess"
    namespace = "Security/Discovery"
    value     = "1"
  }
}

# Step 4: CloudWatch Alarm
resource "aws_cloudwatch_metric_alarm" "process_discovery" {
  alarm_name          = "BrowserProcessDiscovery"
  alarm_description   = "Detects processes enumerating browser data"
  metric_name         = "BrowserEnumerationProcess"
  namespace           = "Security/Discovery"
  statistic           = "Sum"
  period              = 600
  threshold           = 5
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  alarm_actions       = [aws_sns_topic.alerts.arn]
  treat_missing_data  = "notBreaching"
}""",
                alert_severity="high",
                alert_title="Browser Data Enumeration Process Detected",
                alert_description_template="Process {process} on {hostname} is enumerating browser data across multiple browsers.",
                investigation_steps=[
                    "Identify the process and its parent process chain",
                    "Determine execution source (scheduled task, user login, remote execution)",
                    "Review full command line arguments for data exfiltration indicators",
                    "Check process hashes against threat intelligence feeds",
                    "Examine network connections from the process",
                    "Search for similar activity on other instances",
                    "Review user account activity and login history",
                ],
                containment_actions=[
                    "Kill the suspicious process immediately",
                    "Isolate the instance from the network",
                    "Collect memory dump for forensic analysis",
                    "Reset credentials for all users on the system",
                    "Scan for persistence mechanisms (scheduled tasks, registry keys)",
                    "Review outbound network traffic for data exfiltration",
                    "Deploy EDR agent if not already present",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning=(
                "Whitelist authorised administrative scripts. "
                "Exclude browser update processes and sync services. "
                "Filter forensic tools used by security team. "
                "Consider excluding browser processes accessing their own databases."
            ),
            detection_coverage="75% - covers most infostealer activity patterns",
            evasion_considerations=(
                "Custom-compiled binaries may evade process name matching. "
                "Obfuscated PowerShell or encoded commands can bypass pattern detection. "
                "Direct API calls (NtCreateFile) may not appear in process command lines. "
                "In-memory data access without file system interaction evades file-based detection."
            ),
            implementation_effort=EffortLevel.HIGH,
            implementation_time="2-3 hours",
            estimated_monthly_cost="$10-30 (depends on instance count)",
            prerequisites=[
                "CloudWatch Agent with process monitoring enabled",
                "Process command line logging configured",
                "Sysmon or equivalent process monitoring tool",
                "Windows Security Event Log forwarding (Event ID 4688)",
            ],
        ),
        # Strategy 4: GCP - Browser File Access Detection
        DetectionStrategy(
            strategy_id="t1217-gcp-file-access",
            name="Browser Artefact Access Detection (GCP)",
            description="Detect unauthorised access to browser data files on GCP Compute Engine instances.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""resource.type="gce_instance"
(jsonPayload.file_path=~".*\\.config/google-chrome.*" OR
 jsonPayload.file_path=~".*\\.mozilla/firefox.*" OR
 jsonPayload.file_path=~".*Library/Application Support/Google/Chrome.*" OR
 jsonPayload.file_path=~".*AppData.*Chrome.*" OR
 jsonPayload.file_path=~".*AppData.*Firefox.*")
(jsonPayload.file_name=~".*\\.sqlite" OR
 jsonPayload.file_name=~".*Bookmarks.*" OR
 jsonPayload.file_name=~".*History.*" OR
 jsonPayload.file_name=~".*Cookies.*" OR
 jsonPayload.file_name=~".*Login Data.*")
severity>=DEFAULT""",
                gcp_terraform_template="""# GCP: Detect browser information discovery

variable "project_id" {
  type        = string
  description = "GCP project ID"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

# Step 1: Notification channel
resource "google_monitoring_notification_channel" "email" {
  display_name = "Browser Discovery Security Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Log-based metric for browser file access
resource "google_logging_metric" "browser_file_access" {
  name   = "browser-file-access-discovery"
  filter = <<-EOT
    resource.type="gce_instance"
    (jsonPayload.file_path=~".*\\.config/google-chrome.*" OR
     jsonPayload.file_path=~".*\\.mozilla/firefox.*" OR
     jsonPayload.file_path=~".*Library/Application Support/Google/Chrome.*" OR
     jsonPayload.file_path=~".*AppData.*Chrome.*" OR
     jsonPayload.file_path=~".*AppData.*Firefox.*")
    (jsonPayload.file_name=~".*\\.sqlite" OR
     jsonPayload.file_name=~".*Bookmarks.*" OR
     jsonPayload.file_name=~".*History.*" OR
     jsonPayload.file_name=~".*Cookies.*")
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "instance_id"
      value_type  = "STRING"
      description = "Instance accessing browser files"
    }
  }

  label_extractors = {
    "instance_id" = "EXTRACT(resource.labels.instance_id)"
  }
}

# Step 3: Alert policy
resource "google_monitoring_alert_policy" "browser_discovery" {
  display_name = "Browser Information Discovery Detected"
  combiner     = "OR"

  conditions {
    display_name = "Bulk browser file access detected"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.browser_file_access.name}\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 8
      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_SUM"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]

  alert_strategy {
    auto_close = "86400s"
  }

  documentation {
    content = <<-EOT
      ## Browser Information Discovery Detected (T1217)

      Multiple browser data files have been accessed on a GCP Compute Engine instance.
      This may indicate browser information discovery activity by an attacker or infostealer malware.

      **Investigation Steps:**
      1. Identify the user and process accessing browser files
      2. Review Cloud Logging for detailed file access patterns
      3. Check for infostealer malware signatures
      4. Examine network connections for data exfiltration
      5. Review user account activity and authentication logs

      **Containment:**
      - Isolate the affected instance using firewall rules
      - Reset credentials for users on the compromised system
      - Scan for malware and persistence mechanisms
      - Create instance snapshot for forensic analysis
    EOT
  }
}""",
                alert_severity="high",
                alert_title="GCP: Browser Information Discovery Detected",
                alert_description_template="Bulk browser file access detected on GCP instance, indicating potential browser data enumeration.",
                investigation_steps=[
                    "Identify the user and process accessing browser files",
                    "Review Cloud Logging for detailed access patterns",
                    "Check for known infostealer malware signatures",
                    "Examine network traffic for exfiltration indicators",
                    "Review OS Login and SSH authentication logs",
                    "Check for unusual service account activity",
                    "Correlate with VPC Flow Logs for network reconnaissance",
                ],
                containment_actions=[
                    "Isolate instance using VPC firewall rules",
                    "Create instance snapshot for forensic analysis",
                    "Reset credentials and rotate service account keys",
                    "Scan for malware using Cloud Security Command Center",
                    "Review and revoke suspicious SSH keys",
                    "Enable VPC Service Controls to prevent data exfiltration",
                    "Deploy OS Config for vulnerability assessment",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning=(
                "Whitelist authorised backup services and browser sync processes. "
                "Exclude security scanning tools and forensic agents. "
                "Filter browser processes accessing their own profile directories. "
                "Consider excluding Google Chrome Enterprise policies sync."
            ),
            detection_coverage="70% - requires Ops Agent with file access monitoring",
            evasion_considerations=(
                "Direct memory access bypasses file system auditing. "
                "Volume snapshot access can read browser data without triggering file access logs. "
                "Low-frequency access may evade rate-based thresholds. "
                "Encrypted containers can hide browser data exfiltration."
            ),
            implementation_effort=EffortLevel.HIGH,
            implementation_time="3-4 hours",
            estimated_monthly_cost="$20-50 (depends on log volume)",
            prerequisites=[
                "Ops Agent installed on Compute Engine instances",
                "File access monitoring enabled in Ops Agent configuration",
                "Cloud Logging API enabled",
                "Appropriate IAM permissions for log-based metrics",
            ],
        ),
        # Strategy 5: GCP - Browser Discovery Process Detection
        DetectionStrategy(
            strategy_id="t1217-gcp-process",
            name="Browser Enumeration Process Detection (GCP)",
            description="Detect processes accessing browser databases and configuration files on GCP instances.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""resource.type="gce_instance"
jsonPayload.process_name=~"(powershell|python|perl|bash|sh|cmd)"
jsonPayload.command_line=~"(Chrome.*sqlite|Firefox.*cookies|Bookmarks|History|Login Data|Web Data)"
severity>=DEFAULT""",
                gcp_terraform_template="""# GCP: Detect browser enumeration processes

variable "project_id" {
  type        = string
  description = "GCP project ID"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

# Step 1: Notification channel
resource "google_monitoring_notification_channel" "email" {
  display_name = "Browser Process Discovery Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Log-based metric for browser enumeration processes
resource "google_logging_metric" "browser_enum_process" {
  name   = "browser-enumeration-process"
  filter = <<-EOT
    resource.type="gce_instance"
    jsonPayload.process_name=~"(powershell|python|perl|bash|sh|cmd)"
    jsonPayload.command_line=~"(Chrome.*sqlite|Firefox.*cookies|Bookmarks|History|Login Data|Web Data)"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "instance_id"
      value_type  = "STRING"
      description = "Instance running browser enumeration"
    }
    labels {
      key         = "process_name"
      value_type  = "STRING"
      description = "Process enumerating browser data"
    }
  }

  label_extractors = {
    "instance_id"  = "EXTRACT(resource.labels.instance_id)"
    "process_name" = "EXTRACT(jsonPayload.process_name)"
  }
}

# Step 3: Alert policy
resource "google_monitoring_alert_policy" "browser_enum_process" {
  display_name = "Browser Enumeration Process Detected"
  combiner     = "OR"

  conditions {
    display_name = "Process accessing browser data detected"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.browser_enum_process.name}\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 3
      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_SUM"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]

  alert_strategy {
    auto_close = "86400s"
  }

  documentation {
    content = <<-EOT
      ## Browser Enumeration Process Detected (T1217)

      A process has been detected accessing browser databases and configuration files,
      which may indicate infostealer malware or unauthorised browser data collection.

      **Common Infostealers:**
      - RedLine Stealer
      - Lumma Stealer
      - Raccoon Stealer
      - BeaverTail
      - Troll Stealer

      **Immediate Actions:**
      1. Isolate the affected instance
      2. Kill the suspicious process
      3. Collect memory dump for analysis
      4. Reset all credentials on the system
      5. Scan for malware and persistence
    EOT
  }
}""",
                alert_severity="high",
                alert_title="GCP: Browser Enumeration Process Detected",
                alert_description_template="Process {process_name} detected accessing browser data on GCP instance.",
                investigation_steps=[
                    "Identify the process and parent process chain",
                    "Review process command line arguments",
                    "Check process binary hash against threat intelligence",
                    "Examine process network connections",
                    "Review Cloud Logging for process creation events",
                    "Search for similar activity across other instances",
                    "Check for lateral movement indicators",
                ],
                containment_actions=[
                    "Terminate the suspicious process immediately",
                    "Isolate instance using VPC firewall rules",
                    "Collect process memory dump via OS commands",
                    "Reset all user credentials and service account keys",
                    "Scan for malware using VirusTotal or ClamAV",
                    "Review startup scripts and cron jobs for persistence",
                    "Enable Security Command Center for ongoing monitoring",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning=(
                "Whitelist authorised administrative scripts. "
                "Exclude browser update and sync processes. "
                "Filter security tools and forensic utilities. "
                "Consider excluding configuration management automation."
            ),
            detection_coverage="75% - effective against most infostealer malware",
            evasion_considerations=(
                "Obfuscated command lines may bypass pattern matching. "
                "Custom-compiled binaries evade process name detection. "
                "In-memory data access without file operations is undetectable. "
                "Use of legitimate tools (sqlite3) may blend with normal activity."
            ),
            implementation_effort=EffortLevel.HIGH,
            implementation_time="2-3 hours",
            estimated_monthly_cost="$15-40 (depends on instance count)",
            prerequisites=[
                "Ops Agent installed with process monitoring enabled",
                "Process command line logging configured",
                "Cloud Logging API enabled",
                "Sufficient log retention period (90+ days recommended)",
            ],
        ),
    ],
    recommended_order=[
        "t1217-aws-process",
        "t1217-gcp-process",
        "t1217-aws-windows",
        "t1217-aws-linux",
        "t1217-gcp-file-access",
    ],
    total_effort_hours=14.0,
    coverage_improvement="+7% improvement for Discovery tactic",
)
