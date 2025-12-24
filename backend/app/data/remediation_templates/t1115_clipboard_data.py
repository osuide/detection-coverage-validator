"""
T1115 - Clipboard Data

Adversaries collect clipboard data from users copying information between applications.
In cloud environments, this technique targets workstations, bastion hosts, and RDP/SSH sessions.

IMPORTANT DETECTION LIMITATIONS:
The detection strategies below monitor CLIPBOARD UTILITIES (clip.exe, Get-Clipboard,
pbpaste, xclip, xsel). These are effective for script-based and administrative clipboard access.

However, sophisticated malware typically uses:
- Direct Windows API calls (OpenClipboard/GetClipboardData)
- .NET System.Windows.Forms.Clipboard class
- Python/PowerShell clipboard modules without spawning utility processes

These API-level clipboard accesses are NOT detected by process monitoring alone.

For comprehensive clipboard monitoring:
- Windows: Enable AMSI (Antimalware Scan Interface) and use EDR with API hooking
- AWS: GuardDuty Runtime Monitoring for behavioural detection
- All platforms: Deploy EDR solutions (CrowdStrike, SentinelOne, Carbon Black) with
  memory/API monitoring capabilities

The utility-based detection below catches ~20-30% of clipboard theft attempts
(script-based/administrative). API-level malware requires endpoint agent detection.
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
    technique_id="T1115",
    technique_name="Clipboard Data",
    tactic_ids=["TA0009"],  # Collection
    mitre_url="https://attack.mitre.org/techniques/T1115/",
    threat_context=ThreatContext(
        description=(
            "Adversaries collect clipboard data from users copying information between applications. "
            "This includes credentials, API keys, configuration data, and sensitive business information. "
            "In cloud environments, attackers target bastion hosts, Windows workstations, developer "
            "environments, and remote desktop sessions where users frequently copy sensitive data. "
            "Malware monitors clipboard contents using OS APIs (OpenClipboard/GetClipboardData on Windows, "
            "pbpaste on macOS/Linux) or continuously polls for changes. Some malware also performs clipboard "
            "manipulation, swapping cryptocurrency wallet addresses to redirect payments."
        ),
        attacker_goal="Capture sensitive data including credentials, API keys, and tokens copied to the clipboard",
        why_technique=[
            "Users frequently copy credentials and API keys to clipboard",
            "Clipboard monitoring is passive and difficult to detect",
            "No network traffic or file access required for basic monitoring",
            "Can capture data that never touches disk or network",
            "Clipboard often contains configuration and secret data during deployments",
            "Cryptocurrency wallet addresses provide high-value theft opportunity",
        ],
        known_threat_actors=[
            "APT38",
            "APT39",
            "OilRig",
            "Agent Tesla malware",
            "DarkComet",
            "Remcos",
            "TajMahal",
        ],
        recent_campaigns=[
            Campaign(
                name="Operation Wocao",
                year=2019,
                description="Threat actors extracted clipboard data in plaintext during targeting of government and industrial organisations",
                reference_url="https://attack.mitre.org/campaigns/C0014/",
            ),
            Campaign(
                name="Cryptocurrency Clipboard Hijacking",
                year=2022,
                description="Multiple malware families including DarkGate and XLoader targeted cryptocurrency users by monitoring and replacing wallet addresses in clipboard",
                reference_url="https://attack.mitre.org/software/S0674/",
            ),
            Campaign(
                name="TajMahal APT Framework",
                year=2019,
                description="Sophisticated APT framework included clipboard monitoring module to capture sensitive data from diplomatic targets",
                reference_url="https://attack.mitre.org/software/S0467/",
            ),
        ],
        prevalence="common",
        trend="increasing",
        severity_score=6,
        severity_reasoning=(
            "Clipboard monitoring enables passive credential and API key theft without triggering "
            "typical file or network-based detections. While the technique cannot be easily mitigated "
            "with preventive controls (as it abuses legitimate OS features), detection is possible through "
            "process monitoring and behavioural analysis. Severity is moderate as it requires prior system "
            "access but can capture highly sensitive data that would otherwise be protected."
        ),
        business_impact=[
            "Theft of credentials and API keys during deployment activities",
            "Exposure of sensitive configuration data",
            "Cryptocurrency theft via wallet address replacement",
            "Loss of intellectual property during copy/paste operations",
            "Compromise of multi-factor authentication codes",
        ],
        typical_attack_phase="collection",
        often_precedes=["T1078.004", "T1552.001", "T1567"],
        often_follows=["T1078.004", "T1059", "T1105"],
    ),
    detection_strategies=[
        # Strategy 1: AWS - Clipboard Utility Process Execution
        DetectionStrategy(
            strategy_id="t1115-aws-clipboard-procs",
            name="Clipboard Utility Process Detection (EC2 CloudWatch Agent)",
            description=(
                "Detect execution of clipboard-related utilities (clip.exe, Get-Clipboard, pbpaste, xclip, xsel) "
                "on EC2 instances, especially from non-interactive or suspicious processes."
            ),
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query=r"""fields @timestamp, ec2_instance_id, process_name, command_line, parent_process, user
| filter process_name in ["clip.exe", "powershell.exe", "pwsh.exe", "pbpaste", "xclip", "xsel"]
| filter command_line like /(?i)(Get-Clipboard|clip\.exe|pbpaste|xclip|xsel)/
| filter parent_process not in ["explorer.exe", "Terminal.app", "gnome-terminal", "konsole"]
| stats count(*) as clipboard_accesses by ec2_instance_id, process_name, user, bin(15m) as time_window
| filter clipboard_accesses >= 5
| sort clipboard_accesses desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect clipboard utility usage on EC2 instances for T1115

Parameters:
  CloudWatchLogGroup:
    Type: String
    Description: CloudWatch log group receiving CloudWatch Agent process logs
  AlertEmail:
    Type: String

Resources:
  # Step 1: SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Metric filter for clipboard utility execution
  ClipboardUtilityFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudWatchLogGroup
      FilterPattern: '{ ($.process_name = "clip.exe" || $.process_name = "pbpaste" || $.process_name = "xclip" || $.command_line = "*Get-Clipboard*") }'
      MetricTransformations:
        - MetricName: ClipboardUtilityExecution
          MetricNamespace: Security/T1115
          MetricValue: "1"

  # Step 3: Alarm on repeated clipboard access
  ClipboardAccessAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: T1115-ClipboardUtilityAccess
      MetricName: ClipboardUtilityExecution
      Namespace: Security/T1115
      Statistic: Sum
      Period: 900
      Threshold: 5
      ComparisonOperator: GreaterThanOrEqualToThreshold
      EvaluationPeriods: 1
      AlarmActions: [!Ref AlertTopic]""",
                terraform_template="""# Detect clipboard utility execution on EC2

variable "cloudwatch_log_group" {
  type        = string
  description = "CloudWatch log group receiving process logs from CloudWatch Agent"
}

variable "alert_email" {
  type = string
}

# Step 1: SNS topic
resource "aws_sns_topic" "alerts" {
  name = "clipboard-utility-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Metric filter for clipboard utilities
resource "aws_cloudwatch_log_metric_filter" "clipboard_utils" {
  name           = "clipboard-utility-execution"
  log_group_name = var.cloudwatch_log_group
  pattern        = "{ ($.process_name = \"clip.exe\" || $.process_name = \"pbpaste\" || $.process_name = \"xclip\" || $.command_line = \"*Get-Clipboard*\") }"

  metric_transformation {
    name      = "ClipboardUtilityExecution"
    namespace = "Security/T1115"
    value     = "1"
  }
}

# Step 3: Alarm on repeated clipboard access
resource "aws_cloudwatch_metric_alarm" "clipboard_access" {
  alarm_name          = "T1115-ClipboardUtilityAccess"
  metric_name         = "ClipboardUtilityExecution"
  namespace           = "Security/T1115"
  statistic           = "Sum"
  period              = 900
  threshold           = 5
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  alarm_actions       = [aws_sns_topic.alerts.arn]
}""",
                alert_severity="medium",
                alert_title="Clipboard Utility Execution Detected",
                alert_description_template=(
                    "Instance {ec2_instance_id} executed clipboard utility {process_name} "
                    "{clipboard_accesses} times in 15 minutes by user {user}. This may indicate clipboard data collection."
                ),
                investigation_steps=[
                    "Identify the instance and verify if it's a bastion/jump host",
                    "Review the process tree to identify parent process",
                    "Check if clipboard access is from interactive session or automated script",
                    "Examine recent authentication logs for compromised accounts",
                    "Look for data exfiltration following clipboard access",
                    "Review CloudWatch Agent logs for other suspicious process executions",
                ],
                containment_actions=[
                    "Isolate affected instance from production network",
                    "Review and rotate any credentials that may have been copied",
                    "Terminate suspicious processes accessing clipboard",
                    "Conduct full malware scan on affected systems",
                    "Review IAM credentials and session tokens for misuse",
                    "Consider implementing application whitelisting on bastion hosts",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist legitimate administrative scripts; baseline normal clipboard usage patterns on jump hosts",
            detection_coverage="25% - detects utility-based clipboard access only. API-level malware bypasses this detection.",
            evasion_considerations="Malware using direct Windows API calls instead of utilities; slow polling to avoid thresholds",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2 hours",
            estimated_monthly_cost="$15-30",
            prerequisites=[
                "CloudWatch Agent installed on EC2 instances",
                "Process monitoring enabled in CloudWatch Agent configuration",
                "CloudWatch Logs subscription for process events",
            ],
        ),
        # Strategy 2: AWS - Suspicious PowerShell Clipboard Access
        DetectionStrategy(
            strategy_id="t1115-aws-powershell-clipboard",
            name="PowerShell Get-Clipboard Cmdlet Detection",
            description=(
                "Detect PowerShell Get-Clipboard cmdlet usage, especially from non-interactive "
                "sessions or when combined with exfiltration commands."
            ),
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, ec2_instance_id, command_line, parent_process, user, session_type
| filter command_line like /Get-Clipboard/
| filter command_line like /(curl|Invoke-WebRequest|Invoke-RestMethod|Out-File|Set-Content)/
  or session_type != "interactive"
| stats count(*) as suspicious_accesses by ec2_instance_id, user, bin(1h) as time_window
| sort suspicious_accesses desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect suspicious PowerShell clipboard access

Parameters:
  CloudWatchLogGroup:
    Type: String
  AlertEmail:
    Type: String

Resources:
  # Step 1: SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Metric filter for Get-Clipboard usage
  GetClipboardFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudWatchLogGroup
      FilterPattern: '{ $.command_line = "*Get-Clipboard*" }'
      MetricTransformations:
        - MetricName: PowerShellClipboardAccess
          MetricNamespace: Security/T1115
          MetricValue: "1"

  # Step 3: Alarm for clipboard access
  GetClipboardAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: T1115-PowerShellClipboard
      MetricName: PowerShellClipboardAccess
      Namespace: Security/T1115
      Statistic: Sum
      Period: 3600
      Threshold: 3
      ComparisonOperator: GreaterThanOrEqualToThreshold
      EvaluationPeriods: 1
      AlarmActions: [!Ref AlertTopic]""",
                terraform_template="""# Detect PowerShell clipboard access

variable "cloudwatch_log_group" {
  type = string
}

variable "alert_email" {
  type = string
}

# Step 1: SNS topic
resource "aws_sns_topic" "alerts" {
  name = "powershell-clipboard-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Metric filter for Get-Clipboard
resource "aws_cloudwatch_log_metric_filter" "get_clipboard" {
  name           = "powershell-get-clipboard"
  log_group_name = var.cloudwatch_log_group
  pattern        = "{ $.command_line = \"*Get-Clipboard*\" }"

  metric_transformation {
    name      = "PowerShellClipboardAccess"
    namespace = "Security/T1115"
    value     = "1"
  }
}

# Step 3: Alarm for clipboard access
resource "aws_cloudwatch_metric_alarm" "get_clipboard" {
  alarm_name          = "T1115-PowerShellClipboard"
  metric_name         = "PowerShellClipboardAccess"
  namespace           = "Security/T1115"
  statistic           = "Sum"
  period              = 3600
  threshold           = 3
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  alarm_actions       = [aws_sns_topic.alerts.arn]
}""",
                alert_severity="high",
                alert_title="Suspicious PowerShell Clipboard Access Detected",
                alert_description_template=(
                    "Instance {ec2_instance_id} executed Get-Clipboard cmdlet {suspicious_accesses} times "
                    "in 1 hour by user {user}, potentially combined with exfiltration commands."
                ),
                investigation_steps=[
                    "Review full PowerShell command line for exfiltration indicators",
                    "Check if combined with curl, Invoke-WebRequest, or file write operations",
                    "Verify if execution was from interactive or non-interactive session",
                    "Examine PowerShell script block logging for full command context",
                    "Review network connections from the instance during this timeframe",
                    "Check for credential or API key usage following clipboard access",
                ],
                containment_actions=[
                    "Isolate instance pending investigation",
                    "Review and rotate credentials that may have been exposed",
                    "Enable PowerShell module logging and script block logging",
                    "Implement Constrained Language Mode for PowerShell where possible",
                    "Review outbound network connections for data exfiltration",
                    "Consider AppLocker policies to restrict PowerShell execution",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Whitelist legitimate administrative automation; requires PowerShell logging enabled",
            detection_coverage="30% - effective for PowerShell cmdlet-based access. Direct API calls via .NET bypass this.",
            evasion_considerations="Direct Windows API usage; .NET clipboard classes; obfuscated PowerShell",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1.5 hours",
            estimated_monthly_cost="$10-25",
            prerequisites=[
                "CloudWatch Agent with PowerShell logging",
                "PowerShell Script Block Logging enabled via GPO or registry",
                "CloudWatch Logs for PowerShell events",
            ],
        ),
        # Strategy 3: AWS - Container Clipboard Access Detection
        DetectionStrategy(
            strategy_id="t1115-aws-container-clipboard",
            name="Container Clipboard Tool Installation Detection",
            description=(
                "Detect installation or execution of clipboard utilities in containers, "
                "which is unusual and may indicate compromise."
            ),
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query=r"""fields @timestamp, container_id, container_name, process_name, command_line
| filter command_line like /(apt-get|yum|apk)\s+(install|add).*(xclip|xsel|wl-clipboard)/
  or process_name in ["xclip", "xsel", "wl-copy", "wl-paste"]
| stats count(*) as clipboard_activity by container_id, container_name, command_line
| sort @timestamp desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect clipboard utilities in containers for T1115

Parameters:
  ContainerLogGroup:
    Type: String
    Description: CloudWatch log group for container logs
  AlertEmail:
    Type: String

Resources:
  # Step 1: SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Metric filter for clipboard tool installation
  ContainerClipboardFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref ContainerLogGroup
      FilterPattern: '{ ($.command_line = "*xclip*" || $.command_line = "*xsel*" || $.process_name = "xclip") }'
      MetricTransformations:
        - MetricName: ContainerClipboardTools
          MetricNamespace: Security/T1115
          MetricValue: "1"

  # Step 3: Alarm for container clipboard activity
  ContainerClipboardAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: T1115-ContainerClipboard
      MetricName: ContainerClipboardTools
      Namespace: Security/T1115
      Statistic: Sum
      Period: 900
      Threshold: 1
      ComparisonOperator: GreaterThanOrEqualToThreshold
      EvaluationPeriods: 1
      AlarmActions: [!Ref AlertTopic]""",
                terraform_template="""# Detect clipboard utilities in containers

variable "container_log_group" {
  type        = string
  description = "CloudWatch log group for ECS/EKS container logs"
}

variable "alert_email" {
  type = string
}

# Step 1: SNS topic
resource "aws_sns_topic" "alerts" {
  name = "container-clipboard-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Metric filter for clipboard tools
resource "aws_cloudwatch_log_metric_filter" "container_clipboard" {
  name           = "container-clipboard-tools"
  log_group_name = var.container_log_group
  pattern        = "{ ($.command_line = \"*xclip*\" || $.command_line = \"*xsel*\" || $.process_name = \"xclip\") }"

  metric_transformation {
    name      = "ContainerClipboardTools"
    namespace = "Security/T1115"
    value     = "1"
  }
}

# Step 3: Alarm for container clipboard activity
resource "aws_cloudwatch_metric_alarm" "container_clipboard" {
  alarm_name          = "T1115-ContainerClipboard"
  metric_name         = "ContainerClipboardTools"
  namespace           = "Security/T1115"
  statistic           = "Sum"
  period              = 900
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  alarm_actions       = [aws_sns_topic.alerts.arn]
}""",
                alert_severity="high",
                alert_title="Clipboard Utility Detected in Container",
                alert_description_template=(
                    "Container {container_name} ({container_id}) installed or executed clipboard utility. "
                    "This is highly unusual and indicates potential compromise."
                ),
                investigation_steps=[
                    "Identify the container image and task definition",
                    "Review container logs for full command history",
                    "Check if container has interactive sessions (kubectl exec, ECS exec)",
                    "Examine container image for malicious modifications",
                    "Review IAM roles and service accounts attached to container",
                    "Check for data exfiltration from container networking",
                ],
                containment_actions=[
                    "Terminate affected container immediately",
                    "Scan container image for malware and vulnerabilities",
                    "Review and lock down container image sources",
                    "Disable ECS Exec and kubectl exec on production workloads",
                    "Implement runtime security policies to block package installations",
                    "Review secrets and credentials accessible to the container",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Clipboard utilities in containers are almost always suspicious; minimal tuning needed",
            detection_coverage="70% - container runtime detection only, does not cover host clipboard access",
            evasion_considerations="Pre-installed tools in custom base images; compiled binaries instead of package installation",
            implementation_effort=EffortLevel.LOW,
            implementation_time="1 hour",
            estimated_monthly_cost="$5-15",
            prerequisites=[
                "Container logs shipped to CloudWatch (ECS, EKS)",
                "Runtime monitoring for container processes",
            ],
        ),
        # Strategy 4: GCP - Clipboard Process Monitoring on GCE
        DetectionStrategy(
            strategy_id="t1115-gcp-clipboard-procs",
            name="GCP Clipboard Utility Detection on Compute Instances",
            description=(
                "Detect clipboard utility execution on GCE instances via Cloud Logging "
                "and OS inventory tracking."
            ),
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="gce_instance"
(jsonPayload.process_name="pbpaste" OR
 jsonPayload.process_name="xclip" OR
 jsonPayload.process_name="xsel" OR
 jsonPayload.command=~"Get-Clipboard")
jsonPayload.parent_process!~"(Terminal|gnome-terminal|konsole|explorer.exe)"''',
                gcp_terraform_template="""# GCP: Detect clipboard utility execution

variable "project_id" {
  type = string
}

variable "alert_email" {
  type = string
}

# Step 1: Notification channel
resource "google_monitoring_notification_channel" "email" {
  display_name = "Security Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Log-based metric for clipboard utilities
resource "google_logging_metric" "clipboard_utils" {
  name   = "clipboard-utility-execution"
  filter = <<-EOT
    resource.type="gce_instance"
    (jsonPayload.process_name="pbpaste" OR
     jsonPayload.process_name="xclip" OR
     jsonPayload.process_name="xsel" OR
     jsonPayload.command=~"Get-Clipboard")
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Alert policy for clipboard access
resource "google_monitoring_alert_policy" "clipboard_access" {
  display_name = "Clipboard Utility Execution Detected"
  combiner     = "OR"

  conditions {
    display_name = "Clipboard utility executed on GCE"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.clipboard_utils.name}\""
      duration        = "900s"
      comparison      = "COMPARISON_GT"
      threshold_value = 5
      aggregations {
        alignment_period   = "900s"
        per_series_aligner = "ALIGN_RATE"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]

  documentation {
    content = "Clipboard data collection detected on GCE instance (T1115)"
  }
}""",
                alert_severity="medium",
                alert_title="GCP: Clipboard Utility Execution Detected",
                alert_description_template=(
                    "GCE instance executed clipboard utility from non-interactive process. "
                    "This may indicate clipboard data collection."
                ),
                investigation_steps=[
                    "Identify the GCE instance and verify its purpose",
                    "Review OS inventory and process logs via Cloud Logging",
                    "Check if instance is a bastion or developer workstation",
                    "Examine authentication logs for compromised accounts",
                    "Review VPC Flow Logs for data exfiltration patterns",
                    "Check for other suspicious process executions",
                ],
                containment_actions=[
                    "Isolate affected instance via firewall rules",
                    "Rotate credentials and service account keys",
                    "Terminate suspicious processes",
                    "Enable OS Config for compliance and vulnerability scanning",
                    "Review IAM permissions for the instance service account",
                    "Consider VM Manager OS policy for security baselines",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Baseline clipboard usage on jump hosts; whitelist legitimate admin scripts",
            detection_coverage="20% - detects utility execution only, requires OS logging agent. API-level access not detected.",
            evasion_considerations="Direct API calls instead of utilities; low-frequency polling",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2 hours",
            estimated_monthly_cost="$10-20",
            prerequisites=[
                "Cloud Logging enabled",
                "OS Config agent or Ops Agent installed on GCE instances",
                "Process monitoring configuration enabled",
            ],
        ),
        # Strategy 5: GCP - GKE Container Clipboard Activity
        DetectionStrategy(
            strategy_id="t1115-gcp-gke-clipboard",
            name="GKE Container Clipboard Tool Detection",
            description=(
                "Detect clipboard utility installation or execution in GKE containers "
                "via Cloud Logging and runtime monitoring."
            ),
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""resource.type="k8s_container"
(jsonPayload.message=~"(apt-get|yum|apk).*(install|add).*(xclip|xsel)" OR
 jsonPayload.process_name=~"(xclip|xsel|wl-copy|wl-paste)")""",
                gcp_terraform_template="""# GCP: Detect clipboard utilities in GKE containers

variable "project_id" {
  type = string
}

variable "alert_email" {
  type = string
}

# Step 1: Notification channel
resource "google_monitoring_notification_channel" "email" {
  display_name = "Security Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Log-based metric for container clipboard tools
resource "google_logging_metric" "container_clipboard" {
  name   = "gke-container-clipboard-tools"
  filter = <<-EOT
    resource.type="k8s_container"
    (jsonPayload.message=~"(apt-get|yum|apk).*(install|add).*(xclip|xsel)" OR
     jsonPayload.process_name=~"(xclip|xsel|wl-copy)")
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Alert policy
resource "google_monitoring_alert_policy" "container_clipboard" {
  display_name = "GKE Container Clipboard Tool Detected"
  combiner     = "OR"

  conditions {
    display_name = "Clipboard utility in container"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.container_clipboard.name}\""
      duration        = "0s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]

  documentation {
    content = "Clipboard utility detected in GKE container - highly suspicious (T1115)"
  }
}""",
                alert_severity="high",
                alert_title="GCP: Clipboard Utility in GKE Container",
                alert_description_template=(
                    "GKE container installed or executed clipboard utility. This is highly unusual "
                    "and indicates potential compromise of the container workload."
                ),
                investigation_steps=[
                    "Identify the pod, namespace, and container image",
                    "Review container logs for full command history",
                    "Check for kubectl exec sessions to the pod",
                    "Examine container image for malicious content",
                    "Review Workload Identity and service account permissions",
                    "Check for network egress from the pod to external destinations",
                ],
                containment_actions=[
                    "Delete affected pod immediately",
                    "Review and validate container image provenance",
                    "Implement Binary Authorization to prevent unsigned images",
                    "Disable kubectl exec on production namespaces via RBAC",
                    "Deploy runtime security policies (Falco, GKE Security Posture)",
                    "Rotate any secrets accessible to the compromised pod",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Clipboard utilities in containers are almost always malicious; minimal false positives expected",
            detection_coverage="70% - container runtime detection only, does not cover host clipboard access",
            evasion_considerations="Pre-built malicious images with embedded tools; binary injection at runtime",
            implementation_effort=EffortLevel.LOW,
            implementation_time="1 hour",
            estimated_monthly_cost="$5-10",
            prerequisites=[
                "GKE cluster with Cloud Logging enabled",
                "Container runtime logs exported to Cloud Logging",
            ],
        ),
    ],
    recommended_order=[
        "t1115-aws-container-clipboard",
        "t1115-gcp-gke-clipboard",
        "t1115-aws-powershell-clipboard",
        "t1115-aws-clipboard-procs",
        "t1115-gcp-clipboard-procs",
    ],
    total_effort_hours=7.5,
    coverage_improvement="+15% improvement for Collection tactic",
)
