"""
T1010 - Application Window Discovery

Adversaries enumerate application windows to gather information about running
applications, identify security tools, and discover potential data sources.
"""

from .template_loader import (
    RemediationTemplate,
    ThreatContext,
    DetectionStrategy,
    DetectionImplementation,
    DetectionType,
    EffortLevel,
    FalsePositiveRate,
    CloudProvider,
)

TEMPLATE = RemediationTemplate(
    technique_id="T1010",
    technique_name="Application Window Discovery",
    tactic_ids=["TA0007"],
    mitre_url="https://attack.mitre.org/techniques/T1010/",
    threat_context=ThreatContext(
        description=(
            "Adversaries enumerate application windows to obtain a listing of open "
            "applications and their window titles. This reconnaissance helps identify "
            "security tools for evasion, discover valuable applications like cryptocurrency "
            "wallets or email clients, and understand system usage patterns. Attackers "
            "typically leverage Win32 APIs (EnumWindows, GetForegroundWindow), X11 utilities "
            "(xdotool, wmctrl), or macOS AppleScript to perform enumeration."
        ),
        attacker_goal="Enumerate application windows to identify security tools and valuable targets",
        why_technique=[
            "Identifies security tools and defensive software",
            "Discovers cryptocurrency wallets and financial applications",
            "Maps email clients and communication tools",
            "Determines screenshot and keylogging targets",
            "Reveals analysis and sandbox environments",
            "Informs follow-on data collection activities",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="common",
        trend="stable",
        severity_score=5,
        severity_reasoning=(
            "Application window discovery is reconnaissance activity that indicates "
            "active threat actor presence. It typically precedes data collection, "
            "credential theft, or defence evasion. Attackers use this to identify "
            "high-value targets like cryptocurrency wallets and security tools. "
            "Early detection provides opportunity for containment before data theft."
        ),
        business_impact=[
            "Indicates active reconnaissance of applications",
            "Precursor to targeted data collection",
            "Security tool mapping by attackers",
            "Credential theft risk from banking/wallet apps",
            "Email and communication tool targeting",
        ],
        typical_attack_phase="discovery",
        often_precedes=["T1113", "T1056.001", "T1005", "T1114"],
        often_follows=["T1078.004", "T1190", "T1566"],
    ),
    detection_strategies=[
        # Strategy 1: AWS - EC2 Windows API Monitoring via CloudWatch Logs
        DetectionStrategy(
            strategy_id="t1010-aws-windows",
            name="AWS EC2 Windows API Enumeration Detection",
            description="Detect Win32 API calls for window enumeration on Windows EC2 instances.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, EventID, ProcessName, ApiCall
| filter EventID = 7 OR EventID = 10
| filter ApiCall like /EnumWindows|GetForegroundWindow|GetWindowText|FindWindow/
| stats count(*) as api_calls by ProcessName, SourceImage, bin(30m)
| filter api_calls > 10
| sort api_calls desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect application window discovery on Windows EC2 instances

Parameters:
  LogGroupName:
    Type: String
    Description: CloudWatch Log Group for Windows event logs
  AlertEmail:
    Type: String

Resources:
  # Step 1: SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Metric filter for Win32 API window enumeration
  WindowEnumFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref LogGroupName
      FilterPattern: '[time, event_id=7||event_id=10, ..., api_call=*EnumWindows* || api_call=*GetForegroundWindow* || api_call=*GetWindowText*]'
      MetricTransformations:
        - MetricName: WindowEnumeration
          MetricNamespace: Security
          MetricValue: "1"

  # Step 3: CloudWatch alarm for excessive enumeration
  WindowEnumAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: ApplicationWindowDiscovery
      MetricName: WindowEnumeration
      Namespace: Security
      Statistic: Sum
      Period: 1800
      Threshold: 15
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      TreatMissingData: notBreaching

      AlarmActions: [!Ref AlertTopic]""",
                terraform_template="""# Detect application window discovery on Windows EC2

variable "log_group_name" {
  type        = string
  description = "CloudWatch Log Group for Windows event logs"
}

variable "alert_email" {
  type = string
}

# Step 1: SNS topic for alerts
resource "aws_sns_topic" "alerts" {
  name = "window-enumeration-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Metric filter for Win32 API window enumeration
resource "aws_cloudwatch_log_metric_filter" "window_enum" {
  name           = "window-enumeration"
  log_group_name = var.log_group_name
  pattern        = "[time, event_id=7||event_id=10, ..., api_call=*EnumWindows* || api_call=*GetForegroundWindow* || api_call=*GetWindowText*]"

  metric_transformation {
    name      = "WindowEnumeration"
    namespace = "Security"
    value     = "1"
  }
}

# Step 3: CloudWatch alarm for excessive enumeration
resource "aws_cloudwatch_metric_alarm" "window_enum" {
  alarm_name          = "ApplicationWindowDiscovery"
  metric_name         = "WindowEnumeration"
  namespace           = "Security"
  statistic           = "Sum"
  period              = 1800
  threshold           = 15
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions [aws_sns_topic.alerts.arn]
}""",
                alert_severity="medium",
                alert_title="Application Window Discovery Detected",
                alert_description_template="Win32 API calls for window enumeration detected from {ProcessName}.",
                investigation_steps=[
                    "Identify the process performing window enumeration",
                    "Check if the process is legitimate or malicious",
                    "Review what windows were enumerated",
                    "Look for correlation with keylogging or screenshots",
                    "Check for follow-on data collection activity",
                ],
                containment_actions=[
                    "Analyse suspicious process and parent process",
                    "Check for malware signatures",
                    "Monitor for credential theft attempts",
                    "Review security tool status",
                    "Consider isolating affected instance",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist legitimate monitoring tools and UI automation software",
            detection_coverage="70% - detects API-based enumeration with Sysmon logging",
            evasion_considerations="Slow enumeration or use of undocumented APIs may evade detection",
            implementation_effort=EffortLevel.HIGH,
            implementation_time="2 hours",
            estimated_monthly_cost="$10-20",
            prerequisites=[
                "Sysmon installed on Windows instances",
                "CloudWatch Logs agent configured",
            ],
        ),
        # Strategy 2: AWS - PowerShell Script Monitoring
        DetectionStrategy(
            strategy_id="t1010-aws-powershell",
            name="AWS PowerShell Window Enumeration Detection",
            description="Detect PowerShell scripts enumerating application windows via Get-Process or UI Automation.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, EventID, ScriptBlockText, UserName
| filter EventID = 4104
| filter ScriptBlockText like /Get-Process.*MainWindowTitle|\\[Windows\\.Automation|EnumWindows/
| stats count(*) as script_count by UserName, ComputerName, bin(30m)
| sort @timestamp desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect PowerShell-based window enumeration

Parameters:
  PowerShellLogGroup:
    Type: String
    Description: CloudWatch Log Group for PowerShell logs
  AlertEmail:
    Type: String

Resources:
  # Step 1: SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Metric filter for PowerShell window enumeration
  PowerShellWindowFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref PowerShellLogGroup
      FilterPattern: '[..., script=*MainWindowTitle* || script=*Windows.Automation* || script=*EnumWindows*]'
      MetricTransformations:
        - MetricName: PowerShellWindowEnum
          MetricNamespace: Security
          MetricValue: "1"

  # Step 3: CloudWatch alarm
  PowerShellWindowAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: PowerShellWindowEnumeration
      MetricName: PowerShellWindowEnum
      Namespace: Security
      Statistic: Sum
      Period: 1800
      Threshold: 5
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      TreatMissingData: notBreaching

      AlarmActions: [!Ref AlertTopic]""",
                terraform_template="""# Detect PowerShell window enumeration

variable "powershell_log_group" {
  type        = string
  description = "CloudWatch Log Group for PowerShell logs"
}

variable "alert_email" {
  type = string
}

# Step 1: SNS topic for alerts
resource "aws_sns_topic" "alerts" {
  name = "powershell-window-enum-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Metric filter for PowerShell window enumeration
resource "aws_cloudwatch_log_metric_filter" "powershell_window" {
  name           = "powershell-window-enumeration"
  log_group_name = var.powershell_log_group
  pattern        = "[..., script=*MainWindowTitle* || script=*Windows.Automation* || script=*EnumWindows*]"

  metric_transformation {
    name      = "PowerShellWindowEnum"
    namespace = "Security"
    value     = "1"
  }
}

# Step 3: CloudWatch alarm
resource "aws_cloudwatch_metric_alarm" "powershell_window" {
  alarm_name          = "PowerShellWindowEnumeration"
  metric_name         = "PowerShellWindowEnum"
  namespace           = "Security"
  statistic           = "Sum"
  period              = 1800
  threshold           = 5
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions [aws_sns_topic.alerts.arn]
}""",
                alert_severity="medium",
                alert_title="PowerShell Window Enumeration Detected",
                alert_description_template="PowerShell script enumerating application windows executed by {UserName}.",
                investigation_steps=[
                    "Review the complete PowerShell script block",
                    "Identify who executed the script",
                    "Check if this is authorised administrative activity",
                    "Look for associated keylogging or screenshot activity",
                    "Review recent activity from this user",
                ],
                containment_actions=[
                    "Analyse script content for malicious behaviour",
                    "Check for follow-on data exfiltration",
                    "Monitor for credential theft attempts",
                    "Review PowerShell execution policies",
                    "Consider restricting PowerShell access",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Whitelist authorised automation scripts and monitoring tools",
            detection_coverage="85% - detects PowerShell-based enumeration with script block logging",
            evasion_considerations="Obfuscated scripts or AMSI bypass may evade detection",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$8-15",
            prerequisites=[
                "PowerShell script block logging enabled",
                "CloudWatch Logs agent configured",
            ],
        ),
        # Strategy 3: GCP - Linux X11 Utility Detection
        DetectionStrategy(
            strategy_id="t1010-gcp-linux",
            name="GCP Linux X11 Window Enumeration Detection",
            description="Detect X11 utilities (xdotool, wmctrl) used for window enumeration on Linux instances.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''protoPayload.request.cmdline=~"(xdotool|wmctrl|xwininfo|xprop)"
OR textPayload=~"(xdotool.*search|wmctrl -l|xwininfo -root|xprop -root)"''',
                gcp_terraform_template="""# GCP: Detect X11 window enumeration on Linux instances

variable "project_id" {
  type = string
}

variable "alert_email" {
  type = string
}

# Step 1: Notification channel for alerts
resource "google_monitoring_notification_channel" "email" {
  display_name = "Security Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Log-based metric for X11 window enumeration
resource "google_logging_metric" "x11_window_enum" {
  name   = "x11-window-enumeration"
  filter = <<-EOT
    protoPayload.request.cmdline=~"(xdotool|wmctrl|xwininfo|xprop)"
    OR textPayload=~"(xdotool.*search|wmctrl -l|xwininfo -root|xprop -root)"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Alert policy for window enumeration
resource "google_monitoring_alert_policy" "x11_window_enum" {
  display_name = "X11 Window Enumeration Detected"
  combiner     = "OR"

  conditions {
    display_name = "Suspicious X11 utility usage"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.x11_window_enum.name}\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 5
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]
}""",
                alert_severity="medium",
                alert_title="GCP: X11 Window Enumeration Detected",
                alert_description_template="X11 utilities used for window enumeration on Compute instance.",
                investigation_steps=[
                    "Identify which instance and user executed the command",
                    "Review the specific X11 utility and parameters",
                    "Check if this is authorised administrative activity",
                    "Look for correlation with screenshots or keylogging",
                    "Review instance's expected workload",
                ],
                containment_actions=[
                    "Review instance access logs",
                    "Check for data collection activities",
                    "Monitor for credential theft attempts",
                    "Consider disabling X11 forwarding if unused",
                    "Audit user permissions and access",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Whitelist legitimate desktop automation and testing tools",
            detection_coverage="75% - detects X11 utility-based enumeration",
            evasion_considerations="Direct /proc/ access or custom tools may evade detection",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$10-15",
            prerequisites=[
                "Cloud Audit Logs enabled",
                "OS Login or SSH logging configured",
            ],
        ),
        # Strategy 4: GCP - macOS AppleScript Detection
        DetectionStrategy(
            strategy_id="t1010-gcp-macos",
            name="GCP macOS AppleScript Window Enumeration Detection",
            description="Detect AppleScript and macOS APIs used for window enumeration on macOS instances.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''protoPayload.request.cmdline=~"(osascript|CGWindowListCopyWindowInfo|NSRunningApplication)"
OR textPayload=~"(tell application.*windows|CGWindowListCopyWindowInfo|NSRunningApplication)"''',
                gcp_terraform_template="""# GCP: Detect macOS window enumeration

variable "project_id" {
  type = string
}

variable "alert_email" {
  type = string
}

# Step 1: Notification channel for alerts
resource "google_monitoring_notification_channel" "email" {
  display_name = "Security Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Log-based metric for macOS window enumeration
resource "google_logging_metric" "macos_window_enum" {
  name   = "macos-window-enumeration"
  filter = <<-EOT
    protoPayload.request.cmdline=~"(osascript|CGWindowListCopyWindowInfo|NSRunningApplication)"
    OR textPayload=~"(tell application.*windows|CGWindowListCopyWindowInfo|NSRunningApplication)"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Alert policy for macOS window enumeration
resource "google_monitoring_alert_policy" "macos_window_enum" {
  display_name = "macOS Window Enumeration Detected"
  combiner     = "OR"

  conditions {
    display_name = "Suspicious AppleScript or API usage"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.macos_window_enum.name}\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 5
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]
}""",
                alert_severity="medium",
                alert_title="GCP: macOS Window Enumeration Detected",
                alert_description_template="AppleScript or macOS API used for window enumeration on instance.",
                investigation_steps=[
                    "Identify which instance and user executed the script",
                    "Review the AppleScript or API call details",
                    "Check if this is authorised automation",
                    "Look for associated data collection activity",
                    "Review recent user activity",
                ],
                containment_actions=[
                    "Analyse script or binary for malicious behaviour",
                    "Check for follow-on credential theft",
                    "Monitor for screenshot or keylogging activity",
                    "Review user permissions and legitimacy",
                    "Consider restricting AppleScript execution",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Whitelist authorised UI automation and testing frameworks",
            detection_coverage="70% - detects AppleScript and API-based enumeration",
            evasion_considerations="Custom compiled tools or undocumented APIs may evade detection",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$10-15",
            prerequisites=[
                "Cloud Audit Logs enabled",
                "macOS system logging configured",
            ],
        ),
    ],
    recommended_order=[
        "t1010-aws-powershell",
        "t1010-aws-windows",
        "t1010-gcp-linux",
        "t1010-gcp-macos",
    ],
    total_effort_hours=5.0,
    coverage_improvement="+10% improvement for Discovery tactic",
)
