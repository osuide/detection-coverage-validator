"""
T1546.008 - Event Triggered Execution: Accessibility Features

Adversaries exploit Windows accessibility features to establish persistence and
elevate privileges by executing malicious content triggered before user login.
Used by APT29, APT3, APT41, Axiom, Deep Panda, Fox Kitten.
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
    technique_id="T1546.008",
    technique_name="Event Triggered Execution: Accessibility Features",
    tactic_ids=["TA0004", "TA0003"],  # Privilege Escalation, Persistence
    mitre_url="https://attack.mitre.org/techniques/T1546/008/",
    threat_context=ThreatContext(
        description=(
            "Adversaries exploit Windows accessibility features to establish persistence "
            "and elevate privileges by executing malicious content triggered before user login. "
            "The technique leverages programs launched via keyboard shortcuts at the Windows "
            "logon screen, including Sticky Keys (sethc.exe), Utility Manager (utilman.exe), "
            "and other accessibility tools. Attackers replace these binaries or modify Registry "
            "pointers to execute arbitrary code with SYSTEM privileges without authentication."
        ),
        attacker_goal="Establish persistence and gain SYSTEM-level access via accessibility feature exploitation",
        why_technique=[
            "Pre-authentication execution capability",
            "SYSTEM-level privileges without credentials",
            "Accessible via Remote Desktop Protocol",
            "Difficult to detect without file integrity monitoring",
            "Can be triggered from login screen",
            "Bypasses standard authentication controls",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="uncommon",
        trend="declining",
        severity_score=8,
        severity_reasoning=(
            "Provides SYSTEM-level persistence without authentication. However, requires "
            "prior administrative access to modify system files or Registry. Modern Windows "
            "protections make this harder but not impossible."
        ),
        business_impact=[
            "Persistent backdoor access",
            "Privilege escalation to SYSTEM",
            "Bypass of authentication controls",
            "Remote access via RDP sessions",
            "Difficult to remediate without awareness",
        ],
        typical_attack_phase="persistence",
        often_precedes=[
            "T1078",
            "T1021.001",
        ],  # Valid Accounts, Remote Desktop Protocol
        often_follows=[
            "T1068",
            "T1055",
        ],  # Exploitation for Privilege Escalation, Process Injection
    ),
    detection_strategies=[
        DetectionStrategy(
            strategy_id="t1546008-aws-file-integrity",
            name="AWS File Integrity Monitoring for Accessibility Features",
            description="Detect modifications to Windows accessibility binaries in EC2 instances.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, detail.eventName, detail.requestParameters.instanceId
| filter detail.eventName = "ModifyInstanceAttribute"
  OR detail.eventName = "RunCommand"
| filter detail.requestParameters.command like /sethc|utilman|osk|magnify|narrator|displayswitch|atbroker/
| stats count(*) as modifications by detail.userIdentity.principalId, detail.requestParameters.instanceId
| sort modifications desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Monitor for accessibility feature tampering on EC2 Windows instances

Parameters:
  AlertEmail:
    Type: String
    Description: Email address for security alerts

Resources:
  # SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      DisplayName: Accessibility Feature Tampering Alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # EventBridge rule to detect SSM Run Command targeting accessibility features
  AccessibilityTamperRule:
    Type: AWS::Events::Rule
    Properties:
      Name: DetectAccessibilityFeatureTampering
      Description: Detect modifications to Windows accessibility features
      EventPattern:
        source:
          - aws.ssm
        detail-type:
          - AWS API Call via CloudTrail
        detail:
          eventName:
            - SendCommand
      State: ENABLED
      Targets:
        - Arn: !Ref AlertTopic
          Id: AccessibilityTamperTopic

  # CloudWatch Log Metric Filter for file modifications
  FileModificationFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: /aws/ec2/windows/security
      FilterPattern: '[time, event_type="4663", ..., object_name="*sethc.exe*" || object_name="*utilman.exe*" || object_name="*osk.exe*"]'
      MetricTransformations:
        - MetricName: AccessibilityFeatureModifications
          MetricNamespace: Security/Windows
          MetricValue: "1"

  # CloudWatch Alarm for accessibility feature tampering
  AccessibilityTamperAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: AccessibilityFeatureTamperingDetected
      AlarmDescription: Detects potential tampering with Windows accessibility features
      MetricName: AccessibilityFeatureModifications
      Namespace: Security/Windows
      Statistic: Sum
      Period: 300
      Threshold: 1
      ComparisonOperator: GreaterThanOrEqualToThreshold
      EvaluationPeriods: 1
      TreatMissingData: notBreaching

      AlarmActions:
        - !Ref AlertTopic""",
                terraform_template="""# Monitor for accessibility feature tampering on EC2 Windows instances

variable "alert_email" {
  type = string
  description = "Email address for security alerts"

  TopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics:
        - !Ref AlertTopic
      PolicyDocument:
        Statement:
          - Effect: Allow
            Principal:
              Service: events.amazonaws.com
            Action: sns:Publish
            Resource: !Ref AlertTopic
}

# SNS topic for alerts
resource "aws_sns_topic" "accessibility_alerts" {
  name         = "accessibility-feature-tampering-alerts"
  kms_master_key_id = "alias/aws/sns"
  display_name = "Accessibility Feature Tampering Alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.accessibility_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# EventBridge rule to detect SSM commands targeting accessibility features
resource "aws_cloudwatch_event_rule" "accessibility_tamper" {
  name        = "detect-accessibility-feature-tampering"
  description = "Detect modifications to Windows accessibility features"

  event_pattern = jsonencode({
    source      = ["aws.ssm"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = ["SendCommand"]
    }
  })
}

# Dead Letter Queue for failed events
resource "aws_sqs_queue" "dlq" {
  name                      = "accessibility-tamper-dlq"
  message_retention_seconds = 1209600  # 14 days
}

resource "aws_sqs_queue_policy" "dlq" {
  queue_url = aws_sqs_queue.dlq.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sqs:SendMessage"
      Resource  = aws_sqs_queue.dlq.arn
      Condition = {
        ArnEquals = { "aws:SourceArn" = aws_cloudwatch_event_rule.accessibility_tamper.arn }
      }
    }]
  })
}

# EventBridge target with retry and DLQ
resource "aws_cloudwatch_event_target" "sns" {
  rule      = aws_cloudwatch_event_rule.accessibility_tamper.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.accessibility_alerts.arn

  retry_policy {
    maximum_event_age_in_seconds = 3600
    maximum_retry_attempts       = 8
  }

  dead_letter_config {
    arn = aws_sqs_queue.dlq.arn
  }
  input_transformer {
    input_paths = {
      account       = "$.account"
      region        = "$.region"
      time          = "$.time"
      eventName     = "$.detail.eventName"
      eventSource   = "$.detail.eventSource"
      sourceIP      = "$.detail.sourceIPAddress"
      userIdentity  = "$.detail.userIdentity.arn"
    }

    input_template = <<-EOT
"CloudTrail Security Alert
Time: <time>
Account: <account>
Region: <region>
Event: <eventName>
Source: <eventSource>
User: <userIdentity>
Source IP: <sourceIP>
Action: Review CloudTrail event and investigate"
EOT
  }

}

# Allow EventBridge to publish to SNS
data "aws_caller_identity" "current" {}

resource "aws_sns_topic_policy" "allow_eventbridge" {
  arn = aws_sns_topic.accessibility_alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.accessibility_alerts.arn
    Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
          ArnEquals = {
            "aws:SourceArn" = aws_cloudwatch_event_rule.accessibility_tamper.arn
          }
      }
    }]
  })
}

# CloudWatch Log Metric Filter
resource "aws_cloudwatch_log_metric_filter" "file_modifications" {
  name           = "accessibility-feature-modifications"
  log_group_name = "/aws/ec2/windows/security"
  pattern        = "[time, event_type=\"4663\", ..., object_name=\"*sethc.exe*\" || object_name=\"*utilman.exe*\" || object_name=\"*osk.exe*\"]"

  metric_transformation {
    name      = "AccessibilityFeatureModifications"
    namespace = "Security/Windows"
    value     = "1"
  }
}

# CloudWatch Alarm
resource "aws_cloudwatch_metric_alarm" "accessibility_tamper" {
  alarm_name          = "accessibility-feature-tampering-detected"
  alarm_description   = "Detects potential tampering with Windows accessibility features"
  metric_name         = "AccessibilityFeatureModifications"
  namespace           = "Security/Windows"
  statistic           = "Sum"
  period              = 300
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.accessibility_alerts.arn]
}""",
                alert_severity="critical",
                alert_title="Windows Accessibility Feature Tampering Detected",
                alert_description_template="Potential tampering with accessibility features detected on instance {instanceId}.",
                investigation_steps=[
                    "Verify integrity of accessibility binaries (sethc.exe, utilman.exe, osk.exe)",
                    "Check Registry keys: HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options",
                    "Review recent administrative actions and SSM commands",
                    "Examine Windows Security Event Log for file modification events (Event ID 4663, 4656)",
                    "Check for suspicious processes launched with SYSTEM privileges",
                    "Review RDP access logs for unauthorised connections",
                ],
                containment_actions=[
                    "Isolate affected EC2 instance immediately",
                    "Restore accessibility binaries from known good backup or AMI",
                    "Remove malicious Registry keys under Image File Execution Options",
                    "Rotate credentials for affected systems",
                    "Review and restrict RDP access",
                    "Enable enhanced file integrity monitoring",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Legitimate modifications to accessibility features are extremely rare in production",
            detection_coverage="85% - catches file replacements and Registry modifications",
            evasion_considerations="Attackers may use memory-only techniques or alternate persistence methods",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2-3 hours",
            estimated_monthly_cost="$5-20",
            prerequisites=[
                "CloudWatch Logs agent on Windows EC2 instances",
                "Windows Security Event Log forwarding configured",
            ],
        ),
        DetectionStrategy(
            strategy_id="t1546008-aws-registry-monitor",
            name="AWS Registry Monitoring for IFEO Modifications",
            description="Detect Registry changes to Image File Execution Options for accessibility features.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, EventID, TargetObject, Details
| filter EventID = 13 OR EventID = 12
| filter TargetObject like /Image File Execution Options.*sethc|Image File Execution Options.*utilman|Image File Execution Options.*osk|Image File Execution Options.*magnify/
| stats count(*) as registry_changes by TargetObject, Details
| sort registry_changes desc""",
                terraform_template="""# Monitor Registry changes to Image File Execution Options for accessibility features

variable "alert_email" {
  type = string
  description = "Email address for security alerts"
}

variable "windows_log_group" {
  type        = string
  default     = "/aws/ec2/windows/sysmon"
  description = "CloudWatch log group for Windows Sysmon logs"
}

# SNS topic for alerts
resource "aws_sns_topic" "ifeo_alerts" {
  name         = "ifeo-modification-alerts"
  kms_master_key_id = "alias/aws/sns"
  display_name = "Image File Execution Options Modification Alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.ifeo_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# CloudWatch Log Metric Filter for Registry modifications
resource "aws_cloudwatch_log_metric_filter" "ifeo_modifications" {
  name           = "ifeo-accessibility-modifications"
  log_group_name = var.windows_log_group
  pattern        = "{ ($.EventID = 13 || $.EventID = 12) && ($.TargetObject = \"*Image File Execution Options*sethc*\" || $.TargetObject = \"*Image File Execution Options*utilman*\" || $.TargetObject = \"*Image File Execution Options*osk*\") }"

  metric_transformation {
    name      = "IFEOAccessibilityModifications"
    namespace = "Security/Windows/Registry"
    value     = "1"
  }
}

# CloudWatch Alarm
resource "aws_cloudwatch_metric_alarm" "ifeo_tamper" {
  alarm_name          = "ifeo-accessibility-tampering"
  alarm_description   = "Detects Registry modifications to Image File Execution Options for accessibility features"
  metric_name         = "IFEOAccessibilityModifications"
  namespace           = "Security/Windows/Registry"
  statistic           = "Sum"
  period              = 60
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.ifeo_alerts.arn]
  treat_missing_data  = "notBreaching"
}""",
                alert_severity="critical",
                alert_title="Image File Execution Options Tampering Detected",
                alert_description_template="Registry modification detected for accessibility feature IFEO: {TargetObject}.",
                investigation_steps=[
                    "Review specific Registry key modified: HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\[accessibility_binary]",
                    "Check for Debugger value pointing to malicious executables",
                    "Identify user account that made the modification",
                    "Review Sysmon Event ID 12 (Registry object added/deleted) and 13 (Registry value set)",
                    "Correlate with process creation events (Sysmon Event ID 1)",
                    "Check for other indicators of compromise on the system",
                ],
                containment_actions=[
                    "Immediately delete malicious IFEO Registry keys",
                    "Isolate affected instance from network",
                    "Terminate suspicious processes running as SYSTEM",
                    "Review and revoke administrative credentials",
                    "Deploy EDR/File Integrity Monitoring if not present",
                    "Conduct full forensic analysis of the instance",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="IFEO modifications for accessibility features are almost always malicious",
            detection_coverage="90% - highly effective for Registry-based tampering",
            evasion_considerations="Direct binary replacement may bypass Registry monitoring",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2-3 hours",
            estimated_monthly_cost="$5-15",
            prerequisites=[
                "Sysmon installed on Windows EC2 instances",
                "Sysmon logs forwarded to CloudWatch",
            ],
        ),
        DetectionStrategy(
            strategy_id="t1546008-gcp-file-integrity",
            name="GCP File Integrity Monitoring for Windows Accessibility Features",
            description="Monitor Windows VM instances for accessibility feature tampering using Cloud Logging.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="gce_instance"
logName="projects/YOUR_PROJECT/logs/windows-security"
jsonPayload.EventID=4663
(jsonPayload.ObjectName=~".*sethc\\.exe.*" OR
 jsonPayload.ObjectName=~".*utilman\\.exe.*" OR
 jsonPayload.ObjectName=~".*osk\\.exe.*" OR
 jsonPayload.ObjectName=~".*magnify\\.exe.*")
jsonPayload.AccessMask=~".*WRITE.*|.*DELETE.*"''',
                gcp_terraform_template="""# GCP: Monitor for Windows accessibility feature tampering

variable "project_id" {
  type = string
  description = "GCP project ID"
}

variable "alert_email" {
  type = string
  description = "Email address for security alerts"
}

# Notification channel for alerts
resource "google_monitoring_notification_channel" "email_s1" {
  project      = var.project_id
  display_name = "Security Alerts Email"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Log-based metric for accessibility feature modifications
resource "google_logging_metric" "accessibility_tamper" {
  name   = "accessibility-feature-tampering"
  filter = <<-EOT
    resource.type="gce_instance"
    logName="projects/${var.project_id}/logs/windows-security"
    jsonPayload.EventID=4663
    (jsonPayload.ObjectName=~".*sethc\\.exe.*" OR
     jsonPayload.ObjectName=~".*utilman\\.exe.*" OR
     jsonPayload.ObjectName=~".*osk\\.exe.*" OR
     jsonPayload.ObjectName=~".*magnify\\.exe.*")
    jsonPayload.AccessMask=~".*WRITE.*|.*DELETE.*"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    unit        = "1"
    labels {
      key         = "instance_id"
      value_type  = "STRING"
      description = "Instance ID where tampering occurred"
    }
  }

  label_extractors = {
    "instance_id" = "EXTRACT(resource.labels.instance_id)"
  }
}

# Alert policy for accessibility feature tampering
resource "google_monitoring_alert_policy" "accessibility_tamper" {
  project      = var.project_id
  display_name = "Windows Accessibility Feature Tampering"
  combiner     = "OR"

  conditions {
    display_name = "Accessibility feature modification detected"

    condition_threshold {
      filter          = "resource.type=\"gce_instance\" AND metric.type=\"logging.googleapis.com/user/${google_logging_metric.accessibility_tamper.name}\""
      duration        = "60s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0

      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_RATE"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email_s1.id]

  alert_strategy {
    auto_close = "1800s"
    notification_rate_limit {
      period = "300s"
    }
  }

  documentation {
    content   = "Windows accessibility feature tampering detected. This may indicate T1546.008 (Accessibility Features) persistence technique."
    mime_type = "text/markdown"
  }
}

# Log sink to ensure Windows Security logs are captured
resource "google_logging_project_sink" "windows_security" {
  name        = "windows-security-sink"
  destination = "logging.googleapis.com/projects/${var.project_id}/locations/global/buckets/_Default"

  filter = <<-EOT
    resource.type="gce_instance"
    logName="projects/${var.project_id}/logs/windows-security"
  EOT

  unique_writer_identity = true
}""",
                alert_severity="critical",
                alert_title="GCP: Windows Accessibility Feature Tampering",
                alert_description_template="Accessibility feature modification detected on GCE instance in project {project_id}.",
                investigation_steps=[
                    "Identify affected GCE Windows instance from logs",
                    "Connect via Serial Console or IAP to verify accessibility binary integrity",
                    "Check file hashes against known good values",
                    "Review Cloud Audit Logs for administrative actions",
                    "Examine Windows Event Viewer for Security Events (4663, 4656, 4658)",
                    "Look for suspicious processes running as SYSTEM",
                ],
                containment_actions=[
                    "Stop affected GCE instance",
                    "Create disk snapshot for forensics",
                    "Restore system files from clean VM image",
                    "Remove firewall rules allowing RDP from internet",
                    "Rotate service account keys and credentials",
                    "Enable VPC Service Controls for enhanced isolation",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Legitimate modifications are extremely rare; Windows Update may trigger false positives",
            detection_coverage="80% - effective for file-based tampering on GCP VMs",
            evasion_considerations="Requires Windows Security Event logging to be properly configured",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2-3 hours",
            estimated_monthly_cost="$10-25",
            prerequisites=[
                "Windows Security Event Log forwarding to Cloud Logging",
                "Ops Agent or legacy logging agent installed",
            ],
        ),
        # Azure Strategy: Event Triggered Execution: Accessibility Features
        DetectionStrategy(
            strategy_id="t1546008-azure",
            name="Azure Event Triggered Execution: Accessibility Features Detection",
            description=(
                "Azure detection for Event Triggered Execution: Accessibility Features. "
                "Provides native Azure detection using Log Analytics and Defender for Cloud."
            ),
            detection_type=DetectionType.DEFENDER_ALERT,
            aws_service="n/a",
            azure_service="defender",
            cloud_provider=CloudProvider.AZURE,
            implementation=DetectionImplementation(
                defender_alert_types=["Suspicious activity detected"],
                azure_terraform_template="""# Microsoft Defender for Cloud Detection
# Event Triggered Execution: Accessibility Features (T1546.008)
# Microsoft Defender detects Event Triggered Execution: Accessibility Features activity

terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = ">= 3.0"
    }
  }
}

variable "resource_group_name" {
  type        = string
  description = "Resource group name"
}

variable "log_analytics_workspace_id" {
  type        = string
  description = "Log Analytics workspace for Defender"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

# Enable Defender for Cloud plans
resource "azurerm_security_center_subscription_pricing" "defender_servers" {
  tier          = "Standard"
  resource_type = "VirtualMachines"
}

resource "azurerm_security_center_subscription_pricing" "defender_storage" {
  tier          = "Standard"
  resource_type = "StorageAccounts"
}

resource "azurerm_security_center_subscription_pricing" "defender_keyvault" {
  tier          = "Standard"
  resource_type = "KeyVaults"
}

resource "azurerm_security_center_subscription_pricing" "defender_arm" {
  tier          = "Standard"
  resource_type = "Arm"
}

# Action Group for Defender alerts
resource "azurerm_monitor_action_group" "defender_alerts" {
  name                = "defender-t1546-008-alerts"
  resource_group_name = var.resource_group_name
  short_name          = "DefAlerts"

  email_receiver {
    name          = "security-team"
    email_address = var.alert_email
  }
}

# Log Analytics query for Defender alerts
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "defender_detection" {
  name                = "defender-t1546-008"
  resource_group_name = var.resource_group_name
  location            = "uksouth"

  evaluation_frequency = "PT5M"
  window_duration      = "PT1H"
  scopes               = [var.log_analytics_workspace_id]
  severity             = 1

  criteria {
    query = <<-QUERY
SecurityAlert
| where TimeGenerated > ago(1h)
| where ProductName == "Azure Security Center" or ProductName == "Microsoft Defender for Cloud"
| where AlertName has_any (
                    "Suspicious activity detected",
                )
| project
    TimeGenerated,
    AlertName,
    AlertSeverity,
    Description,
    RemediationSteps,
    ExtendedProperties,
    Entities
    QUERY

    time_aggregation_method = "Count"
    threshold               = 0
    operator                = "GreaterThan"

    failing_periods {
      minimum_failing_periods_to_trigger_alert = 1
      number_of_evaluation_periods             = 1
    }
  }

  action {
    action_groups = [azurerm_monitor_action_group.defender_alerts.id]
  }

  description = "Microsoft Defender detects Event Triggered Execution: Accessibility Features activity"
  display_name = "Defender: Event Triggered Execution: Accessibility Features"
  enabled      = true

  tags = {
    "mitre-technique" = "T1546.008"
    "detection-type"  = "security"
  }
}

output "alert_rule_id" {
  value = azurerm_monitor_scheduled_query_rules_alert_v2.defender_detection.id
}""",
                alert_severity="high",
                alert_title="Azure: Event Triggered Execution: Accessibility Features Detected",
                alert_description_template=(
                    "Event Triggered Execution: Accessibility Features activity detected. "
                    "Caller: {Caller}. Resource: {Resource}."
                ),
                investigation_steps=[
                    "Review Azure Activity Log for full operation details",
                    "Check caller identity and verify if authorised",
                    "Review affected resources and assess impact",
                    "Check for related activities in the same time window",
                    "Verify against change management records",
                ],
                containment_actions=[
                    "Disable compromised user/service principal if unauthorised",
                    "Revoke active sessions using Entra ID",
                    "Review and restrict Azure RBAC permissions",
                    "Enable additional Defender for Cloud protections",
                    "Implement Azure Policy to prevent recurrence",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning=(
                "Allowlist known automation accounts and CI/CD service principals. "
                "Use Azure Policy to define expected behaviour baselines."
            ),
            detection_coverage="70% - Azure-native detection for cloud operations",
            evasion_considerations=(
                "Attackers may use legitimate credentials from expected locations. "
                "Combine with Defender for Cloud for ML-based anomaly detection."
            ),
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$10-50 (Log Analytics + Defender)",
            prerequisites=[
                "Azure subscription with Log Analytics workspace",
                "Defender for Cloud enabled (recommended)",
                "Appropriate Azure RBAC permissions for deployment",
            ],
        ),
    ],
    recommended_order=[
        "t1546008-aws-registry-monitor",
        "t1546008-aws-file-integrity",
        "t1546008-gcp-file-integrity",
    ],
    total_effort_hours=7.0,
    coverage_improvement="+15% improvement for Persistence and Privilege Escalation tactics",
)
