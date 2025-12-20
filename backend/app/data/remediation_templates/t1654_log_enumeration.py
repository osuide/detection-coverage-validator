"""
T1654 - Log Enumeration

Adversaries enumerate system and service logs to discover valuable intelligence including
user authentication records, vulnerable software, and network hosts. This reconnaissance
enables threat actors to understand environments better and monitor incident response
in real-time to adjust tactics for persistence or evasion.
Used by APT5, Aquatic Panda, Ember Bear, Mustang Panda, Volt Typhoon.
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
    technique_id="T1654",
    technique_name="Log Enumeration",
    tactic_ids=["TA0007"],
    mitre_url="https://attack.mitre.org/techniques/T1654/",
    threat_context=ThreatContext(
        description=(
            "Adversaries enumerate system and service logs to discover valuable intelligence "
            "including user authentication records, vulnerable software, and network hosts. "
            "This reconnaissance enables threat actors to understand environments better and "
            "monitor incident response in real-time to adjust tactics for persistence or evasion. "
            "Targets include centralised logging infrastructure (SIEMs), CloudTrail, CloudWatch logs, "
            "and system authentication logs."
        ),
        attacker_goal="Enumerate logs to discover authentication records, vulnerabilities, and monitor incident response",
        why_technique=[
            "Reveals user authentication patterns",
            "Identifies vulnerable software versions",
            "Monitors incident response procedures",
            "Discovers network hosts and services",
            "Enables log deletion to evade detection",
            "Cloud logs contain API activity and credentials",
        ],
        known_threat_actors=[
            "APT5",
            "Aquatic Panda",
            "Ember Bear",
            "Mustang Panda",
            "Volt Typhoon",
        ],
        recent_campaigns=[
            Campaign(
                name="Volt Typhoon Living-off-the-Land",
                year=2024,
                description="Used wevtutil.exe and PowerShell to search for successful logons in Security Event Logs",
                reference_url="https://attack.mitre.org/groups/G1017/",
            ),
            Campaign(
                name="Mustang Panda Log Collection",
                year=2023,
                description="Employed Wevtutil for Windows Security Event Log gathering",
                reference_url="https://attack.mitre.org/groups/G0129/",
            ),
        ],
        prevalence="common",
        trend="increasing",
        severity_score=6,
        severity_reasoning=(
            "Log enumeration provides adversaries with intelligence for further attacks and "
            "enables monitoring of defensive responses. Often precedes log deletion (T1070.001) "
            "and credential harvesting. Moderate severity as it's a reconnaissance activity "
            "that enables more damaging follow-on attacks."
        ),
        business_impact=[
            "Reveals authentication patterns",
            "Exposes incident response procedures",
            "Enables targeted credential theft",
            "Facilitates log tampering",
            "Compromises forensic evidence",
        ],
        typical_attack_phase="discovery",
        often_precedes=["T1070.001", "T1552.001", "T1078"],
        often_follows=["T1078", "T1059"],
    ),
    detection_strategies=[
        DetectionStrategy(
            strategy_id="t1654-aws-cloudtrail-logs",
            name="AWS CloudTrail Log Enumeration Detection",
            description="Detect enumeration of CloudTrail logs and CloudWatch log streams.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, userIdentity.principalId, eventName, sourceIPAddress
| filter eventName in ["DescribeLogStreams", "GetLogEvents", "FilterLogEvents", "LookupEvents", "DescribeEventAggregates"]
| stats count(*) as api_calls by userIdentity.principalId, sourceIPAddress, bin(5m)
| filter api_calls > 20
| sort api_calls desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect CloudTrail and CloudWatch log enumeration activity

Parameters:
  CloudTrailLogGroup:
    Type: String
    Description: CloudTrail log group name
  AlertEmail:
    Type: String
    Description: Email for security alerts

Resources:
  # SNS Topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      DisplayName: Log Enumeration Alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Metric filter for log enumeration API calls
  LogEnumerationFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ ($.eventName = "DescribeLogStreams") || ($.eventName = "GetLogEvents") || ($.eventName = "FilterLogEvents") || ($.eventName = "LookupEvents") }'
      MetricTransformations:
        - MetricName: LogEnumerationAPICalls
          MetricNamespace: Security/LogEnumeration
          MetricValue: "1"
          DefaultValue: 0

  # Alarm for excessive log enumeration
  LogEnumerationAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: ExcessiveLogEnumeration
      AlarmDescription: Alert on excessive CloudWatch/CloudTrail log enumeration
      MetricName: LogEnumerationAPICalls
      Namespace: Security/LogEnumeration
      Statistic: Sum
      Period: 300
      EvaluationPeriods: 1
      Threshold: 50
      ComparisonOperator: GreaterThanThreshold
      AlarmActions:
        - !Ref AlertTopic
      TreatMissingData: notBreaching""",
                terraform_template="""# AWS: Detect CloudTrail and CloudWatch log enumeration

variable "cloudtrail_log_group" {
  type        = string
  description = "CloudTrail log group name"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

# SNS topic for alerts
resource "aws_sns_topic" "log_enumeration_alerts" {
  name         = "log-enumeration-alerts"
  display_name = "Log Enumeration Alerts"
}

resource "aws_sns_topic_subscription" "email_alerts" {
  topic_arn = aws_sns_topic.log_enumeration_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Metric filter for log enumeration activities
resource "aws_cloudwatch_log_metric_filter" "log_enumeration" {
  name           = "log-enumeration-detection"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ ($.eventName = \"DescribeLogStreams\") || ($.eventName = \"GetLogEvents\") || ($.eventName = \"FilterLogEvents\") || ($.eventName = \"LookupEvents\") }"

  metric_transformation {
    name          = "LogEnumerationAPICalls"
    namespace     = "Security/LogEnumeration"
    value         = "1"
    default_value = 0
  }
}

# Alarm for excessive log enumeration
resource "aws_cloudwatch_metric_alarm" "excessive_log_enumeration" {
  alarm_name          = "ExcessiveLogEnumeration"
  alarm_description   = "Alert on excessive CloudWatch/CloudTrail log enumeration"
  metric_name         = "LogEnumerationAPICalls"
  namespace           = "Security/LogEnumeration"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 50
  comparison_operator = "GreaterThanThreshold"
  alarm_actions       = [aws_sns_topic.log_enumeration_alerts.arn]
  treat_missing_data  = "notBreaching"
}""",
                alert_severity="medium",
                alert_title="Excessive Log Enumeration Detected",
                alert_description_template="User {principalId} performed {api_calls} log enumeration API calls from {sourceIPAddress}.",
                investigation_steps=[
                    "Identify the user/role performing log enumeration",
                    "Review the specific logs being accessed",
                    "Check if activity correlates with known incident response",
                    "Look for subsequent log deletion attempts (DeleteLogStream, DeleteLogGroup)",
                    "Review IAM permissions for the principal",
                    "Check for data exfiltration after enumeration",
                ],
                containment_actions=[
                    "Revoke sessions for suspicious principals",
                    "Restrict CloudWatch Logs read permissions",
                    "Enable MFA for sensitive log access",
                    "Review and rotate exposed credentials",
                    "Create SCPs to restrict log access patterns",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Exclude legitimate monitoring tools and incident response activities. Tune threshold based on environment size.",
            detection_coverage="75% - catches API-based log enumeration",
            evasion_considerations="Attackers may throttle requests or use multiple identities",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30-60 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=[
                "CloudTrail logging enabled",
                "CloudTrail logs sent to CloudWatch",
            ],
        ),
        DetectionStrategy(
            strategy_id="t1654-aws-ec2-log-access",
            name="EC2 Instance Log File Access Detection",
            description="Detect unusual access to system log files on EC2 instances.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, process, command, user
| filter process in ["cat", "grep", "tail", "head", "less", "more", "wevtutil.exe", "Get-EventLog", "Get-WinEvent"]
| filter command like /\/var\/log|\/var\/log\/auth\.log|\/var\/log\/secure|\.evtx|Security|System/
| stats count(*) as log_reads by user, bin(10m)
| filter log_reads > 10
| sort log_reads desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect unusual system log file access on EC2 instances

Parameters:
  SystemLogGroup:
    Type: String
    Description: Log group containing system/audit logs
  AlertEmail:
    Type: String
    Description: Email for security alerts

Resources:
  # SNS Topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      DisplayName: System Log Access Alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Metric filter for suspicious log file access
  LogFileAccessFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref SystemLogGroup
      FilterPattern: '[timestamp, process=cat||process=grep||process=tail||process=wevtutil.exe, ...]'
      MetricTransformations:
        - MetricName: SystemLogFileAccess
          MetricNamespace: Security/LogEnumeration
          MetricValue: "1"
          DefaultValue: 0

  # Alarm for excessive log file access
  LogFileAccessAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: ExcessiveSystemLogAccess
      AlarmDescription: Alert on excessive system log file access
      MetricName: SystemLogFileAccess
      Namespace: Security/LogEnumeration
      Statistic: Sum
      Period: 600
      EvaluationPeriods: 1
      Threshold: 20
      ComparisonOperator: GreaterThanThreshold
      AlarmActions:
        - !Ref AlertTopic
      TreatMissingData: notBreaching""",
                terraform_template="""# AWS: Detect unusual system log file access on EC2

variable "system_log_group" {
  type        = string
  description = "Log group containing system/audit logs"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

# SNS topic for alerts
resource "aws_sns_topic" "log_access_alerts" {
  name         = "system-log-access-alerts"
  display_name = "System Log Access Alerts"
}

resource "aws_sns_topic_subscription" "email_alerts" {
  topic_arn = aws_sns_topic.log_access_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Metric filter for suspicious log file access
resource "aws_cloudwatch_log_metric_filter" "log_file_access" {
  name           = "system-log-file-access"
  log_group_name = var.system_log_group
  pattern        = "[timestamp, process=cat||process=grep||process=tail||process=wevtutil.exe, ...]"

  metric_transformation {
    name          = "SystemLogFileAccess"
    namespace     = "Security/LogEnumeration"
    value         = "1"
    default_value = 0
  }
}

# Alarm for excessive log file access
resource "aws_cloudwatch_metric_alarm" "excessive_log_access" {
  alarm_name          = "ExcessiveSystemLogAccess"
  alarm_description   = "Alert on excessive system log file access"
  metric_name         = "SystemLogFileAccess"
  namespace           = "Security/LogEnumeration"
  statistic           = "Sum"
  period              = 600
  evaluation_periods  = 1
  threshold           = 20
  comparison_operator = "GreaterThanThreshold"
  alarm_actions       = [aws_sns_topic.log_access_alerts.arn]
  treat_missing_data  = "notBreaching"
}""",
                alert_severity="medium",
                alert_title="Suspicious System Log Access",
                alert_description_template="User {user} accessed system logs {log_reads} times.",
                investigation_steps=[
                    "Identify the user and process accessing logs",
                    "Review command history for log enumeration tools",
                    "Check if logs were exfiltrated or deleted",
                    "Correlate with authentication events",
                    "Review CloudTrail for related API activity",
                    "Check for credential dumping attempts",
                ],
                containment_actions=[
                    "Isolate compromised instance",
                    "Revoke user sessions",
                    "Review file access permissions",
                    "Enable file integrity monitoring",
                    "Capture memory/disk forensics",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Exclude system administrators and monitoring tools. Requires process auditing (auditd/CloudWatch agent).",
            detection_coverage="60% - requires CloudWatch agent with process monitoring",
            evasion_considerations="Attackers may use native tools like 'strings' or direct file reads",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2-3 hours",
            estimated_monthly_cost="$10-20",
            prerequisites=[
                "CloudWatch agent with process monitoring enabled",
                "System audit logs forwarded to CloudWatch",
            ],
        ),
        DetectionStrategy(
            strategy_id="t1654-gcp-log-enumeration",
            name="GCP Cloud Logging Enumeration Detection",
            description="Detect enumeration of Cloud Logging logs and log entries.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''protoPayload.methodName=~"google.logging.v2.LoggingServiceV2.(ListLogEntries|ListLogs)"
OR protoPayload.methodName="storage.objects.get"
protoPayload.resourceName=~"logs/"''',
                gcp_terraform_template="""# GCP: Detect Cloud Logging enumeration activity

variable "project_id" {
  type        = string
  description = "GCP project ID"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

# Notification channel for alerts
resource "google_monitoring_notification_channel" "email_alerts" {
  display_name = "Log Enumeration Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
  project = var.project_id
}

# Log metric for log enumeration API calls
resource "google_logging_metric" "log_enumeration" {
  name    = "log-enumeration-api-calls"
  project = var.project_id
  filter  = <<-EOT
    protoPayload.methodName=~"google.logging.v2.LoggingServiceV2.(ListLogEntries|ListLogs)"
    OR (protoPayload.methodName="storage.objects.get" AND protoPayload.resourceName=~"logs/")
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "principal"
      value_type  = "STRING"
      description = "Principal performing log enumeration"
    }
  }

  label_extractors = {
    "principal" = "EXTRACT(protoPayload.authenticationInfo.principalEmail)"
  }
}

# Alert policy for excessive log enumeration
resource "google_monitoring_alert_policy" "excessive_log_enumeration" {
  display_name = "Excessive Log Enumeration"
  project      = var.project_id
  combiner     = "OR"

  conditions {
    display_name = "High rate of log enumeration API calls"
    condition_threshold {
      filter          = "resource.type=\"global\" AND metric.type=\"logging.googleapis.com/user/${google_logging_metric.log_enumeration.name}\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 50
      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_RATE"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email_alerts.id]

  alert_strategy {
    auto_close = "1800s"
  }

  documentation {
    content   = "Excessive Cloud Logging enumeration detected. Review the principal and investigate potential unauthorised log access."
    mime_type = "text/markdown"
  }
}""",
                alert_severity="medium",
                alert_title="GCP: Excessive Log Enumeration",
                alert_description_template="Principal {principal} performed excessive log enumeration API calls.",
                investigation_steps=[
                    "Identify the principal performing log enumeration",
                    "Review the specific logs being accessed",
                    "Check for subsequent log deletion or export",
                    "Correlate with Cloud Audit Logs",
                    "Review IAM permissions for the principal",
                    "Check for data exfiltration via Storage",
                ],
                containment_actions=[
                    "Revoke service account keys or user sessions",
                    "Restrict logging.viewer and logging.privateLogViewer roles",
                    "Enable VPC Service Controls for Logging API",
                    "Review and rotate exposed credentials",
                    "Create organisation policies to restrict log access",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Exclude legitimate monitoring services and SIEM integrations. Tune threshold based on environment.",
            detection_coverage="75% - catches API-based log enumeration",
            evasion_considerations="Attackers may use service accounts or throttle requests",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30-60 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=["Cloud Audit Logs enabled", "Admin Read audit logs enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1654-gcp-vm-log-access",
            name="GCP VM Instance Log File Access",
            description="Detect unusual access to system log files on GCP Compute instances.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="gce_instance"
jsonPayload.message=~"(cat|grep|tail|head|less) .*(\/var\/log|auth\.log|syslog|secure)"
OR jsonPayload.process_name=~"(cat|grep|tail|journalctl)"''',
                gcp_terraform_template="""# GCP: Detect system log file access on Compute instances

variable "project_id" {
  type        = string
  description = "GCP project ID"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

# Notification channel
resource "google_monitoring_notification_channel" "vm_log_access_alerts" {
  display_name = "VM Log Access Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
  project = var.project_id
}

# Log metric for system log file access
resource "google_logging_metric" "vm_log_access" {
  name    = "vm-system-log-access"
  project = var.project_id
  filter  = <<-EOT
    resource.type="gce_instance"
    jsonPayload.message=~"(cat|grep|tail|head|less) .*(\/var\/log|auth\.log|syslog|secure)"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "instance"
      value_type  = "STRING"
      description = "Instance accessing logs"
    }
    labels {
      key         = "user"
      value_type  = "STRING"
      description = "User accessing logs"
    }
  }

  label_extractors = {
    "instance" = "EXTRACT(resource.labels.instance_id)"
    "user"     = "EXTRACT(jsonPayload.user)"
  }
}

# Alert policy
resource "google_monitoring_alert_policy" "excessive_vm_log_access" {
  display_name = "Excessive VM Log File Access"
  project      = var.project_id
  combiner     = "OR"

  conditions {
    display_name = "High rate of system log access"
    condition_threshold {
      filter          = "resource.type=\"global\" AND metric.type=\"logging.googleapis.com/user/${google_logging_metric.vm_log_access.name}\""
      duration        = "600s"
      comparison      = "COMPARISON_GT"
      threshold_value = 15
      aggregations {
        alignment_period   = "600s"
        per_series_aligner = "ALIGN_SUM"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.vm_log_access_alerts.id]

  documentation {
    content   = "Excessive system log file access detected on GCE instance. Investigate potential log enumeration activity."
    mime_type = "text/markdown"
  }
}""",
                alert_severity="medium",
                alert_title="GCP: Suspicious VM Log Access",
                alert_description_template="User {user} on instance {instance} accessed system logs excessively.",
                investigation_steps=[
                    "Identify the instance and user accessing logs",
                    "Review OS Login audit logs",
                    "Check for log exfiltration to Cloud Storage",
                    "Review command history via Cloud Logging",
                    "Check for credential dumping or privilege escalation",
                    "Correlate with other suspicious VM activity",
                ],
                containment_actions=[
                    "Isolate compromised instance (firewall rules)",
                    "Revoke SSH keys and OS Login access",
                    "Take disk snapshot for forensics",
                    "Review IAM permissions",
                    "Enable OS Config for vulnerability assessment",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Exclude system administrators. Requires Cloud Logging agent with process monitoring.",
            detection_coverage="60% - requires Ops Agent with process monitoring",
            evasion_considerations="Attackers may use less common tools or direct file reads",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2-3 hours",
            estimated_monthly_cost="$10-20",
            prerequisites=[
                "Cloud Logging agent (Ops Agent) installed",
                "Process monitoring enabled",
            ],
        ),
    ],
    recommended_order=[
        "t1654-aws-cloudtrail-logs",
        "t1654-gcp-log-enumeration",
        "t1654-aws-ec2-log-access",
        "t1654-gcp-vm-log-access",
    ],
    total_effort_hours=6.0,
    coverage_improvement="+15% improvement for Discovery tactic",
)
