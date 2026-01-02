"""
T1007 - System Service Discovery

Adversaries enumerate running services and scheduled tasks on systems
to identify reconnaissance opportunities, persistence mechanisms, or
targets for service manipulation. This technique involves using native
OS commands like 'sc query', 'tasklist /svc', 'systemctl', and 'net start'.
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
    technique_id="T1007",
    technique_name="System Service Discovery",
    tactic_ids=["TA0007"],
    mitre_url="https://attack.mitre.org/techniques/T1007/",
    threat_context=ThreatContext(
        description=(
            "Adversaries enumerate registered local system services to gather information "
            "about running services and scheduled tasks. Attackers use native OS utilities "
            "such as 'sc query', 'tasklist /svc', 'systemctl --type=service', 'net start', "
            "and 'schtasks' to discover services that may be vulnerable or useful for "
            "persistence, privilege escalation, or lateral movement."
        ),
        attacker_goal="Discover system services to identify persistence and exploitation opportunities",
        why_technique=[
            "Identifies services for exploitation",
            "Reveals persistence mechanisms",
            "Discovers security tool processes",
            "Maps scheduled tasks for backdoors",
            "Supports lateral movement planning",
            "Helps evade detection by identifying security services",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="common",
        trend="stable",
        severity_score=4,
        severity_reasoning=(
            "Low impact discovery technique that cannot be easily prevented. "
            "Indicates active reconnaissance by threat actor. Typically precedes "
            "service manipulation, persistence establishment, or security tool evasion. "
            "Important early warning signal of compromise."
        ),
        business_impact=[
            "Indicates active threat actor in environment",
            "Precursor to persistence or privilege escalation",
            "Early detection opportunity",
            "May precede security tool disablement",
        ],
        typical_attack_phase="discovery",
        often_precedes=["T1489", "T1562.001", "T1543"],
        often_follows=["T1078", "T1059"],
    ),
    detection_strategies=[
        # Strategy 1: AWS - CloudWatch Agent Command Detection (Windows)
        DetectionStrategy(
            strategy_id="t1007-aws-windows",
            name="Windows Service Discovery Detection (AWS)",
            description="Detect Windows service enumeration commands on EC2 instances.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query=r"""fields @timestamp, @message
| filter @logStream like /windows-commands/
| filter @message like /sc query|tasklist \/svc|net start|schtasks|Get-Service|Get-ScheduledTask/
| parse @message "* * *" as timestamp, hostname, command
| stats count(*) as cmd_count by hostname, bin(5m)
| filter cmd_count > 5
| sort cmd_count desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect Windows service discovery on EC2

Parameters:
  AlertEmail:
    Type: String
    Description: Email for security alerts

Resources:
  # Step 1: SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      TopicName: service-discovery-alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: CloudWatch Log Group for command logging
  CommandLogGroup:
    Type: AWS::Logs::LogGroup
    Properties:
      LogGroupName: /aws/ec2/windows/commands
      RetentionInDays: 90

  # Step 3: Metric filter for service discovery commands
  ServiceDiscoveryFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CommandLogGroup
      FilterPattern: '[time, host, command="*sc query*" || command="*tasklist*" || command="*net start*" || command="*schtasks*"]'
      MetricTransformations:
        - MetricName: WindowsServiceDiscovery
          MetricNamespace: Security/Discovery
          MetricValue: "1"
          DefaultValue: 0

  # Step 4: CloudWatch Alarm
  ServiceDiscoveryAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: WindowsServiceDiscovery
      AlarmDescription: Detects bulk Windows service enumeration
      MetricName: WindowsServiceDiscovery
      Namespace: Security/Discovery
      Statistic: Sum
      Period: 300
      EvaluationPeriods: 1
      Threshold: 5
      ComparisonOperator: GreaterThanThreshold
      TreatMissingData: notBreaching
      AlarmActions:
        - !Ref AlertTopic

  # Step 5: SNS topic policy to allow CloudWatch alarms
  AlertTopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      PolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Sid: AllowCloudWatchAlarms
            Effect: Allow
            Principal:
              Service: cloudwatch.amazonaws.com
            Action: sns:Publish
            Resource: !Ref AlertTopic
            Condition:
              StringEquals:
                AWS:SourceAccount: !Ref AWS::AccountId
      Topics:
        - !Ref AlertTopic""",
                terraform_template="""# AWS: Detect Windows service discovery

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

# Step 1: SNS topic for alerts
resource "aws_sns_topic" "alerts" {
  name = "service-discovery-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: CloudWatch Log Group
resource "aws_cloudwatch_log_group" "commands" {
  name              = "/aws/ec2/windows/commands"
  retention_in_days = 90
}

# Step 3: Metric filter for service discovery
resource "aws_cloudwatch_log_metric_filter" "service_discovery" {
  name           = "windows-service-discovery"
  log_group_name = aws_cloudwatch_log_group.commands.name
  pattern        = "[time, host, command=\"*sc query*\" || command=\"*tasklist*\" || command=\"*net start*\" || command=\"*schtasks*\"]"

  metric_transformation {
    name      = "WindowsServiceDiscovery"
    namespace = "Security/Discovery"
    value     = "1"
  }
}

# Step 4: CloudWatch Alarm
resource "aws_cloudwatch_metric_alarm" "service_discovery" {
  alarm_name          = "WindowsServiceDiscovery"
  alarm_description   = "Detects bulk Windows service enumeration"
  metric_name         = "WindowsServiceDiscovery"
  namespace           = "Security/Discovery"
  statistic           = "Sum"
  period              = 300
  threshold           = 5
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alerts.arn]
}

# Step 5: SNS topic policy (scoped to account)
data "aws_caller_identity" "current" {}

resource "aws_sns_topic_policy" "allow_cloudwatch" {
  arn = aws_sns_topic.alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowCloudWatchAlarms"
      Effect    = "Allow"
      Principal = { Service = "cloudwatch.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.alerts.arn
      Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
      }
    }]
  })
}""",
                alert_severity="medium",
                alert_title="Windows Service Discovery Detected",
                alert_description_template="Multiple service enumeration commands detected on {hostname}.",
                investigation_steps=[
                    "Identify which user executed service discovery commands",
                    "Determine if activity is authorised (e.g., admin troubleshooting)",
                    "Review command timeline and sequence",
                    "Check for follow-on service manipulation or security tool disablement",
                    "Correlate with other suspicious activity on the host",
                    "Review CloudTrail for related API calls",
                ],
                containment_actions=[
                    "Isolate the instance if unauthorised activity is confirmed",
                    "Review and rotate credentials for affected user accounts",
                    "Enable enhanced monitoring on the instance",
                    "Check for persistence mechanisms (scheduled tasks, services)",
                    "Investigate other instances for similar activity",
                    "Consider implementing Process Command Line auditing",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning=(
                "Whitelist authorised system administrators and automation accounts. "
                "Filter routine monitoring and patching activities. Consider time-based "
                "whitelisting for maintenance windows."
            ),
            detection_coverage="70% - requires CloudWatch Agent with command logging",
            evasion_considerations=(
                "Slow, deliberate enumeration may evade rate-based detection. "
                "WMI-based queries or direct API calls may bypass command logging. "
                "Adversaries may use obfuscation techniques."
            ),
            implementation_effort=EffortLevel.HIGH,
            implementation_time="2-3 hours",
            estimated_monthly_cost="$10-30 (depends on log volume)",
            prerequisites=[
                "CloudWatch Agent installed on EC2 instances",
                "Process command line logging enabled",
                "Windows Event Logs forwarded to CloudWatch",
            ],
        ),
        # Strategy 2: AWS - Linux Service Discovery
        DetectionStrategy(
            strategy_id="t1007-aws-linux",
            name="Linux Service Discovery Detection (AWS)",
            description="Detect Linux service enumeration commands on EC2 instances.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, @message
| filter @logStream like /linux-commands/
| filter @message like /systemctl.*list|service --status-all|chkconfig --list|launchctl list|crontab -l/
| parse @message "* * *" as timestamp, hostname, command
| stats count(*) as cmd_count by hostname, bin(5m)
| filter cmd_count > 3
| sort cmd_count desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect Linux service discovery on EC2

Parameters:
  AlertEmail:
    Type: String
    Description: Email for security alerts

Resources:
  # Step 1: SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      TopicName: linux-service-discovery-alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: CloudWatch Log Group
  CommandLogGroup:
    Type: AWS::Logs::LogGroup
    Properties:
      LogGroupName: /aws/ec2/linux/commands
      RetentionInDays: 90

  # Step 3: Metric filter for Linux service discovery
  LinuxServiceFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CommandLogGroup
      FilterPattern: '[time, host, command="*systemctl*" || command="*service*" || command="*launchctl*" || command="*crontab*"]'
      MetricTransformations:
        - MetricName: LinuxServiceDiscovery
          MetricNamespace: Security/Discovery
          MetricValue: "1"
          DefaultValue: 0

  # Step 4: CloudWatch Alarm
  LinuxServiceAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: LinuxServiceDiscovery
      AlarmDescription: Detects bulk Linux service enumeration
      MetricName: LinuxServiceDiscovery
      Namespace: Security/Discovery
      Statistic: Sum
      Period: 300
      EvaluationPeriods: 1
      Threshold: 3
      ComparisonOperator: GreaterThanThreshold
      TreatMissingData: notBreaching
      AlarmActions:
        - !Ref AlertTopic

  # Step 5: SNS topic policy to allow CloudWatch alarms
  AlertTopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      PolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Sid: AllowCloudWatchAlarms
            Effect: Allow
            Principal:
              Service: cloudwatch.amazonaws.com
            Action: sns:Publish
            Resource: !Ref AlertTopic
            Condition:
              StringEquals:
                AWS:SourceAccount: !Ref AWS::AccountId
      Topics:
        - !Ref AlertTopic""",
                terraform_template="""# AWS: Detect Linux service discovery

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

# Step 1: SNS topic for alerts
resource "aws_sns_topic" "alerts" {
  name = "linux-service-discovery-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: CloudWatch Log Group
resource "aws_cloudwatch_log_group" "commands" {
  name              = "/aws/ec2/linux/commands"
  retention_in_days = 90
}

# Step 3: Metric filter for service discovery
resource "aws_cloudwatch_log_metric_filter" "service_discovery" {
  name           = "linux-service-discovery"
  log_group_name = aws_cloudwatch_log_group.commands.name
  pattern        = "[time, host, command=\"*systemctl*\" || command=\"*service*\" || command=\"*launchctl*\" || command=\"*crontab*\"]"

  metric_transformation {
    name      = "LinuxServiceDiscovery"
    namespace = "Security/Discovery"
    value     = "1"
  }
}

# Step 4: CloudWatch Alarm
resource "aws_cloudwatch_metric_alarm" "service_discovery" {
  alarm_name          = "LinuxServiceDiscovery"
  alarm_description   = "Detects bulk Linux service enumeration"
  metric_name         = "LinuxServiceDiscovery"
  namespace           = "Security/Discovery"
  statistic           = "Sum"
  period              = 300
  threshold           = 3
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alerts.arn]
}

# Step 5: SNS topic policy (scoped to account)
data "aws_caller_identity" "current" {}

resource "aws_sns_topic_policy" "allow_cloudwatch" {
  arn = aws_sns_topic.alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowCloudWatchAlarms"
      Effect    = "Allow"
      Principal = { Service = "cloudwatch.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.alerts.arn
      Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
      }
    }]
  })
}""",
                alert_severity="medium",
                alert_title="Linux Service Discovery Detected",
                alert_description_template="Multiple service enumeration commands detected on {hostname}.",
                investigation_steps=[
                    "Identify which user executed service discovery commands",
                    "Check if activity aligns with authorised operations",
                    "Review command sequence and timing",
                    "Look for subsequent service manipulation attempts",
                    "Correlate with other reconnaissance activities",
                    "Check bash history for additional context",
                ],
                containment_actions=[
                    "Isolate instance if compromise is suspected",
                    "Rotate credentials and SSH keys",
                    "Enable detailed process auditing",
                    "Check for cron jobs and systemd timers",
                    "Review /etc/init.d and systemd unit files",
                    "Investigate privilege escalation vectors",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning=(
                "Whitelist system administrators and automation scripts. "
                "Consider excluding package manager post-install scripts. "
                "Filter monitoring agents and configuration management tools."
            ),
            detection_coverage="65% - requires command logging configuration",
            evasion_considerations=(
                "Direct reading of /proc or /sys may bypass detection. "
                "Attackers may use custom binaries or scripts. "
                "API-based service queries may not trigger alerts."
            ),
            implementation_effort=EffortLevel.HIGH,
            implementation_time="2-3 hours",
            estimated_monthly_cost="$10-30 (depends on log volume)",
            prerequisites=[
                "CloudWatch Agent installed on EC2 instances",
                "auditd or process accounting configured",
                "System logs forwarded to CloudWatch",
            ],
        ),
        # Strategy 3: GCP - Windows Service Discovery
        DetectionStrategy(
            strategy_id="t1007-gcp-windows",
            name="Windows Service Discovery Detection (GCP)",
            description="Detect Windows service enumeration on GCP Compute Engine instances.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""resource.type="gce_instance"
jsonPayload.command=~"(sc query|tasklist /svc|net start|schtasks|Get-Service)"
severity>=DEFAULT""",
                gcp_terraform_template="""# GCP: Detect Windows service discovery

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
  project      = var.project_id
  display_name = "Security Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Log-based metric for Windows service discovery
resource "google_logging_metric" "windows_service_discovery" {
  project = var.project_id
  name   = "windows-service-discovery"
  filter = <<-EOT
    resource.type="gce_instance"
    jsonPayload.command=~"(sc query|tasklist /svc|net start|schtasks|Get-Service)"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "instance_id"
      value_type  = "STRING"
      description = "Instance performing discovery"
    }
  }

  label_extractors = {
    "instance_id" = "EXTRACT(resource.labels.instance_id)"
  }
}

# Step 3: Alert policy
resource "google_monitoring_alert_policy" "windows_service_discovery" {
  project      = var.project_id
  display_name = "Windows Service Discovery Detected"
  combiner     = "OR"

  conditions {
    display_name = "Multiple service enumeration commands"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.windows_service_discovery.name}\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 5
      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_SUM"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]

  alert_strategy {
    auto_close = "86400s"
    notification_rate_limit {
      period = "300s"
    }
  }
}""",
                alert_severity="medium",
                alert_title="GCP: Windows Service Discovery Detected",
                alert_description_template="Multiple service enumeration commands detected on GCP instance.",
                investigation_steps=[
                    "Identify the user account executing commands",
                    "Review instance metadata and SSH keys",
                    "Check Cloud Logging for command history",
                    "Look for persistence mechanisms",
                    "Correlate with VPC Flow Logs",
                    "Review OS Login audit logs",
                ],
                containment_actions=[
                    "Isolate instance using firewall rules",
                    "Snapshot the instance for forensics",
                    "Rotate service account keys",
                    "Enable OS Config for patch verification",
                    "Review IAM permissions on the instance",
                    "Check for malicious scheduled tasks",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning=(
                "Whitelist authorised administrator accounts and automation service accounts. "
                "Exclude OS Config Agent and patch management activities. "
                "Consider time-based exceptions for maintenance windows."
            ),
            detection_coverage="70% - requires Ops Agent with process monitoring",
            evasion_considerations=(
                "WMI queries may bypass command-line logging. "
                "Slow enumeration can evade rate-based detection. "
                "PowerShell obfuscation may hide service discovery."
            ),
            implementation_effort=EffortLevel.HIGH,
            implementation_time="2-3 hours",
            estimated_monthly_cost="$15-40 (depends on log volume)",
            prerequisites=[
                "Ops Agent installed on Compute Engine instances",
                "Process monitoring enabled",
                "Cloud Logging API enabled",
            ],
        ),
        # Strategy 4: GCP - Linux Service Discovery
        DetectionStrategy(
            strategy_id="t1007-gcp-linux",
            name="Linux Service Discovery Detection (GCP)",
            description="Detect Linux service enumeration on GCP Compute Engine instances.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""resource.type="gce_instance"
jsonPayload.command=~"(systemctl.*list|service --status-all|chkconfig|launchctl|crontab -l)"
severity>=DEFAULT""",
                gcp_terraform_template="""# GCP: Detect Linux service discovery

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
  project      = var.project_id
  display_name = "Security Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Log-based metric for Linux service discovery
resource "google_logging_metric" "linux_service_discovery" {
  project = var.project_id
  name   = "linux-service-discovery"
  filter = <<-EOT
    resource.type="gce_instance"
    jsonPayload.command=~"(systemctl.*list|service --status-all|chkconfig|launchctl|crontab -l)"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "instance_id"
      value_type  = "STRING"
      description = "Instance performing discovery"
    }
  }

  label_extractors = {
    "instance_id" = "EXTRACT(resource.labels.instance_id)"
  }
}

# Step 3: Alert policy
resource "google_monitoring_alert_policy" "linux_service_discovery" {
  project      = var.project_id
  display_name = "Linux Service Discovery Detected"
  combiner     = "OR"

  conditions {
    display_name = "Multiple service enumeration commands"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.linux_service_discovery.name}\""
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
    notification_rate_limit {
      period = "300s"
    }
  }
}""",
                alert_severity="medium",
                alert_title="GCP: Linux Service Discovery Detected",
                alert_description_template="Multiple service enumeration commands detected on GCP instance.",
                investigation_steps=[
                    "Identify the user executing commands",
                    "Review SSH authentication logs",
                    "Check Cloud Logging for full command history",
                    "Look for cron jobs or systemd timers",
                    "Correlate with network activity",
                    "Review sudo and privilege escalation attempts",
                ],
                containment_actions=[
                    "Isolate instance with firewall rules",
                    "Create instance snapshot for forensics",
                    "Rotate SSH keys and credentials",
                    "Review systemd unit files for backdoors",
                    "Check /etc/cron* directories",
                    "Audit IAM permissions and service accounts",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning=(
                "Whitelist automation service accounts and administrators. "
                "Exclude package manager activities and system updates. "
                "Filter monitoring agents and configuration management."
            ),
            detection_coverage="65% - requires Ops Agent configuration",
            evasion_considerations=(
                "Direct /proc filesystem access bypasses command logging. "
                "Custom binaries may evade pattern matching. "
                "Rootkits can hide processes and services."
            ),
            implementation_effort=EffortLevel.HIGH,
            implementation_time="2-3 hours",
            estimated_monthly_cost="$15-40 (depends on log volume)",
            prerequisites=[
                "Ops Agent installed on Compute Engine instances",
                "auditd configured for process monitoring",
                "Cloud Logging API enabled",
            ],
        ),
    ],
    recommended_order=[
        "t1007-aws-windows",
        "t1007-aws-linux",
        "t1007-gcp-windows",
        "t1007-gcp-linux",
    ],
    total_effort_hours=10.0,
    coverage_improvement="+8% improvement for Discovery tactic",
)
