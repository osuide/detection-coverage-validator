"""
T1124 - System Time Discovery

Adversaries gather system time and timezone information to schedule malware
execution, determine victim locality, and evade detection through time-based logic.
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
    technique_id="T1124",
    technique_name="System Time Discovery",
    tactic_ids=["TA0007"],
    mitre_url="https://attack.mitre.org/techniques/T1124/",
    threat_context=ThreatContext(
        description=(
            "Adversaries gather system time, timezone settings, and uptime information from "
            "local or remote systems. This reconnaissance enables scheduling malware execution "
            "via time bombs, determining victim locality for targeted operations, synchronising "
            "C2 communications, and evading sandbox detection."
        ),
        attacker_goal="Gather time information to schedule attacks, determine locality, and evade detection",
        why_technique=[
            "Schedule malware execution via time bombs",
            "Determine victim geographical location",
            "Check system activity patterns before encryption/wiping",
            "Evade sandbox detection through timing analysis",
            "Synchronise command and control communications",
            "Verify system uptime for persistence planning",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="common",
        trend="stable",
        severity_score=4,
        severity_reasoning=(
            "Discovery technique with moderate impact. Whilst gathering time information itself "
            "is benign, it frequently precedes destructive actions like ransomware deployment or "
            "time-based malware activation. Common in sophisticated attacks using geofencing or "
            "time-delayed payloads. Important early warning signal when combined with other "
            "reconnaissance activities."
        ),
        business_impact=[
            "Indicates active reconnaissance in environment",
            "Precursor to time-bombed malware deployment",
            "May signal ransomware preparation",
            "Early warning for scheduled destructive attacks",
            "Potential geofencing for targeted operations",
        ],
        typical_attack_phase="discovery",
        often_precedes=[
            "T1053",
            "T1486",
            "T1485",
        ],  # Scheduled Task, Data Encrypted for Impact, Data Destruction
        often_follows=[
            "T1078",
            "T1059",
        ],  # Valid Accounts, Command and Scripting Interpreter
    ),
    detection_strategies=[
        # Strategy 1: AWS - EC2 Instance Time Queries
        DetectionStrategy(
            strategy_id="t1124-aws-ec2time",
            name="EC2 System Time Query Detection",
            description="Detect unusual time/date command execution on EC2 instances via CloudWatch Logs.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, @message, instanceId, commandId
| filter @message like /date|timedatectl|w32tm|net time|systemsetup.*time|hwclock|GetSystemTime|gettimeofday/
| filter @message not like /yum|apt|dpkg|systemd/
| stats count(*) as time_queries by instanceId, bin(1h)
| filter time_queries > 5
| sort time_queries desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect system time discovery attempts

Parameters:
  CloudWatchLogGroup:
    Type: String
    Description: CloudWatch log group for EC2 system logs
  AlertEmail:
    Type: String
    Description: Email for security alerts

Resources:
  # Step 1: SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      KmsMasterKeyId: alias/aws/sns
      DisplayName: System Time Discovery Alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Metric filter for time discovery commands
  TimeDiscoveryFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudWatchLogGroup
      FilterPattern: '[timestamp, request_id, event_type=*date* || event_type=*timedatectl* || event_type=*w32tm* || event_type=*"net time"*]'
      MetricTransformations:
        - MetricName: SystemTimeDiscovery
          MetricNamespace: Security/Discovery
          MetricValue: "1"
          DefaultValue: 0

  # Step 3: Alarm for unusual time queries
  TimeDiscoveryAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: SystemTimeDiscoveryDetected
      AlarmDescription: Multiple system time queries detected
      MetricName: SystemTimeDiscovery
      Namespace: Security/Discovery
      Statistic: Sum
      Period: 3600
      EvaluationPeriods: 1
      Threshold: 5
      ComparisonOperator: GreaterThanThreshold
      AlarmActions:
        - !Ref AlertTopic
      TreatMissingData: notBreaching""",
                terraform_template="""# AWS: Detect system time discovery

variable "cloudwatch_log_group" {
  type        = string
  description = "CloudWatch log group for EC2 system logs"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

# Step 1: SNS topic for alerts
resource "aws_sns_topic" "time_discovery_alerts" {
  name         = "system-time-discovery-alerts"
  kms_master_key_id = "alias/aws/sns"
  display_name = "System Time Discovery Alerts"
}

resource "aws_sns_topic_subscription" "email_alerts" {
  topic_arn = aws_sns_topic.time_discovery_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Metric filter for time discovery commands
resource "aws_cloudwatch_log_metric_filter" "time_discovery" {
  name           = "system-time-discovery"
  log_group_name = var.cloudwatch_log_group
  pattern        = "[timestamp, request_id, event_type=*date* || event_type=*timedatectl* || event_type=*w32tm* || event_type=*\"net time\"*]"

  metric_transformation {
    name          = "SystemTimeDiscovery"
    namespace     = "Security/Discovery"
    value         = "1"
    default_value = 0
  }
}

# Step 3: Alarm for unusual time queries
resource "aws_cloudwatch_metric_alarm" "time_discovery" {
  alarm_name          = "SystemTimeDiscoveryDetected"
  alarm_description   = "Multiple system time queries detected"
  metric_name         = aws_cloudwatch_log_metric_filter.time_discovery.metric_transformation[0].name
  namespace           = aws_cloudwatch_log_metric_filter.time_discovery.metric_transformation[0].namespace
  statistic           = "Sum"
  period              = 3600
  evaluation_periods  = 1
  threshold           = 5
  comparison_operator = "GreaterThanThreshold"
  alarm_actions       = [aws_sns_topic.time_discovery_alerts.arn]
  treat_missing_data  = "notBreaching"
}""",
                alert_severity="low",
                alert_title="System Time Discovery Detected",
                alert_description_template="Multiple system time queries detected from instance {instanceId}. This may indicate reconnaissance activity.",
                investigation_steps=[
                    "Identify the process and user executing time queries",
                    "Check if this is legitimate system administration or application behaviour",
                    "Review command history for the user account",
                    "Look for other reconnaissance activities (T1082, T1083, T1087)",
                    "Check for scheduled tasks or cron jobs created recently",
                    "Investigate follow-on activities within the next 24-48 hours",
                ],
                containment_actions=[
                    "Review user account permissions and recent activity",
                    "Check for unauthorised scheduled tasks or persistence mechanisms",
                    "Monitor for time-based malware execution attempts",
                    "Consider isolating instance if part of broader attack pattern",
                    "Audit system logs for suspicious modifications",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning=(
                "Whitelist legitimate system administration tools, monitoring agents, and "
                "configuration management systems (Ansible, Puppet, Chef). Filter out package "
                "managers and system update processes. Consider time-of-day and user context."
            ),
            detection_coverage="65% - catches explicit time query commands but may miss API calls",
            evasion_considerations=(
                "Attackers can use direct API calls (GetSystemTimeAsFileTime, clock_gettime) "
                "instead of command-line utilities, or query time as part of legitimate "
                "application behaviour. Time queries spread over extended periods evade thresholds."
            ),
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1.5 hours",
            estimated_monthly_cost="$8-15 (depends on log volume)",
            prerequisites=[
                "CloudWatch Logs agent installed on EC2 instances",
                "System logs forwarded to CloudWatch",
                "Command execution logging enabled",
            ],
        ),
        # Strategy 2: AWS - Systems Manager Command Execution
        DetectionStrategy(
            strategy_id="t1124-aws-ssm",
            name="SSM Time Discovery Command Detection",
            description="Detect time-related commands executed via AWS Systems Manager.",
            detection_type=DetectionType.EVENTBRIDGE_RULE,
            aws_service="eventbridge",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                event_pattern={
                    "source": ["aws.ssm"],
                    "detail-type": ["AWS API Call via CloudTrail"],
                    "detail": {
                        "eventName": ["SendCommand"],
                        "requestParameters": {
                            "documentName": [
                                "AWS-RunShellScript",
                                "AWS-RunPowerShellScript",
                            ]
                        },
                    },
                },
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect time discovery via Systems Manager

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
      KmsMasterKeyId: alias/aws/sns
      DisplayName: SSM Time Discovery Alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: EventBridge rule for SSM time commands
  TimeDiscoveryRule:
    Type: AWS::Events::Rule
    Properties:
      Name: SSMTimeDiscoveryDetection
      Description: Detect time discovery commands via SSM
      State: ENABLED
      EventPattern:
        source:
          - aws.ssm
        detail-type:
          - AWS API Call via CloudTrail
        detail:
          eventName:
            - SendCommand
          requestParameters:
            documentName:
              - AWS-RunShellScript
              - AWS-RunPowerShellScript
      Targets:
        - Id: SecurityAlerts
          Arn: !Ref AlertTopic

  # Step 3: SNS topic policy
  TopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics:
        - !Ref AlertTopic
      PolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              Service: events.amazonaws.com
            Action: sns:Publish
            Resource: !Ref AlertTopic""",
                terraform_template="""# AWS: Detect time discovery via Systems Manager

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

# Step 1: SNS topic for alerts
resource "aws_sns_topic" "ssm_alerts" {
  name         = "ssm-time-discovery-alerts"
  kms_master_key_id = "alias/aws/sns"
  display_name = "SSM Time Discovery Alerts"
}

resource "aws_sns_topic_subscription" "email_alerts" {
  topic_arn = aws_sns_topic.ssm_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: EventBridge rule for SSM time commands
resource "aws_cloudwatch_event_rule" "ssm_time_discovery" {
  name        = "SSMTimeDiscoveryDetection"
  description = "Detect time discovery commands via SSM"
  state       = "ENABLED"

  event_pattern = jsonencode({
    source      = ["aws.ssm"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = ["SendCommand"]
      requestParameters = {
        documentName = [
          "AWS-RunShellScript",
          "AWS-RunPowerShellScript"
        ]
      }
    }
  })
}

resource "aws_cloudwatch_event_target" "sns_target" {
  rule      = aws_cloudwatch_event_rule.ssm_time_discovery.name
  target_id = "SecurityAlerts"
  arn       = aws_sns_topic.ssm_alerts.arn
}

# Step 3: SNS topic policy
resource "aws_sns_topic_policy" "allow_events" {
  arn = aws_sns_topic.ssm_alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.ssm_alerts.arn
    }]
  })
}""",
                alert_severity="medium",
                alert_title="Time Discovery Command via SSM",
                alert_description_template="Time-related command executed via Systems Manager. Requires manual review of command content.",
                investigation_steps=[
                    "Review the complete SSM command parameters in CloudTrail",
                    "Identify the IAM principal who executed the command",
                    "Check target instances for command execution results",
                    "Verify if this is authorised administrative activity",
                    "Look for patterns of multiple discovery commands",
                ],
                containment_actions=[
                    "Review IAM permissions for SSM command execution",
                    "Check for unauthorised access to Systems Manager",
                    "Monitor target instances for suspicious activity",
                    "Consider restricting SSM command execution permissions",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.HIGH,
            false_positive_tuning=(
                "This rule captures all SSM shell/PowerShell commands, requiring additional "
                "filtering in CloudWatch Logs Insights to identify actual time queries. Consider "
                "implementing content inspection or Lambda-based filtering."
            ),
            detection_coverage="85% - captures SSM-based time queries but requires content analysis",
            evasion_considerations="Attackers can use other remote execution methods (SSM Session Manager, EC2 Instance Connect)",
            implementation_effort=EffortLevel.LOW,
            implementation_time="45 minutes",
            estimated_monthly_cost="$3-8",
            prerequisites=[
                "CloudTrail enabled with SSM API logging",
                "Systems Manager in use",
            ],
        ),
        # Strategy 3: GCP - Compute Instance Time Queries
        DetectionStrategy(
            strategy_id="t1124-gcp-compute",
            name="GCP Compute Instance Time Discovery",
            description="Detect system time queries on GCP Compute Engine instances via Cloud Logging.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="gce_instance"
(textPayload=~"date" OR textPayload=~"timedatectl" OR textPayload=~"hwclock" OR textPayload=~"/etc/timezone")
-textPayload=~"(yum|apt|dpkg|systemd|cron)"''',
                gcp_terraform_template="""# GCP: Detect system time discovery

variable "project_id" {
  type        = string
  description = "GCP project ID"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

# Step 1: Notification channel for alerts
resource "google_monitoring_notification_channel" "email_alerts" {
  display_name = "Security Alerts"
  type         = "email"
  project      = var.project_id

  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Log-based metric for time discovery
resource "google_logging_metric" "time_discovery" {
  name   = "system-time-discovery"
  project = var.project_id
  filter = <<-EOT
    resource.type="gce_instance"
    (textPayload=~"date" OR textPayload=~"timedatectl" OR textPayload=~"hwclock" OR textPayload=~"/etc/timezone")
    -textPayload=~"(yum|apt|dpkg|systemd|cron)"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    unit        = "1"
  }
}

# Step 3: Alert policy for unusual time queries
resource "google_monitoring_alert_policy" "time_discovery_alert" {
  display_name = "System Time Discovery Detected"
  project      = var.project_id
  combiner     = "OR"

  conditions {
    display_name = "High volume of time queries"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.time_discovery.name}\" AND resource.type=\"gce_instance\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 5
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
}""",
                alert_severity="low",
                alert_title="GCP: System Time Discovery Detected",
                alert_description_template="Multiple system time queries detected on GCP Compute Engine instance.",
                investigation_steps=[
                    "Identify the GCE instance and user account",
                    "Review Cloud Logging for command execution context",
                    "Check if this is legitimate administrative activity",
                    "Look for other discovery techniques (metadata queries, network enumeration)",
                    "Review recent VM access logs and SSH sessions",
                    "Check for scheduled tasks or cron jobs",
                ],
                containment_actions=[
                    "Review IAM permissions for instance access",
                    "Check for unauthorised SSH keys or service accounts",
                    "Monitor instance for time-based malware execution",
                    "Consider VPC Service Controls for additional protection",
                    "Review OS Login and metadata settings",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning=(
                "Whitelist GCP-managed services, monitoring agents (Ops Agent, Cloud Logging agent), "
                "and configuration management tools. Filter package management activities."
            ),
            detection_coverage="60% - captures common time query commands in logs",
            evasion_considerations=(
                "Requires Cloud Logging agent configured to capture system commands. "
                "API-based time queries or silent execution won't be logged."
            ),
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1.5 hours",
            estimated_monthly_cost="$10-20 (depends on log volume)",
            prerequisites=[
                "Cloud Logging agent installed on GCE instances",
                "System logs ingested into Cloud Logging",
                "Audit logging enabled",
            ],
        ),
        # Strategy 4: GCP - OS Login and SSH Session Monitoring
        DetectionStrategy(
            strategy_id="t1124-gcp-oslogin",
            name="GCP OS Login Time Command Detection",
            description="Monitor OS Login sessions for time discovery commands via Cloud Audit Logs.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''protoPayload.methodName="ExecuteCommand"
protoPayload.request.command=~"(date|timedatectl|hwclock|systemsetup|gettimeofday)"''',
                gcp_terraform_template="""# GCP: Monitor OS Login sessions for time discovery

variable "project_id" {
  type        = string
  description = "GCP project ID"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

# Step 1: Notification channel
resource "google_monitoring_notification_channel" "email_alerts" {
  display_name = "Security Alerts"
  type         = "email"
  project      = var.project_id

  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Log-based metric for OS Login time commands
resource "google_logging_metric" "oslogin_time_discovery" {
  name    = "oslogin-time-discovery"
  project = var.project_id
  filter  = <<-EOT
    protoPayload.methodName="ExecuteCommand"
    protoPayload.request.command=~"(date|timedatectl|hwclock|systemsetup|gettimeofday)"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Alert policy
resource "google_monitoring_alert_policy" "oslogin_time_alert" {
  display_name = "Time Discovery via OS Login"
  project      = var.project_id
  combiner     = "OR"

  conditions {
    display_name = "Time commands in OS Login sessions"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.oslogin_time_discovery.name}\""
      duration        = "60s"
      comparison      = "COMPARISON_GT"
      threshold_value = 3
      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_SUM"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email_alerts.id]

  alert_strategy {
    auto_close = "1800s"
  }
}""",
                alert_severity="medium",
                alert_title="GCP: Time Discovery in OS Login Session",
                alert_description_template="Time discovery commands detected in OS Login session.",
                investigation_steps=[
                    "Identify the user account and source IP address",
                    "Review complete command history for the session",
                    "Check if this is authorised administrative access",
                    "Look for other reconnaissance commands in the session",
                    "Verify user account is legitimate and not compromised",
                    "Check for privilege escalation attempts",
                ],
                containment_actions=[
                    "Review OS Login IAM permissions",
                    "Verify SSH keys and service account access",
                    "Monitor for follow-on suspicious activities",
                    "Consider enabling 2FA for OS Login",
                    "Review VPC firewall rules for SSH access",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning=(
                "Generally low false positives as this requires explicit command execution. "
                "Whitelist known administrative users and automation accounts."
            ),
            detection_coverage="50% - only detects if OS Login and command auditing are enabled",
            evasion_considerations="Only effective if OS Login is used; traditional SSH access bypasses this detection",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$8-12",
            prerequisites=[
                "OS Login enabled on GCE instances",
                "Cloud Audit Logs enabled for Compute Engine",
                "Command execution logging configured",
            ],
        ),
    ],
    recommended_order=[
        "t1124-aws-ssm",  # Low effort, good coverage for AWS
        "t1124-aws-ec2time",  # Broader coverage for EC2
        "t1124-gcp-oslogin",  # Best coverage for GCP with OS Login
        "t1124-gcp-compute",  # General GCP coverage
    ],
    total_effort_hours=4.5,
    coverage_improvement="+8% improvement for Discovery tactic",
)
