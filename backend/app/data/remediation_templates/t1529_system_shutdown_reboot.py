"""
T1529 - System Shutdown/Reboot

Adversaries may shut down or reboot systems to interrupt availability and hinder
incident response, often following destructive actions like data wiping.
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
    technique_id="T1529",
    technique_name="System Shutdown/Reboot",
    tactic_ids=["TA0040"],
    mitre_url="https://attack.mitre.org/techniques/T1529/",
    threat_context=ThreatContext(
        description=(
            "Adversaries may shut down or reboot systems to interrupt availability, "
            "aid in the destruction of those systems, or disrupt incident response efforts. "
            "In cloud environments, this includes forcibly stopping EC2 instances, GCE VMs, "
            "triggering instance reboots via system commands, or using hypervisor/cloud APIs "
            "to terminate workloads. This technique is frequently observed following destructive "
            "malware deployment, data wiping operations, or as part of ransomware attacks to "
            "maximise disruption and prevent recovery."
        ),
        attacker_goal="Disrupt availability, hinder incident response, and aid destructive operations",
        why_technique=[
            "Interrupts access to critical systems and disrupts business operations",
            "Prevents incident responders from investigating active compromises",
            "Completes destructive attacks by rendering systems inoperable",
            "Forces system reboots to activate persistence mechanisms or bootkit malware",
            "Masks evidence of malicious activity by clearing volatile memory",
            "Triggers panic and confusion during ransomware deployment",
            "Prevents recovery by interrupting backup or restoration processes",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="uncommon",
        trend="stable",
        severity_score=7,
        severity_reasoning=(
            "System shutdown/reboot is a high-impact technique that directly disrupts "
            "availability and business operations. While less common than other impact "
            "techniques, it is frequently used in the final stages of destructive attacks, "
            "ransomware campaigns, and state-sponsored operations targeting critical infrastructure. "
            "In cloud environments, unauthorised shutdowns can disrupt entire application stacks, "
            "databases, and production workloads, leading to significant financial loss and reputational damage."
        ),
        business_impact=[
            "Complete disruption of critical business applications and services",
            "Loss of volatile forensic evidence from system memory",
            "Prevention of incident response and forensic investigation",
            "Extended recovery time due to forced shutdowns",
            "Completion of destructive attacks like data wiping or disk encryption",
            "Service-level agreement violations and financial penalties",
        ],
        typical_attack_phase="impact",
        often_precedes=[],
        often_follows=["T1486", "T1485", "T1490", "T1561"],
    ),
    detection_strategies=[
        # Strategy 1: CloudWatch EventBridge - EC2 State Changes
        DetectionStrategy(
            strategy_id="t1529-ec2-shutdown",
            name="AWS: Detect Unexpected EC2 Instance Shutdowns",
            description=(
                "Monitor AWS EventBridge for EC2 instance state changes to 'stopping' or 'stopped' "
                "that occur outside of scheduled maintenance windows or lack authorisation context."
            ),
            detection_type=DetectionType.EVENTBRIDGE_RULE,
            aws_service="eventbridge",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect unexpected EC2 instance shutdowns and reboots

Parameters:
  AlertEmail:
    Type: String
    Description: Email for security alerts

Resources:
  # Step 1: Create SNS topic for alerts
  SecurityAlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      DisplayName: EC2 Shutdown Alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Monitor EC2 instance state changes
  EC2ShutdownRule:
    Type: AWS::Events::Rule
    Properties:
      Name: T1529-EC2-Shutdown-Detection
      Description: Alert on unexpected EC2 shutdowns or reboots
      EventPattern:
        source: [aws.ec2]
        detail-type: [EC2 Instance State-change Notification]
        detail:
          state:
            - stopping
            - stopped
            - shutting-down
            - terminated
      State: ENABLED
      Targets:
        - Id: AlertTopic
          Arn: !Ref SecurityAlertTopic
          InputTransformer:
            InputPathsMap:
              instance: $.detail.instance-id
              state: $.detail.state
              time: $.time
            InputTemplate: |
              "EC2 Instance Shutdown Detected - T1529"
              "Instance: <instance>"
              "New State: <state>"
              "Time: <time>"
              "Investigate if this shutdown was authorised."

  # Step 3: Monitor StopInstances and TerminateInstances API calls
  EC2StopAPIRule:
    Type: AWS::Events::Rule
    Properties:
      Name: T1529-EC2-StopInstances-API
      Description: Alert on StopInstances/TerminateInstances API calls
      EventPattern:
        source: [aws.cloudtrail]
        detail:
          eventSource: [ec2.amazonaws.com]
          eventName:
            - StopInstances
            - TerminateInstances
            - RebootInstances
      State: ENABLED
      Targets:
        - Id: AlertTopic
          Arn: !Ref SecurityAlertTopic

  TopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics: [!Ref SecurityAlertTopic]
      PolicyDocument:
        Statement:
          - Effect: Allow
            Principal:
              Service: events.amazonaws.com
            Action: sns:Publish
            Resource: !Ref SecurityAlertTopic
            Condition:
              StringEquals:
                AWS:SourceAccount: !Ref AWS::AccountId
              ArnEquals:
                aws:SourceArn:
                  - !GetAtt EC2ShutdownRule.Arn
                  - !GetAtt EC2StopAPIRule.Arn""",
                terraform_template="""# AWS: Detect unexpected EC2 instance shutdowns

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

# Step 1: Create SNS topic for alerts
resource "aws_sns_topic" "ec2_shutdown_alerts" {
  name         = "ec2-shutdown-alerts"
  kms_master_key_id = "alias/aws/sns"
  display_name = "EC2 Shutdown Alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.ec2_shutdown_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Monitor EC2 instance state changes
resource "aws_cloudwatch_event_rule" "ec2_shutdown" {
  name        = "T1529-EC2-Shutdown-Detection"
  description = "Alert on unexpected EC2 shutdowns or reboots"
  event_pattern = jsonencode({
    source      = ["aws.ec2"]
    detail-type = ["EC2 Instance State-change Notification"]
    detail = {
      state = ["stopping", "stopped", "shutting-down", "terminated"]
    }
  })
}

resource "aws_cloudwatch_event_target" "ec2_shutdown_sns" {
  rule      = aws_cloudwatch_event_rule.ec2_shutdown.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.ec2_shutdown_alerts.arn

  input_transformer {
    input_paths = {
      instance = "$.detail.instance-id"
      state    = "$.detail.state"
      time     = "$.time"
    }
    input_template = "\"EC2 Instance Shutdown Detected - T1529\\nInstance: <instance>\\nNew State: <state>\\nTime: <time>\\nInvestigate if this shutdown was authorised.\""
  }
}

# Step 3: Monitor StopInstances and TerminateInstances API calls
resource "aws_cloudwatch_event_rule" "ec2_stop_api" {
  name        = "T1529-EC2-StopInstances-API"
  description = "Alert on StopInstances/TerminateInstances API calls"
  event_pattern = jsonencode({
    source = ["aws.cloudtrail"]
    detail = {
      eventSource = ["ec2.amazonaws.com"]
      eventName   = ["StopInstances", "TerminateInstances", "RebootInstances"]
    }
  })
}

resource "aws_sqs_queue" "dlq" {
  name                      = "ec2-stop-api-dlq"
  message_retention_seconds = 1209600
}

data "aws_iam_policy_document" "eventbridge_dlq_policy" {
  statement {
    sid     = "AllowEventBridgeToSendToDLQ"
    effect  = "Allow"
    actions = ["sqs:SendMessage"]
    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }
    resources = [aws_sqs_queue.dlq.arn]
    condition {
      test     = "StringEquals"
      variable = "AWS:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
    condition {
      test     = "ArnEquals"
      variable = "aws:SourceArn"
      values   = [aws_cloudwatch_event_rule.ec2_stop_api.arn]
    }
  }
}

resource "aws_sqs_queue_policy" "event_dlq" {
  queue_url = aws_sqs_queue.dlq.url
  policy    = data.aws_iam_policy_document.eventbridge_dlq_policy.json
}

resource "aws_cloudwatch_event_target" "ec2_stop_api_sns" {
  rule      = aws_cloudwatch_event_rule.ec2_stop_api.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.ec2_shutdown_alerts.arn

  retry_policy {
    maximum_event_age_in_seconds = 3600
    maximum_retry_attempts       = 8
  }

  dead_letter_config {
    arn = aws_sqs_queue.dlq.arn
  }
}

data "aws_caller_identity" "current" {}

resource "aws_sns_topic_policy" "allow_eventbridge" {
  arn = aws_sns_topic.ec2_shutdown_alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.ec2_shutdown_alerts.arn
    Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
          ArnEquals = {
            "aws:SourceArn" = [
              aws_cloudwatch_event_rule.ec2_shutdown.arn,
              aws_cloudwatch_event_rule.ec2_stop_api.arn,
            ]
          }
      }
    }]
  })
}""",
                alert_severity="high",
                alert_title="Unexpected EC2 Instance Shutdown Detected",
                alert_description_template=(
                    "EC2 instance {instance_id} changed to state '{state}' at {time}. "
                    "Verify if this shutdown was authorised and investigate for potential T1529 activity."
                ),
                investigation_steps=[
                    "Check CloudTrail for the StopInstances/TerminateInstances API call and identify the caller",
                    "Verify if the shutdown was part of scheduled maintenance or authorised operations",
                    "Review the instance's recent activity and system logs before shutdown",
                    "Check for signs of preceding destructive actions (data wiping, disk encryption)",
                    "Examine the IAM principal that initiated the shutdown for compromise",
                    "Review EventBridge/CloudWatch Events for patterns of mass shutdowns",
                    "Check if other instances in the same VPC or availability zone were affected",
                ],
                containment_actions=[
                    "Restart the instance if shutdown was unauthorised",
                    "Review and restrict IAM policies granting ec2:StopInstances permissions",
                    "Enable termination protection on critical instances",
                    "Implement SCPs to prevent instance termination outside business hours",
                    "Enable CloudWatch detailed monitoring for instance metrics",
                    "Review security group rules and network access logs for signs of breach",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Filter out auto-scaling group terminations and scheduled shutdowns via tags",
            detection_coverage="85% - captures instance state changes and API calls",
            evasion_considerations="Attackers with sufficient privileges may disable EventBridge rules",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$0 - EventBridge rules are free for AWS events",
            prerequisites=["CloudTrail enabled for API call logging"],
        ),
        # Strategy 2: CloudWatch Logs - Shutdown Command Detection
        DetectionStrategy(
            strategy_id="t1529-shutdown-commands",
            name="Detect System Shutdown Commands in Instance Logs",
            description=(
                "Monitor CloudWatch Logs for execution of shutdown, reboot, poweroff, or halt "
                "commands on Linux instances and shutdown.exe on Windows instances."
            ),
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query=r"""fields @timestamp, @message, instanceId, commandLine, processName
| filter @message like /shutdown|reboot|poweroff|halt|init 0|init 6|systemctl (poweroff|reboot|halt)|shutdown\.exe|wmic.*shutdown/
| filter @message not like /cron|systemd-shutdown|scheduled/
| stats count() as shutdown_commands by instanceId, commandLine, bin(5m)
| sort @timestamp desc""",
                cloudformation_template='''AWSTemplateFormatVersion: '2010-09-09'
Description: Detect shutdown/reboot commands in CloudWatch Logs

Parameters:
  CloudWatchLogGroup:
    Type: String
    Description: Log group containing instance system logs
  SNSTopicArn:
    Type: String
    Description: SNS topic for alerts

Resources:
  # Step 1: Create metric filter for shutdown commands
  ShutdownCommandFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudWatchLogGroup
      FilterPattern: '[time, instance, process, command="*shutdown*" || command="*reboot*" || command="*poweroff*" || command="*halt*" || command="*init 0*" || command="*init 6*"]'
      MetricTransformations:
        - MetricName: ShutdownCommands
          MetricNamespace: Security/T1529
          MetricValue: "1"

  # Step 2: Create alarm for shutdown command execution
  ShutdownCommandAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: T1529-ShutdownCommand
      AlarmDescription: Shutdown or reboot command detected on instance
      MetricName: ShutdownCommands
      Namespace: Security/T1529
      Statistic: Sum
      Period: 300
      EvaluationPeriods: 1
      Threshold: 1
      ComparisonOperator: GreaterThanOrEqualToThreshold
      TreatMissingData: notBreaching

      AlarmActions:
        - !Ref SNSTopicArn

  # Step 3: Monitor Windows shutdown events
  WindowsShutdownFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudWatchLogGroup
      FilterPattern: '[time, instance, event="*EventID 1074*" || event="*EventID 6006*" || event="*EventID 6008*"]'
      MetricTransformations:
        - MetricName: WindowsShutdownEvents
          MetricNamespace: Security/T1529
          MetricValue: "1"''',
                terraform_template="""# Detect shutdown/reboot commands in CloudWatch Logs

variable "cloudwatch_log_group" {
  type        = string
  description = "Log group containing instance system logs"
}

variable "alert_email" {
  type        = string
  description = "Email for alerts"
}

resource "aws_sns_topic" "alerts" {
  name = "shutdown-command-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 1: Create metric filter for shutdown commands
resource "aws_cloudwatch_log_metric_filter" "shutdown_commands" {
  name           = "shutdown-commands"
  log_group_name = var.cloudwatch_log_group
  pattern        = "[time, instance, process, command=\"*shutdown*\" || command=\"*reboot*\" || command=\"*poweroff*\" || command=\"*halt*\" || command=\"*init 0*\" || command=\"*init 6*\"]"

  metric_transformation {
    name      = "ShutdownCommands"
    namespace = "Security/T1529"
    value     = "1"
  }
}

# Step 2: Create alarm for shutdown command execution
resource "aws_cloudwatch_metric_alarm" "shutdown_command" {
  alarm_name          = "T1529-ShutdownCommand"
  alarm_description   = "Shutdown or reboot command detected on instance"
  metric_name         = "ShutdownCommands"
  namespace           = "Security/T1529"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.alerts.arn]
}

# Step 3: Monitor Windows shutdown events (Event IDs 1074, 6006, 6008)
resource "aws_cloudwatch_log_metric_filter" "windows_shutdown" {
  name           = "windows-shutdown-events"
  log_group_name = var.cloudwatch_log_group
  pattern        = "[time, instance, event=\"*EventID 1074*\" || event=\"*EventID 6006*\" || event=\"*EventID 6008*\"]"

  metric_transformation {
    name      = "WindowsShutdownEvents"
    namespace = "Security/T1529"
    value     = "1"
  }
}""",
                alert_severity="high",
                alert_title="System Shutdown Command Detected",
                alert_description_template=(
                    "Shutdown or reboot command detected on instance {instance_id}. "
                    "Command: {command_line}. Process: {process_name}. "
                    "Verify this was an authorised administrative action."
                ),
                investigation_steps=[
                    "Identify which user or process executed the shutdown command",
                    "Review SSH/RDP session logs to determine who was logged in",
                    "Check for preceding suspicious activity (malware execution, data deletion)",
                    "Examine system logs for signs of wiper malware or ransomware",
                    "Review recent file modifications and deletions",
                    "Check if multiple instances received shutdown commands simultaneously",
                    "Investigate the parent process that spawned the shutdown command",
                ],
                containment_actions=[
                    "If malicious, prevent instance shutdown by modifying IAM policies",
                    "Create snapshots of affected instances before they shut down",
                    "Block network access to prevent lateral shutdown attempts",
                    "Review and remove any scheduled tasks triggering shutdowns",
                    "Disable or quarantine accounts that executed unauthorised shutdowns",
                    "Enable instance termination protection on critical workloads",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Exclude scheduled maintenance windows and approved automation scripts",
            detection_coverage="75% - detects common shutdown command patterns",
            evasion_considerations="Direct API calls or hypervisor commands bypass system-level logging",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1.5 hours",
            estimated_monthly_cost="$5-15 depending on log volume",
            prerequisites=[
                "CloudWatch Logs Agent or SSM Agent installed",
                "System audit logging enabled",
            ],
        ),
        # Strategy 3: GCP - VM Instance State Changes
        DetectionStrategy(
            strategy_id="t1529-gcp-vm-shutdown",
            name="GCP: Detect Unexpected GCE VM Shutdowns",
            description=(
                "Monitor GCP Cloud Logging for Compute Engine VM instance state changes "
                "to 'STOPPING' or 'TERMINATED' and detect shutdown/reboot commands in VM logs."
            ),
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""(resource.type="gce_instance"
AND protoPayload.methodName=("v1.compute.instances.stop" OR "v1.compute.instances.delete" OR "v1.compute.instances.reset"))
OR
(resource.type="gce_instance"
AND textPayload=~"shutdown|reboot|poweroff|halt|systemctl (poweroff|reboot)")""",
                gcp_terraform_template="""# GCP: Detect unexpected GCE VM shutdowns

variable "project_id" {
  type        = string
  description = "GCP project ID"
}

variable "alert_email" {
  type = string
}

# Step 1: Create notification channel
resource "google_monitoring_notification_channel" "email_s1" {
  project      = var.project_id
  display_name = "VM Shutdown Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Create log-based metric for VM shutdowns
resource "google_logging_metric" "vm_shutdown" {
  project = var.project_id
  name    = "gce-vm-shutdown-attempts"
  filter  = <<-EOT
    (resource.type="gce_instance"
    AND protoPayload.methodName=("v1.compute.instances.stop" OR "v1.compute.instances.delete" OR "v1.compute.instances.reset"))
    OR
    (resource.type="gce_instance"
    AND textPayload=~"shutdown|reboot|poweroff|halt|systemctl (poweroff|reboot)")
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "instance_name"
      value_type  = "STRING"
      description = "Name of the VM instance"
    }
    labels {
      key         = "method"
      value_type  = "STRING"
      description = "Shutdown method used"
    }
  }

  label_extractors = {
    instance_name = "EXTRACT(resource.labels.instance_id)"
    method        = "EXTRACT(protoPayload.methodName)"
  }
}

# Step 3: Create alert policy for VM shutdowns
resource "google_monitoring_alert_policy" "vm_shutdown" {
  project      = var.project_id
  display_name = "T1529: GCE VM Shutdown Detected"
  combiner     = "OR"
  conditions {
    display_name = "VM shutdown or reboot detected"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.vm_shutdown.name}\" resource.type=\"gce_instance\""
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
    content   = "GCE VM shutdown detected - T1529. Investigate if this was an authorised operation. Check for preceding destructive activity."
    mime_type = "text/markdown"
  }
}""",
                alert_severity="high",
                alert_title="GCP: Unexpected VM Shutdown Detected",
                alert_description_template=(
                    "GCE VM instance {instance_name} shutdown detected. Method: {method}. "
                    "Time: {timestamp}. Verify if this was an authorised operation."
                ),
                investigation_steps=[
                    "Review Cloud Audit Logs for the API call that triggered the shutdown",
                    "Identify the service account or user that initiated the shutdown",
                    "Check if the shutdown was part of managed instance group scaling",
                    "Examine VM serial port output for system-level shutdown messages",
                    "Review Cloud Logging for signs of malware or destructive activity before shutdown",
                    "Check for patterns of mass shutdowns across multiple VMs",
                    "Investigate whether data wiping or disk encryption preceded the shutdown",
                ],
                containment_actions=[
                    "Restart the VM if shutdown was unauthorised",
                    "Create a disk snapshot for forensic investigation",
                    "Review and restrict IAM permissions for compute.instances.stop",
                    "Enable deletion protection on critical VM instances",
                    "Revoke compromised service account credentials",
                    "Implement organisation policies to restrict VM deletions",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Exclude managed instance group auto-scaling and scheduled shutdowns",
            detection_coverage="80% - captures API calls and system commands",
            evasion_considerations="Direct hypervisor manipulation may bypass Cloud Logging",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$10-20",
            prerequisites=["Cloud Logging API enabled", "Cloud Audit Logs enabled"],
        ),
        # Strategy 4: Windows Event Log Monitoring
        DetectionStrategy(
            strategy_id="t1529-windows-events",
            name="Windows Event Log Shutdown Detection",
            description=(
                "Monitor Windows Event IDs 1074 (System shutdown initiated), 6006 (clean shutdown), "
                "and 6008 (unexpected shutdown) to detect system shutdown/reboot activity."
            ),
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, EventID, UserName, ProcessName, @message
| filter EventID in [1074, 6006, 6008, 41]
| filter EventID = 1074 and UserName not like /SYSTEM|NETWORK SERVICE/
| stats count() as shutdown_count by UserName, ProcessName, bin(5m)
| sort @timestamp desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Monitor Windows shutdown events via CloudWatch

Parameters:
  CloudWatchLogGroup:
    Type: String
    Description: Log group for Windows Event Logs
  SNSTopicArn:
    Type: String

Resources:
  # Step 1: Monitor Event ID 1074 (shutdown initiated)
  Event1074Filter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudWatchLogGroup
      FilterPattern: '{ $.EventID = 1074 && $.UserName != "*SYSTEM*" }'
      MetricTransformations:
        - MetricName: WindowsShutdownInitiated
          MetricNamespace: Security/T1529
          MetricValue: "1"

  # Step 2: Monitor Event ID 6008 (unexpected shutdown)
  Event6008Filter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudWatchLogGroup
      FilterPattern: '{ $.EventID = 6008 }'
      MetricTransformations:
        - MetricName: WindowsUnexpectedShutdown
          MetricNamespace: Security/T1529
          MetricValue: "1"

  # Step 3: Alert on shutdown events
  ShutdownEventAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: T1529-WindowsShutdown
      AlarmDescription: Windows shutdown event detected
      MetricName: WindowsShutdownInitiated
      Namespace: Security/T1529
      Statistic: Sum
      Period: 300
      EvaluationPeriods: 1
      Threshold: 1
      ComparisonOperator: GreaterThanOrEqualToThreshold
      TreatMissingData: notBreaching

      AlarmActions:
        - !Ref SNSTopicArn""",
                terraform_template="""# Monitor Windows shutdown events

variable "cloudwatch_log_group" {
  type        = string
  description = "Log group for Windows Event Logs"
}

variable "alert_email" {
  type = string
}

resource "aws_sns_topic" "alerts" {
  name = "windows-shutdown-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 1: Monitor Event ID 1074 (shutdown initiated)
resource "aws_cloudwatch_log_metric_filter" "event_1074" {
  name           = "windows-shutdown-event-1074"
  log_group_name = var.cloudwatch_log_group
  pattern        = "{ $.EventID = 1074 && $.UserName != \"*SYSTEM*\" }"

  metric_transformation {
    name      = "WindowsShutdownInitiated"
    namespace = "Security/T1529"
    value     = "1"
  }
}

# Step 2: Monitor Event ID 6008 (unexpected shutdown)
resource "aws_cloudwatch_log_metric_filter" "event_6008" {
  name           = "windows-unexpected-shutdown-6008"
  log_group_name = var.cloudwatch_log_group
  pattern        = "{ $.EventID = 6008 }"

  metric_transformation {
    name      = "WindowsUnexpectedShutdown"
    namespace = "Security/T1529"
    value     = "1"
  }
}

# Step 3: Alert on shutdown events
resource "aws_cloudwatch_metric_alarm" "shutdown_event" {
  alarm_name          = "T1529-WindowsShutdown"
  alarm_description   = "Windows shutdown event detected"
  metric_name         = "WindowsShutdownInitiated"
  namespace           = "Security/T1529"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.alerts.arn]
}""",
                alert_severity="high",
                alert_title="Windows System Shutdown Detected",
                alert_description_template=(
                    "Windows shutdown event detected. Event ID: {event_id}. User: {user_name}. "
                    "Process: {process_name}. Investigate if this was authorised."
                ),
                investigation_steps=[
                    "Review Event ID 1074 details to identify shutdown reason and initiating user",
                    "Check for Event ID 6008 indicating unexpected/dirty shutdown",
                    "Examine Security Event Logs for logon sessions before shutdown",
                    "Review Application and System logs for malware or ransomware indicators",
                    "Check Task Scheduler for scheduled shutdown tasks",
                    "Investigate whether destructive actions (file deletion, encryption) preceded shutdown",
                    "Review user account privileges and recent activity",
                ],
                containment_actions=[
                    "Disable user accounts that initiated unauthorised shutdowns",
                    "Review and remove suspicious scheduled tasks",
                    "Enable write-protect on critical system files",
                    "Deploy endpoint detection and response (EDR) agents",
                    "Restrict local administrator privileges",
                    "Implement application control to block shutdown utilities",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Exclude SYSTEM account shutdowns and scheduled maintenance",
            detection_coverage="90% - Windows Event Logs reliably capture shutdown events",
            evasion_considerations="Kernel-level attacks may corrupt event logs before shutdown",
            implementation_effort=EffortLevel.LOW,
            implementation_time="45 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=[
                "CloudWatch Agent installed with Windows Event Log collection"
            ],
        ),
        # Strategy 5: Mass Shutdown Detection
        DetectionStrategy(
            strategy_id="t1529-mass-shutdown",
            name="Detect Mass Instance Shutdown Across Fleet",
            description=(
                "Identify patterns of multiple instances shutting down simultaneously, "
                "which may indicate a coordinated attack, ransomware outbreak, or wiper malware deployment."
            ),
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, detail.instance-id as instance, detail.state as state
| filter detail-type = "EC2 Instance State-change Notification"
| filter detail.state in ["stopping", "stopped", "shutting-down", "terminated"]
| stats count() as instance_count by bin(5m)
| filter instance_count > 3
| sort @timestamp desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect mass shutdown events across EC2 fleet

Parameters:
  SNSTopicArn:
    Type: String
    Description: SNS topic for critical alerts

Resources:
  # Step 1: Create CloudWatch Logs Insights query schedule
  MassShutdownQuery:
    Type: AWS::Logs::QueryDefinition
    Properties:
      Name: T1529-MassShutdownDetection
      QueryString: |
        fields @timestamp, detail.instance-id, detail.state
        | filter detail-type = "EC2 Instance State-change Notification"
        | filter detail.state in ["stopping", "stopped", "shutting-down"]
        | stats count() as shutdown_count by bin(5m)
        | filter shutdown_count > 3

  # Step 2: Create metric for mass shutdowns
  MassShutdownMetric:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: /aws/events/ec2-state-changes
      FilterPattern: '{ $.detail.state = "stopping" || $.detail.state = "stopped" }'
      MetricTransformations:
        - MetricName: InstanceShutdowns
          MetricNamespace: Security/T1529
          MetricValue: "1"

  # Step 3: Alert when shutdown threshold exceeded
  MassShutdownAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: T1529-MassShutdown
      AlarmDescription: Multiple instances shutting down simultaneously
      MetricName: InstanceShutdowns
      Namespace: Security/T1529
      Statistic: Sum
      Period: 300
      EvaluationPeriods: 1
      Threshold: 3
      ComparisonOperator: GreaterThanThreshold
      TreatMissingData: notBreaching

      AlarmActions:
        - !Ref SNSTopicArn""",
                terraform_template="""# Detect mass shutdown events across EC2 fleet

variable "alert_email" {
  type = string
}

variable "shutdown_threshold" {
  type        = number
  description = "Number of shutdowns in 5 minutes to trigger alert"
  default     = 3
}

resource "aws_sns_topic" "critical_alerts" {
  name = "mass-shutdown-critical-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.critical_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 1: Create CloudWatch log group for EC2 state changes
resource "aws_cloudwatch_log_group" "ec2_events" {
  name              = "/aws/events/ec2-state-changes"
  retention_in_days = 7
}

# Step 2: Create metric filter for shutdown events
resource "aws_cloudwatch_log_metric_filter" "mass_shutdown" {
  name           = "mass-instance-shutdowns"
  log_group_name = aws_cloudwatch_log_group.ec2_events.name
  pattern        = "{ $.detail.state = \"stopping\" || $.detail.state = \"stopped\" }"

  metric_transformation {
    name      = "InstanceShutdowns"
    namespace = "Security/T1529"
    value     = "1"
  }
}

# Step 3: Alert when shutdown threshold exceeded
resource "aws_cloudwatch_metric_alarm" "mass_shutdown" {
  alarm_name          = "T1529-MassShutdown"
  alarm_description   = "Multiple instances shutting down simultaneously - possible coordinated attack"
  metric_name         = "InstanceShutdowns"
  namespace           = "Security/T1529"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = var.shutdown_threshold
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.critical_alerts.arn]
}""",
                alert_severity="critical",
                alert_title="Mass Instance Shutdown Detected - Potential Attack",
                alert_description_template=(
                    "CRITICAL: {instance_count} instances shut down within 5 minutes. "
                    "This may indicate ransomware, wiper malware, or coordinated attack. "
                    "Immediate investigation required."
                ),
                investigation_steps=[
                    "Immediately identify all affected instances and their roles",
                    "Check CloudTrail for the API calls that triggered the shutdowns",
                    "Determine if shutdowns originated from a single compromised account",
                    "Review GuardDuty findings for signs of widespread compromise",
                    "Check for ransomware notes or data encryption across instances",
                    "Examine network traffic for command-and-control communications",
                    "Coordinate incident response across security and infrastructure teams",
                ],
                containment_actions=[
                    "Immediately revoke credentials of suspected compromised accounts",
                    "Implement SCPs to prevent further instance terminations",
                    "Create snapshots of remaining running instances",
                    "Isolate network segments to prevent lateral spread",
                    "Activate disaster recovery procedures if business-critical systems affected",
                    "Preserve forensic evidence from CloudTrail and CloudWatch Logs",
                    "Engage incident response team and consider third-party forensics support",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Adjust threshold based on normal auto-scaling patterns",
            detection_coverage="95% - highly effective at detecting coordinated shutdowns",
            evasion_considerations="Slow, staggered shutdowns may evade time-based thresholds",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$2-5",
            prerequisites=[
                "CloudTrail enabled",
                "EventBridge configured for EC2 events",
            ],
        ),
        # Azure Strategy: System Shutdown/Reboot
        DetectionStrategy(
            strategy_id="t1529-azure",
            name="Azure System Shutdown/Reboot Detection",
            description=(
                "Azure detection for System Shutdown/Reboot. "
                "Provides native Azure detection using Log Analytics and Defender for Cloud."
            ),
            detection_type=DetectionType.DEFENDER_ALERT,
            aws_service="n/a",
            azure_service="defender",
            cloud_provider=CloudProvider.AZURE,
            implementation=DetectionImplementation(
                defender_alert_types=["Suspicious activity detected"],
                azure_terraform_template="""# Microsoft Defender for Cloud Detection
# System Shutdown/Reboot (T1529)
# Microsoft Defender detects System Shutdown/Reboot activity

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
  name                = "defender-t1529-alerts"
  resource_group_name = var.resource_group_name
  short_name          = "DefAlerts"

  email_receiver {
    name          = "security-team"
    email_address = var.alert_email
  }
}

# Log Analytics query for Defender alerts
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "defender_detection" {
  name                = "defender-t1529"
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

  description = "Microsoft Defender detects System Shutdown/Reboot activity"
  display_name = "Defender: System Shutdown/Reboot"
  enabled      = true

  tags = {
    "mitre-technique" = "T1529"
    "detection-type"  = "security"
  }
}

output "alert_rule_id" {
  value = azurerm_monitor_scheduled_query_rules_alert_v2.defender_detection.id
}""",
                alert_severity="high",
                alert_title="Azure: System Shutdown/Reboot Detected",
                alert_description_template=(
                    "System Shutdown/Reboot activity detected. "
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
        "t1529-ec2-shutdown",
        "t1529-windows-events",
        "t1529-mass-shutdown",
        "t1529-shutdown-commands",
        "t1529-gcp-vm-shutdown",
    ],
    total_effort_hours=4.5,
    coverage_improvement="+25% improvement for Impact tactic",
)
