"""
T1219 - Remote Access Software

Adversaries employ legitimate remote access tools to establish interactive command and
control channels using graphical interfaces, command-line interactions, or protocol tunnels.
Used by Akira, BlackByte, Carbanak, Cobalt Group, FIN7, MuddyWater, OilRig, Sandworm Team.
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
    technique_id="T1219",
    technique_name="Remote Access Tools",
    tactic_ids=["TA0011"],
    mitre_url="https://attack.mitre.org/techniques/T1219/",
    threat_context=ThreatContext(
        description=(
            "Adversaries employ legitimate remote access tools to establish interactive command "
            "and control channels. These tools operate through graphical interfaces, command-line "
            "interactions, protocol tunnels, or hardware-level access like KVM solutions. In cloud "
            "environments, threat actors deploy tools like AnyDesk, TeamViewer, ScreenConnect, and "
            "ngrok on EC2 instances or GCP VMs for persistent access, redundant C2 channels, or as "
            "malware components for reverse connections."
        ),
        attacker_goal="Establish persistent interactive command and control access using legitimate remote administration tools",
        why_technique=[
            "Legitimate tools blend with normal IT operations",
            "Built-in persistence mechanisms",
            "Encrypted communication channels",
            "Provides redundant access if primary C2 fails",
            "Often whitelisted by security tools",
            "Enables interactive GUI access to compromised systems",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="common",
        trend="increasing",
        severity_score=8,
        severity_reasoning=(
            "High severity due to the legitimate nature of these tools making detection challenging. "
            "Provides persistent, encrypted, interactive access to compromised systems. In cloud "
            "environments, remote access tools can be used to maintain access to instances even after "
            "credentials are rotated, enabling long-term persistence and data exfiltration."
        ),
        business_impact=[
            "Persistent unauthorised access to cloud resources",
            "Data exfiltration via encrypted channels",
            "Lateral movement to other cloud services",
            "Credential harvesting and privilege escalation",
            "Compliance violations due to unauthorised software",
            "Difficulty in detection and remediation",
        ],
        typical_attack_phase="command_and_control",
        often_precedes=["T1078.004", "T1530", "T1552.001", "T1486", "T1567"],
        often_follows=["T1190", "T1078.004", "T1552.005", "T1105"],
    ),
    detection_strategies=[
        DetectionStrategy(
            strategy_id="t1219-aws-ec2-remote-tools",
            name="AWS EC2 Remote Access Tool Installation",
            description="Detect installation and execution of remote access tools on EC2 instances.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, @message, userIdentity.principalId, requestParameters.instanceId
| filter eventSource = "ssm.amazonaws.com" or eventSource = "ec2.amazonaws.com"
| filter @message like /anydesk|teamviewer|screenconnect|ammyy|vnc|ngrok|atera|simplehelp|connectwise|pdq|eHorus|tmate|dameware/i
| stats count(*) as tool_installations by userIdentity.principalId, requestParameters.instanceId, bin(1h)
| filter tool_installations > 0
| sort @timestamp desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect remote access tool installation on EC2 instances

Parameters:
  CloudTrailLogGroup:
    Type: String
    Description: CloudTrail log group name
  AlertEmail:
    Type: String
    Description: Email for security alerts

Resources:
  # Step 1: Create SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      TopicName: ec2-remote-tool-alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Create metric filter for remote access tools
  RemoteToolMetricFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ ($.eventSource = "ssm.amazonaws.com" || $.eventSource = "ec2.amazonaws.com") && ($.requestParameters.commands[0] = "*anydesk*" || $.requestParameters.commands[0] = "*teamviewer*" || $.requestParameters.commands[0] = "*screenconnect*" || $.requestParameters.commands[0] = "*ngrok*" || $.requestParameters.commands[0] = "*atera*") }'
      MetricTransformations:
        - MetricName: RemoteAccessToolInstallation
          MetricNamespace: Security/EC2
          MetricValue: "1"
          DefaultValue: 0

  # Step 3: Create alarm for remote tool installation
  RemoteToolAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: EC2-RemoteAccessToolDetected
      AlarmDescription: Detects installation of remote access tools on EC2
      MetricName: RemoteAccessToolInstallation
      Namespace: Security/EC2
      Statistic: Sum
      Period: 300
      EvaluationPeriods: 1
      Threshold: 1
      ComparisonOperator: GreaterThanOrEqualToThreshold
      TreatMissingData: notBreaching

      AlarmActions:
        - !Ref AlertTopic""",
                terraform_template="""# AWS: Detect remote access tool installation on EC2

variable "cloudtrail_log_group" {
  description = "CloudTrail log group name"
  type        = string
}

variable "alert_email" {
  description = "Email for security alerts"
  type        = string
}

# Step 1: Create SNS topic for alerts
resource "aws_sns_topic" "alerts" {
  name = "ec2-remote-tool-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Create metric filter for remote access tools
resource "aws_cloudwatch_log_metric_filter" "remote_tools" {
  name           = "remote-access-tool-installation"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ ($.eventSource = \"ssm.amazonaws.com\" || $.eventSource = \"ec2.amazonaws.com\") && ($.requestParameters.commands[0] = \"*anydesk*\" || $.requestParameters.commands[0] = \"*teamviewer*\" || $.requestParameters.commands[0] = \"*screenconnect*\" || $.requestParameters.commands[0] = \"*ngrok*\" || $.requestParameters.commands[0] = \"*atera*\") }"

  metric_transformation {
    name          = "RemoteAccessToolInstallation"
    namespace     = "Security/EC2"
    value         = "1"
    default_value = 0
  }
}

# Step 3: Create alarm for remote tool installation
resource "aws_cloudwatch_metric_alarm" "remote_tool_alert" {
  alarm_name          = "EC2-RemoteAccessToolDetected"
  alarm_description   = "Detects installation of remote access tools on EC2"
  metric_name         = "RemoteAccessToolInstallation"
  namespace           = "Security/EC2"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.alerts.arn]
}""",
                alert_severity="high",
                alert_title="Remote Access Tool Detected on EC2",
                alert_description_template="Instance {instanceId} has remote access software installed: {toolName}.",
                investigation_steps=[
                    "Identify the remote access tool installed",
                    "Review instance role and user permissions",
                    "Check if tool was installed via authorised change management",
                    "Analyse network connections from the instance",
                    "Review process execution history and timeline",
                    "Check for other indicators of compromise",
                ],
                containment_actions=[
                    "Isolate instance via security group modification",
                    "Create snapshot for forensic analysis",
                    "Terminate remote access tool processes",
                    "Block remote access tool domains at VPC level",
                    "Revoke instance profile credentials",
                    "Consider instance replacement if compromised",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Exclude authorised IT support tools and approved remote access solutions",
            detection_coverage="70% - catches common remote access tools",
            evasion_considerations="Custom or lesser-known tools, renamed binaries, or obfuscated installations may evade",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$5-15",
            prerequisites=[
                "CloudTrail enabled with SSM and EC2 logging",
                "CloudWatch Logs integration",
            ],
        ),
        DetectionStrategy(
            strategy_id="t1219-aws-vpc-remote-connections",
            name="AWS VPC Remote Access Tool Network Patterns",
            description="Detect network connections characteristic of remote access tools via VPC Flow Logs.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, srcAddr, dstAddr, dstPort, protocol, bytes
| filter action = "ACCEPT"
| filter dstPort in [5938, 5656, 7070, 8000, 4899, 5900, 3389]
| stats count(*) as connections, sum(bytes) as total_bytes by srcAddr, dstPort, bin(5m)
| filter connections > 5
| sort connections desc""",
                terraform_template="""# AWS: Detect remote access tool network patterns via VPC Flow Logs

variable "vpc_flow_log_group" {
  description = "VPC Flow Logs log group name"
  type        = string
}

variable "alert_email" {
  description = "Email for security alerts"
  type        = string
}

# Step 1: Create SNS topic for alerts
resource "aws_sns_topic" "alerts" {
  name = "vpc-remote-tool-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Create metric filter for remote access ports
resource "aws_cloudwatch_log_metric_filter" "remote_ports" {
  name           = "remote-access-tool-ports"
  log_group_name = var.vpc_flow_log_group
  pattern        = "[version, account_id, interface_id, srcaddr, dstaddr, srcport, dstport IN (5938,5656,7070,8000,4899,5900,3389), protocol, packets, bytes, ...]"

  metric_transformation {
    name          = "RemoteAccessConnections"
    namespace     = "Security/VPC"
    value         = "1"
    default_value = 0
  }
}

# Step 3: Create alarm for remote access connections
resource "aws_cloudwatch_metric_alarm" "remote_connection_alert" {
  alarm_name          = "VPC-RemoteAccessToolConnections"
  alarm_description   = "Detects network connections to remote access tool ports"
  metric_name         = "RemoteAccessConnections"
  namespace           = "Security/VPC"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 10
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.alerts.arn]
}""",
                alert_severity="high",
                alert_title="Remote Access Tool Network Activity Detected",
                alert_description_template="Instance {srcAddr} established connections to remote access ports: {dstPort}.",
                investigation_steps=[
                    "Identify source instance and its purpose",
                    "Verify destination IP legitimacy",
                    "Check if remote access is authorised for this instance",
                    "Review instance security group rules",
                    "Analyse connection patterns and duration",
                    "Check for other suspicious network activity",
                ],
                containment_actions=[
                    "Block destination IPs via security groups",
                    "Restrict outbound ports using NACLs",
                    "Isolate affected instance",
                    "Review and tighten security group rules",
                    "Implement VPC endpoint policies",
                    "Enable GuardDuty for enhanced monitoring",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist approved remote access solutions and IT support infrastructure",
            detection_coverage="65% - detects common remote tool ports",
            evasion_considerations="Tools using non-standard ports, port forwarding, or tunnelling may evade",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$10-20",
            prerequisites=["VPC Flow Logs enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1219-aws-guardduty-c2",
            name="AWS GuardDuty C2 Detection for Remote Tools",
            description="Leverage GuardDuty to detect instances communicating with known remote tool C2 infrastructure.",
            detection_type=DetectionType.GUARDDUTY,
            aws_service="guardduty",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                guardduty_finding_types=[
                    "Backdoor:EC2/C&CActivity.B!DNS",
                    "Behavior:EC2/NetworkPortUnusual",
                    "Behavior:EC2/TrafficVolumeUnusual",
                ],
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: GuardDuty detection for remote access tool C2 activity

Parameters:
  AlertEmail:
    Type: String
    Description: Email for security alerts

Resources:
  # Step 1: Create SNS topic for GuardDuty alerts
  GuardDutyAlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      TopicName: guardduty-remote-tool-alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Create EventBridge rule for GuardDuty findings
  GuardDutyEventRule:
    Type: AWS::Events::Rule
    Properties:
      Name: guardduty-remote-access-tools
      Description: Alert on GuardDuty remote access tool findings
      EventPattern:
        source:
          - aws.guardduty
        detail-type:
          - GuardDuty Finding
        detail:
          type:
            - Backdoor:EC2/C&CActivity.B!DNS
            - Behavior:EC2/NetworkPortUnusual
            - Behavior:EC2/TrafficVolumeUnusual
      State: ENABLED
      Targets:
        - Arn: !Ref GuardDutyAlertTopic
          Id: SNSTarget

  # Step 3: Grant EventBridge permission to publish to SNS
  SNSTopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics:
        - !Ref GuardDutyAlertTopic
      PolicyDocument:
        Statement:
          - Effect: Allow
            Principal:
              Service: events.amazonaws.com
            Action: sns:Publish
            Resource: !Ref GuardDutyAlertTopic
            Condition:
              StringEquals:
                AWS:SourceAccount: !Ref AWS::AccountId
              ArnEquals:
                aws:SourceArn: !GetAtt GuardDutyEventRule.Arn""",
                terraform_template="""# AWS: GuardDuty remote access tool C2 detection

variable "alert_email" {
  description = "Email for security alerts"
  type        = string
}

# Step 1: Create SNS topic for GuardDuty alerts
resource "aws_sns_topic" "guardduty_alerts" {
  name = "guardduty-remote-tool-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.guardduty_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Create EventBridge rule for GuardDuty findings
resource "aws_cloudwatch_event_rule" "guardduty_remote_tools" {
  name        = "guardduty-remote-access-tools"
  description = "Alert on GuardDuty remote access tool findings"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail = {
      type = [
        "Backdoor:EC2/C&CActivity.B!DNS",
        "Behavior:EC2/NetworkPortUnusual",
        "Behavior:EC2/TrafficVolumeUnusual"
      ]
    }
  })
}

# Step 3: Configure target to send alerts to SNS
resource "aws_sqs_queue" "dlq" {
  name                      = "guardduty-remote-tools-dlq"
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
      values   = [aws_cloudwatch_event_rule.guardduty_remote_tools.arn]
    }
  }
}

resource "aws_sqs_queue_policy" "event_dlq" {
  queue_url = aws_sqs_queue.dlq.url
  policy    = data.aws_iam_policy_document.eventbridge_dlq_policy.json
}

resource "aws_cloudwatch_event_target" "sns" {
  rule      = aws_cloudwatch_event_rule.guardduty_remote_tools.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.guardduty_alerts.arn

  retry_policy {
    maximum_event_age_in_seconds = 3600
    maximum_retry_attempts       = 8
  }

  dead_letter_config {
    arn = aws_sqs_queue.dlq.arn
  }
}

data "aws_caller_identity" "current" {}

resource "aws_sns_topic_policy" "guardduty_publish" {
  arn = aws_sns_topic.guardduty_alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "SNS:Publish"
      Resource  = aws_sns_topic.guardduty_alerts.arn
      Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
        ArnEquals = {
          "aws:SourceArn" = aws_cloudwatch_event_rule.guardduty_remote_tools.arn
        }
      }
    }]
  })
}""",
                alert_severity="high",
                alert_title="GuardDuty: Remote Access Tool C2 Activity",
                alert_description_template="Instance {instanceId} exhibiting remote access tool C2 behaviour.",
                investigation_steps=[
                    "Review GuardDuty finding details and severity",
                    "Identify remote tool infrastructure from finding",
                    "Check instance for installed remote access software",
                    "Review instance timeline and network connections",
                    "Correlate with CloudTrail for user activity",
                    "Check for persistence mechanisms",
                ],
                containment_actions=[
                    "Isolate affected instance immediately",
                    "Block remote tool C2 domains/IPs",
                    "Terminate remote access tool processes",
                    "Rotate instance credentials and keys",
                    "Scan for additional compromised instances",
                    "Consider full instance replacement",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="GuardDuty findings are pre-vetted; configure suppression rules for known legitimate remote tools",
            detection_coverage="75% - leverages threat intelligence for known remote tool infrastructure",
            evasion_considerations="New or private remote tool infrastructure may not be in threat intelligence feeds",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$1-5 (requires GuardDuty)",
            prerequisites=["AWS GuardDuty enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1219-gcp-vm-remote-tools",
            name="GCP VM Remote Access Tool Detection",
            description="Detect installation and execution of remote access tools on GCP VMs.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""resource.type="gce_instance"
(jsonPayload.message=~"anydesk|teamviewer|screenconnect|ammyy|vnc|ngrok|atera|simplehelp|connectwise|tmate" OR
 protoPayload.request.commands=~"anydesk|teamviewer|screenconnect|ammyy|vnc|ngrok|atera|simplehelp|connectwise|tmate")""",
                gcp_terraform_template="""# GCP: Detect remote access tools on VM instances

variable "project_id" {
  description = "GCP project ID"
  type        = string
}

variable "alert_email" {
  description = "Email for security alerts"
  type        = string
}

# Step 1: Create notification channel for alerts
resource "google_monitoring_notification_channel" "email" {
  display_name = "Security Alerts - Remote Access Tools"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Create log metric for remote access tools
resource "google_logging_metric" "remote_tools" {
  name   = "vm-remote-access-tools"
  filter = <<-EOT
    resource.type="gce_instance"
    (jsonPayload.message=~"anydesk|teamviewer|screenconnect|ammyy|vnc|ngrok|atera|simplehelp|connectwise|tmate" OR
     protoPayload.request.commands=~"anydesk|teamviewer|screenconnect|ammyy|vnc|ngrok|atera|simplehelp|connectwise|tmate")
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "instance_id"
      value_type  = "STRING"
      description = "VM instance ID"
    }
  }

  label_extractors = {
    "instance_id" = "EXTRACT(resource.labels.instance_id)"
  }
}

# Step 3: Create alert policy for remote tool detection
resource "google_monitoring_alert_policy" "remote_tool_alert" {
  display_name = "GCE Remote Access Tool Detected"
  combiner     = "OR"

  conditions {
    display_name = "Remote access tool detected on VM"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.remote_tools.name}\" AND resource.type=\"gce_instance\""
      duration        = "60s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0
      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_RATE"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]

  alert_strategy {
    auto_close = "1800s"
  }
}""",
                alert_severity="high",
                alert_title="GCP: Remote Access Tool Detected on VM",
                alert_description_template="VM instance {instance_id} has remote access software installed.",
                investigation_steps=[
                    "Review VM instance logs and metadata",
                    "Identify the specific remote access tool",
                    "Check if installation was authorised",
                    "Verify service account permissions",
                    "Analyse network connections from the VM",
                    "Review recent API activity for the project",
                ],
                containment_actions=[
                    "Isolate VM using firewall rules",
                    "Create disk snapshot for forensic analysis",
                    "Stop remote access tool services",
                    "Revoke service account access",
                    "Block remote tool domains via Cloud DNS",
                    "Consider VM replacement if compromised",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Exclude authorised IT support infrastructure and approved remote access solutions",
            detection_coverage="70% - catches common remote access tools",
            evasion_considerations="Custom tools, renamed binaries, or containerised deployments may evade",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$10-20",
            prerequisites=[
                "Cloud Logging enabled for GCE",
                "OS Login or SSH logging configured",
            ],
        ),
        DetectionStrategy(
            strategy_id="t1219-gcp-firewall-remote-ports",
            name="GCP Firewall Remote Access Port Monitoring",
            description="Monitor VPC firewall logs for connections to remote access tool ports.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="gce_subnetwork"
logName="projects/PROJECT_ID/logs/compute.googleapis.com%2Ffirewall"
jsonPayload.connection.dest_port:(5938 OR 5656 OR 7070 OR 8000 OR 4899 OR 5900 OR 3389)
jsonPayload.disposition="ALLOWED"''',
                gcp_terraform_template="""# GCP: Monitor remote access tool network connections

variable "project_id" {
  description = "GCP project ID"
  type        = string
}

variable "alert_email" {
  description = "Email for security alerts"
  type        = string
}

# Step 1: Create notification channel
resource "google_monitoring_notification_channel" "email" {
  display_name = "Security Alerts - Remote Ports"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Create log metric for remote access ports
resource "google_logging_metric" "remote_ports" {
  name   = "firewall-remote-access-ports"
  filter = <<-EOT
    resource.type="gce_subnetwork"
    logName="projects/${var.project_id}/logs/compute.googleapis.com%2Ffirewall"
    jsonPayload.connection.dest_port:(5938 OR 5656 OR 7070 OR 8000 OR 4899 OR 5900 OR 3389)
    jsonPayload.disposition="ALLOWED"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "dest_ip"
      value_type  = "STRING"
      description = "Destination IP address"
    }
  }

  label_extractors = {
    "dest_ip" = "EXTRACT(jsonPayload.connection.dest_ip)"
  }
}

# Step 3: Create alert for remote port connections
resource "google_monitoring_alert_policy" "remote_port_alert" {
  display_name = "Remote Access Port Connections"
  combiner     = "OR"

  conditions {
    display_name = "Remote access ports detected"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.remote_ports.name}\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 10
      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_RATE"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]

  alert_strategy {
    auto_close = "1800s"
  }
}""",
                alert_severity="high",
                alert_title="GCP: Remote Access Tool Port Activity",
                alert_description_template="Network connections detected to remote access tool ports: {dest_port}.",
                investigation_steps=[
                    "Identify source VM and its purpose",
                    "Verify destination IP legitimacy",
                    "Check VPC firewall rules for misconfigurations",
                    "Review if remote access is authorised",
                    "Analyse connection patterns and frequency",
                    "Check for other suspicious network activity",
                ],
                containment_actions=[
                    "Block destination IPs via firewall rules",
                    "Restrict outbound connections using egress rules",
                    "Isolate affected VMs",
                    "Review and tighten firewall policies",
                    "Implement VPC Service Controls",
                    "Enable Cloud IDS for enhanced detection",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist approved remote access infrastructure and IT support systems",
            detection_coverage="65% - detects common remote tool ports",
            evasion_considerations="Non-standard ports, protocol tunnelling, or VPN usage may evade detection",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$10-20",
            prerequisites=["VPC firewall logging enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1219-gcp-scc-remote-tools",
            name="GCP Security Command Centre Remote Tool Detection",
            description="Leverage Security Command Centre to detect remote access tool anomalies.",
            detection_type=DetectionType.SECURITY_COMMAND_CENTER,
            aws_service="n/a",
            gcp_service="security_command_center",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                scc_finding_categories=[
                    "Persistence: Remote Access Tool",
                    "Execution: Suspicious Binary",
                    "Command and Control: Suspicious Network",
                ],
                gcp_terraform_template="""# GCP: Security Command Centre remote tool detection

variable "organization_id" {
  description = "GCP organisation ID"
  type        = string
}

variable "alert_email" {
  description = "Email for security alerts"
  type        = string
}

# Step 1: Create notification channel
resource "google_monitoring_notification_channel" "email" {
  display_name = "SCC Alerts - Remote Tools"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Create notification config for SCC findings
resource "google_scc_notification_config" "remote_tools" {
  config_id    = "remote-access-tools"
  organization = var.organization_id
  description  = "Alerts for remote access tool detections"

  pubsub_topic = google_pubsub_topic.scc_alerts.id

  streaming_config {
    filter = "category=\"Persistence: Remote Access Tool\" OR category=\"Execution: Suspicious Binary\" OR category=\"Command and Control: Suspicious Network\""
  }
}

# Step 3: Create Pub/Sub topic and subscription for alerts
resource "google_pubsub_topic" "scc_alerts" {
  name = "scc-remote-tool-alerts"
}

resource "google_pubsub_subscription" "scc_email" {
  name  = "scc-remote-tool-email"
  topic = google_pubsub_topic.scc_alerts.name

  push_config {
    push_endpoint = "https://pubsub.googleapis.com/v1/projects/${var.organization_id}/topics/scc-remote-tool-alerts"
  }

  ack_deadline_seconds = 20
}""",
                alert_severity="high",
                alert_title="GCP SCC: Remote Access Tool Detected",
                alert_description_template="Security Command Centre detected remote access tool activity.",
                investigation_steps=[
                    "Review Security Command Centre finding details",
                    "Identify affected GCP resources",
                    "Check for authorised remote access deployments",
                    "Analyse finding severity and confidence",
                    "Correlate with other security events",
                    "Review resource access logs",
                ],
                containment_actions=[
                    "Isolate affected resources using firewall rules",
                    "Disable compromised service accounts",
                    "Remove remote access tool installations",
                    "Block C2 infrastructure at network level",
                    "Enable additional SCC detections",
                    "Consider resource replacement if compromised",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Configure SCC exceptions for authorised remote access infrastructure",
            detection_coverage="80% - comprehensive threat detection capabilities",
            evasion_considerations="Sophisticated custom tools or obfuscation techniques may evade SCC detections",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2-3 hours",
            estimated_monthly_cost="$15-30 (requires SCC Standard or Premium)",
            prerequisites=[
                "Security Command Centre Standard/Premium enabled",
                "Asset Discovery enabled",
            ],
        ),
    ],
    recommended_order=[
        "t1219-aws-guardduty-c2",
        "t1219-gcp-scc-remote-tools",
        "t1219-aws-ec2-remote-tools",
        "t1219-gcp-vm-remote-tools",
        "t1219-aws-vpc-remote-connections",
        "t1219-gcp-firewall-remote-ports",
    ],
    total_effort_hours=9.5,
    coverage_improvement="+18% improvement for Command and Control tactic",
)
