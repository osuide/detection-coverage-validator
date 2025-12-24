"""
T1104 - Multi-Stage Channels

Adversaries establish multiple command and control stages deployed under different conditions
to obfuscate C2 channels and make detection more difficult.
Used by APT3, APT41, Lazarus Group, MuddyWater, UNC3886.
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
    technique_id="T1104",
    technique_name="Multi-Stage Channels",
    tactic_ids=["TA0011"],
    mitre_url="https://attack.mitre.org/techniques/T1104/",
    threat_context=ThreatContext(
        description=(
            "Adversaries establish multiple command and control stages deployed under different "
            "conditions to obfuscate their C2 infrastructure. The initial remote access tool "
            "contacts a first-stage C2 server for basic functions like host information collection "
            "and tool updates. A secondary RAT then redirects to a second-stage C2 server for "
            "advanced capabilities. Infrastructure remains separate with no overlapping resources "
            "to avoid detection, often with backup first-stage callbacks or fallback channels."
        ),
        attacker_goal="Obfuscate command and control infrastructure through multi-tiered C2 architecture",
        why_technique=[
            "Makes attribution and infrastructure tracking difficult",
            "Protects advanced C2 infrastructure from discovery",
            "Allows infrastructure segmentation and redundancy",
            "Enables staged capability deployment",
            "Provides fallback channels if primary C2 detected",
        ],
        known_threat_actors=[],
        recent_campaigns=[
            Campaign(
                name="APT41 BEACON Multi-Stage Deployment",
                year=2024,
                description="Deployed storescyncsvc.dll BEACON to download secondary backdoors from separate C2 infrastructure",
                reference_url="https://attack.mitre.org/groups/G0096/",
            ),
            Campaign(
                name="Latrodectus Two-Tier C2",
                year=2024,
                description="Operated a two-tiered C2 configuration with tier one nodes connecting to victims and tier two nodes to backend infrastructure",
                reference_url="https://attack.mitre.org/software/S1160/",
            ),
            Campaign(
                name="RedPenguin Separate Channels",
                year=2023,
                description="Used malware with separate channels for task requests and execution, obfuscating C2 relationships",
                reference_url="https://attack.mitre.org/campaigns/C0056/",
            ),
            Campaign(
                name="APT3 SOCKS5 Intermediaries",
                year=2023,
                description="Established SOCKS5 connections through intermediate servers before final C2 contact",
                reference_url="https://attack.mitre.org/groups/G0022/",
            ),
        ],
        prevalence="common",
        trend="increasing",
        severity_score=8,
        severity_reasoning=(
            "Multi-stage C2 channels significantly increase detection difficulty and enable "
            "sophisticated attack operations. By separating infrastructure tiers, attackers protect "
            "their most valuable C2 assets from discovery. In cloud environments, compromised instances "
            "may beacon to staging servers before connecting to final C2, blending with legitimate "
            "outbound traffic patterns."
        ),
        business_impact=[
            "Difficult to completely remediate without full infrastructure discovery",
            "Extended dwell time as detection is delayed",
            "Increased incident response complexity and cost",
            "Secondary payloads may remain undetected",
            "Potential for persistent re-compromise via backup channels",
        ],
        typical_attack_phase="command_and_control",
        often_precedes=["T1041", "T1485", "T1530", "T1078.004"],
        often_follows=["T1190", "T1078.004", "T1105"],
    ),
    detection_strategies=[
        DetectionStrategy(
            strategy_id="t1104-aws-multi-stage-network",
            name="AWS Multi-Stage Network Connection Detection",
            description="Detect instances establishing sequential connections to different external hosts.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, srcAddr, dstAddr, srcPort, dstPort, bytes
| filter action = "ACCEPT" and dstPort in [80, 443, 8080, 8443]
| sort @timestamp asc
| stats count(*) as connections, count_distinct(dstAddr) as unique_destinations,
        earliest(@timestamp) as first_connection, latest(@timestamp) as last_connection
        by srcAddr, bin(10m)
| filter unique_destinations > 3 and connections > 5
| filter (last_connection - first_connection) < 600000
| sort unique_destinations desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect multi-stage C2 connections via VPC Flow Logs

Parameters:
  VPCFlowLogGroup:
    Type: String
    Description: VPC Flow Logs log group name
  AlertEmail:
    Type: String
    Description: Email for security alerts

Resources:
  # Step 1: Create SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      TopicName: multi-stage-c2-alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Create metric filter for multi-stage connections
  MultiStageFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref VPCFlowLogGroup
      FilterPattern: '[version, account, eni, srcaddr, dstaddr, srcport, dstport IN (80,443,8080,8443), protocol, packets, bytes, ...]'
      MetricTransformations:
        - MetricName: MultiStageConnections
          MetricNamespace: Security/C2
          MetricValue: "1"
          DefaultValue: 0

  # Step 3: Create alarm for multi-stage C2 patterns
  MultiStageAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: Multi-Stage-C2-Detected
      AlarmDescription: Detects instances connecting to multiple sequential external hosts
      MetricName: MultiStageConnections
      Namespace: Security/C2
      Statistic: Sum
      Period: 600
      EvaluationPeriods: 1
      Threshold: 10
      ComparisonOperator: GreaterThanThreshold
      AlarmActions:
        - !Ref AlertTopic
      TreatMissingData: notBreaching""",
                terraform_template="""# AWS: Detect multi-stage C2 connections

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
  name = "multi-stage-c2-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Create metric filter for multi-stage connections
resource "aws_cloudwatch_log_metric_filter" "multi_stage" {
  name           = "multi-stage-connections"
  log_group_name = var.vpc_flow_log_group
  pattern        = "[version, account, eni, srcaddr, dstaddr, srcport, dstport IN (80,443,8080,8443), protocol, packets, bytes, ...]"

  metric_transformation {
    name          = "MultiStageConnections"
    namespace     = "Security/C2"
    value         = "1"
    default_value = 0
  }
}

# Step 3: Create alarm for multi-stage C2 patterns
resource "aws_cloudwatch_metric_alarm" "multi_stage_alert" {
  alarm_name          = "Multi-Stage-C2-Detected"
  alarm_description   = "Detects instances connecting to multiple sequential external hosts"
  metric_name         = "MultiStageConnections"
  namespace           = "Security/C2"
  statistic           = "Sum"
  period              = 600
  evaluation_periods  = 1
  threshold           = 10
  comparison_operator = "GreaterThanThreshold"
  alarm_actions       = [aws_sns_topic.alerts.arn]
  treat_missing_data  = "notBreaching"
}""",
                alert_severity="high",
                alert_title="Multi-Stage C2 Connection Pattern Detected",
                alert_description_template="Instance {srcAddr} connected to {unique_destinations} different external hosts in rapid succession.",
                investigation_steps=[
                    "Identify the source instance and its purpose",
                    "Review all destination IPs and their reputation",
                    "Analyse connection timing and data transfer patterns",
                    "Check for downloaded files between connections",
                    "Correlate with process execution and API activity",
                    "Review instance user activity and authentication logs",
                ],
                containment_actions=[
                    "Isolate instance via security group modification",
                    "Create snapshot for forensic analysis",
                    "Block identified C2 infrastructure at network level",
                    "Revoke instance profile credentials",
                    "Terminate instance if confirmed malicious",
                    "Search for similar patterns across other instances",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Exclude known CDN endpoints and legitimate multi-service applications; adjust destination count threshold",
            detection_coverage="60% - catches multi-stage connection patterns",
            evasion_considerations="Slow and deliberate staging with delays, using internal proxies, single destination with port changes",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2-3 hours",
            estimated_monthly_cost="$15-30",
            prerequisites=["VPC Flow Logs enabled", "CloudWatch Logs integration"],
        ),
        DetectionStrategy(
            strategy_id="t1104-aws-process-network",
            name="AWS Process Network Sequence Detection",
            description="Detect processes spawning child processes with different network destinations.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, requestParameters.commands, userIdentity.principalId, sourceIPAddress
| filter eventSource = "ssm.amazonaws.com" and eventName = "SendCommand"
| filter @message like /curl|wget|python|powershell.*downloadstring/i
| stats count(*) as command_count, count_distinct(sourceIPAddress) as unique_sources
        by userIdentity.principalId, bin(15m)
| filter command_count > 2 and unique_sources > 1
| sort command_count desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect process spawning with multi-stage network activity

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
      TopicName: process-network-sequence-alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Create metric filter for process sequences
  ProcessSequenceFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ ($.eventSource = "ssm.amazonaws.com" && $.eventName = "SendCommand") && ($.requestParameters.commands[0] = "*curl*" || $.requestParameters.commands[0] = "*wget*" || $.requestParameters.commands[0] = "*python*") }'
      MetricTransformations:
        - MetricName: ProcessNetworkSequence
          MetricNamespace: Security/Process
          MetricValue: "1"
          DefaultValue: 0

  # Step 3: Create alarm for suspicious sequences
  ProcessSequenceAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: Process-Network-Sequence-Detected
      AlarmDescription: Detects processes spawning with sequential network connections
      MetricName: ProcessNetworkSequence
      Namespace: Security/Process
      Statistic: Sum
      Period: 900
      EvaluationPeriods: 1
      Threshold: 3
      ComparisonOperator: GreaterThanThreshold
      AlarmActions:
        - !Ref AlertTopic
      TreatMissingData: notBreaching""",
                terraform_template="""# AWS: Detect process network sequences

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
  name = "process-network-sequence-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Create metric filter for process sequences
resource "aws_cloudwatch_log_metric_filter" "process_sequence" {
  name           = "process-network-sequence"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ ($.eventSource = \"ssm.amazonaws.com\" && $.eventName = \"SendCommand\") && ($.requestParameters.commands[0] = \"*curl*\" || $.requestParameters.commands[0] = \"*wget*\" || $.requestParameters.commands[0] = \"*python*\") }"

  metric_transformation {
    name          = "ProcessNetworkSequence"
    namespace     = "Security/Process"
    value         = "1"
    default_value = 0
  }
}

# Step 3: Create alarm for suspicious sequences
resource "aws_cloudwatch_metric_alarm" "process_sequence_alert" {
  alarm_name          = "Process-Network-Sequence-Detected"
  alarm_description   = "Detects processes spawning with sequential network connections"
  metric_name         = "ProcessNetworkSequence"
  namespace           = "Security/Process"
  statistic           = "Sum"
  period              = 900
  evaluation_periods  = 1
  threshold           = 3
  comparison_operator = "GreaterThanThreshold"
  alarm_actions       = [aws_sns_topic.alerts.arn]
  treat_missing_data  = "notBreaching"
}""",
                alert_severity="high",
                alert_title="Process Network Sequence Detected",
                alert_description_template="Instance {principalId} executed {command_count} network commands with {unique_sources} different sources.",
                investigation_steps=[
                    "Review command execution timeline",
                    "Identify parent and child process relationships",
                    "Analyse downloaded payloads between stages",
                    "Check network destinations for each stage",
                    "Review process memory for injected code",
                    "Examine file system for dropped files",
                ],
                containment_actions=[
                    "Terminate suspicious processes",
                    "Isolate affected instance",
                    "Block C2 infrastructure at network level",
                    "Collect memory dumps for analysis",
                    "Revoke credentials and rotate keys",
                    "Scan for persistence mechanisms",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Exclude authorised automation tools and deployment scripts; whitelist known orchestration systems",
            detection_coverage="55% - catches process-based multi-stage patterns",
            evasion_considerations="Using single-process downloaders, avoiding SSM, employing built-in utilities without spawning",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2 hours",
            estimated_monthly_cost="$10-20",
            prerequisites=[
                "CloudTrail enabled with SSM logging",
                "SSM Session Manager logging configured",
            ],
        ),
        DetectionStrategy(
            strategy_id="t1104-aws-guardduty-staging",
            name="AWS GuardDuty C2 Staging Detection",
            description="Leverage GuardDuty to detect instances communicating with multiple C2 stages.",
            detection_type=DetectionType.GUARDDUTY,
            aws_service="guardduty",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                guardduty_finding_types=[
                    "Backdoor:EC2/C&CActivity.B",
                    "Backdoor:EC2/C&CActivity.B!DNS",
                    "Trojan:EC2/DropPoint",
                    "UnauthorizedAccess:EC2/MaliciousIPCaller.Custom",
                ],
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: GuardDuty detection for multi-stage C2 activity

Parameters:
  AlertEmail:
    Type: String
    Description: Email for security alerts

Resources:
  # Step 1: Create SNS topic for GuardDuty alerts
  GuardDutyAlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      TopicName: guardduty-multi-stage-alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Create EventBridge rule for GuardDuty C2 findings
  GuardDutyEventRule:
    Type: AWS::Events::Rule
    Properties:
      Name: guardduty-multi-stage-c2
      Description: Alert on GuardDuty multi-stage C2 findings
      EventPattern:
        source:
          - aws.guardduty
        detail-type:
          - GuardDuty Finding
        detail:
          type:
            - Backdoor:EC2/C&CActivity.B
            - Backdoor:EC2/C&CActivity.B!DNS
            - Trojan:EC2/DropPoint
            - UnauthorizedAccess:EC2/MaliciousIPCaller.Custom
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
            Resource: !Ref GuardDutyAlertTopic""",
                terraform_template="""# AWS: GuardDuty multi-stage C2 detection

variable "alert_email" {
  description = "Email for security alerts"
  type        = string
}

# Step 1: Create SNS topic for GuardDuty alerts
resource "aws_sns_topic" "guardduty_alerts" {
  name = "guardduty-multi-stage-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.guardduty_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Create EventBridge rule for GuardDuty C2 findings
resource "aws_cloudwatch_event_rule" "guardduty_c2" {
  name        = "guardduty-multi-stage-c2"
  description = "Alert on GuardDuty multi-stage C2 findings"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail = {
      type = [
        "Backdoor:EC2/C&CActivity.B",
        "Backdoor:EC2/C&CActivity.B!DNS",
        "Trojan:EC2/DropPoint",
        "UnauthorizedAccess:EC2/MaliciousIPCaller.Custom"
      ]
    }
  })
}

# Step 3: Configure target to send alerts to SNS
resource "aws_cloudwatch_event_target" "sns" {
  rule      = aws_cloudwatch_event_rule.guardduty_c2.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.guardduty_alerts.arn
}

resource "aws_sns_topic_policy" "guardduty_publish" {
  arn = aws_sns_topic.guardduty_alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "SNS:Publish"
      Resource  = aws_sns_topic.guardduty_alerts.arn
    }]
  })
}""",
                alert_severity="critical",
                alert_title="GuardDuty: Multi-Stage C2 Activity Detected",
                alert_description_template="Instance {instanceId} communicating with known C2 infrastructure across multiple stages.",
                investigation_steps=[
                    "Review all GuardDuty finding details and severity",
                    "Identify all C2 infrastructure IPs/domains",
                    "Map communication timeline across stages",
                    "Review instance network activity comprehensively",
                    "Check for downloaded payloads and persistence",
                    "Correlate with CloudTrail and VPC Flow Logs",
                ],
                containment_actions=[
                    "Immediately isolate affected instance",
                    "Block all identified C2 IPs/domains network-wide",
                    "Revoke instance credentials and rotate keys",
                    "Create forensic snapshot before termination",
                    "Search for indicators across all instances",
                    "Consider complete instance replacement",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="GuardDuty findings are pre-vetted; review threat intelligence sources and suppression rules",
            detection_coverage="75% - leverages threat intelligence and behavioural analysis",
            evasion_considerations="Previously unknown C2 infrastructure, domain generation algorithms, legitimate services as proxies",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$1-5 (requires GuardDuty)",
            prerequisites=["AWS GuardDuty enabled", "VPC DNS query logging enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1104-gcp-multi-stage-network",
            name="GCP Multi-Stage Connection Detection",
            description="Detect GCP instances establishing sequential connections to different external hosts.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""resource.type="gce_subnetwork"
jsonPayload.connection.dest_port:(80 OR 443 OR 8080 OR 8443)
| stats count() as connections, count_distinct(jsonPayload.connection.dest_ip) as unique_destinations
  by jsonPayload.connection.src_ip
| connections > 5 AND unique_destinations > 3""",
                gcp_terraform_template="""# GCP: Detect multi-stage C2 connections

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
  display_name = "Security Alerts - Multi-Stage C2"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Create log metric for multi-stage connections
resource "google_logging_metric" "multi_stage_c2" {
  name   = "multi-stage-c2-connections"
  filter = <<-EOT
    resource.type="gce_subnetwork"
    (jsonPayload.connection.dest_port=80 OR
     jsonPayload.connection.dest_port=443 OR
     jsonPayload.connection.dest_port=8080 OR
     jsonPayload.connection.dest_port=8443)
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "src_ip"
      value_type  = "STRING"
      description = "Source IP address"
    }
  }

  label_extractors = {
    "src_ip" = "EXTRACT(jsonPayload.connection.src_ip)"
  }
}

# Step 3: Create alert policy for multi-stage patterns
resource "google_monitoring_alert_policy" "multi_stage_alert" {
  display_name = "GCE Multi-Stage C2 Detected"
  combiner     = "OR"

  conditions {
    display_name = "Multiple sequential connections detected"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.multi_stage_c2.name}\" AND resource.type=\"gce_subnetwork\""
      duration        = "600s"
      comparison      = "COMPARISON_GT"
      threshold_value = 10
      aggregations {
        alignment_period   = "600s"
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
                alert_title="GCP: Multi-Stage C2 Pattern Detected",
                alert_description_template="VM instance connected to {unique_destinations} different external hosts in rapid succession.",
                investigation_steps=[
                    "Identify the source VM instance and its purpose",
                    "Review all destination IPs via VPC Flow Logs",
                    "Analyse connection timing and data volume patterns",
                    "Check for file downloads between connections",
                    "Review Cloud Logging for API and process activity",
                    "Examine service account permissions",
                ],
                containment_actions=[
                    "Isolate VM using VPC firewall rules",
                    "Create persistent disk snapshot for forensics",
                    "Block identified C2 infrastructure via Cloud Armor",
                    "Revoke service account access",
                    "Stop VM if confirmed compromise",
                    "Search for similar patterns across project",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Exclude known CDN endpoints, API gateways, and legitimate distributed applications",
            detection_coverage="60% - catches multi-stage connection patterns",
            evasion_considerations="Using Cloud NAT, internal proxies, slow staging with delays",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2-3 hours",
            estimated_monthly_cost="$15-25",
            prerequisites=["VPC Flow Logs enabled on subnets", "Cloud Logging enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1104-gcp-process-network",
            name="GCP Process Network Sequence Detection",
            description="Detect processes spawning with sequential network destinations on GCP VMs.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""resource.type="gce_instance"
(jsonPayload.message=~"curl|wget|python.*requests|gcloud.*download" OR
 protoPayload.request.commands=~"curl|wget|python.*requests")
| stats count() as command_count by resource.labels.instance_id
| command_count > 2""",
                gcp_terraform_template="""# GCP: Detect process network sequences on VMs

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
  display_name = "Security Alerts - Process Sequences"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Create log metric for process network sequences
resource "google_logging_metric" "process_sequence" {
  name   = "process-network-sequence"
  filter = <<-EOT
    resource.type="gce_instance"
    (jsonPayload.message=~"curl|wget|python.*requests|gcloud.*download" OR
     protoPayload.request.commands=~"curl|wget|python.*requests")
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

# Step 3: Create alert policy for suspicious sequences
resource "google_monitoring_alert_policy" "process_sequence_alert" {
  display_name = "GCE Process Network Sequence"
  combiner     = "OR"

  conditions {
    display_name = "Multiple network commands detected"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.process_sequence.name}\" AND resource.type=\"gce_instance\""
      duration        = "900s"
      comparison      = "COMPARISON_GT"
      threshold_value = 3
      aggregations {
        alignment_period   = "900s"
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
                alert_title="GCP: Process Network Sequence Detected",
                alert_description_template="VM instance {instance_id} executed multiple network download commands in sequence.",
                investigation_steps=[
                    "Review command execution timeline via Cloud Logging",
                    "Identify process hierarchy and parent processes",
                    "Analyse downloaded content between stages",
                    "Check network flow logs for destination patterns",
                    "Review OS Login and SSH session logs",
                    "Examine file system for persistence mechanisms",
                ],
                containment_actions=[
                    "Stop suspicious processes via SSH or OS Login",
                    "Isolate VM using firewall rules",
                    "Block C2 domains via Cloud DNS policies",
                    "Create snapshot for forensic investigation",
                    "Revoke service account and SSH keys",
                    "Consider VM replacement if heavily compromised",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist authorised deployment tools, CI/CD pipelines, and configuration management systems",
            detection_coverage="55% - catches process-based multi-stage activity",
            evasion_considerations="Using compiled binaries, avoiding common utilities, leveraging GCP SDKs directly",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2 hours",
            estimated_monthly_cost="$10-20",
            prerequisites=[
                "Cloud Logging enabled for GCE",
                "OS Login or SSH logging configured",
            ],
        ),
    ],
    recommended_order=[
        "t1104-aws-guardduty-staging",
        "t1104-aws-multi-stage-network",
        "t1104-gcp-multi-stage-network",
        "t1104-aws-process-network",
        "t1104-gcp-process-network",
    ],
    total_effort_hours=9.0,
    coverage_improvement="+18% improvement for Command and Control tactic",
)
