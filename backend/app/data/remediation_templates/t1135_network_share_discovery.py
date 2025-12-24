"""
T1135 - Network Share Discovery

Adversaries identify shared folders and drives on remote systems to locate
information sources and potential lateral movement targets.
Used by APT1, APT32, APT41, Chimera, FIN8, and ransomware groups.
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
    technique_id="T1135",
    technique_name="Network Share Discovery",
    tactic_ids=["TA0007"],
    mitre_url="https://attack.mitre.org/techniques/T1135/",
    threat_context=ThreatContext(
        description=(
            "Adversaries leverage shared network drives and folders—commonly accessible "
            "via the SMB protocol—to identify valuable targets. This technique involves "
            "querying systems for available shared resources, enabling attackers to "
            "understand the network structure and locate data of interest for exfiltration "
            "or lateral movement."
        ),
        attacker_goal="Discover network shares to identify data sources and lateral movement opportunities",
        why_technique=[
            "Locate sensitive data on shared drives",
            "Identify lateral movement targets",
            "Map network structure and resources",
            "Find backup locations and archives",
            "Establish persistence via shared folders",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="common",
        trend="stable",
        severity_score=6,
        severity_reasoning=(
            "Network share discovery is a common reconnaissance technique that enables "
            "adversaries to locate sensitive data and lateral movement opportunities. "
            "While not directly damaging, it precedes data exfiltration and ransomware deployment."
        ),
        business_impact=[
            "Precursor to data theft",
            "Enables lateral movement",
            "Identifies backup targets for ransomware",
            "Maps sensitive data locations",
        ],
        typical_attack_phase="discovery",
        often_precedes=["T1021.002", "T1039", "T1570", "T1486"],
        often_follows=["T1087", "T1069", "T1018"],
    ),
    detection_strategies=[
        DetectionStrategy(
            strategy_id="t1135-aws-net-share",
            name="Windows Share Enumeration Detection",
            description="Detect net view/net share commands and SMB enumeration activity in CloudWatch.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, eventName, sourceIPAddress, userIdentity.principalId, requestParameters
| filter eventName like /net view|net share|Get-SmbShare|NetShareEnum/
OR (eventName = "RunInstances" AND requestParameters.instanceType like /Windows/)
| stats count(*) as shareEnumEvents by userIdentity.principalId, bin(1h)
| filter shareEnumEvents > 5
| sort shareEnumEvents desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect network share enumeration via process and network monitoring

Parameters:
  LogGroupName:
    Type: String
    Description: CloudWatch Log Group for Windows EC2 instances
  AlertEmail:
    Type: String
    Description: Email for security alerts

Resources:
  # SNS Topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      TopicName: share-discovery-alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Metric filter for net view/net share commands
  ShareEnumFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref LogGroupName
      FilterPattern: '[time, request_id, event_type, process_name="net.exe" || process_name="powershell.exe", command_line="*net view*" || command_line="*net share*" || command_line="*Get-SmbShare*"]'
      MetricTransformations:
        - MetricName: ShareEnumerationCommands
          MetricNamespace: Security/NetworkDiscovery
          MetricValue: "1"

  # Alarm for excessive share enumeration
  ShareEnumAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: HighShareEnumeration
      MetricName: ShareEnumerationCommands
      Namespace: Security/NetworkDiscovery
      Statistic: Sum
      Period: 300
      Threshold: 10
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      AlarmDescription: Detects excessive network share enumeration attempts
      AlarmActions: [!Ref AlertTopic]""",
                terraform_template="""# Detect network share enumeration via process monitoring

variable "log_group_name" {
  description = "CloudWatch Log Group for Windows instances"
  type        = string
}

variable "alert_email" {
  description = "Email for security alerts"
  type        = string
}

# SNS topic for alerts
resource "aws_sns_topic" "share_enum_alerts" {
  name = "share-discovery-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.share_enum_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Metric filter for share enumeration commands
resource "aws_cloudwatch_log_metric_filter" "share_enum" {
  name           = "share-enumeration-commands"
  log_group_name = var.log_group_name
  pattern        = "[time, request_id, event_type, process_name=\"net.exe\" || process_name=\"powershell.exe\", command_line=\"*net view*\" || command_line=\"*net share*\" || command_line=\"*Get-SmbShare*\"]"

  metric_transformation {
    name      = "ShareEnumerationCommands"
    namespace = "Security/NetworkDiscovery"
    value     = "1"
  }
}

# Alarm for excessive share enumeration
resource "aws_cloudwatch_metric_alarm" "share_enum_alarm" {
  alarm_name          = "HighShareEnumeration"
  metric_name         = "ShareEnumerationCommands"
  namespace           = "Security/NetworkDiscovery"
  statistic           = "Sum"
  period              = 300
  threshold           = 10
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  alarm_description   = "Detects excessive network share enumeration attempts"
  alarm_actions       = [aws_sns_topic.share_enum_alerts.arn]
}""",
                alert_severity="medium",
                alert_title="Network Share Enumeration Detected",
                alert_description_template="Multiple share enumeration commands detected from {principalId}.",
                investigation_steps=[
                    "Review CloudWatch Logs for net view/net share command execution",
                    "Check VPC Flow Logs for SMB traffic (ports 445, 139)",
                    "Identify source instance and associated IAM principal",
                    "Review command-line arguments and target systems",
                    "Check for subsequent lateral movement or data access",
                    "Correlate with other discovery techniques (T1087, T1018)",
                ],
                containment_actions=[
                    "Isolate affected instances via security group modifications",
                    "Review and restrict SMB access via NACLs",
                    "Revoke compromised IAM credentials",
                    "Enable GuardDuty for behavioural detection",
                    "Review file shares for unauthorised access",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Legitimate administrators may enumerate shares; whitelist known admin accounts",
            detection_coverage="65% - catches command-line tools but may miss API-based enumeration",
            evasion_considerations="Direct API calls (NetShareEnum) or WMI queries may evade command-line detection",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2-3 hours",
            estimated_monthly_cost="$15-25",
            prerequisites=[
                "CloudWatch Logs agent on Windows EC2 instances",
                "Process command-line logging enabled",
            ],
        ),
        DetectionStrategy(
            strategy_id="t1135-aws-smb-traffic",
            name="SMB Traffic Pattern Detection",
            description="Detect SMB enumeration via VPC Flow Logs and network patterns.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, srcaddr, dstaddr, dstport, protocol, packets, bytes
| filter dstport in [139, 445] and protocol = 6
| stats count(*) as smbConnections, count_distinct(dstaddr) as uniqueTargets by srcaddr, bin(5m)
| filter uniqueTargets > 10
| sort smbConnections desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect SMB enumeration via VPC Flow Logs analysis

Parameters:
  FlowLogGroup:
    Type: String
    Description: VPC Flow Logs CloudWatch Log Group
  AlertEmail:
    Type: String
    Description: Email for security alerts

Resources:
  # SNS Topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      TopicName: smb-enumeration-alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Metric filter for SMB connections to multiple targets
  SMBEnumFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref FlowLogGroup
      FilterPattern: '[version, account, eni, source, destination, srcport, destport="445" || destport="139", protocol="6", packets, bytes, start, end, action="ACCEPT", logstatus]'
      MetricTransformations:
        - MetricName: SMBConnections
          MetricNamespace: Security/NetworkDiscovery
          MetricValue: "1"

  # Alarm for excessive SMB connections
  SMBEnumAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: HighSMBEnumeration
      MetricName: SMBConnections
      Namespace: Security/NetworkDiscovery
      Statistic: Sum
      Period: 300
      Threshold: 50
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      AlarmDescription: Detects excessive SMB connections indicating share enumeration
      AlarmActions: [!Ref AlertTopic]""",
                terraform_template="""# Detect SMB enumeration via VPC Flow Logs

variable "flow_log_group" {
  description = "VPC Flow Logs CloudWatch Log Group"
  type        = string
}

variable "alert_email" {
  description = "Email for security alerts"
  type        = string
}

# SNS topic for alerts
resource "aws_sns_topic" "smb_enum_alerts" {
  name = "smb-enumeration-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.smb_enum_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Metric filter for SMB connections
resource "aws_cloudwatch_log_metric_filter" "smb_connections" {
  name           = "smb-connections"
  log_group_name = var.flow_log_group
  pattern        = "[version, account, eni, source, destination, srcport, destport=\"445\" || destport=\"139\", protocol=\"6\", packets, bytes, start, end, action=\"ACCEPT\", logstatus]"

  metric_transformation {
    name      = "SMBConnections"
    namespace = "Security/NetworkDiscovery"
    value     = "1"
  }
}

# Alarm for excessive SMB enumeration
resource "aws_cloudwatch_metric_alarm" "smb_enum_alarm" {
  alarm_name          = "HighSMBEnumeration"
  metric_name         = "SMBConnections"
  namespace           = "Security/NetworkDiscovery"
  statistic           = "Sum"
  period              = 300
  threshold           = 50
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  alarm_description   = "Detects excessive SMB connections indicating share enumeration"
  alarm_actions       = [aws_sns_topic.smb_enum_alerts.arn]
}""",
                alert_severity="medium",
                alert_title="SMB Share Enumeration Pattern Detected",
                alert_description_template="Excessive SMB connections from {srcaddr} to multiple targets.",
                investigation_steps=[
                    "Review VPC Flow Logs for SMB connection patterns",
                    "Identify source instance and destination targets",
                    "Check for rapid connections to multiple hosts",
                    "Review security group rules allowing SMB",
                    "Correlate with CloudTrail for instance activity",
                    "Check for data transfer volumes post-discovery",
                ],
                containment_actions=[
                    "Block SMB traffic from source via security groups",
                    "Update NACLs to restrict SMB ports (445, 139)",
                    "Isolate affected instances",
                    "Review file server access logs",
                    "Enable GuardDuty for automated threat detection",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist legitimate file servers and backup systems; adjust threshold based on environment",
            detection_coverage="70% - catches network-level SMB enumeration",
            evasion_considerations="Slow enumeration or encrypted protocols may reduce detection effectiveness",
            implementation_effort=EffortLevel.LOW,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$10-20",
            prerequisites=["VPC Flow Logs enabled", "Flow Logs sent to CloudWatch"],
        ),
        DetectionStrategy(
            strategy_id="t1135-gcp-smb-detection",
            name="GCP SMB Enumeration Detection",
            description="Detect SMB share enumeration via VPC Flow Logs and Cloud Logging.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""resource.type="gce_subnetwork"
logName="projects/PROJECT_ID/logs/compute.googleapis.com%2Fvpc_flows"
jsonPayload.connection.dest_port=(445 OR 139)
jsonPayload.connection.protocol=6""",
                gcp_terraform_template="""# GCP: Detect network share enumeration via VPC Flow Logs

variable "project_id" {
  description = "GCP Project ID"
  type        = string
}

variable "alert_email" {
  description = "Email for security alerts"
  type        = string
}

# Notification channel for alerts
resource "google_monitoring_notification_channel" "email" {
  display_name = "Share Discovery Security Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Log-based metric for SMB connections
resource "google_logging_metric" "smb_connections" {
  name   = "smb-enumeration-connections"
  filter = <<-EOT
    resource.type="gce_subnetwork"
    logName="projects/${var.project_id}/logs/compute.googleapis.com%2Fvpc_flows"
    jsonPayload.connection.dest_port=(445 OR 139)
    jsonPayload.connection.protocol=6
  EOT
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "source_ip"
      value_type  = "STRING"
      description = "Source IP address"
    }
  }
  label_extractors = {
    "source_ip" = "EXTRACT(jsonPayload.connection.src_ip)"
  }
}

# Alert policy for excessive SMB enumeration
resource "google_monitoring_alert_policy" "smb_enum_alert" {
  display_name = "Network Share Enumeration Detected"
  combiner     = "OR"
  conditions {
    display_name = "High SMB connection rate"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.smb_connections.name}\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 50
      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_RATE"
      }
    }
  }
  notification_channels = [google_monitoring_notification_channel.email.id]
  alert_strategy {
    auto_close = "86400s"
  }
}""",
                alert_severity="medium",
                alert_title="GCP: Network Share Enumeration Detected",
                alert_description_template="Excessive SMB connections detected from source IP in GCP environment.",
                investigation_steps=[
                    "Review VPC Flow Logs for SMB traffic patterns",
                    "Identify source VM instance and project",
                    "Check for connections to multiple targets",
                    "Review firewall rules allowing SMB",
                    "Check Cloud Audit Logs for VM activity",
                    "Investigate subsequent file access or data transfer",
                ],
                containment_actions=[
                    "Update firewall rules to block SMB from source",
                    "Isolate affected VM instance",
                    "Review Filestore and file share access logs",
                    "Enable Security Command Centre detections",
                    "Review IAM permissions for affected principal",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist legitimate file servers; adjust threshold based on normal traffic patterns",
            detection_coverage="70% - catches network-level enumeration",
            evasion_considerations="Encrypted or tunnelled connections may evade detection",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2-3 hours",
            estimated_monthly_cost="$15-25",
            prerequisites=["VPC Flow Logs enabled", "Cloud Logging configured"],
        ),
        DetectionStrategy(
            strategy_id="t1135-aws-guardduty",
            name="AWS GuardDuty Reconnaissance Detection",
            description="Leverage GuardDuty's built-in detection for reconnaissance behaviour including share enumeration.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="guardduty",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, detail.type, detail.severity, detail.resource.instanceDetails.instanceId, detail.service.action.networkConnectionAction.remotePortDetails.port
| filter detail.type like /Recon:EC2|UnauthorizedAccess:EC2/
| filter detail.service.action.networkConnectionAction.remotePortDetails.port in [139, 445]
| sort @timestamp desc""",
                terraform_template="""# Leverage GuardDuty for reconnaissance detection

variable "alert_email" {
  description = "Email for security alerts"
  type        = string
}

# SNS topic for GuardDuty findings
resource "aws_sns_topic" "guardduty_alerts" {
  name = "guardduty-recon-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.guardduty_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# EventBridge rule for reconnaissance findings
resource "aws_cloudwatch_event_rule" "guardduty_recon" {
  name        = "guardduty-reconnaissance-detection"
  description = "Detect reconnaissance behaviour including share enumeration"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail = {
      type = [{
        prefix = "Recon:EC2"
      }, {
        prefix = "UnauthorizedAccess:EC2"
      }]
    }
  })
}

# EventBridge target to send to SNS
resource "aws_cloudwatch_event_target" "sns" {
  rule      = aws_cloudwatch_event_rule.guardduty_recon.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.guardduty_alerts.arn
}

# SNS topic policy for EventBridge
resource "aws_sns_topic_policy" "guardduty_alerts_policy" {
  arn = aws_sns_topic.guardduty_alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "events.amazonaws.com"
      }
      Action   = "SNS:Publish"
      Resource = aws_sns_topic.guardduty_alerts.arn
    }]
  })
}""",
                alert_severity="medium",
                alert_title="GuardDuty: Reconnaissance Activity Detected",
                alert_description_template="GuardDuty detected reconnaissance behaviour from instance {instanceId}.",
                investigation_steps=[
                    "Review GuardDuty finding details",
                    "Check affected EC2 instance metadata",
                    "Review CloudTrail for instance actions",
                    "Analyse network connections and targets",
                    "Check for related GuardDuty findings",
                    "Review IAM role and permissions",
                ],
                containment_actions=[
                    "Isolate affected instance",
                    "Revoke IAM role credentials",
                    "Enable network isolation via security groups",
                    "Investigate and remediate root cause",
                    "Review and rotate credentials",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="GuardDuty findings are generally high-fidelity; review suppression rules for known behaviour",
            detection_coverage="80% - GuardDuty uses machine learning and threat intelligence",
            evasion_considerations="Sophisticated adversaries may avoid patterns GuardDuty detects",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$5-15",
            prerequisites=["GuardDuty enabled in region"],
        ),
    ],
    recommended_order=[
        "t1135-aws-guardduty",
        "t1135-aws-smb-traffic",
        "t1135-aws-net-share",
        "t1135-gcp-smb-detection",
    ],
    total_effort_hours=6.5,
    coverage_improvement="+25% improvement for Discovery tactic detection",
)
