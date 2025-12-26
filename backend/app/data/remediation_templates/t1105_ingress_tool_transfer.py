"""
T1105 - Ingress Tool Transfer

Adversaries transfer tools and files from external systems into compromised environments
via command and control channels, FTP, and alternate protocols.
Used by APT28, APT29, APT41, Lazarus Group, FIN7, Kimsuky, OilRig.
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
    technique_id="T1105",
    technique_name="Ingress Tool Transfer",
    tactic_ids=["TA0011"],
    mitre_url="https://attack.mitre.org/techniques/T1105/",
    threat_context=ThreatContext(
        description=(
            "Adversaries transfer tools and files from external systems into compromised "
            "environments using command and control channels, FTP, and other protocols. "
            "In cloud environments, attackers commonly download tools to EC2 instances, "
            "containers, or Lambda functions using utilities like curl, wget, or cloud SDKs."
        ),
        attacker_goal="Transfer malicious tools and files into compromised systems for post-exploitation",
        why_technique=[
            "Essential for multi-stage attacks",
            "Enables post-exploitation toolkit delivery",
            "Small initial payload can download larger tools",
            "Cloud instances often have unrestricted outbound access",
            "Blends with legitimate software downloads",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="common",
        trend="increasing",
        severity_score=8,
        severity_reasoning=(
            "Critical technique for attack progression. Nearly all sophisticated attacks "
            "require tool transfer. In cloud environments, compromised instances can download "
            "mining software, privilege escalation tools, or data exfiltration utilities."
        ),
        business_impact=[
            "Enables advanced attack capabilities",
            "Cryptomining and resource abuse",
            "Data exfiltration tooling deployment",
            "Lateral movement enabler",
            "Credential theft utilities",
        ],
        typical_attack_phase="command_and_control",
        often_precedes=["T1078.004", "T1530", "T1552.001", "T1485", "T1496.001"],
        often_follows=["T1190", "T1078.004", "T1552.005"],
    ),
    detection_strategies=[
        DetectionStrategy(
            strategy_id="t1105-aws-ec2-download",
            name="AWS EC2 Suspicious Download Activity",
            description="Detect EC2 instances downloading files using wget, curl, or certutil.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, @message, userIdentity.principalId, requestParameters.instanceId
| filter eventSource = "ssm.amazonaws.com" or eventSource = "ec2.amazonaws.com"
| filter @message like /wget|curl|certutil|Invoke-WebRequest|iwr|IEX|powershell.*downloadfile/i
| stats count(*) as download_commands by userIdentity.principalId, requestParameters.instanceId, bin(1h)
| filter download_commands > 3
| sort download_commands desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect suspicious file downloads on EC2 instances

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
      TopicName: ec2-download-alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Create metric filter for download commands
  DownloadMetricFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ ($.eventSource = "ssm.amazonaws.com" || $.eventSource = "ec2.amazonaws.com") && ($.requestParameters.commands[0] = "*wget*" || $.requestParameters.commands[0] = "*curl*" || $.requestParameters.commands[0] = "*certutil*") }'
      MetricTransformations:
        - MetricName: SuspiciousDownloads
          MetricNamespace: Security/EC2
          MetricValue: "1"
          DefaultValue: 0

  # Step 3: Create alarm for suspicious downloads
  DownloadAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: EC2-SuspiciousDownloads
      AlarmDescription: Detects suspicious file download activity on EC2
      MetricName: SuspiciousDownloads
      Namespace: Security/EC2
      Statistic: Sum
      Period: 300
      EvaluationPeriods: 1
      Threshold: 5
      ComparisonOperator: GreaterThanThreshold
      TreatMissingData: notBreaching

      AlarmActions:
        - !Ref AlertTopic

  TopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics:
        - !Ref AlertTopic
      PolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Sid: AllowCloudWatchPublishScoped
            Effect: Allow
            Principal:
              Service: cloudwatch.amazonaws.com
            Action: sns:Publish
            Resource: !Ref AlertTopic
            Condition:
              StringEquals:
                AWS:SourceAccount: !Ref AWS::AccountId""",
                terraform_template="""# AWS: Detect suspicious file downloads on EC2

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
  name = "ec2-download-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Create metric filter for download commands
resource "aws_cloudwatch_log_metric_filter" "downloads" {
  name           = "suspicious-ec2-downloads"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ ($.eventSource = \"ssm.amazonaws.com\" || $.eventSource = \"ec2.amazonaws.com\") && ($.requestParameters.commands[0] = \"*wget*\" || $.requestParameters.commands[0] = \"*curl*\" || $.requestParameters.commands[0] = \"*certutil*\") }"

  metric_transformation {
    name          = "SuspiciousDownloads"
    namespace     = "Security/EC2"
    value         = "1"
    default_value = 0
  }
}

# Step 3: Create alarm for suspicious downloads
resource "aws_cloudwatch_metric_alarm" "download_alert" {
  alarm_name          = "EC2-SuspiciousDownloads"
  alarm_description   = "Detects suspicious file download activity on EC2"
  metric_name         = "SuspiciousDownloads"
  namespace           = "Security/EC2"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 5
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data = "notBreaching"
  alarm_actions      = [aws_sns_topic.alerts.arn]
}

data "aws_caller_identity" "current" {}

resource "aws_sns_topic_policy" "allow_cloudwatch" {
  arn = aws_sns_topic.alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowCloudWatchPublishScoped"
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
                alert_severity="high",
                alert_title="Suspicious File Download Detected on EC2",
                alert_description_template="Instance {instanceId} executed download commands using {command}.",
                investigation_steps=[
                    "Review downloaded file source and destination",
                    "Check instance role permissions and recent activity",
                    "Analyse network connections from the instance",
                    "Verify file hash against threat intelligence",
                    "Review process execution history",
                ],
                containment_actions=[
                    "Isolate instance via security group modification",
                    "Create snapshot for forensic analysis",
                    "Revoke instance profile credentials",
                    "Block malicious domains at VPC level",
                    "Terminate instance if confirmed malicious",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Exclude known software deployment patterns and authorised automation",
            detection_coverage="65% - catches common download utilities",
            evasion_considerations="Custom downloaders, encoded commands, or alternative utilities may evade",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$5-15",
            prerequisites=[
                "CloudTrail enabled with SSM and EC2 logging",
                "CloudWatch Logs integration",
            ],
        ),
        DetectionStrategy(
            strategy_id="t1105-aws-guardduty",
            name="AWS GuardDuty Malicious Download Detection",
            description="Leverage GuardDuty to detect instances communicating with known malicious domains.",
            detection_type=DetectionType.GUARDDUTY,
            aws_service="guardduty",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                guardduty_finding_types=[
                    # C2 and malicious infrastructure
                    "Backdoor:EC2/C&CActivity.B",
                    "UnauthorizedAccess:EC2/MaliciousIPCaller.Custom",
                    "Trojan:EC2/DropPoint",
                    # Runtime Monitoring findings (requires Runtime Monitoring enabled)
                    "Execution:Runtime/MaliciousFileExecuted",
                    "Execution:Runtime/SuspiciousTool",
                    "Execution:Runtime/ReverseShell",
                    "DefenseEvasion:Runtime/FilelessExecution",
                ],
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: GuardDuty detection for malicious downloads

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
      TopicName: guardduty-download-alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Create EventBridge rule for GuardDuty findings
  GuardDutyEventRule:
    Type: AWS::Events::Rule
    Properties:
      Name: guardduty-malicious-download
      Description: Alert on GuardDuty malicious download findings
      EventPattern:
        source:
          - aws.guardduty
        detail-type:
          - GuardDuty Finding
        detail:
          type:
            - prefix: Backdoor:EC2/C&CActivity
            - prefix: UnauthorizedAccess:EC2/MaliciousIPCaller
            - prefix: Trojan:EC2/DropPoint
            - prefix: Execution:Runtime/MaliciousFileExecuted
            - prefix: Execution:Runtime/SuspiciousTool
            - prefix: Execution:Runtime/ReverseShell
            - prefix: DefenseEvasion:Runtime
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
                terraform_template="""# AWS: GuardDuty malicious download detection

variable "alert_email" {
  description = "Email for security alerts"
  type        = string
}

# Step 1: Create SNS topic for GuardDuty alerts
resource "aws_sns_topic" "guardduty_alerts" {
  name = "guardduty-download-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.guardduty_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Create EventBridge rule for GuardDuty findings
resource "aws_cloudwatch_event_rule" "guardduty_download" {
  name        = "guardduty-malicious-download"
  description = "Alert on GuardDuty malicious download findings"

  event_pattern = jsonencode({
    source        = ["aws.guardduty"]
    "detail-type" = ["GuardDuty Finding"]
    detail = {
      type = [
        { prefix = "Backdoor:EC2/C&CActivity.B" },
        { prefix = "UnauthorizedAccess:EC2/MaliciousIPCaller.Custom" },
        { prefix = "Trojan:EC2/DropPoint" },
        { prefix = "Execution:Runtime/MaliciousFileExecuted" },
        { prefix = "Execution:Runtime/SuspiciousTool" },
        { prefix = "Execution:Runtime/ReverseShell" },
        { prefix = "DefenseEvasion:Runtime" }
      ]
    }
  })
}

# Step 3: Configure target to send alerts to SNS
resource "aws_sqs_queue" "dlq" {
  name                      = "guardduty-download-dlq"
  message_retention_seconds = 1209600
}

data "aws_caller_identity" "current" {}

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
      values   = [aws_cloudwatch_event_rule.guardduty_download.arn]
    }
  }
}

resource "aws_sqs_queue_policy" "event_dlq" {
  queue_url = aws_sqs_queue.dlq.url
  policy    = data.aws_iam_policy_document.eventbridge_dlq_policy.json
}

resource "aws_cloudwatch_event_target" "sns" {
  rule      = aws_cloudwatch_event_rule.guardduty_download.name
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
            "aws:SourceArn" = aws_cloudwatch_event_rule.guardduty_download.arn
          }
      }
    }]
  })
}""",
                alert_severity="high",
                alert_title="GuardDuty: Malicious Download Activity",
                alert_description_template="Instance {instanceId} communicating with known malicious infrastructure.",
                investigation_steps=[
                    "Review GuardDuty finding details and severity",
                    "Identify malicious domain/IP from finding",
                    "Check instance for downloaded files",
                    "Review instance timeline and network activity",
                    "Correlate with other security events",
                ],
                containment_actions=[
                    "Isolate affected instance immediately",
                    "Block malicious IPs/domains at network level",
                    "Rotate instance credentials",
                    "Scan for persistence mechanisms",
                    "Consider instance replacement",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="GuardDuty findings are pre-vetted; review suppression rules for known safe IPs",
            detection_coverage="80% - leverages threat intelligence",
            evasion_considerations="New or unknown C2 infrastructure may not be detected",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$1-5 (requires GuardDuty)",
            prerequisites=[
                "AWS GuardDuty enabled",
                "GuardDuty Runtime Monitoring for EC2 enabled (for Runtime findings)",
                "EC2 instances must be SSM-managed for Runtime Monitoring",
            ],
        ),
        DetectionStrategy(
            strategy_id="t1105-aws-vpc-flows",
            name="AWS VPC Suspicious Download Patterns",
            description="Detect unusual outbound connections indicative of tool downloads.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, srcAddr, dstAddr, dstPort, bytes, packets
| filter action = "ACCEPT" and dstPort in [80, 443, 8080, 8443]
| filter bytes > 1048576
| stats count(*) as connections, sum(bytes) as total_bytes by srcAddr, dstAddr, bin(5m)
| filter connections > 10 and total_bytes > 10485760
| sort total_bytes desc""",
                terraform_template="""# AWS: Detect download patterns via VPC Flow Logs

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
  name = "vpc-download-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Create metric filter for large downloads
resource "aws_cloudwatch_log_metric_filter" "large_downloads" {
  name           = "large-outbound-downloads"
  log_group_name = var.vpc_flow_log_group
  pattern        = "[version, account_id, interface_id, srcaddr, dstaddr, srcport, dstport IN (80,443,8080,8443), protocol, packets, bytes > 1048576, ...]"

  metric_transformation {
    name          = "LargeDownloads"
    namespace     = "Security/VPC"
    value         = "$bytes"
    default_value = 0
  }
}

# Step 3: Create alarm for suspicious download patterns
resource "aws_cloudwatch_metric_alarm" "download_alert" {
  alarm_name          = "VPC-SuspiciousDownloads"
  alarm_description   = "Detects large file downloads from external sources"
  metric_name         = "LargeDownloads"
  namespace           = "Security/VPC"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 52428800
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data = "notBreaching"
  alarm_actions      = [aws_sns_topic.alerts.arn]
}

data "aws_caller_identity" "current" {}

resource "aws_sns_topic_policy" "allow_cloudwatch" {
  arn = aws_sns_topic.alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowCloudWatchPublishScoped"
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
                alert_title="Large Download Pattern Detected",
                alert_description_template="Instance {srcAddr} downloaded {total_bytes} bytes from {dstAddr}.",
                investigation_steps=[
                    "Identify source instance and its purpose",
                    "Verify destination legitimacy",
                    "Check for authorised software installations",
                    "Review instance user activity logs",
                    "Analyse downloaded content if accessible",
                ],
                containment_actions=[
                    "Block destination IP if malicious",
                    "Review security group rules",
                    "Enable VPC endpoint for AWS services",
                    "Implement network segmentation",
                    "Require proxy for external downloads",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.HIGH,
            false_positive_tuning="Exclude known update servers, CDNs, and authorised software repositories",
            detection_coverage="50% - network-level pattern detection",
            evasion_considerations="Low and slow downloads, encrypted channels, or fragmented transfers may evade",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$10-25",
            prerequisites=["VPC Flow Logs enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1105-gcp-vm-download",
            name="GCP VM Suspicious Download Commands",
            description="Detect GCP VM instances executing download commands.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""resource.type="gce_instance"
protoPayload.methodName=~"compute.instances.osLogin"
(jsonPayload.message=~"wget|curl|gcloud.*download|gsutil.*cp" OR
 protoPayload.request.commands=~"wget|curl|gcloud.*download|gsutil.*cp")""",
                gcp_terraform_template="""# GCP: Detect suspicious downloads on VM instances

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
  display_name = "Security Alerts - Downloads"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Create log metric for download commands
resource "google_logging_metric" "vm_downloads" {
  name   = "vm-suspicious-downloads"
  filter = <<-EOT
    resource.type="gce_instance"
    protoPayload.methodName=~"compute.instances.osLogin"
    (jsonPayload.message=~"wget|curl|gcloud.*download|gsutil.*cp" OR
     protoPayload.request.commands=~"wget|curl|gcloud.*download|gsutil.*cp")
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

# Step 3: Create alert policy for download activity
resource "google_monitoring_alert_policy" "download_alert" {
  display_name = "GCE Suspicious Downloads"
  combiner     = "OR"

  conditions {
    display_name = "Download commands detected"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.vm_downloads.name}\" AND resource.type=\"gce_instance\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 5
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
                alert_title="GCP: Suspicious Download on VM Instance",
                alert_description_template="VM instance {instance_id} executed download commands.",
                investigation_steps=[
                    "Review VM instance logs and metadata",
                    "Check downloaded file source and content",
                    "Verify service account permissions",
                    "Analyse network traffic patterns",
                    "Review recent API activity",
                ],
                containment_actions=[
                    "Isolate VM using firewall rules",
                    "Create disk snapshot for forensics",
                    "Revoke service account access",
                    "Block malicious domains via Cloud DNS",
                    "Stop instance if confirmed compromise",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Exclude authorised deployment pipelines and patch management systems",
            detection_coverage="65% - catches common download utilities",
            evasion_considerations="Custom tools, API-based transfers, or Cloud Storage SDK usage may evade",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$10-20",
            prerequisites=[
                "Cloud Logging enabled for GCE",
                "OS Login or SSH logging configured",
            ],
        ),
        DetectionStrategy(
            strategy_id="t1105-gcp-cloud-armor",
            name="GCP Cloud Armor Malicious File Download",
            description="Detect file download attempts from compromised web applications.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_armor",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""resource.type="http_load_balancer"
httpRequest.requestUrl=~"\\.(exe|dll|ps1|sh|bin|elf|py)$"
httpRequest.requestMethod="GET"
httpRequest.status>=200
httpRequest.status<300""",
                gcp_terraform_template="""# GCP: Detect malicious file downloads via load balancer

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
  display_name = "Security Alerts - File Downloads"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Create log metric for suspicious file downloads
resource "google_logging_metric" "malicious_downloads" {
  name   = "malicious-file-downloads"
  filter = <<-EOT
    resource.type="http_load_balancer"
    httpRequest.requestUrl=~"\\.(exe|dll|ps1|sh|bin|elf|py)$"
    httpRequest.requestMethod="GET"
    httpRequest.status>=200
    httpRequest.status<300
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Create alert for file download patterns
resource "google_monitoring_alert_policy" "download_alert" {
  display_name = "Malicious File Downloads"
  combiner     = "OR"

  conditions {
    display_name = "Executable downloads detected"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.malicious_downloads.name}\""
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
}""",
                alert_severity="high",
                alert_title="GCP: Malicious File Download Detected",
                alert_description_template="Suspicious executable downloads detected via load balancer.",
                investigation_steps=[
                    "Identify source of download requests",
                    "Review application serving the files",
                    "Check if application is compromised",
                    "Analyse file content and hashes",
                    "Review access logs for patterns",
                ],
                containment_actions=[
                    "Block source IPs via Cloud Armor",
                    "Isolate compromised application",
                    "Remove malicious files from storage",
                    "Review application security",
                    "Enable additional Cloud Armor rules",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist legitimate software distribution endpoints",
            detection_coverage="60% - detects web-based downloads",
            evasion_considerations="Encoded filenames, compressed archives, or non-standard extensions may evade",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$5-15",
            prerequisites=["Load Balancer logging enabled"],
        ),
    ],
    recommended_order=[
        "t1105-aws-guardduty",
        "t1105-aws-ec2-download",
        "t1105-gcp-vm-download",
        "t1105-aws-vpc-flows",
        "t1105-gcp-cloud-armor",
    ],
    total_effort_hours=6.5,
    coverage_improvement="+22% improvement for Command and Control tactic",
)
