"""
T1570 - Lateral Tool Transfer

Adversaries transfer tools and files between compromised systems within a victim
environment to enable lateral movement and distribute their toolkit across the network.
Used by Sandworm Team, APT41, APT32, Wizard Spider, BlackByte, BlackCat, GALLIUM.
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
    technique_id="T1570",
    technique_name="Lateral Tool Transfer",
    tactic_ids=["TA0008"],
    mitre_url="https://attack.mitre.org/techniques/T1570/",
    threat_context=ThreatContext(
        description=(
            "Adversaries transfer tools and files between compromised systems within a victim "
            "environment after initial compromise. Common methods include SMB/Windows Admin Shares, "
            "native utilities (scp, rsync, curl), and remote execution tools like PsExec. "
            "In cloud environments, attackers use SSH between instances, S3/GCS as staging areas, "
            "and container registries to distribute malicious tools across compromised infrastructure."
        ),
        attacker_goal="Distribute attack tools across compromised systems for lateral movement",
        why_technique=[
            "Essential for multi-system attacks and lateral movement",
            "Distributes ransomware and malware across network",
            "Deploys post-exploitation tools to new systems",
            "Cloud instances can share files via storage services",
            "Appears as normal administrative activity",
        ],
        known_threat_actors=[],
        recent_campaigns=[
            Campaign(
                name="Sandworm Team Wiper Deployment",
                year=2024,
                description="Used `move` command and GPO to deploy CaddyWiper and Prestige ransomware via network shares",
                reference_url="https://attack.mitre.org/groups/G0034/",
            ),
            Campaign(
                name="BlackCat/ALPHV Ransomware Distribution",
                year=2024,
                description="Leveraged SMB shares and PsExec to distribute ransomware payloads across networks",
                reference_url="https://attack.mitre.org/software/S1068/",
            ),
            Campaign(
                name="Volt Typhoon Web Shell Propagation",
                year=2023,
                description="Copied web shells between servers using internal file transfers",
                reference_url="https://attack.mitre.org/groups/G1017/",
            ),
        ],
        prevalence="common",
        trend="increasing",
        severity_score=8,
        severity_reasoning=(
            "Critical for ransomware deployment and multi-system attacks. Enables rapid "
            "propagation of malware across environments. In cloud, attackers use storage "
            "services and container registries to distribute tools efficiently. Essential "
            "technique for advanced persistent threats."
        ),
        business_impact=[
            "Ransomware deployment across infrastructure",
            "Rapid malware propagation",
            "Multi-system compromise",
            "Distributed cryptomining operations",
            "Network-wide data theft",
        ],
        typical_attack_phase="lateral_movement",
        often_precedes=["T1486", "T1485", "T1021.007", "T1496.001"],
        often_follows=["T1078.004", "T1105", "T1021.007"],
    ),
    detection_strategies=[
        DetectionStrategy(
            strategy_id="t1570-aws-s3-internal-transfer",
            name="AWS S3 Internal File Transfer Staging",
            description="Detect instances using S3 as a staging area for lateral tool transfer.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query=r"""fields @timestamp, userIdentity.principalId, requestParameters.bucketName, requestParameters.key
| filter eventSource = "s3.amazonaws.com"
| filter eventName in ["PutObject", "CopyObject", "GetObject"]
| filter requestParameters.key like /\.(exe|dll|ps1|sh|bin|elf|py|bat)$/
| stats count(*) as transfers, count_distinct(userIdentity.principalId) as unique_principals by requestParameters.bucketName, requestParameters.key, bin(5m)
| filter unique_principals > 2
| sort transfers desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect S3 used for lateral tool transfer between instances

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
      TopicName: s3-lateral-transfer-alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Create metric filter for tool transfers
  S3TransferMetricFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ ($.eventSource = "s3.amazonaws.com") && ($.eventName = "PutObject" || $.eventName = "GetObject" || $.eventName = "CopyObject") && ($.requestParameters.key = "*.exe" || $.requestParameters.key = "*.dll" || $.requestParameters.key = "*.ps1" || $.requestParameters.key = "*.sh" || $.requestParameters.key = "*.bin") }'
      MetricTransformations:
        - MetricName: S3LateralTransfers
          MetricNamespace: Security/S3
          MetricValue: "1"
          DefaultValue: 0

  # Step 3: Create alarm for suspicious transfers
  S3TransferAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: S3-LateralToolTransfer
      AlarmDescription: Detects S3 used for lateral tool transfer
      MetricName: S3LateralTransfers
      Namespace: Security/S3
      Statistic: Sum
      Period: 300
      EvaluationPeriods: 1
      Threshold: 5
      ComparisonOperator: GreaterThanThreshold
      AlarmActions:
        - !Ref AlertTopic
      TreatMissingData: notBreaching""",
                terraform_template="""# AWS: Detect S3 lateral tool transfer

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
  name = "s3-lateral-transfer-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Create metric filter for tool transfers
resource "aws_cloudwatch_log_metric_filter" "s3_transfers" {
  name           = "s3-lateral-transfers"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ ($.eventSource = \"s3.amazonaws.com\") && ($.eventName = \"PutObject\" || $.eventName = \"GetObject\" || $.eventName = \"CopyObject\") && ($.requestParameters.key = \"*.exe\" || $.requestParameters.key = \"*.dll\" || $.requestParameters.key = \"*.ps1\" || $.requestParameters.key = \"*.sh\" || $.requestParameters.key = \"*.bin\") }"

  metric_transformation {
    name          = "S3LateralTransfers"
    namespace     = "Security/S3"
    value         = "1"
    default_value = 0
  }
}

# Step 3: Create alarm for suspicious transfers
resource "aws_cloudwatch_metric_alarm" "transfer_alert" {
  alarm_name          = "S3-LateralToolTransfer"
  alarm_description   = "Detects S3 used for lateral tool transfer"
  metric_name         = "S3LateralTransfers"
  namespace           = "Security/S3"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 5
  comparison_operator = "GreaterThanThreshold"
  alarm_actions       = [aws_sns_topic.alerts.arn]
  treat_missing_data  = "notBreaching"
}""",
                alert_severity="high",
                alert_title="S3 Lateral Tool Transfer Detected",
                alert_description_template="S3 bucket {bucketName} used for transferring executable files between principals.",
                investigation_steps=[
                    "Identify the bucket and file(s) transferred",
                    "Review all principals accessing the files",
                    "Check instance roles and associated instances",
                    "Analyse file content and hash against threat intelligence",
                    "Review timeline of uploads and downloads",
                ],
                containment_actions=[
                    "Delete suspicious files from S3 bucket",
                    "Block bucket access via bucket policy",
                    "Isolate affected instances via security groups",
                    "Revoke instance profile credentials",
                    "Enable S3 Object Lock for protection",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Exclude authorised deployment buckets and known software distribution patterns",
            detection_coverage="70% - catches S3-based lateral transfers",
            evasion_considerations="Compressed archives, renamed files, or direct instance-to-instance transfers may evade",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$5-15",
            prerequisites=[
                "CloudTrail enabled with S3 data events",
                "CloudWatch Logs integration",
            ],
        ),
        DetectionStrategy(
            strategy_id="t1570-aws-ssm-lateral",
            name="AWS SSM Inter-Instance File Transfer",
            description="Detect file transfers between EC2 instances using SSM commands.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query=r"""fields @timestamp, requestParameters.instanceId, requestParameters.commands
| filter eventSource = "ssm.amazonaws.com"
| filter eventName = "SendCommand"
| filter requestParameters.commands like /scp|rsync|curl.*http:\/\/.*\/|wget.*http:\/\/.*\//
| stats count(*) as commands by userIdentity.principalId, requestParameters.instanceId, bin(5m)
| filter commands > 3
| sort commands desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect lateral file transfers via SSM

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
      TopicName: ssm-lateral-transfer-alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Create EventBridge rule for SSM transfers
  SSMTransferRule:
    Type: AWS::Events::Rule
    Properties:
      Name: ssm-lateral-file-transfer
      Description: Alert on SSM commands transferring files
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
          Id: SNSTarget

  # Step 3: Grant EventBridge permission to publish to SNS
  SNSTopicPolicy:
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
            Resource: !Ref AlertTopic""",
                terraform_template="""# AWS: Detect lateral file transfers via SSM

variable "alert_email" {
  description = "Email for security alerts"
  type        = string
}

# Step 1: Create SNS topic for alerts
resource "aws_sns_topic" "alerts" {
  name = "ssm-lateral-transfer-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Create EventBridge rule for SSM transfers
resource "aws_cloudwatch_event_rule" "ssm_transfer" {
  name        = "ssm-lateral-file-transfer"
  description = "Alert on SSM commands transferring files"

  event_pattern = jsonencode({
    source      = ["aws.ssm"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = ["SendCommand"]
    }
  })
}

# Step 3: Configure target to send alerts to SNS
resource "aws_cloudwatch_event_target" "sns" {
  rule      = aws_cloudwatch_event_rule.ssm_transfer.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.alerts.arn
}

resource "aws_sns_topic_policy" "ssm_publish" {
  arn = aws_sns_topic.alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "SNS:Publish"
      Resource  = aws_sns_topic.alerts.arn
    }]
  })
}""",
                alert_severity="high",
                alert_title="SSM Lateral File Transfer Detected",
                alert_description_template="Instance {instanceId} executing file transfer commands via SSM.",
                investigation_steps=[
                    "Review SSM command history and parameters",
                    "Identify source and destination instances",
                    "Check files being transferred",
                    "Review instance role permissions",
                    "Correlate with other suspicious activity",
                ],
                containment_actions=[
                    "Revoke SSM permissions on affected instances",
                    "Isolate instances via security groups",
                    "Review and rotate instance credentials",
                    "Disable SSM agent if not required",
                    "Implement least privilege for SSM",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Exclude authorised configuration management and deployment automation",
            detection_coverage="65% - catches SSM-based transfers",
            evasion_considerations="Direct SSH, custom transfer methods, or encoded commands may evade",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30-60 minutes",
            estimated_monthly_cost="$2-5",
            prerequisites=["CloudTrail enabled with SSM logging"],
        ),
        DetectionStrategy(
            strategy_id="t1570-aws-vpc-internal-traffic",
            name="AWS VPC Internal SMB/SSH File Transfer",
            description="Detect internal file transfers via SMB and SSH using VPC Flow Logs.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, srcAddr, dstAddr, dstPort, bytes, packets
| filter (dstPort = 22 or dstPort = 445 or dstPort = 139)
| filter action = "ACCEPT"
| filter bytes > 10485760
| stats count(*) as connections, sum(bytes) as total_bytes by srcAddr, dstAddr, dstPort, bin(5m)
| filter connections > 5 and total_bytes > 52428800
| sort total_bytes desc""",
                terraform_template="""# AWS: Detect internal file transfers via VPC Flow Logs

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
  name = "vpc-internal-transfer-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Create metric filter for large internal transfers
resource "aws_cloudwatch_log_metric_filter" "internal_transfers" {
  name           = "vpc-internal-file-transfers"
  log_group_name = var.vpc_flow_log_group
  pattern        = "[version, account_id, interface_id, srcaddr, dstaddr, srcport, dstport IN (22,445,139), protocol, packets, bytes > 10485760, ...]"

  metric_transformation {
    name          = "InternalFileTransfers"
    namespace     = "Security/VPC"
    value         = "$bytes"
    default_value = 0
  }
}

# Step 3: Create alarm for suspicious transfer patterns
resource "aws_cloudwatch_metric_alarm" "transfer_alert" {
  alarm_name          = "VPC-InternalFileTransfer"
  alarm_description   = "Detects large file transfers between instances"
  metric_name         = "InternalFileTransfers"
  namespace           = "Security/VPC"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 104857600
  comparison_operator = "GreaterThanThreshold"
  alarm_actions       = [aws_sns_topic.alerts.arn]
  treat_missing_data  = "notBreaching"
}""",
                alert_severity="medium",
                alert_title="Large Internal File Transfer Detected",
                alert_description_template="Instance {srcAddr} transferred {total_bytes} bytes to {dstAddr} via port {dstPort}.",
                investigation_steps=[
                    "Identify source and destination instances",
                    "Verify if instances should communicate",
                    "Check instance purposes and owners",
                    "Review security group rules",
                    "Analyse historical traffic patterns",
                ],
                containment_actions=[
                    "Restrict security group rules to required traffic",
                    "Implement network segmentation",
                    "Enable VPC Flow Logs analysis automation",
                    "Deploy network IDS/IPS",
                    "Isolate suspicious instances",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.HIGH,
            false_positive_tuning="Exclude known database replication, backup operations, and authorised file sharing",
            detection_coverage="55% - network-level pattern detection",
            evasion_considerations="Encrypted transfers, low and slow transfers, or non-standard ports may evade",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$10-25",
            prerequisites=["VPC Flow Logs enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1570-gcp-gcs-lateral",
            name="GCP Cloud Storage Lateral Tool Transfer",
            description="Detect GCS buckets used for transferring tools between VM instances.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="gcs_bucket"
(protoPayload.methodName="storage.objects.create" OR
 protoPayload.methodName="storage.objects.get")
protoPayload.resourceName=~".*\\.(exe|elf|sh|py|bin|ps1)$"''',
                gcp_terraform_template="""# GCP: Detect GCS lateral tool transfer

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
  display_name = "Security Alerts - Lateral Transfer"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Create log metric for tool transfers
resource "google_logging_metric" "gcs_lateral_transfer" {
  name   = "gcs-lateral-tool-transfer"
  filter = <<-EOT
    resource.type="gcs_bucket"
    (protoPayload.methodName="storage.objects.create" OR
     protoPayload.methodName="storage.objects.get")
    protoPayload.resourceName=~".*\\.(exe|elf|sh|py|bin|ps1)$"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "bucket_name"
      value_type  = "STRING"
      description = "GCS bucket name"
    }
  }

  label_extractors = {
    "bucket_name" = "EXTRACT(resource.labels.bucket_name)"
  }
}

# Step 3: Create alert policy for transfer activity
resource "google_monitoring_alert_policy" "transfer_alert" {
  display_name = "GCS Lateral Tool Transfer"
  combiner     = "OR"

  conditions {
    display_name = "Executable transfers detected"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.gcs_lateral_transfer.name}\" AND resource.type=\"gcs_bucket\""
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
                alert_title="GCP: GCS Lateral Tool Transfer",
                alert_description_template="GCS bucket {bucket_name} used for transferring executable files.",
                investigation_steps=[
                    "Review GCS bucket and object access logs",
                    "Identify all service accounts accessing files",
                    "Check associated VM instances",
                    "Analyse file content and hashes",
                    "Review bucket IAM permissions",
                ],
                containment_actions=[
                    "Delete suspicious objects from bucket",
                    "Remove unauthorised IAM bindings",
                    "Isolate affected VMs via firewall rules",
                    "Revoke service account credentials",
                    "Enable Object Versioning for forensics",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Exclude authorised deployment buckets and known software distribution",
            detection_coverage="70% - catches GCS-based transfers",
            evasion_considerations="Compressed archives, renamed files, or direct VM transfers may evade",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$10-20",
            prerequisites=["Cloud Audit Logs enabled for GCS"],
        ),
        DetectionStrategy(
            strategy_id="t1570-gcp-internal-ssh",
            name="GCP Internal SSH File Transfer",
            description="Detect SSH-based file transfers between GCP VM instances.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="gce_instance"
jsonPayload.message=~"scp|rsync|sftp"
jsonPayload.connection.protocol="ssh"''',
                gcp_terraform_template="""# GCP: Detect internal SSH file transfers

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
  display_name = "Security Alerts - SSH Transfer"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Create log metric for SSH transfers
resource "google_logging_metric" "ssh_transfers" {
  name   = "gce-internal-ssh-transfer"
  filter = <<-EOT
    resource.type="gce_instance"
    jsonPayload.message=~"scp|rsync|sftp"
    jsonPayload.connection.protocol="ssh"
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

# Step 3: Create alert for SSH transfer activity
resource "google_monitoring_alert_policy" "ssh_alert" {
  display_name = "GCE Internal SSH File Transfer"
  combiner     = "OR"

  conditions {
    display_name = "SSH file transfer detected"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.ssh_transfers.name}\" AND resource.type=\"gce_instance\""
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
                alert_severity="medium",
                alert_title="GCP: Internal SSH File Transfer",
                alert_description_template="VM instance {instance_id} performing SSH-based file transfers.",
                investigation_steps=[
                    "Review VM instance SSH logs",
                    "Identify source and destination instances",
                    "Check files being transferred",
                    "Verify service account permissions",
                    "Analyse network connectivity patterns",
                ],
                containment_actions=[
                    "Restrict firewall rules for SSH access",
                    "Isolate affected VMs",
                    "Review and rotate SSH keys",
                    "Implement network segmentation",
                    "Enable VPC Flow Logs for analysis",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.HIGH,
            false_positive_tuning="Exclude authorised configuration management, deployment pipelines, and backup operations",
            detection_coverage="60% - catches SSH-based transfers if logged",
            evasion_considerations="Custom protocols, encrypted tunnels, or alternative transfer methods may evade",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$10-20",
            prerequisites=["Cloud Logging enabled for GCE", "SSH logging configured"],
        ),
    ],
    recommended_order=[
        "t1570-aws-s3-internal-transfer",
        "t1570-aws-ssm-lateral",
        "t1570-gcp-gcs-lateral",
        "t1570-aws-vpc-internal-traffic",
        "t1570-gcp-internal-ssh",
    ],
    total_effort_hours=7.5,
    coverage_improvement="+18% improvement for Lateral Movement tactic",
)
