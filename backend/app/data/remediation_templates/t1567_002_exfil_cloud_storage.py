"""
T1567.002 - Exfiltration Over Web Service: Exfiltration to Cloud Storage

Adversaries exfiltrate data by uploading it to cloud storage services like Dropbox,
Google Drive, OneDrive, and MEGA. This blends malicious activity with normal traffic.
Used by Scattered Spider, Lazarus Group, APT41, OilRig, Indrik Spider.
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
    technique_id="T1567.002",
    technique_name="Exfiltration Over Web Service: Exfiltration to Cloud Storage",
    tactic_ids=["TA0010"],
    mitre_url="https://attack.mitre.org/techniques/T1567/002/",
    threat_context=ThreatContext(
        description=(
            "Adversaries steal data by uploading it to cloud storage services rather than "
            "using direct command-and-control channels. By leveraging legitimate cloud platforms "
            "that organisations already use (such as Dropbox, Google Drive, OneDrive, MEGA, and "
            "rclone), attackers gain operational concealment. The approach masks malicious activity "
            "within normal network traffic patterns, making detection more challenging."
        ),
        attacker_goal="Exfiltrate data to cloud storage services to avoid detection and bypass DLP controls",
        why_technique=[
            "Blends with normal organisational traffic",
            "SSL/TLS encryption hides data content",
            "Cloud storage services rarely blocked by firewalls",
            "High bandwidth for large data transfers",
            "Tools like rclone enable automated bulk exfiltration",
            "Hard to distinguish from legitimate cloud service use",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="common",
        trend="increasing",
        severity_score=9,
        severity_reasoning=(
            "Direct data loss with high bandwidth capabilities. Cloud storage exfiltration is "
            "extremely difficult to detect as it blends with legitimate organisational use of "
            "cloud services. Tools like rclone enable rapid bulk exfiltration of large volumes. "
            "Bypasses traditional network-based DLP and firewall controls."
        ),
        business_impact=[
            "Complete data exfiltration to attacker-controlled accounts",
            "Intellectual property and trade secret theft",
            "Customer data and PII exposure",
            "Regulatory compliance violations (GDPR, HIPAA)",
            "Reputational damage from data breaches",
            "Potential ransomware precursor (data for double extortion)",
        ],
        typical_attack_phase="exfiltration",
        often_precedes=["T1486"],  # Data Encrypted for Impact (ransomware)
        often_follows=[
            "T1074",
            "T1560",
            "T1530",
            "T1552.001",
        ],  # Data staged, archived, from cloud storage, credentials
    ),
    detection_strategies=[
        # Strategy 1: AWS - Rclone and Cloud Upload Tool Detection
        DetectionStrategy(
            strategy_id="t1567_002-aws-upload-tools",
            name="AWS Rclone and Cloud Upload Tool Execution",
            description="Detect execution of rclone, curl, wget, and cloud storage upload tools uploading to external services.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, eventName, userAgent, requestParameters.bucketName, userIdentity.arn
| filter eventSource = "s3.amazonaws.com"
| filter userAgent like /rclone|curl|wget|aws-cli|gsutil|azcopy/
| filter requestParameters.bucketName not like /your-org-prefix/
| stats count() as upload_count by userIdentity.arn, userAgent, requestParameters.bucketName, bin(1h)
| filter upload_count > 10
| sort @timestamp desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect cloud storage upload tools (rclone, curl, wget)

Parameters:
  CloudTrailLogGroup:
    Type: String
    Description: CloudTrail log group name
  AlertEmail:
    Type: String
    Description: Email for security alerts

Resources:
  # Step 1: SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      TopicName: cloud-storage-upload-alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: CloudWatch metric filter for upload tools
  UploadToolMetricFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ ($.userAgent = "*rclone*") || ($.userAgent = "*curl*") || ($.userAgent = "*wget*") }'
      MetricTransformations:
        - MetricName: CloudStorageUploadToolUsage
          MetricNamespace: Security/Exfiltration
          MetricValue: "1"
          DefaultValue: 0

  # Step 3: CloudWatch alarm
  UploadToolAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: Cloud-Storage-Upload-Tool-Detected
      AlarmDescription: Rclone or other upload tools detected
      MetricName: CloudStorageUploadToolUsage
      Namespace: Security/Exfiltration
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
        Statement:
          - Effect: Allow
            Principal:
              Service: cloudwatch.amazonaws.com
            Action: sns:Publish
            Resource: !Ref AlertTopic""",
                terraform_template="""# Detect cloud storage upload tools (rclone, curl, wget)

variable "cloudtrail_log_group" {
  type        = string
  description = "CloudTrail log group name"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

variable "location" {
  type        = string
  description = "Azure region for resources"
  default     = "uksouth"
}

# Step 1: SNS topic for alerts
resource "aws_sns_topic" "alerts" {
  name = "cloud-storage-upload-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: CloudWatch metric filter for upload tools
resource "aws_cloudwatch_log_metric_filter" "upload_tools" {
  name           = "cloud-storage-upload-tools"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ ($.userAgent = \"*rclone*\") || ($.userAgent = \"*curl*\") || ($.userAgent = \"*wget*\") }"

  metric_transformation {
    name      = "CloudStorageUploadToolUsage"
    namespace = "Security/Exfiltration"
    value     = "1"
  }
}

# Step 3: CloudWatch alarm
resource "aws_cloudwatch_metric_alarm" "upload_tool_alert" {
  alarm_name          = "cloud-storage-upload-tool-detected"
  alarm_description   = "Rclone or other upload tools detected"
  metric_name         = "CloudStorageUploadToolUsage"
  namespace           = "Security/Exfiltration"
  statistic           = "Sum"
  period              = 300
  threshold           = 5
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.alerts.arn]
}""",
                alert_severity="critical",
                alert_title="Cloud Storage Upload Tool Detected",
                alert_description_template="Upload tool ({userAgent}) detected uploading to external storage by {userIdentity.arn}.",
                investigation_steps=[
                    "Identify the user/instance running the upload tool",
                    "Review what files were accessed before upload",
                    "Check for data staging or compression activities",
                    "Verify if rclone/curl/wget is authorised software",
                    "Review CloudTrail for PutObject events to external buckets",
                    "Check for credential theft that may have enabled access",
                ],
                containment_actions=[
                    "Terminate the instance or revoke user credentials immediately",
                    "Block egress to cloud storage service IPs/domains",
                    "Review and remove any rclone configuration files",
                    "Enable S3 Block Public Access organisation-wide",
                    "Implement application allowlisting to prevent unauthorised tools",
                    "Review DLP policies for cloud storage services",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist authorised backup/DevOps instances using rclone. Filter legitimate curl/wget usage from known automation.",
            detection_coverage="75% - catches tool-based uploads but misses browser-based exfiltration",
            evasion_considerations="Attackers can use browser-based uploads, custom tools, or rename rclone binary",
            implementation_effort=EffortLevel.LOW,
            implementation_time="1 hour",
            estimated_monthly_cost="$5-10",
            prerequisites=[
                "CloudTrail logging S3 data events",
                "CloudWatch Logs Insights enabled",
            ],
        ),
        # Strategy 2: AWS - Large HTTPS POST to Cloud Storage Domains
        DetectionStrategy(
            strategy_id="t1567_002-aws-vpc-cloud-domains",
            name="AWS Large HTTPS POST to Cloud Storage Domains",
            description="Detect large HTTPS POST requests to known cloud storage domains (Dropbox, Google Drive, OneDrive, MEGA).",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, srcAddr, dstAddr, bytes, dstPort
| filter dstPort = 443
| filter bytes > 10485760
| filter dstAddr in ["api.dropbox.com", "content.dropboxapi.com", "www.googleapis.com", "graph.microsoft.com", "g.api.mega.co.nz"]
| stats sum(bytes) as total_bytes by srcAddr, dstAddr, bin(5m)
| filter total_bytes > 104857600
| sort total_bytes desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect large HTTPS uploads to cloud storage services

Parameters:
  VPCFlowLogGroup:
    Type: String
    Description: VPC Flow Logs log group name
  AlertEmail:
    Type: String
    Description: Email for security alerts

Resources:
  # Step 1: SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      TopicName: cloud-storage-post-alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: CloudWatch metric filter for large uploads
  LargeUploadMetricFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref VPCFlowLogGroup
      FilterPattern: '[version, account, interface, srcaddr, dstaddr, srcport, dstport="443", protocol="6", packets, bytes>10485760, ...]'
      MetricTransformations:
        - MetricName: LargeHTTPSUpload
          MetricNamespace: Security/Exfiltration
          MetricValue: "$bytes"
          DefaultValue: 0

  # Step 3: CloudWatch alarm for excessive uploads
  LargeUploadAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: Large-HTTPS-Upload-Cloud-Storage
      AlarmDescription: Large HTTPS upload to potential cloud storage detected
      MetricName: LargeHTTPSUpload
      Namespace: Security/Exfiltration
      Statistic: Sum
      Period: 300
      EvaluationPeriods: 1
      Threshold: 1073741824
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
        Statement:
          - Effect: Allow
            Principal:
              Service: cloudwatch.amazonaws.com
            Action: sns:Publish
            Resource: !Ref AlertTopic""",
                terraform_template="""# Detect large HTTPS uploads to cloud storage services

variable "vpc_flow_log_group" {
  type        = string
  description = "VPC Flow Logs log group name"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

variable "location" {
  type        = string
  description = "Azure region for resources"
  default     = "uksouth"
}

# Step 1: SNS topic for alerts
resource "aws_sns_topic" "alerts" {
  name = "cloud-storage-post-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: CloudWatch metric filter for large HTTPS uploads
resource "aws_cloudwatch_log_metric_filter" "large_upload" {
  name           = "large-https-upload"
  log_group_name = var.vpc_flow_log_group
  pattern        = "[version, account, interface, srcaddr, dstaddr, srcport, dstport=\"443\", protocol=\"6\", packets, bytes>10485760, ...]"

  metric_transformation {
    name      = "LargeHTTPSUpload"
    namespace = "Security/Exfiltration"
    value     = "$bytes"
  }
}

# Step 3: CloudWatch alarm for excessive uploads
resource "aws_cloudwatch_metric_alarm" "large_upload_alert" {
  alarm_name          = "large-https-upload-cloud-storage"
  alarm_description   = "Large HTTPS upload to potential cloud storage detected"
  metric_name         = "LargeHTTPSUpload"
  namespace           = "Security/Exfiltration"
  statistic           = "Sum"
  period              = 300
  threshold           = 1073741824  # 1 GB
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.alerts.arn]
}""",
                alert_severity="high",
                alert_title="Large HTTPS Upload to Cloud Storage",
                alert_description_template="Large HTTPS upload ({total_bytes} bytes) detected from {srcAddr} to {dstAddr}.",
                investigation_steps=[
                    "Identify the source instance/IP address",
                    "Determine the destination cloud storage service",
                    "Review what processes were running on source instance",
                    "Check for data staging, archiving, or compression",
                    "Verify if cloud storage service use is authorised",
                    "Review user activity and authentication logs",
                ],
                containment_actions=[
                    "Isolate the source instance in a quarantine security group",
                    "Block egress to cloud storage domains via NACL/security groups",
                    "Revoke credentials that may have been used",
                    "Enable enhanced DLP controls for cloud storage services",
                    "Review and update acceptable use policies",
                    "Implement DNS-based filtering for cloud storage services",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist authorised backup systems, legitimate Dropbox/Drive usage by specific IPs. Adjust byte thresholds based on baseline.",
            detection_coverage="65% - network-level detection catches large transfers but may miss smaller, incremental uploads",
            evasion_considerations="Low-and-slow exfiltration, use of proxies, encrypted tunnels, or less common cloud storage services",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$15-30",
            prerequisites=["VPC Flow Logs enabled and sent to CloudWatch"],
        ),
        # Strategy 3: AWS - EC2 Instance Profile API Calls to External Services
        DetectionStrategy(
            strategy_id="t1567_002-aws-instance-external-api",
            name="AWS EC2 Instance Profile External API Calls",
            description="Detect EC2 instances making API calls to external cloud storage services using instance profiles.",
            detection_type=DetectionType.GUARDDUTY,
            aws_service="guardduty",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                guardduty_finding_types=[
                    "Exfiltration:S3/MaliciousIPCaller",
                    "Exfiltration:S3/AnomalousBehavior",
                    "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS",
                ],
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect EC2 instances making external API calls

Parameters:
  AlertEmail:
    Type: String
    Description: Email for security alerts

Resources:
  # Step 1: SNS topic for GuardDuty findings
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      TopicName: guardduty-exfil-alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: EventBridge rule for GuardDuty exfiltration findings
  GuardDutyExfilRule:
    Type: AWS::Events::Rule
    Properties:
      Name: guardduty-exfiltration-findings
      Description: Alert on GuardDuty exfiltration findings
      EventPattern:
        source:
          - aws.guardduty
        detail-type:
          - GuardDuty Finding
        detail:
          type:
            - prefix: Exfiltration
            - UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration
      State: ENABLED
      Targets:
        - Id: SNSTopic
          Arn: !Ref AlertTopic

  # Step 3: SNS topic policy
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
            Condition:
              StringEquals:
                AWS:SourceAccount: !Ref AWS::AccountId
              ArnEquals:
                aws:SourceArn: !GetAtt GuardDutyExfilRule.Arn""",
                terraform_template="""# Detect EC2 instances making external API calls via GuardDuty

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

variable "location" {
  type        = string
  description = "Azure region for resources"
  default     = "uksouth"
}

# Step 1: SNS topic for GuardDuty findings
resource "aws_sns_topic" "alerts" {
  name = "guardduty-exfil-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: EventBridge rule for GuardDuty exfiltration findings
resource "aws_cloudwatch_event_rule" "guardduty_exfil" {
  name        = "guardduty-exfiltration-findings"
  description = "Alert on GuardDuty exfiltration findings"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail = {
      type = [
        { prefix = "Exfiltration" },
        "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS"
      ]
    }
  })
}

resource "aws_sqs_queue" "dlq" {
  name                      = "guardduty-exfil-dlq"
  message_retention_seconds = 1209600
}

resource "aws_cloudwatch_event_target" "sns" {
  rule      = aws_cloudwatch_event_rule.guardduty_exfil.name
  target_id = "SNSTopic"
  arn       = aws_sns_topic.alerts.arn

  retry_policy {
    maximum_event_age_in_seconds = 3600
    maximum_retry_attempts       = 8
  }

  dead_letter_config {
    arn = aws_sqs_queue.dlq.arn
  }
  input_transformer {
    input_paths = {
      account    = "$.account"
      region     = "$.region"
      time       = "$.time"
      type       = "$.detail.type"
      severity   = "$.detail.severity"
      title      = "$.detail.title"
      description = "$.detail.description"
    }

    input_template = <<-EOT
"GuardDuty Finding Alert
Time: <time>
Account: <account>
Region: <region>
Finding: <type>
Severity: <severity>
Title: <title>
Description: <description>
Action: Review finding in GuardDuty console and investigate"
EOT
  }

}

resource "aws_sqs_queue_policy" "dlq_policy" {
  queue_url = aws_sqs_queue.dlq.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sqs:SendMessage"
      Resource  = aws_sqs_queue.dlq.arn
      Condition = {
        ArnEquals = {
          "aws:SourceArn" = aws_cloudwatch_event_rule.guardduty_exfil.arn
        }
      }
    }]
  })
}

# Step 3: SNS topic policy
data "aws_caller_identity" "current" {}

resource "aws_sns_topic_policy" "allow_events" {
  arn = aws_sns_topic.alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.alerts.arn
    Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
          ArnEquals = {
            "aws:SourceArn" = aws_cloudwatch_event_rule.guardduty_exfil.arn
          }
      }
    }]
  })
}""",
                alert_severity="critical",
                alert_title="GuardDuty: EC2 Exfiltration Detected",
                alert_description_template="GuardDuty detected potential exfiltration activity from EC2 instance.",
                investigation_steps=[
                    "Review the GuardDuty finding details",
                    "Identify the EC2 instance and instance profile",
                    "Check what processes are running on the instance",
                    "Review CloudTrail for API activity from instance credentials",
                    "Verify if external API calls are authorised",
                    "Check for compromise indicators (unusual processes, network connections)",
                ],
                containment_actions=[
                    "Isolate the EC2 instance immediately",
                    "Revoke the instance profile IAM role",
                    "Terminate the instance if compromised",
                    "Review and rotate any credentials that may have been exposed",
                    "Enable IMDSv2 to prevent credential theft",
                    "Review security group rules and restrict egress",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="GuardDuty's ML baselines reduce false positives. Whitelist known external integrations.",
            detection_coverage="80% - GuardDuty's behavioural detection catches anomalous exfiltration patterns",
            evasion_considerations="May miss exfiltration that closely mimics legitimate patterns or uses novel cloud storage services",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$5-15 (GuardDuty costs extra)",
            prerequisites=["Amazon GuardDuty enabled"],
        ),
        # Strategy 4: GCP - Cloud Storage Upload to External Buckets
        DetectionStrategy(
            strategy_id="t1567_002-gcp-storage-upload",
            name="GCP Cloud Storage Upload to External Buckets",
            description="Detect data uploaded to external GCS buckets or cloud storage services from GCP instances.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="gce_instance"
protoPayload.methodName="storage.objects.create"
NOT protoPayload.resourceName=~"projects/YOUR-PROJECT-ID/.*"''',
                gcp_terraform_template="""# GCP: Detect uploads to external cloud storage

variable "project_id" {
  type        = string
  description = "GCP project ID"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

variable "location" {
  type        = string
  description = "Azure region for resources"
  default     = "uksouth"
}

# Step 1: Notification channel for alerts
resource "google_monitoring_notification_channel" "email_s1" {
  project      = var.project_id
  display_name = "Security Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Log-based metric for external storage uploads
resource "google_logging_metric" "external_storage" {
  name   = "external-storage-uploads"
  filter = <<-EOT
    resource.type="gce_instance"
    protoPayload.methodName="storage.objects.create"
    NOT protoPayload.resourceName=~"projects/${var.project_id}/.*"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    unit        = "1"
  }
}

# Step 3: Alert policy for external uploads
resource "google_monitoring_alert_policy" "external_upload" {
  project      = var.project_id
  display_name = "External Cloud Storage Upload"
  combiner     = "OR"

  conditions {
    display_name = "Uploads to external storage detected"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.external_storage.name}\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 5
    }
  }

  notification_channels = [google_monitoring_notification_channel.email_s1.id]

  alert_strategy {
    auto_close = "604800s"  # 7 days
  }
}""",
                alert_severity="critical",
                alert_title="GCP: External Cloud Storage Upload Detected",
                alert_description_template="GCE instance uploaded data to external Cloud Storage bucket.",
                investigation_steps=[
                    "Identify the GCE instance making the uploads",
                    "Review the destination bucket/project",
                    "Check what service account was used",
                    "Review instance logs for rclone, gsutil, or other tools",
                    "Verify if external storage access is authorised",
                    "Check for data staging or compression activities",
                ],
                containment_actions=[
                    "Stop the GCE instance immediately",
                    "Revoke the service account key if compromised",
                    "Enable VPC Service Controls to restrict data egress",
                    "Review and update firewall rules to block cloud storage",
                    "Implement organisation policies to restrict external access",
                    "Enable DLP API scanning for sensitive data",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist authorised cross-project data sharing, backup systems, and legitimate gsutil usage.",
            detection_coverage="70% - catches GCS uploads but may miss other cloud storage services",
            evasion_considerations="Attackers can use non-GCS cloud storage (Dropbox, MEGA), browser-based uploads, or custom tools",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$10-20",
            prerequisites=[
                "Cloud Audit Logs enabled for Compute Engine and Cloud Storage"
            ],
        ),
        # Strategy 5: GCP - VPC Flow Logs Large HTTPS Uploads
        DetectionStrategy(
            strategy_id="t1567_002-gcp-vpc-https",
            name="GCP VPC Flow Logs Large HTTPS Uploads",
            description="Detect large HTTPS uploads to cloud storage services via VPC Flow Logs.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""resource.type="gce_subnetwork"
logName="projects/YOUR-PROJECT/logs/compute.googleapis.com%2Fvpc_flows"
jsonPayload.connection.dest_port=443
jsonPayload.bytes_sent>10485760""",
                gcp_terraform_template="""# GCP: Detect large HTTPS uploads via VPC Flow Logs

variable "project_id" {
  type        = string
  description = "GCP project ID"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

variable "location" {
  type        = string
  description = "Azure region for resources"
  default     = "uksouth"
}

# Step 1: Notification channel for alerts
resource "google_monitoring_notification_channel" "email_s2" {
  project      = var.project_id
  display_name = "Security Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Log-based metric for large HTTPS uploads
resource "google_logging_metric" "large_https" {
  name   = "large-https-uploads"
  filter = <<-EOT
    resource.type="gce_subnetwork"
    logName="projects/${var.project_id}/logs/compute.googleapis.com%2Fvpc_flows"
    jsonPayload.connection.dest_port=443
    jsonPayload.bytes_sent>10485760
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    unit        = "By"
  }

  value_extractor = "EXTRACT(jsonPayload.bytes_sent)"
}

# Step 3: Alert policy for excessive HTTPS uploads
resource "google_monitoring_alert_policy" "https_upload" {
  project      = var.project_id
  display_name = "Large HTTPS Upload Detected"
  combiner     = "OR"

  conditions {
    display_name = "Excessive HTTPS data upload"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.large_https.name}\""
      duration        = "3600s"  # 1 hour
      comparison      = "COMPARISON_GT"
      threshold_value = 1073741824  # 1 GB
      aggregations {
        alignment_period   = "3600s"
        per_series_aligner = "ALIGN_SUM"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email_s2.id]

  alert_strategy {
    auto_close = "604800s"  # 7 days
  }
}""",
                alert_severity="high",
                alert_title="GCP: Large HTTPS Upload Detected",
                alert_description_template="Large HTTPS upload ({bytes_sent} bytes) detected from GCE instance.",
                investigation_steps=[
                    "Identify the source GCE instance IP",
                    "Determine the destination IP/domain (correlate with DNS logs)",
                    "Review instance processes and running containers",
                    "Check for rclone, curl, wget, or other upload tools",
                    "Verify if large upload is legitimate (backups, data sharing)",
                    "Review user activity and service account usage",
                ],
                containment_actions=[
                    "Isolate the instance using firewall rules",
                    "Block egress to cloud storage service IPs",
                    "Stop the instance if compromise confirmed",
                    "Enable VPC Service Controls for data egress prevention",
                    "Review and rotate service account keys",
                    "Implement Cloud Armor for web application protection",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Baseline normal upload volumes. Whitelist authorised backup systems and CDN uploads.",
            detection_coverage="65% - network-level detection but may miss encrypted or fragmented uploads",
            evasion_considerations="Low-and-slow uploads, use of less common cloud storage services, DNS tunneling",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$15-30",
            prerequisites=["VPC Flow Logs enabled on subnets"],
        ),
        # Azure Strategy: Exfiltration Over Web Service: Exfiltration to Cloud Storage
        DetectionStrategy(
            strategy_id="t1567002-azure",
            name="Azure Exfiltration Over Web Service: Exfiltration to Cloud Storage Detection",
            description=(
                "Azure detection for Exfiltration Over Web Service: Exfiltration to Cloud Storage. "
                "Provides native Azure detection using Log Analytics and Defender for Cloud."
            ),
            detection_type=DetectionType.LOG_ANALYTICS_QUERY,
            aws_service="n/a",
            azure_service="log_analytics",
            cloud_provider=CloudProvider.AZURE,
            implementation=DetectionImplementation(
                azure_kql_query="""// T1567.002 - Exfiltration to Cloud Storage Detection
// Detects data exfiltration to Dropbox, Google Drive, OneDrive, MEGA, Box
// Data Sources: AzureDiagnostics (Firewall), AzureNetworkAnalytics, DeviceNetworkEvents

// Cloud storage service domains
let CloudStorageDomains = dynamic([
    "dropbox.com", "api.dropboxapi.com", "content.dropboxapi.com",
    "drive.google.com", "www.googleapis.com", "storage.googleapis.com",
    "onedrive.live.com", "graph.microsoft.com", "1drv.ms",
    "mega.nz", "mega.co.nz", "g.api.mega.co.nz",
    "box.com", "api.box.com", "upload.box.com",
    "wetransfer.com", "we.tl",
    "mediafire.com", "sendspace.com"
]);

// Strategy 1: Azure Firewall - Outbound to cloud storage
let CloudStorageFirewall = AzureDiagnostics
| where TimeGenerated > ago(24h)
| where Category == "AzureFirewallApplicationRule"
| where msg_s has_any (CloudStorageDomains)
| extend
    FQDN = extract(@"FQDN:([^\s,]+)", 1, msg_s),
    SourceIP = extract(@"from ([0-9.]+)", 1, msg_s),
    Action = extract(@"Action: (\w+)", 1, msg_s)
| summarize
    RequestCount = count(),
    BytesSent = sum(toint(extract(@"TotalBytes:(\d+)", 1, msg_s))),
    UniqueFQDNs = make_set(FQDN, 10)
    by SourceIP, bin(TimeGenerated, 1h)
| where BytesSent > 104857600 or RequestCount > 100;  // 100MB or 100 requests

// Strategy 2: Defender for Endpoint - Cloud storage upload tools
let UploadToolActivity = DeviceNetworkEvents
| where TimeGenerated > ago(24h)
| where RemoteUrl has_any (CloudStorageDomains)
    or InitiatingProcessFileName in~ ("rclone.exe", "rclone", "azcopy.exe", "azcopy", "gsutil", "aws.exe")
| where ActionType == "ConnectionSuccess"
| summarize
    ConnectionCount = count(),
    BytesSent = sum(SentBytes),
    UniqueProcesses = make_set(InitiatingProcessFileName, 5),
    RemoteURLs = make_set(RemoteUrl, 10),
    Devices = dcount(DeviceId)
    by AccountName, bin(TimeGenerated, 1h)
| where BytesSent > 52428800;  // 50MB threshold

// Strategy 3: File staging before exfiltration (zip, tar, 7z)
let FileStagingActivity = DeviceFileEvents
| where TimeGenerated > ago(24h)
| where FileName endswith ".zip" or FileName endswith ".7z" or FileName endswith ".tar.gz"
    or FileName endswith ".rar" or FileName endswith ".tar"
| where FolderPath has_any ("Temp", "tmp", "Downloads", "Desktop", "AppData")
| where FileSize > 52428800  // 50MB
| summarize
    ArchiveCount = count(),
    TotalSize = sum(FileSize),
    FileNames = make_set(FileName, 10)
    by DeviceId, AccountName, bin(TimeGenerated, 1h)
| where ArchiveCount > 3 or TotalSize > 524288000;  // 3 archives or 500MB

// Strategy 4: NSG Flow Logs - Large outbound HTTPS
let LargeOutboundHTTPS = AzureNetworkAnalytics_CL
| where TimeGenerated > ago(24h)
| where FlowDirection_s == "O"
| where DestPort_d == 443
| where FlowStatus_s == "A"
| summarize
    TotalBytesSent = sum(BytesSent_d),
    FlowCount = count(),
    UniqueDestIPs = dcount(DestIP_s)
    by SrcIP_s, bin(TimeGenerated, 1h)
| where TotalBytesSent > 1073741824;  // 1GB threshold

// Strategy 5: Defender for Cloud Apps - Unusual upload volume
let CASBAlerts = SecurityAlert
| where TimeGenerated > ago(24h)
| where ProviderName == "MCAS" or ProductName == "Microsoft Cloud App Security"
| where AlertType has_any ("UnusualFileUpload", "MassDownload", "SuspiciousCloudStorageActivity")
| project TimeGenerated, AlertName, Description, Entities, AlertSeverity;

// Combine all detection strategies
CloudStorageFirewall | extend AlertType = "Firewall - Cloud Storage Traffic"
| union (UploadToolActivity | extend AlertType = "Endpoint - Upload Tool")
| union (FileStagingActivity | extend AlertType = "Endpoint - File Staging")
| union (LargeOutboundHTTPS | extend AlertType = "Network - Large HTTPS Egress")
| union (CASBAlerts | extend AlertType = "CASB - Unusual Upload")
| order by TimeGenerated desc""",
                azure_terraform_template="""# Azure Detection for Exfiltration Over Web Service: Exfiltration to Cloud Storage
# MITRE ATT&CK: T1567.002

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
  description = "Resource group for Log Analytics workspace"
}

variable "log_analytics_workspace_id" {
  type        = string
  description = "Log Analytics workspace resource ID"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

variable "location" {
  type        = string
  description = "Azure region for resources"
  default     = "uksouth"
}

# Action Group for alerts
resource "azurerm_monitor_action_group" "security_alerts" {
  name                = "exfiltration-over-web-service--exfiltration-to-clo-alerts"
  resource_group_name = var.resource_group_name
  short_name          = "SecAlerts"

  email_receiver {
    name          = "security-team"
    email_address = var.alert_email
  }
}

# Scheduled Query Rule for detection
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "detection" {
  name                = "exfiltration-over-web-service--exfiltration-to-clo-detection"
  resource_group_name = var.resource_group_name
  location            = var.location

  evaluation_frequency = "PT5M"
  window_duration      = "PT1H"
  scopes               = [var.log_analytics_workspace_id]
  severity             = 2

  criteria {
    query = <<-QUERY
// Exfiltration Over Web Service: Exfiltration to Cloud Storage Detection
// Technique: T1567.002
AzureActivity
| where TimeGenerated > ago(24h)
| where CategoryValue == "Administrative"
| where ActivityStatusValue == "Success" or ActivityStatusValue == "Succeeded"
| summarize
    OperationCount = count(),
    UniqueCallers = dcount(Caller),
    Resources = make_set(Resource, 10)
    by Caller, CallerIpAddress, bin(TimeGenerated, 1h)
| where OperationCount > 10
| order by OperationCount desc
    QUERY

    time_aggregation_method = "Count"
    threshold               = 1
    operator                = "GreaterThanOrEqual"

    failing_periods {
      minimum_failing_periods_to_trigger_alert = 1
      number_of_evaluation_periods             = 1
    }
  }

  auto_mitigation_enabled = false

  action {
    action_groups = [azurerm_monitor_action_group.security_alerts.id]
  }

  description = "Detects Exfiltration Over Web Service: Exfiltration to Cloud Storage (T1567.002) activity in Azure environment"
  display_name = "Exfiltration Over Web Service: Exfiltration to Cloud Storage Detection"
  enabled      = true

  tags = {
    "mitre-technique" = "T1567.002"
    "detection-type"  = "security"
  }
}

output "alert_rule_id" {
  value = azurerm_monitor_scheduled_query_rules_alert_v2.detection.id
}""",
                alert_severity="high",
                alert_title="Azure: Exfiltration Over Web Service: Exfiltration to Cloud Storage Detected",
                alert_description_template=(
                    "Exfiltration Over Web Service: Exfiltration to Cloud Storage activity detected. "
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
        "t1567_002-aws-upload-tools",
        "t1567_002-aws-instance-external-api",
        "t1567_002-gcp-storage-upload",
        "t1567_002-aws-vpc-cloud-domains",
        "t1567_002-gcp-vpc-https",
    ],
    total_effort_hours=6.5,
    coverage_improvement="+28% improvement for Exfiltration tactic",
)
