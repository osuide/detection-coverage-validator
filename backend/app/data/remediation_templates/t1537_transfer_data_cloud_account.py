"""
T1537 - Transfer Data to Cloud Account

Adversaries exfiltrate data by transferring it to cloud accounts they control.
Common methods include cross-account S3 copies, snapshot sharing, and AMI sharing.
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
    technique_id="T1537",
    technique_name="Transfer Data to Cloud Account",
    tactic_ids=["TA0010"],
    mitre_url="https://attack.mitre.org/techniques/T1537/",
    threat_context=ThreatContext(
        description=(
            "Adversaries exfiltrate data by transferring it to cloud accounts under "
            "their control. This includes cross-account S3/GCS copies, sharing snapshots "
            "or images to external accounts, and cross-project data transfers."
        ),
        attacker_goal="Exfiltrate data to attacker-controlled cloud account",
        why_technique=[
            "High bandwidth cloud-to-cloud transfers",
            "Appears as normal cloud operations",
            "Bypasses network-based exfil detection",
            "Maintains cloud-native format",
            "Can exfiltrate large volumes quickly",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="common",
        trend="increasing",
        severity_score=9,
        severity_reasoning=(
            "Direct data loss to adversary. Cloud-to-cloud transfers are fast and "
            "hard to detect. Snapshot/AMI sharing provides complete copies of data "
            "and systems."
        ),
        business_impact=[
            "Complete data exfiltration",
            "Intellectual property theft",
            "Regulatory compliance violations",
            "Customer data exposure",
        ],
        typical_attack_phase="exfiltration",
        often_precedes=["T1486"],
        often_follows=["T1530", "T1078.004", "T1528"],
    ),
    detection_strategies=[
        # =====================================================================
        # STRATEGY 1: GuardDuty S3 Exfiltration Detection (Recommended)
        # =====================================================================
        DetectionStrategy(
            strategy_id="t1537-aws-guardduty",
            name="AWS GuardDuty S3 Exfiltration Detection",
            description=(
                "Leverage GuardDuty's ML-based detection for S3 exfiltration patterns. "
                "Detects anomalous S3 access, unusual data transfer volumes, and cross-account activity. "
                "See: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-s3.html"
            ),
            detection_type=DetectionType.GUARDDUTY,
            aws_service="guardduty",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                guardduty_finding_types=[
                    "Exfiltration:S3/AnomalousBehavior",
                    "Exfiltration:S3/MaliciousIPCaller",
                    "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS",
                    "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.InsideAWS",
                ],
                terraform_template="""# AWS GuardDuty S3 Exfiltration Detection
# Detects: Exfiltration:S3/AnomalousBehavior, credential exfiltration
# See: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-s3.html

variable "alert_email" {
  type        = string
  description = "Email for exfiltration alerts"
}

variable "location" {
  type        = string
  description = "Azure region for resources"
  default     = "uksouth"
}

# Step 1: Create encrypted SNS topic
resource "aws_sns_topic" "exfil_alerts" {
  name              = "guardduty-exfiltration-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "alert_email" {
  topic_arn = aws_sns_topic.exfil_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Enable GuardDuty with S3 Protection
resource "aws_guardduty_detector" "main" {
  enable = true
  datasources {
    s3_logs {
      enable = true
    }
  }
}

# Step 3: Route exfiltration findings to SNS
resource "aws_cloudwatch_event_rule" "exfil_findings" {
  name        = "guardduty-exfiltration-findings"
  description = "Detect S3 exfiltration and credential theft"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail = {
      type = [
        { prefix = "Exfiltration:S3/" },
        { prefix = "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS" }
      ]
    }
  })
}

data "aws_caller_identity" "current" {}

# Step 4: Dead letter queue
resource "aws_sqs_queue" "dlq" {
  name                      = "guardduty-exfil-dlq"
  message_retention_seconds = 1209600
}

# SQS Queue Policy for EventBridge DLQ (CRITICAL)
# Without this, EventBridge cannot send failed events to the DLQ
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
      values   = [aws_cloudwatch_event_rule.exfil_findings.arn]
    }
  }
}

resource "aws_sqs_queue_policy" "event_dlq" {
  queue_url = aws_sqs_queue.dlq.url
  policy    = data.aws_iam_policy_document.eventbridge_dlq_policy.json
}

# Step 5: EventBridge target with DLQ, retry, input transformer
resource "aws_cloudwatch_event_target" "to_sns" {
  rule      = aws_cloudwatch_event_rule.exfil_findings.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.exfil_alerts.arn

  retry_policy {
    maximum_event_age_in_seconds = 3600
    maximum_retry_attempts       = 8
  }

  dead_letter_config {
    arn = aws_sqs_queue.dlq.arn
  }

  input_transformer {
    input_paths = {
      findingType = "$.detail.type"
      severity    = "$.detail.severity"
      bucket      = "$.detail.resource.s3BucketDetails[0].name"
      principal   = "$.detail.resource.accessKeyDetails.userName"
      accountId   = "$.account"
    }
    input_template = <<-EOF
"CRITICAL: GuardDuty Exfiltration Alert (T1537)
Type: <findingType>
Severity: <severity>
Bucket: <bucket>
Principal: <principal>
Account: <accountId>
Action: Immediately investigate data transfer activity"
EOF
  }
}

# Step 6: Scoped SNS topic policy
resource "aws_sns_topic_policy" "allow_eventbridge" {
  arn = aws_sns_topic.exfil_alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowEventBridgePublishScoped"
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.exfil_alerts.arn
      Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
        ArnEquals = {
          "aws:SourceArn" = aws_cloudwatch_event_rule.exfil_findings.arn
        }
      }
    }]
  })
}""",
                alert_severity="critical",
                alert_title="GuardDuty: S3 Data Exfiltration Detected",
                alert_description_template=(
                    "GuardDuty detected S3 exfiltration activity: {type}. "
                    "Bucket {bucket} accessed by {principal}."
                ),
                investigation_steps=[
                    "Review the specific GuardDuty finding for full context",
                    "Identify all S3 objects accessed in the time window",
                    "Check for cross-account data transfers",
                    "Verify if credentials were exfiltrated from EC2",
                    "Review S3 access logs for data volume transferred",
                ],
                containment_actions=[
                    "Revoke credentials used for the exfiltration",
                    "Enable S3 Block Public Access immediately",
                    "Review and remove cross-account bucket policies",
                    "Enable S3 Object Lock on critical buckets",
                    "Check for compromised EC2 instances",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning=(
                "GuardDuty's ML learns baseline S3 access patterns over 7-14 days. "
                "Use trusted IP lists for known data transfer partners. "
                "Suppress findings for authorised backup/DR accounts."
            ),
            detection_coverage="90% - ML-based anomaly detection",
            evasion_considerations="Very slow exfiltration may blend into baseline",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost=(
                "S3 Protection: ~$0.80 per million S3 events. "
                "See: https://aws.amazon.com/guardduty/pricing/"
            ),
            prerequisites=["CloudTrail S3 data events enabled"],
        ),
        # =====================================================================
        # STRATEGY 2: AWS - S3 Cross-Account Copy
        # =====================================================================
        DetectionStrategy(
            strategy_id="t1537-aws-s3-crossaccount",
            name="S3 Cross-Account Data Transfer",
            description="Detect S3 data copied or shared to external AWS accounts.",
            detection_type=DetectionType.EVENTBRIDGE_RULE,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, eventName, requestParameters.bucketName, userIdentity.accountId
| filter eventSource = "s3.amazonaws.com"
| filter eventName in ["PutBucketPolicy", "PutBucketAcl", "CopyObject"]
| filter requestParameters.accessControlList.grant.grantee.id != userIdentity.accountId
| sort @timestamp desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect S3 cross-account transfers

Parameters:
  CloudTrailLogGroup:
    Type: String
  AlertEmail:
    Type: String

Resources:
  # Step 1: SNS topic
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: EventBridge rule for cross-account S3
  S3CrossAccountRule:
    Type: AWS::Events::Rule
    Properties:
      EventPattern:
        source: [aws.s3]
        detail-type: [AWS API Call via CloudTrail]
        detail:
          eventName:
            - PutBucketPolicy
            - PutBucketAcl
            - PutObjectAcl
      Targets:
        - Id: Alert
          Arn: !Ref AlertTopic

  TopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics: [!Ref AlertTopic]
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
                aws:SourceArn: !GetAtt S3CrossAccountRule.Arn""",
                terraform_template="""# Detect S3 cross-account transfers

variable "alert_email" {
  type = string
}

# Step 1: SNS topic
resource "aws_sns_topic" "alerts" {
  name = "s3-crossaccount-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: EventBridge rule
resource "aws_cloudwatch_event_rule" "s3_crossaccount" {
  name = "s3-crossaccount-transfers"
  event_pattern = jsonencode({
    source      = ["aws.s3"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = ["PutBucketPolicy", "PutBucketAcl", "PutObjectAcl"]
    }
  })
}

resource "aws_cloudwatch_event_target" "sns" {
  rule = aws_cloudwatch_event_rule.s3_crossaccount.name
target_id = "SendToSNS"
  arn  = aws_sns_topic.alerts.arn
}

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
            "aws:SourceArn" = [
              aws_cloudwatch_event_rule.s3_crossaccount.arn,
              aws_cloudwatch_event_rule.snapshot_share.arn,
            ]
          }
      }
    }]
  })
}""",
                alert_severity="critical",
                alert_title="S3 Cross-Account Access Granted",
                alert_description_template="S3 bucket {bucketName} policy modified to allow external account access.",
                investigation_steps=[
                    "Review the bucket policy change",
                    "Identify the external account granted access",
                    "Check if this is an authorised partner account",
                    "Review S3 access logs for data transfers",
                ],
                containment_actions=[
                    "Revert bucket policy to deny external access",
                    "Enable S3 Object Lock if not already",
                    "Review and revoke cross-account IAM roles",
                    "Enable S3 Block Public Access",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Whitelist known partner/backup accounts",
            detection_coverage="85% - catches policy changes",
            evasion_considerations="Pre-existing cross-account permissions",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$2-5",
            prerequisites=["CloudTrail logging S3 data events"],
        ),
        # Strategy 2: AWS - Snapshot Sharing
        DetectionStrategy(
            strategy_id="t1537-aws-snapshot",
            name="EBS/RDS Snapshot External Sharing",
            description="Detect snapshots shared to external accounts.",
            detection_type=DetectionType.GUARDDUTY,
            aws_service="guardduty",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                guardduty_finding_types=[
                    "Exfiltration:S3/MaliciousIPCaller",
                    "Exfiltration:S3/AnomalousBehavior",
                ],
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect snapshot external sharing

Parameters:
  AlertEmail:
    Type: String

Resources:
  # Step 1: SNS topic
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: EventBridge for snapshot modifications
  SnapshotShareRule:
    Type: AWS::Events::Rule
    Properties:
      EventPattern:
        source: [aws.ec2]
        detail-type: [AWS API Call via CloudTrail]
        detail:
          eventName:
            - ModifySnapshotAttribute
            - ModifyDBSnapshotAttribute
      Targets:
        - Id: Alert
          Arn: !Ref AlertTopic

  TopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics: [!Ref AlertTopic]
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
                aws:SourceArn: !GetAtt SnapshotShareRule.Arn""",
                terraform_template="""# Detect snapshot external sharing

variable "alert_email" {
  type = string
}

# Step 1: SNS topic
resource "aws_sns_topic" "alerts" {
  name = "snapshot-share-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: EventBridge rule
resource "aws_cloudwatch_event_rule" "snapshot_share" {
  name = "snapshot-external-sharing"
  event_pattern = jsonencode({
    source      = ["aws.ec2", "aws.rds"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = [
        "ModifySnapshotAttribute",
        "ModifyDBSnapshotAttribute",
        "ModifyDBClusterSnapshotAttribute"
      ]
    }
  })
}

resource "aws_cloudwatch_event_target" "sns" {
  rule = aws_cloudwatch_event_rule.snapshot_share.name
target_id = "SendToSNS"
  arn  = aws_sns_topic.alerts.arn
}

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
            "aws:SourceArn" = [
              aws_cloudwatch_event_rule.s3_crossaccount.arn,
              aws_cloudwatch_event_rule.snapshot_share.arn,
            ]
          }
      }
    }]
  })
}""",
                alert_severity="critical",
                alert_title="Snapshot Shared to External Account",
                alert_description_template="EBS/RDS snapshot shared to external AWS account.",
                investigation_steps=[
                    "Identify which snapshot was shared",
                    "Review the target account ID",
                    "Check what data was in the snapshot",
                    "Verify if legitimate disaster recovery",
                ],
                containment_actions=[
                    "Remove external account from snapshot permissions",
                    "Delete the shared snapshot",
                    "Enable AWS Backup with no external sharing",
                    "Review IAM policies for snapshot permissions",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Whitelist DR/backup account IDs",
            detection_coverage="95% - catches all sharing events",
            evasion_considerations="Cannot detect already-copied snapshots",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$2-5",
            prerequisites=["CloudTrail enabled"],
        ),
        # Strategy 3: GCP - Cross-Project Data Transfer
        DetectionStrategy(
            strategy_id="t1537-gcp-crossproject",
            name="GCP Cross-Project Data Transfer",
            description="Detect data transferred to external GCP projects.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="gcs_bucket"
protoPayload.methodName=~"storage.objects.(copy|rewrite)"
protoPayload.request.destinationBucket!~"projects/_/buckets/${PROJECT_ID}"''',
                gcp_terraform_template="""# GCP: Detect cross-project data transfer

variable "project_id" {
  type = string
}

variable "alert_email" {
  type = string
}

# Step 1: Notification channel
resource "google_monitoring_notification_channel" "email_s1" {
  project      = var.project_id
  display_name = "Security Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Log sink for cross-project transfers
resource "google_logging_project_sink" "crossproject" {
  name        = "crossproject-transfer-sink"
  destination = "pubsub.googleapis.com/projects/${var.project_id}/topics/crossproject-alerts"
  filter      = <<-EOT
    resource.type="gcs_bucket"
    protoPayload.methodName=~"storage.objects.(copy|rewrite)"
  EOT

  unique_writer_identity = true
}

# Step 3: Pub/Sub topic for alerts
resource "google_pubsub_topic" "alerts" {
  name = "crossproject-alerts"
}

# Step 4: Alert policy
resource "google_monitoring_alert_policy" "crossproject" {
  project      = var.project_id
  display_name = "Cross-Project Data Transfer"
  combiner     = "OR"

  conditions {
    display_name = "GCS cross-project copy"
    condition_threshold {
      filter          = "resource.type=\"gcs_bucket\" AND protoPayload.methodName=~\"storage.objects.(copy|rewrite)\""
      duration        = "0s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0
    }
  }

  notification_channels = [google_monitoring_notification_channel.email_s1.id]

  alert_strategy {
    auto_close = "1800s"
    notification_rate_limit {
      period = "300s"
    }
  }
}""",
                alert_severity="critical",
                alert_title="GCP: Cross-Project Data Transfer",
                alert_description_template="Data copied from GCS to external project.",
                investigation_steps=[
                    "Identify source and destination projects",
                    "Review what data was transferred",
                    "Verify destination project ownership",
                    "Check for authorised data sharing",
                ],
                containment_actions=[
                    "Remove cross-project IAM bindings",
                    "Enable VPC Service Controls",
                    "Review organisation policies",
                    "Revoke external service account access",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist known partner projects",
            detection_coverage="80% - catches object copy operations",
            evasion_considerations="Download and re-upload bypasses",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$10-20",
            prerequisites=["Cloud Audit Logs enabled for GCS"],
        ),
        # Strategy 4: GCP - Disk/Image External Sharing
        DetectionStrategy(
            strategy_id="t1537-gcp-image",
            name="GCP Disk/Image External Sharing",
            description="Detect compute images or disks shared externally.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="gce_image" OR resource.type="gce_disk"
protoPayload.methodName=~"compute.images.setIamPolicy|compute.disks.setIamPolicy"''',
                gcp_terraform_template="""# GCP: Detect disk/image external sharing

variable "project_id" {
  type = string
}

variable "alert_email" {
  type = string
}

# Step 1: Notification channel
resource "google_monitoring_notification_channel" "email_s2" {
  project      = var.project_id
  display_name = "Security Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Log-based metric
resource "google_logging_metric" "image_sharing" {
  project = var.project_id
  name   = "gce-image-disk-sharing"
  filter = <<-EOT
    resource.type=("gce_image" OR "gce_disk")
    protoPayload.methodName=~"compute.(images|disks).setIamPolicy"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Alert policy
resource "google_monitoring_alert_policy" "image_share" {
  project      = var.project_id
  display_name = "GCE Image/Disk External Share"
  combiner     = "OR"

  conditions {
    display_name = "Image or disk IAM policy changed"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.image_sharing.name}\""
      duration        = "0s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0
    }
  }

  notification_channels = [google_monitoring_notification_channel.email_s2.id]

  alert_strategy {
    auto_close = "1800s"
    notification_rate_limit {
      period = "300s"
    }
  }
}""",
                alert_severity="critical",
                alert_title="GCP: Compute Image/Disk Shared Externally",
                alert_description_template="GCE image or disk IAM policy modified for external access.",
                investigation_steps=[
                    "Identify which image/disk was shared",
                    "Review the IAM policy change",
                    "Check if external principals added",
                    "Verify authorised image sharing",
                ],
                containment_actions=[
                    "Remove external IAM bindings",
                    "Delete shared images if compromised",
                    "Enable organisation policy constraints",
                    "Review image sharing permissions",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Whitelist authorised shared images",
            detection_coverage="90% - catches IAM policy changes",
            evasion_considerations="Pre-existing permissions",
            implementation_effort=EffortLevel.LOW,
            implementation_time="1 hour",
            estimated_monthly_cost="$5-10",
            prerequisites=["Cloud Audit Logs enabled"],
        ),
        # Azure Strategy: Transfer Data to Cloud Account
        DetectionStrategy(
            strategy_id="t1537-azure",
            name="Azure Transfer Data to Cloud Account Detection",
            description=(
                "Monitor data transfer to external accounts. "
                "Provides native Azure detection using Log Analytics and Defender for Cloud."
            ),
            detection_type=DetectionType.LOG_ANALYTICS_QUERY,
            aws_service="n/a",
            azure_service="log_analytics",
            cloud_provider=CloudProvider.AZURE,
            implementation=DetectionImplementation(
                azure_kql_query="""// T1537 - Transfer Data to Cloud Account Detection
// Detects data transfer to external/attacker-controlled Azure accounts
// Data Sources: AzureActivity, StorageBlobLogs, AzureDiagnostics

// Strategy 1: Disk Snapshot sharing to external subscriptions
let SnapshotSharing = AzureActivity
| where TimeGenerated > ago(24h)
| where OperationNameValue in (
    "Microsoft.Compute/snapshots/write",
    "Microsoft.Compute/disks/beginGetAccess/action",
    "Microsoft.Compute/snapshots/beginGetAccess/action"
)
| where ActivityStatusValue == "Succeeded"
| extend PropertiesJson = parse_json(Properties)
| extend TargetSubscription = tostring(PropertiesJson.targetResourceId)
| where TargetSubscription != "" and TargetSubscription != SubscriptionId
| project TimeGenerated, SubscriptionId, Caller, CallerIpAddress, OperationNameValue,
          Resource, TargetSubscription, AlertType = "Snapshot External Share";

// Strategy 2: Storage Account cross-subscription copy operations
let CrossSubCopy = StorageBlobLogs
| where TimeGenerated > ago(24h)
| where OperationName in ("CopyBlob", "CopyBlobFromURL", "StartCopyBlob")
| where StatusCode in (200, 202)
| extend SourceUri = tostring(parse_json(RequestHeaderValue).["x-ms-copy-source"])
| where SourceUri != "" and SourceUri !contains AccountName
| summarize
    CopyCount = count(),
    TotalBytes = sum(RequestBodySize),
    DestinationAccounts = make_set(AccountName, 10)
    by CallerIpAddress, SourceUri, bin(TimeGenerated, 1h)
| where CopyCount > 10 or TotalBytes > 104857600;

// Strategy 3: SAS token generation for external access
let SASGeneration = AzureActivity
| where TimeGenerated > ago(24h)
| where OperationNameValue in (
    "Microsoft.Storage/storageAccounts/listServiceSas/action",
    "Microsoft.Storage/storageAccounts/listAccountSas/action",
    "Microsoft.Storage/storageAccounts/listkeys/action"
)
| where ActivityStatusValue == "Succeeded"
| summarize
    TokenCount = count(),
    StorageAccounts = make_set(Resource, 10)
    by Caller, CallerIpAddress, bin(TimeGenerated, 1h)
| where TokenCount > 5;

// Strategy 4: VM Image/Disk shared to external tenants
let ImageSharing = AzureActivity
| where TimeGenerated > ago(24h)
| where OperationNameValue in (
    "Microsoft.Compute/galleries/images/versions/write",
    "Microsoft.Compute/galleries/share/action",
    "Microsoft.Compute/images/write"
)
| where ActivityStatusValue == "Succeeded"
| extend PropertiesJson = parse_json(Properties)
| project TimeGenerated, SubscriptionId, Caller, CallerIpAddress, OperationNameValue,
          Resource, Properties, AlertType = "VM Image External Share";

// Strategy 5: Cross-subscription storage replication
let ReplicationConfig = AzureActivity
| where TimeGenerated > ago(24h)
| where OperationNameValue in (
    "Microsoft.Storage/storageAccounts/objectReplicationPolicies/write",
    "Microsoft.Storage/storageAccounts/write"
)
| where ActivityStatusValue == "Succeeded"
| extend PropertiesJson = parse_json(Properties)
| where PropertiesJson has "objectReplication" or PropertiesJson has "geoReplication"
| project TimeGenerated, SubscriptionId, Caller, CallerIpAddress, OperationNameValue,
          Resource, Properties, AlertType = "Replication Configuration";

// Combine all detection patterns
SnapshotSharing
| union ImageSharing
| union ReplicationConfig
| union (SASGeneration | extend AlertType = "SAS Token Bulk Generation")
| order by TimeGenerated desc""",
                azure_activity_operations=[
                    "Microsoft.Compute/snapshots/write",
                    "Microsoft.Compute/snapshots/beginGetAccess/action",
                    "Microsoft.Compute/disks/beginGetAccess/action",
                    "Microsoft.Compute/galleries/share/action",
                    "Microsoft.Storage/storageAccounts/listServiceSas/action",
                    "Microsoft.Storage/storageAccounts/listAccountSas/action",
                    "Microsoft.Storage/storageAccounts/objectReplicationPolicies/write",
                ],
                azure_terraform_template="""# Azure Detection for Transfer Data to Cloud Account
# MITRE ATT&CK: T1537

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
  name                = "transfer-data-to-cloud-account-alerts"
  resource_group_name = var.resource_group_name
  short_name          = "SecAlerts"

  email_receiver {
    name          = "security-team"
    email_address = var.alert_email
  }
}

# Scheduled Query Rule for detection
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "detection" {
  name                = "transfer-data-to-cloud-account-detection"
  resource_group_name = var.resource_group_name
  location            = var.location

  evaluation_frequency = "PT5M"
  window_duration      = "PT1H"
  scopes               = [var.log_analytics_workspace_id]
  severity             = 2

  criteria {
    query = <<-QUERY
// Transfer Data to Cloud Account Detection
// Technique: T1537
AzureActivity
| where TimeGenerated > ago(24h)
| where OperationNameValue contains "Microsoft.Storage/storageAccounts/" or OperationNameValue contains "Microsoft.Cdn/"
| where ActivityStatusValue == "Success" or ActivityStatusValue == "Succeeded"
| project
    TimeGenerated,
    SubscriptionId,
    ResourceGroup,
    Resource,
    Caller,
    CallerIpAddress,
    OperationNameValue,
    ActivityStatusValue,
    Properties
| order by TimeGenerated desc
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

  description = "Detects Transfer Data to Cloud Account (T1537) activity in Azure environment"
  display_name = "Transfer Data to Cloud Account Detection"
  enabled      = true

  tags = {
    "mitre-technique" = "T1537"
    "detection-type"  = "security"
  }
}

output "alert_rule_id" {
  value = azurerm_monitor_scheduled_query_rules_alert_v2.detection.id
}""",
                alert_severity="high",
                alert_title="Azure: Transfer Data to Cloud Account Detected",
                alert_description_template=(
                    "Transfer Data to Cloud Account activity detected. "
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
        "t1537-aws-guardduty",
        "t1537-aws-snapshot",
        "t1537-aws-s3-crossaccount",
        "t1537-gcp-image",
        "t1537-gcp-crossproject",
    ],
    total_effort_hours=4.0,
    coverage_improvement="+22% improvement for Exfiltration tactic",
)
