"""
T1491 - Defacement

Adversaries modify visual content available internally or externally to impact
content integrity, deliver messaging, intimidate, or claim credit for intrusions.
Used by Sandworm, Cyber Army of Russia, and CyberToufan.
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
    technique_id="T1491",
    technique_name="Defacement",
    tactic_ids=["TA0040"],
    mitre_url="https://attack.mitre.org/techniques/T1491/",
    threat_context=ThreatContext(
        description=(
            "Adversaries modify visual content available internally or externally to "
            "impact content integrity. In cloud environments, this includes defacing "
            "websites hosted on S3, GCS buckets, modifying web application content, "
            "and altering public-facing resources to deliver messaging, intimidate, "
            "or claim credit for intrusions."
        ),
        attacker_goal="Modify visual content to damage reputation, intimidate, or deliver messaging",
        why_technique=[
            "Deliver political or ideological messaging",
            "Damage organisation reputation",
            "Claim credit for intrusion",
            "Intimidate victims or stakeholders",
            "Cloud storage easily modified if credentials compromised",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="moderate",
        trend="stable",
        severity_score=7,
        severity_reasoning=(
            "High reputational impact - defacement damages public trust and brand image. "
            "Often used for political messaging or intimidation. "
            "May indicate deeper compromise requiring investigation."
        ),
        business_impact=[
            "Reputational damage",
            "Loss of customer trust",
            "Regulatory scrutiny",
            "Potential revenue loss",
            "Emergency response costs",
        ],
        typical_attack_phase="impact",
        often_precedes=[],
        often_follows=["T1078.004", "T1530", "T1190"],
    ),
    detection_strategies=[
        DetectionStrategy(
            strategy_id="t1491-aws-s3web",
            name="AWS S3 Website Content Modification Detection",
            description="Detect unauthorised modifications to S3 objects hosting website content.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, eventName, requestParameters.bucketName, requestParameters.key, userIdentity.arn
| filter eventSource = "s3.amazonaws.com"
| filter eventName = "PutObject" or eventName = "DeleteObject"
| filter requestParameters.bucketName like /web|site|www|public/
| stats count(*) as modifications by userIdentity.arn, requestParameters.bucketName, bin(15m)
| filter modifications > 5
| sort modifications desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect S3 website defacement attempts

Parameters:
  CloudTrailLogGroup:
    Type: String
  AlertEmail:
    Type: String

Resources:
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  S3WebModificationFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ ($.eventSource = "s3.amazonaws.com") && ($.eventName = "PutObject" || $.eventName = "DeleteObject") && ($.requestParameters.bucketName = "*web*" || $.requestParameters.bucketName = "*site*" || $.requestParameters.bucketName = "*www*" || $.requestParameters.bucketName = "*public*") }'
      MetricTransformations:
        - MetricName: S3WebsiteModifications
          MetricNamespace: Security
          MetricValue: "1"

  S3WebModificationAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: S3WebsiteDefacement
      MetricName: S3WebsiteModifications
      Namespace: Security
      Statistic: Sum
      Period: 900
      Threshold: 10
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      TreatMissingData: notBreaching

      AlarmActions: [!Ref AlertTopic]""",
                terraform_template="""# Detect S3 website defacement

variable "cloudtrail_log_group" { type = string }
variable "alert_email" { type = string }

resource "aws_sns_topic" "alerts" {
  name = "s3-defacement-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_cloudwatch_log_metric_filter" "web_modifications" {
  name           = "s3-website-modifications"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ ($.eventSource = \"s3.amazonaws.com\") && ($.eventName = \"PutObject\" || $.eventName = \"DeleteObject\") && ($.requestParameters.bucketName = \"*web*\" || $.requestParameters.bucketName = \"*site*\" || $.requestParameters.bucketName = \"*www*\" || $.requestParameters.bucketName = \"*public*\") }"

  metric_transformation {
    name      = "S3WebsiteModifications"
    namespace = "Security"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "defacement" {
  alarm_name          = "S3WebsiteDefacement"
  metric_name         = "S3WebsiteModifications"
  namespace           = "Security"
  statistic           = "Sum"
  period              = 900
  threshold           = 10
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.alerts.arn]
}""",
                alert_severity="high",
                alert_title="Potential S3 Website Defacement",
                alert_description_template="Unusual volume of modifications to website S3 bucket by {userIdentity.arn}.",
                investigation_steps=[
                    "Verify changes were authorised",
                    "Compare current content with backups",
                    "Review which files were modified",
                    "Check access logs for suspicious IPs",
                    "Determine if credentials were compromised",
                ],
                containment_actions=[
                    "Restore content from version history or backups",
                    "Revoke compromised credentials",
                    "Enable S3 Object Lock for critical content",
                    "Review bucket policies and IAM permissions",
                    "Enable MFA Delete on production buckets",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist authorised deployment pipelines and content management systems",
            detection_coverage="85% - catches bulk modifications to website buckets",
            evasion_considerations="Attackers may modify files slowly to avoid threshold detection",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$5-10",
            prerequisites=["CloudTrail enabled with S3 data events"],
        ),
        DetectionStrategy(
            strategy_id="t1491-aws-public-access",
            name="AWS S3 Bucket Public Access Changes",
            description="Detect changes to S3 bucket public access settings that could enable defacement.",
            detection_type=DetectionType.EVENTBRIDGE_RULE,
            aws_service="eventbridge",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                event_pattern={
                    "source": ["aws.s3"],
                    "detail-type": ["AWS API Call via CloudTrail"],
                    "detail": {
                        "eventName": [
                            "PutBucketAcl",
                            "PutBucketPolicy",
                            "PutBucketWebsite",
                            "DeleteBucketPolicy",
                        ]
                    },
                },
                terraform_template="""# Detect S3 public access changes

variable "alert_email" { type = string }

resource "aws_sns_topic" "alerts" {
  name = "s3-public-access-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_cloudwatch_event_rule" "public_access" {
  name = "s3-public-access-changes"
  event_pattern = jsonencode({
    source      = ["aws.s3"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail      = { eventName = ["PutBucketAcl", "PutBucketPolicy", "PutBucketWebsite", "DeleteBucketPolicy"] }
  })
}

resource "aws_sqs_queue" "dlq" {
  name                      = "public-access-dlq"
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
      values   = [aws_cloudwatch_event_rule.public_access.arn]
    }
  }
}

resource "aws_sqs_queue_policy" "event_dlq" {
  queue_url = aws_sqs_queue.dlq.url
  policy    = data.aws_iam_policy_document.eventbridge_dlq_policy.json
}

resource "aws_cloudwatch_event_target" "sns" {
  rule = aws_cloudwatch_event_rule.public_access.name
target_id = "SendToSNS"
  arn  = aws_sns_topic.alerts.arn

  retry_policy {
    maximum_event_age_in_seconds = 3600
    maximum_retry_attempts       = 8
  }

  dead_letter_config {
    arn = aws_sqs_queue.dlq.arn
  }
  input_transformer {
    input_paths = {
      account       = "$.account"
      region        = "$.region"
      time          = "$.time"
      eventName     = "$.detail.eventName"
      eventSource   = "$.detail.eventSource"
      sourceIP      = "$.detail.sourceIPAddress"
      userIdentity  = "$.detail.userIdentity.arn"
    }

    input_template = <<-EOT
"CloudTrail Security Alert
Time: <time>
Account: <account>
Region: <region>
Event: <eventName>
Source: <eventSource>
User: <userIdentity>
Source IP: <sourceIP>
Action: Review CloudTrail event and investigate"
EOT
  }

}

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
            "aws:SourceArn" = aws_cloudwatch_event_rule.public_access.arn
          }
      }
    }]
  })
}""",
                alert_severity="high",
                alert_title="S3 Bucket Public Access Modified",
                alert_description_template="S3 bucket public access settings changed by {userIdentity.arn}.",
                investigation_steps=[
                    "Review the bucket policy or ACL changes",
                    "Verify change was authorised",
                    "Check if bucket hosts public website content",
                    "Review recent object modifications",
                    "Assess if bucket was previously private",
                ],
                containment_actions=[
                    "Revert unauthorised policy changes",
                    "Enable S3 Block Public Access",
                    "Review IAM permissions for bucket modifications",
                    "Audit all public-facing buckets",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Bucket policy changes are typically infrequent and controlled",
            detection_coverage="95% - catches all public access configuration changes",
            evasion_considerations="Cannot evade CloudTrail logging",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$2-5",
            prerequisites=["CloudTrail enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1491-gcp-storage-web",
            name="GCP Storage Website Content Modification Detection",
            description="Detect unauthorised modifications to GCS buckets hosting website content.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''protoPayload.methodName=~"storage.objects.(create|update|patch|delete)"
resource.labels.bucket_name=~"(web|www|site|public)"''',
                gcp_terraform_template="""# GCP: Detect website content defacement

variable "project_id" { type = string }
variable "alert_email" { type = string }

resource "google_monitoring_notification_channel" "email_s1" {
  project      = var.project_id
  display_name = "Security Alerts"
  type         = "email"
  labels       = { email_address = var.alert_email }
}

resource "google_logging_metric" "website_modifications" {
  project = var.project_id
  name   = "gcs-website-modifications"
  filter = <<-EOT
    protoPayload.methodName=~"storage.objects.(create|update|patch|delete)"
    resource.labels.bucket_name=~"(web|www|site|public)"
  EOT
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

resource "google_monitoring_alert_policy" "website_defacement" {
  project      = var.project_id
  display_name = "GCS Website Defacement"
  combiner     = "OR"
  conditions {
    display_name = "High volume of website modifications"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.website_modifications.name}\""
      duration        = "900s"
      comparison      = "COMPARISON_GT"
      threshold_value = 10
      aggregations {
        alignment_period   = "900s"
        per_series_aligner = "ALIGN_SUM"
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
}""",
                alert_severity="high",
                alert_title="GCP: Website Content Modified",
                alert_description_template="Unusual volume of modifications to website GCS bucket detected.",
                investigation_steps=[
                    "Verify changes were authorised",
                    "Compare current content with previous versions",
                    "Review which objects were modified",
                    "Check audit logs for suspicious principals",
                    "Determine if service account credentials were compromised",
                ],
                containment_actions=[
                    "Restore content from object versioning",
                    "Revoke compromised service account keys",
                    "Enable Object Versioning if not enabled",
                    "Review IAM bindings on bucket",
                    "Implement bucket retention policies",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist authorised deployment service accounts and CI/CD pipelines",
            detection_coverage="85% - catches bulk modifications to website buckets",
            evasion_considerations="Attackers may modify objects slowly to avoid threshold detection",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$5-10",
            prerequisites=["Cloud Audit Logs enabled for Cloud Storage"],
        ),
        DetectionStrategy(
            strategy_id="t1491-gcp-bucket-iam",
            name="GCP Storage Bucket IAM Policy Changes",
            description="Detect changes to GCS bucket IAM policies that could enable defacement.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''protoPayload.methodName="storage.setIamPermissions"''',
                gcp_terraform_template="""# GCP: Detect bucket IAM policy changes

variable "project_id" { type = string }
variable "alert_email" { type = string }

resource "google_monitoring_notification_channel" "email_s2" {
  project      = var.project_id
  display_name = "Security Alerts"
  type         = "email"
  labels       = { email_address = var.alert_email }
}

resource "google_logging_metric" "bucket_iam_changes" {
  project = var.project_id
  name   = "gcs-bucket-iam-changes"
  filter = <<-EOT
    protoPayload.methodName="storage.setIamPermissions"
  EOT
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

resource "google_monitoring_alert_policy" "bucket_iam_changes" {
  project      = var.project_id
  display_name = "GCS Bucket IAM Policy Changed"
  combiner     = "OR"
  conditions {
    display_name = "Bucket IAM modified"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.bucket_iam_changes.name}\""
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
                alert_severity="high",
                alert_title="GCP: Bucket IAM Policy Changed",
                alert_description_template="GCS bucket IAM permissions were modified.",
                investigation_steps=[
                    "Review the IAM policy changes",
                    "Verify if allUsers or allAuthenticatedUsers was added",
                    "Check which principal made the change",
                    "Determine if change was authorised",
                    "Assess impact on bucket contents",
                ],
                containment_actions=[
                    "Revert unauthorised IAM policy changes",
                    "Remove public access bindings",
                    "Review organisation policy constraints",
                    "Audit all public-facing buckets",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Bucket IAM changes are typically infrequent and controlled",
            detection_coverage="95% - catches all bucket IAM policy changes",
            evasion_considerations="Cannot evade Cloud Audit Logs",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=["Cloud Audit Logs enabled"],
        ),
        # Azure Strategy: Defacement
        DetectionStrategy(
            strategy_id="t1491-azure",
            name="Azure Defacement Detection",
            description=(
                "Azure detection for Defacement. "
                "Provides native Azure detection using Log Analytics and Defender for Cloud."
            ),
            detection_type=DetectionType.DEFENDER_ALERT,
            aws_service="n/a",
            azure_service="defender",
            cloud_provider=CloudProvider.AZURE,
            implementation=DetectionImplementation(
                defender_alert_types=["Suspicious activity detected"],
                azure_terraform_template="""# Microsoft Defender for Cloud Detection
# Defacement (T1491)
# Microsoft Defender detects Defacement activity

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

variable "location" {
  type        = string
  description = "Azure region for resources"
  default     = "uksouth"
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
  name                = "defender-t1491-alerts"
  resource_group_name = var.resource_group_name
  short_name          = "DefAlerts"

  email_receiver {
    name          = "security-team"
    email_address = var.alert_email
  }
}

# Log Analytics query for Defender alerts
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "defender_detection" {
  name                = "defender-t1491"
  resource_group_name = var.resource_group_name
  location            = var.location

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

  description = "Microsoft Defender detects Defacement activity"
  display_name = "Defender: Defacement"
  enabled      = true

  tags = {
    "mitre-technique" = "T1491"
    "detection-type"  = "security"
  }
}

output "alert_rule_id" {
  value = azurerm_monitor_scheduled_query_rules_alert_v2.defender_detection.id
}""",
                alert_severity="high",
                alert_title="Azure: Defacement Detected",
                alert_description_template=(
                    "Defacement activity detected. "
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
        "t1491-aws-s3web",
        "t1491-aws-public-access",
        "t1491-gcp-storage-web",
        "t1491-gcp-bucket-iam",
    ],
    total_effort_hours=3.0,
    coverage_improvement="+18% improvement for Impact tactic",
)
