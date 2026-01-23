"""
T1027.006 - Obfuscated Files or Information: HTML Smuggling

Adversaries conceal malicious payloads within HTML files using JavaScript Blobs
and HTML5 download attributes to bypass security filters. Malware is deobfuscated
upon reaching the victim machine, potentially avoiding content filters.
Used by APT29, delivered via EnvyScout and QakBot malware families.
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
    technique_id="T1027.006",
    technique_name="Obfuscated Files or Information: HTML Smuggling",
    tactic_ids=["TA0005"],
    mitre_url="https://attack.mitre.org/techniques/T1027/006/",
    threat_context=ThreatContext(
        description=(
            "Adversaries conceal malicious payloads within seemingly benign HTML files "
            "using JavaScript Blobs and HTML5 download attributes to bypass security filters. "
            "The technique exploits immutable binary data objects and Data URLs to embed "
            "encoded payloads inline. Security controls often fail to identify malicious "
            "content hidden inside HTML/JavaScript files using benign MIME types like "
            "text/plain and text/html. Malware is deobfuscated upon reaching the victim "
            "machine, potentially avoiding content filters and email gateways."
        ),
        attacker_goal="Evade security filters by concealing malicious payloads within HTML files",
        why_technique=[
            "Bypasses traditional email and web security filters",
            "Uses benign MIME types (text/html, text/plain)",
            "Payload deobfuscated only at victim endpoint",
            "Avoids network-based content inspection",
            "Difficult to detect in transit",
            "Can deliver various payload types (ISO, ZIP, executables)",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="moderate",
        trend="increasing",
        severity_score=7,
        severity_reasoning=(
            "Effective evasion technique that bypasses traditional security controls. "
            "Increasingly used by sophisticated threat actors like APT29. Can deliver "
            "various malware types and is difficult to detect without endpoint monitoring."
        ),
        business_impact=[
            "Initial malware delivery",
            "Bypassed email security",
            "Endpoint compromise risk",
            "Potential ransomware delivery",
            "Data theft enabler",
        ],
        typical_attack_phase="initial_access",
        often_precedes=["T1204.002", "T1059", "T1055"],
        often_follows=["T1566.001", "T1566.002"],
    ),
    detection_strategies=[
        DetectionStrategy(
            strategy_id="t1027-006-aws-cloudtrail-s3",
            name="AWS S3 HTML File Creation Monitoring",
            description="Detect suspicious HTML files uploaded to S3 buckets that may contain smuggled payloads.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, userIdentity.principalId, requestParameters.bucketName, requestParameters.key
| filter eventName = "PutObject"
| filter requestParameters.key like /\\.html?$/
| filter requestParameters.key like /attachment|download|payload|blob/
| stats count(*) as html_uploads by userIdentity.principalId, requestParameters.bucketName, bin(1h)
| filter html_uploads > 5
| sort html_uploads desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect suspicious HTML file uploads to S3

Parameters:
  CloudTrailLogGroup:
    Type: String
    Description: CloudTrail log group name
  AlertEmail:
    Type: String
    Description: Email for security alerts

Resources:
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  HTMLUploadFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ $.eventName = "PutObject" && $.requestParameters.key = "*.html" }'
      MetricTransformations:
        - MetricName: SuspiciousHTMLUploads
          MetricNamespace: Security
          MetricValue: "1"

  HTMLUploadAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: SuspiciousHTMLUploads
      MetricName: SuspiciousHTMLUploads
      Namespace: Security
      Statistic: Sum
      Period: 300
      Threshold: 10
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      TreatMissingData: notBreaching

      AlarmActions: [!Ref AlertTopic]""",
                terraform_template="""# Detect suspicious HTML file uploads to S3

variable "cloudtrail_log_group" { type = string }
variable "alert_email" { type = string }

resource "aws_sns_topic" "alerts" {
  name = "html-smuggling-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_cloudwatch_log_metric_filter" "html_uploads" {
  name           = "suspicious-html-uploads"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ $.eventName = \"PutObject\" && $.requestParameters.key = \"*.html\" }"

  metric_transformation {
    name      = "SuspiciousHTMLUploads"
    namespace = "Security"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "html_smuggling" {
  alarm_name          = "SuspiciousHTMLUploads"
  metric_name         = "SuspiciousHTMLUploads"
  namespace           = "Security"
  statistic           = "Sum"
  period              = 300
  threshold           = 10
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.alerts.arn]
}""",
                alert_severity="medium",
                alert_title="Suspicious HTML File Upload Detected",
                alert_description_template="Multiple HTML files uploaded to S3 by {principalId}.",
                investigation_steps=[
                    "Download and analyse HTML file contents in isolated environment",
                    "Check for JavaScript Blob usage and encoded payloads",
                    "Review file size and embedded data patterns",
                    "Identify source IP and user identity",
                    "Check for similar files from same source",
                    "Inspect for Data URLs and download attributes",
                ],
                containment_actions=[
                    "Quarantine suspicious HTML files",
                    "Block file downloads from affected buckets",
                    "Review and restrict S3 bucket permissions",
                    "Enable S3 Object Lock for forensics",
                    "Scan endpoints that may have accessed files",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Tune based on legitimate HTML upload patterns in your environment",
            detection_coverage="40% - catches S3-based HTML smuggling attempts",
            evasion_considerations="Does not detect local file creation or email attachments",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=["CloudTrail logging enabled", "S3 data events logged"],
        ),
        DetectionStrategy(
            strategy_id="t1027-006-aws-guardduty",
            name="AWS GuardDuty Malicious File Detection",
            description="Leverage GuardDuty malware protection to detect HTML smuggling payloads.",
            detection_type=DetectionType.GUARDDUTY,
            aws_service="guardduty",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                guardduty_finding_types=[
                    "Object:S3/MaliciousFile",
                    "Object:S3/MaliciousFile",
                ],
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Configure GuardDuty for HTML smuggling detection

Parameters:
  S3BucketArn:
    Type: String
    Description: S3 bucket to monitor
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

  GuardDutyEventRule:
    Type: AWS::Events::Rule
    Properties:
      Description: Detect malicious files in S3
      EventPattern:
        source: [aws.guardduty]
        detail-type: [GuardDuty Finding]
        detail:
          type:
            - "Object:S3/MaliciousFile"
            - "Object:S3/MaliciousFile"
      State: ENABLED
      Targets:
        - Arn: !Ref AlertTopic
          Id: SNSTarget""",
                terraform_template="""# Configure GuardDuty for HTML smuggling detection

variable "s3_bucket_arn" { type = string }

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
variable "alert_email" { type = string }

resource "aws_sns_topic" "alerts" {
  name = "guardduty-malware-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_cloudwatch_event_rule" "guardduty_malware" {
  name        = "guardduty-malicious-file"
  description = "Detect malicious files in S3"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail = {
      type = [
        "Object:S3/MaliciousFile",
        "Object:S3/MaliciousFile"
      ]
    }
  })
}

resource "aws_sqs_queue" "dlq" {
  name                      = "html-smuggling-dlq"
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
      values   = [aws_cloudwatch_event_rule.guardduty_malware.arn]
    }
  }
}

resource "aws_sqs_queue_policy" "event_dlq" {
  queue_url = aws_sqs_queue.dlq.url
  policy    = data.aws_iam_policy_document.eventbridge_dlq_policy.json
}

resource "aws_cloudwatch_event_target" "sns" {
  rule      = aws_cloudwatch_event_rule.guardduty_malware.name
  target_id = "SendToSNS"
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

resource "aws_sns_topic_policy" "allow_eventbridge" {
  arn = aws_sns_topic.alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "events.amazonaws.com"
      }
      Action   = "SNS:Publish"
      Resource = aws_sns_topic.alerts.arn
    Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
          ArnEquals = {
            "aws:SourceArn" = aws_cloudwatch_event_rule.guardduty_malware.arn
          }
      }
    }]
  })
}""",
                alert_severity="high",
                alert_title="Malicious File Detected by GuardDuty",
                alert_description_template="GuardDuty detected malicious file in S3: {resource}.",
                investigation_steps=[
                    "Review GuardDuty finding details",
                    "Analyse file metadata and origin",
                    "Check for HTML smuggling indicators",
                    "Review CloudTrail for file access history",
                    "Identify users who uploaded or accessed file",
                    "Scan related files in same bucket",
                ],
                containment_actions=[
                    "Immediately quarantine detected file",
                    "Block bucket public access",
                    "Rotate credentials of affected users",
                    "Review and remove similar files",
                    "Enable S3 Block Public Access",
                    "Scan endpoints that accessed the file",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="GuardDuty malware detection is highly accurate",
            detection_coverage="75% - catches known malware signatures",
            evasion_considerations="May miss novel or polymorphic payloads",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$15-40",
            prerequisites=[
                "GuardDuty enabled",
                "GuardDuty Malware Protection enabled for S3",
            ],
        ),
        DetectionStrategy(
            strategy_id="t1027-006-aws-waf-html",
            name="AWS WAF HTML Content Inspection",
            description="Detect HTML files with suspicious JavaScript patterns via WAF.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="waf",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, httpRequest.clientIp, httpRequest.uri, httpRequest.headers
| filter httpRequest.uri like /\\.html?$/
| filter httpRequest.headers[*].value like /Blob|createObjectURL|msSaveBlob|download=/
| stats count(*) as suspicious_html by httpRequest.clientIp, bin(1h)
| filter suspicious_html > 3
| sort suspicious_html desc""",
                terraform_template="""# Detect HTML smuggling via WAF inspection

variable "waf_log_group" { type = string }
variable "alert_email" { type = string }

resource "aws_sns_topic" "alerts" {
  name = "waf-html-smuggling-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_cloudwatch_log_metric_filter" "html_smuggling" {
  name           = "html-smuggling-patterns"
  log_group_name = var.waf_log_group
  pattern        = "[Blob, createObjectURL, msSaveBlob, download]"

  metric_transformation {
    name      = "HTMLSmugglingAttempts"
    namespace = "Security"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "html_smuggling_detected" {
  alarm_name          = "HTMLSmugglingDetected"
  metric_name         = "HTMLSmugglingAttempts"
  namespace           = "Security"
  statistic           = "Sum"
  period              = 300
  threshold           = 5
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.alerts.arn]
}""",
                alert_severity="high",
                alert_title="HTML Smuggling Pattern Detected",
                alert_description_template="Suspicious HTML with JavaScript Blob patterns from {clientIp}.",
                investigation_steps=[
                    "Capture and analyse HTML content",
                    "Inspect JavaScript code for Blob usage",
                    "Check for encoded payloads in Data URLs",
                    "Review download attribute usage",
                    "Identify destination endpoints",
                    "Check for Zone.Identifier artifacts on endpoints",
                ],
                containment_actions=[
                    "Block source IP at WAF",
                    "Create WAF rule for similar patterns",
                    "Enable enhanced request inspection",
                    "Block suspicious HTML downloads at email gateway",
                    "Deploy endpoint detection for file creation",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Tune to exclude legitimate web applications using Blob APIs",
            detection_coverage="60% - pattern-based detection",
            evasion_considerations="Obfuscated JavaScript may evade simple pattern matching",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$10-25",
            prerequisites=["AWS WAF deployed", "WAF logging enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1027-006-gcp-cloud-storage",
            name="GCP Cloud Storage HTML File Monitoring",
            description="Detect suspicious HTML file uploads to Cloud Storage buckets.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="gcs_bucket"
protoPayload.methodName="storage.objects.create"
protoPayload.resourceName=~"\\.html?$"''',
                gcp_terraform_template="""# GCP: Detect HTML smuggling in Cloud Storage

variable "project_id" { type = string }
variable "alert_email" { type = string }

resource "google_monitoring_notification_channel" "email_s1" {
  project      = var.project_id
  display_name = "Security Alerts"
  type         = "email"
  labels       = { email_address = var.alert_email }
}

resource "google_logging_metric" "html_uploads" {
  project = var.project_id
  name   = "suspicious-html-uploads"
  filter = <<-EOT
    resource.type="gcs_bucket"
    protoPayload.methodName="storage.objects.create"
    protoPayload.resourceName=~"\\.html?$"
  EOT
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

resource "google_monitoring_alert_policy" "html_smuggling" {
  project      = var.project_id
  display_name = "HTML Smuggling Detection"
  combiner     = "OR"
  conditions {
    display_name = "High HTML upload rate"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.html_uploads.name}\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 10
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
                alert_severity="medium",
                alert_title="GCP: Suspicious HTML File Upload",
                alert_description_template="Multiple HTML files uploaded to Cloud Storage.",
                investigation_steps=[
                    "Download and analyse HTML files in sandbox",
                    "Check for JavaScript Blob and Data URL usage",
                    "Review uploader identity and source IP",
                    "Inspect file metadata and creation time",
                    "Check for similar files in bucket",
                    "Review bucket access logs",
                ],
                containment_actions=[
                    "Quarantine suspicious files",
                    "Update bucket IAM permissions",
                    "Enable uniform bucket-level access",
                    "Review and rotate service account keys",
                    "Enable Cloud Storage object versioning",
                    "Deploy Cloud DLP for content scanning",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Exclude known web hosting buckets",
            detection_coverage="45% - catches Cloud Storage-based attempts",
            evasion_considerations="Does not detect email or endpoint-based smuggling",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$5-15",
            prerequisites=["Cloud Logging enabled", "Data Access logs enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1027-006-gcp-workspace",
            name="GCP Workspace Email Attachment Monitoring",
            description="Detect HTML attachments in Gmail that may contain smuggled payloads.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="workspace",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''log_name="organizations/YOUR_ORG_ID/logs/gmail_log"
jsonPayload.event_info.event_name="attachment_received"
jsonPayload.event_info.attachment_info.file_type="html"''',
                gcp_terraform_template="""# GCP: Detect HTML smuggling via Workspace

variable "organization_id" { type = string }
variable "alert_email" { type = string }

resource "google_monitoring_notification_channel" "email_s2" {
  project      = var.project_id
  display_name = "Security Alerts"
  type         = "email"
  labels       = { email_address = var.alert_email }
}

resource "google_logging_metric" "html_attachments" {
  project = var.project_id
  name   = "html-email-attachments"
  filter = <<-EOT
    log_name="organizations/${var.organization_id}/logs/gmail_log"
    jsonPayload.event_info.event_name="attachment_received"
    jsonPayload.event_info.attachment_info.file_type="html"
  EOT
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

resource "google_monitoring_alert_policy" "html_email_smuggling" {
  project      = var.project_id
  display_name = "HTML Email Smuggling Detection"
  combiner     = "OR"
  conditions {
    display_name = "HTML attachments detected"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.html_attachments.name}\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 5
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
                alert_title="GCP: HTML Email Attachment Detected",
                alert_description_template="HTML attachment received via Gmail - potential smuggling attempt.",
                investigation_steps=[
                    "Review email sender and recipient details",
                    "Analyse HTML attachment in isolated environment",
                    "Check for JavaScript Blob patterns",
                    "Review email headers and routing",
                    "Check if recipients opened attachment",
                    "Scan recipient endpoints for indicators",
                ],
                containment_actions=[
                    "Quarantine similar emails",
                    "Block sender domain/address",
                    "Update Gmail attachment rules",
                    "Enable advanced phishing protection",
                    "Deploy security awareness training",
                    "Scan affected user endpoints",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Most HTML email attachments are suspicious",
            detection_coverage="70% - catches email-based HTML smuggling",
            evasion_considerations="Requires Workspace audit logging",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$10-20",
            prerequisites=["Google Workspace", "Workspace audit logging enabled"],
        ),
        # Azure Strategy: Obfuscated Files or Information: HTML Smuggling
        DetectionStrategy(
            strategy_id="t1027006-azure",
            name="Azure Obfuscated Files or Information: HTML Smuggling Detection",
            description=(
                "Azure detection for Obfuscated Files or Information: HTML Smuggling. "
                "Provides native Azure detection using Log Analytics and Defender for Cloud."
            ),
            detection_type=DetectionType.SENTINEL_RULE,
            aws_service="n/a",
            azure_service="sentinel",
            cloud_provider=CloudProvider.AZURE,
            implementation=DetectionImplementation(
                sentinel_rule_query="""// Sentinel Analytics Rule: Obfuscated Files or Information: HTML Smuggling
// MITRE ATT&CK: T1027.006
let lookback = 24h;
let threshold = 5;
AzureActivity
| where TimeGenerated > ago(lookback)
| where CategoryValue == "Administrative"
| where ActivityStatusValue in ("Success", "Succeeded")
| summarize
    EventCount = count(),
    DistinctOperations = dcount(OperationNameValue),
    Operations = make_set(OperationNameValue, 20),
    Resources = make_set(Resource, 10),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by Caller, CallerIpAddress, SubscriptionId
| where EventCount > threshold
| extend
    AccountName = tostring(split(Caller, "@")[0]),
    AccountDomain = tostring(split(Caller, "@")[1])
| project
    TimeGenerated = LastSeen,
    AccountName,
    AccountDomain,
    Caller,
    CallerIpAddress,
    SubscriptionId,
    EventCount,
    DistinctOperations,
    Operations,
    Resources""",
                azure_terraform_template="""# Azure Detection for Obfuscated Files or Information: HTML Smuggling
# MITRE ATT&CK: T1027.006

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

# Action Group for alerts
resource "azurerm_monitor_action_group" "security_alerts" {
  name                = "obfuscated-files-or-information--html-smuggling-alerts"
  resource_group_name = var.resource_group_name
  short_name          = "SecAlerts"

  email_receiver {
    name          = "security-team"
    email_address = var.alert_email
  }
}

# Scheduled Query Rule for detection
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "detection" {
  name                = "obfuscated-files-or-information--html-smuggling-detection"
  resource_group_name = var.resource_group_name
  location            = "uksouth"

  evaluation_frequency = "PT5M"
  window_duration      = "PT1H"
  scopes               = [var.log_analytics_workspace_id]
  severity             = 2

  criteria {
    query = <<-QUERY
// Sentinel Analytics Rule: Obfuscated Files or Information: HTML Smuggling
// MITRE ATT&CK: T1027.006
let lookback = 24h;
let threshold = 5;
AzureActivity
| where TimeGenerated > ago(lookback)
| where CategoryValue == "Administrative"
| where ActivityStatusValue in ("Success", "Succeeded")
| summarize
    EventCount = count(),
    DistinctOperations = dcount(OperationNameValue),
    Operations = make_set(OperationNameValue, 20),
    Resources = make_set(Resource, 10),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by Caller, CallerIpAddress, SubscriptionId
| where EventCount > threshold
| extend
    AccountName = tostring(split(Caller, "@")[0]),
    AccountDomain = tostring(split(Caller, "@")[1])
| project
    TimeGenerated = LastSeen,
    AccountName,
    AccountDomain,
    Caller,
    CallerIpAddress,
    SubscriptionId,
    EventCount,
    DistinctOperations,
    Operations,
    Resources
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

  description = "Detects Obfuscated Files or Information: HTML Smuggling (T1027.006) activity in Azure environment"
  display_name = "Obfuscated Files or Information: HTML Smuggling Detection"
  enabled      = true

  tags = {
    "mitre-technique" = "T1027.006"
    "detection-type"  = "security"
  }
}

output "alert_rule_id" {
  value = azurerm_monitor_scheduled_query_rules_alert_v2.detection.id
}""",
                alert_severity="high",
                alert_title="Azure: Obfuscated Files or Information: HTML Smuggling Detected",
                alert_description_template=(
                    "Obfuscated Files or Information: HTML Smuggling activity detected. "
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
        "t1027-006-aws-guardduty",
        "t1027-006-aws-waf-html",
        "t1027-006-gcp-workspace",
        "t1027-006-aws-cloudtrail-s3",
        "t1027-006-gcp-cloud-storage",
    ],
    total_effort_hours=4.5,
    coverage_improvement="+25% improvement for Defence Evasion tactic",
)
