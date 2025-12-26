"""
T1566 - Phishing

Adversaries send phishing messages to gain access to victim systems via
malicious attachments, links, or third-party services. Initial access technique
used by APT29, Kimsuky, LAPSUS$, Scattered Spider.
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
    technique_id="T1566",
    technique_name="Phishing",
    tactic_ids=["TA0001"],
    mitre_url="https://attack.mitre.org/techniques/T1566/",
    threat_context=ThreatContext(
        description=(
            "Adversaries send phishing messages via email or third-party services "
            "to gain access to victim systems. Phishing typically involves malicious "
            "attachments, embedded links, or callback schemes that trick users into "
            "executing code or providing credentials. Techniques include email spoofing, "
            "thread hijacking, and hidden email rules."
        ),
        attacker_goal="Gain initial access through social engineering and malicious content delivery",
        why_technique=[
            "Bypasses perimeter security controls",
            "Exploits human trust and behaviour",
            "Low technical barrier for attackers",
            "Can scale to mass campaigns",
            "Effective against multi-factor authentication",
            "Thread hijacking increases legitimacy",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="common",
        trend="increasing",
        severity_score=9,
        severity_reasoning=(
            "Phishing remains the most common initial access vector, accounting for over 90% "
            "of successful breaches. Modern techniques like callback phishing and thread "
            "hijacking make detection increasingly difficult. Can lead to complete environment "
            "compromise including cloud infrastructure."
        ),
        business_impact=[
            "Initial access and credential theft",
            "Data breach and exfiltration",
            "Ransomware deployment",
            "Business email compromise",
            "Regulatory violations (GDPR, HIPAA)",
            "Reputation damage",
        ],
        typical_attack_phase="initial_access",
        often_precedes=["T1078.004", "T1114.003", "T1110", "T1621"],
        often_follows=[],
    ),
    detection_strategies=[
        DetectionStrategy(
            strategy_id="t1566-aws-ses-analysis",
            name="AWS SES Email Security Detection",
            description=(
                "Detect suspicious email patterns in AWS SES including spam, malicious "
                "attachments, and phishing attempts using SES event publishing."
            ),
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, mail.destination, mail.source, mail.commonHeaders.subject, eventType
| filter eventSource = "ses.amazonaws.com"
| filter eventType in ["Bounce", "Complaint", "Reject"]
| stats count(*) as suspicious_events by mail.source, bin(1h)
| filter suspicious_events > 5
| sort suspicious_events desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: AWS SES phishing detection with SNS alerts

Parameters:
  AlertEmail:
    Type: String
    Description: Email address for security alerts

Resources:
  # Step 1: Create SNS topic for phishing alerts
  PhishingAlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      DisplayName: SES Phishing Alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Create EventBridge rule for suspicious email events
  SuspiciousEmailRule:
    Type: AWS::Events::Rule
    Properties:
      Name: SES-PhishingDetection
      Description: Detect suspicious email patterns in SES
      EventPattern:
        source:
          - aws.ses
        detail:
          eventType:
            - Bounce
            - Complaint
            - Reject
      State: ENABLED
      Targets:
        - Id: PhishingAlerts
          Arn: !Ref PhishingAlertTopic

  # Step 3: Dead letter queue
  DeadLetterQueue:
    Type: AWS::SQS::Queue
    Properties:
      QueueName: ses-phishing-dlq
      MessageRetentionPeriod: 1209600

  # Step 4: Allow EventBridge to publish to SNS with scoped policy
  TopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics:
        - !Ref PhishingAlertTopic
      PolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Sid: AllowEventBridgePublishScoped
            Effect: Allow
            Principal:
              Service: events.amazonaws.com
            Action: sns:Publish
            Resource: !Ref PhishingAlertTopic
            Condition:
              StringEquals:
                AWS:SourceAccount: !Ref AWS::AccountId
              ArnEquals:
                aws:SourceArn: !GetAtt SuspiciousEmailRule.Arn""",
                terraform_template="""# AWS SES phishing detection with alerts

variable "alert_email" {
  type        = string
  description = "Email address for security alerts"
}

# Step 1: Create SNS topic for phishing alerts
resource "aws_sns_topic" "phishing_alerts" {
  name         = "ses-phishing-alerts"
  kms_master_key_id = "alias/aws/sns"
  display_name = "SES Phishing Alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.phishing_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Create EventBridge rule for suspicious email events
resource "aws_cloudwatch_event_rule" "suspicious_email" {
  name        = "ses-phishing-detection"
  description = "Detect suspicious email patterns in SES"

  event_pattern = jsonencode({
    source = ["aws.ses"]
    detail = {
      eventType = ["Bounce", "Complaint", "Reject"]
    }
  })
}

data "aws_caller_identity" "current" {}

# Step 3: Dead letter queue
resource "aws_sqs_queue" "dlq" {
  name                      = "ses-phishing-dlq"
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
      values   = [aws_cloudwatch_event_rule.suspicious_email.arn]
    }
  }
}

resource "aws_sqs_queue_policy" "event_dlq" {
  queue_url = aws_sqs_queue.dlq.url
  policy    = data.aws_iam_policy_document.eventbridge_dlq_policy.json
}

# Step 4: EventBridge target with DLQ, retry, input transformer
resource "aws_cloudwatch_event_target" "sns" {
  rule      = aws_cloudwatch_event_rule.suspicious_email.name
  target_id = "PhishingAlerts"
  arn       = aws_sns_topic.phishing_alerts.arn

  retry_policy {
    maximum_event_age_in_seconds = 3600
    maximum_retry_attempts       = 8
  }

  dead_letter_config {
    arn = aws_sqs_queue.dlq.arn
  }

  input_transformer {
    input_paths = {
      account   = "$.account"
      region    = "$.region"
      time      = "$.time"
      eventType = "$.detail.eventType"
      source    = "$.detail.mail.source"
      dest      = "$.detail.mail.destination"
    }

    input_template = <<-EOT
"SES Phishing Alert (T1566)
time=<time> account=<account> region=<region>
event=<eventType> source=<source>
destination=<dest>
Action: Investigate sender and email content"
EOT
  }
}

# Step 5: Allow EventBridge to publish to SNS with scoped policy
resource "aws_sns_topic_policy" "allow_eventbridge" {
  arn = aws_sns_topic.phishing_alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowEventBridgePublishScoped"
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.phishing_alerts.arn
      Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
        ArnEquals = {
          "aws:SourceArn" = aws_cloudwatch_event_rule.suspicious_email.arn
        }
      }
    }]
  })
}""",
                alert_severity="high",
                alert_title="AWS SES: Suspicious Email Activity Detected",
                alert_description_template=(
                    "Suspicious email activity detected from {mail.source}. "
                    "Event type: {eventType}. Multiple bounces, complaints, or rejections "
                    "may indicate phishing campaign."
                ),
                investigation_steps=[
                    "Review the email source and subject line for legitimacy",
                    "Check if sender domain has valid SPF, DKIM, DMARC records",
                    "Analyse email content and attachments if available",
                    "Verify if any recipients clicked links or opened attachments",
                    "Check for similar emails from the same source",
                    "Review recipient list for targeted individuals",
                ],
                containment_actions=[
                    "Block sender address and domain in SES",
                    "Update email filtering rules to catch similar patterns",
                    "Notify affected users if emails were delivered",
                    "Review and strengthen email authentication (SPF/DKIM/DMARC)",
                    "Consider implementing AWS SES receipt rules for filtering",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Legitimate marketing emails may trigger bounces; whitelist known senders",
            detection_coverage="50% - covers SES-delivered emails only",
            evasion_considerations="Attackers using external email providers bypass SES detection",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$2-5",
            prerequisites=["AWS SES configured", "SES event publishing enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1566-aws-guardduty-malware",
            name="GuardDuty Malware Detection in S3",
            description=(
                "Detect malicious files uploaded to S3 buckets that could be distributed "
                "via phishing campaigns or stored for later use."
            ),
            detection_type=DetectionType.GUARDDUTY,
            aws_service="guardduty",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                guardduty_finding_types=[
                    "Discovery:S3/MaliciousIPCaller",
                    "Impact:S3/MaliciousIPCaller",
                    "Object:S3/MaliciousFile",
                ],
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: GuardDuty malware protection for phishing detection

Parameters:
  AlertEmail:
    Type: String

Resources:
  # Step 1: Enable GuardDuty with S3 protection
  GuardDutyDetector:
    Type: AWS::GuardDuty::Detector
    Properties:
      Enable: true
      DataSources:
        S3Logs:
          Enable: true

  # Step 2: Create SNS topic for malware alerts
  MalwareAlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 3: Route malware findings to SNS
  MalwareFindingsRule:
    Type: AWS::Events::Rule
    Properties:
      EventPattern:
        source:
          - aws.guardduty
        detail:
          type:
            - prefix: "Discovery:S3"
            - prefix: "Impact:S3"
            - prefix: "Execution:S3"
      Targets:
        - Id: Email
          Arn: !Ref MalwareAlertTopic

  TopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics:
        - !Ref MalwareAlertTopic
      PolicyDocument:
        Statement:
          - Effect: Allow
            Principal:
              Service: events.amazonaws.com
            Action: sns:Publish
            Resource: !Ref MalwareAlertTopic""",
                terraform_template="""# GuardDuty malware protection for phishing detection

variable "alert_email" { type = string }

# Step 1: Enable GuardDuty with S3 protection
resource "aws_guardduty_detector" "main" {
  enable = true

  datasources {
    s3_logs {
      enable = true
    }
  }
}

# Step 2: Create SNS topic for malware alerts
resource "aws_sns_topic" "malware_alerts" {
  name = "guardduty-malware-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.malware_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 3: Route malware findings to SNS
resource "aws_cloudwatch_event_rule" "malware_findings" {
  name = "guardduty-malware-detection"

  event_pattern = jsonencode({
    source = ["aws.guardduty"]
    "detail-type" = ["GuardDuty Finding"]
    detail = {
      type = [
        { prefix = "Discovery:S3" },
        { prefix = "Impact:S3" },
        { prefix = "Execution:S3" }
      ]
    }
  })
}

resource "aws_cloudwatch_event_target" "sns" {
  rule      = aws_cloudwatch_event_rule.malware_findings.name
  target_id = "Email"
  arn       = aws_sns_topic.malware_alerts.arn
}

resource "aws_sns_topic_policy" "allow_eventbridge" {
  arn = aws_sns_topic.malware_alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.malware_alerts.arn
    Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
      }
    }]
  })
}""",
                alert_severity="critical",
                alert_title="GuardDuty: Malicious File Detected in S3",
                alert_description_template=(
                    "GuardDuty detected malicious activity in S3: {finding_type}. "
                    "Bucket: {bucket_name}. This may indicate phishing infrastructure or malware distribution."
                ),
                investigation_steps=[
                    "Review the S3 bucket and object identified in the finding",
                    "Check bucket access logs for who uploaded the file",
                    "Analyse the malicious file if safe to do so",
                    "Review other objects in the same bucket",
                    "Check CloudTrail for related API activity",
                    "Identify any users who may have downloaded the file",
                ],
                containment_actions=[
                    "Quarantine or delete the malicious object immediately",
                    "Block public access to the bucket",
                    "Rotate credentials used to upload the file",
                    "Review and restrict bucket permissions",
                    "Enable S3 Block Public Access",
                    "Scan other buckets for similar content",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="GuardDuty malware detection is highly accurate",
            detection_coverage="70% - covers S3-based phishing infrastructure",
            evasion_considerations="Encrypted or obfuscated malware may evade initial detection",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$4 per million events",
            prerequisites=["AWS account with GuardDuty permissions"],
        ),
        DetectionStrategy(
            strategy_id="t1566-aws-workmail-rules",
            name="AWS WorkMail Suspicious Rule Detection",
            description=(
                "Detect creation of email forwarding rules and filters that could "
                "hide phishing emails or exfiltrate sensitive communications."
            ),
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, eventName, userIdentity.arn, requestParameters
| filter eventSource = "workmail.amazonaws.com"
| filter eventName in ["CreateInboxRule", "UpdateInboxRule", "PutMailboxPermissions"]
| sort @timestamp desc""",
                terraform_template="""# Detect suspicious WorkMail rule changes

variable "cloudtrail_log_group" { type = string }
variable "alert_email" { type = string }

resource "aws_sns_topic" "alerts" {
  name = "workmail-rule-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_cloudwatch_log_metric_filter" "suspicious_rules" {
  name           = "workmail-suspicious-rules"
  log_group_name = var.cloudtrail_log_group

  pattern = "{ ($.eventSource = \"workmail.amazonaws.com\") && ($.eventName = \"CreateInboxRule\" || $.eventName = \"UpdateInboxRule\" || $.eventName = \"PutMailboxPermissions\") }"

  metric_transformation {
    name      = "WorkMailRuleChanges"
    namespace = "Security/T1566"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "rule_change" {
  alarm_name          = "T1566-WorkMailRuleChange"
  metric_name         = "WorkMailRuleChanges"
  namespace           = "Security/T1566"
  statistic           = "Sum"
  period              = 300
  threshold           = 0
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.alerts.arn]
}""",
                alert_severity="medium",
                alert_title="WorkMail: Email Rule Modified",
                alert_description_template=(
                    "Email rule was created or modified by {userIdentity.arn}. "
                    "Event: {eventName}. This could be used to hide phishing emails or forward sensitive data."
                ),
                investigation_steps=[
                    "Review the specific rule that was created or modified",
                    "Check if the rule forwards emails externally",
                    "Verify the user who created the rule",
                    "Check for rules that auto-delete certain emails",
                    "Review other rules for the same user",
                ],
                containment_actions=[
                    "Delete suspicious rules immediately",
                    "Review all mailbox rules organisation-wide",
                    "Restrict rule creation permissions",
                    "Reset credentials if compromise suspected",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Users rarely create email rules; investigate all occurrences",
            detection_coverage="85% - covers WorkMail rule changes",
            evasion_considerations="MAPI-based hidden rules may not appear in CloudTrail",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$5-10",
            prerequisites=["CloudTrail enabled for WorkMail events"],
        ),
        DetectionStrategy(
            strategy_id="t1566-gcp-gmail-api",
            name="GCP Workspace Phishing Detection",
            description=(
                "Detect phishing-related activities in Google Workspace including "
                "suspicious email forwarding, attachment downloads, and link clicks."
            ),
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""protoPayload.serviceName="admin.googleapis.com"
AND (
  protoPayload.methodName=~"gmail.*forward"
  OR protoPayload.methodName=~"SUSPICIOUS_LOGIN"
  OR protoPayload.methodName=~"CHANGE_EMAIL_SETTINGS"
  OR protoPayload.eventName=~"phish"
)""",
                gcp_terraform_template="""# GCP: Workspace phishing detection

variable "project_id" { type = string }
variable "alert_email" { type = string }

# Step 1: Create notification channel
resource "google_monitoring_notification_channel" "email" {
  display_name = "Security Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Create log metric for phishing indicators
resource "google_logging_metric" "phishing_activity" {
  name   = "workspace-phishing-indicators"
  filter = <<-EOT
    protoPayload.serviceName="admin.googleapis.com"
    AND (
      protoPayload.methodName=~"gmail.*forward"
      OR protoPayload.methodName=~"SUSPICIOUS_LOGIN"
      OR protoPayload.methodName=~"CHANGE_EMAIL_SETTINGS"
      OR protoPayload.eventName=~"phish"
    )
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Create alert policy for phishing activity
resource "google_monitoring_alert_policy" "phishing_alert" {
  display_name = "Workspace Phishing Activity"
  combiner     = "OR"

  conditions {
    display_name = "Phishing indicator detected"

    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.phishing_activity.name}\""
      duration        = "0s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]

  alert_strategy {
    auto_close = "604800s"  # 7 days
  }
}""",
                alert_severity="high",
                alert_title="GCP Workspace: Phishing Activity Detected",
                alert_description_template=(
                    "Suspicious activity detected in Google Workspace that may indicate "
                    "phishing attempt or compromise. Review immediately."
                ),
                investigation_steps=[
                    "Review the specific Workspace audit log entry",
                    "Check if email forwarding rules were created",
                    "Verify user login location and device",
                    "Review recent email activity for the affected user",
                    "Check for unusual email send patterns",
                    "Look for credential sharing or delegation changes",
                ],
                containment_actions=[
                    "Suspend affected user account if compromise confirmed",
                    "Remove unauthorised email forwarding rules",
                    "Reset user password and revoke sessions",
                    "Enable enhanced security features for affected users",
                    "Review organisation-wide email security settings",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Legitimate forwarding rules exist; baseline normal activity",
            detection_coverage="75% - covers Workspace email security events",
            evasion_considerations="Some phishing may occur entirely via external email",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$10-20",
            prerequisites=["Google Workspace with audit logging enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1566-gcp-safe-browsing",
            name="GCP Web Risk API for Malicious URLs",
            description=(
                "Leverage Google Web Risk API to detect malicious URLs that may be "
                "distributed via phishing campaigns, checking links in real-time."
            ),
            detection_type=DetectionType.CLOUD_FUNCTIONS,
            aws_service="n/a",
            gcp_service="cloud_functions",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="cloud_function"
protoPayload.methodName="webrisk.uris.search"
jsonPayload.threat_types!=""''',
                gcp_terraform_template="""# GCP: Web Risk API for malicious URL detection

variable "project_id" { type = string }
variable "alert_email" { type = string }

# Step 1: Enable Web Risk API
resource "google_project_service" "webrisk" {
  service = "webrisk.googleapis.com"
}

# Step 2: Create notification channel
resource "google_monitoring_notification_channel" "email" {
  display_name = "Security Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 3: Create alert for malicious URL detections
resource "google_logging_metric" "malicious_urls" {
  name   = "malicious-url-detections"
  filter = <<-EOT
    resource.type="cloud_function"
    protoPayload.methodName="webrisk.uris.search"
    jsonPayload.threat_types!=""
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

resource "google_monitoring_alert_policy" "malicious_url_alert" {
  display_name = "Malicious URL Detected"
  combiner     = "OR"

  conditions {
    display_name = "Web Risk threat detected"

    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.malicious_urls.name}\""
      duration        = "60s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]
}""",
                alert_severity="high",
                alert_title="GCP: Malicious URL Detected via Web Risk",
                alert_description_template=(
                    "Web Risk API detected malicious URL. This may indicate phishing campaign "
                    "or malware distribution. Investigate immediately."
                ),
                investigation_steps=[
                    "Review the URL and threat classification",
                    "Identify source of the URL (email, upload, etc.)",
                    "Check if URL was accessed by any users",
                    "Search logs for other instances of the domain",
                    "Analyse threat type (phishing, malware, etc.)",
                ],
                containment_actions=[
                    "Block domain at organisation firewall/proxy",
                    "Add to blocklist in email gateway",
                    "Notify users who may have clicked the link",
                    "Scan systems for compromise if clicked",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Google Web Risk is highly accurate",
            detection_coverage="80% - covers known malicious URLs",
            evasion_considerations="Zero-day phishing sites not yet in database",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2 hours",
            estimated_monthly_cost="$5-15 depending on query volume",
            prerequisites=["Web Risk API enabled", "Cloud Functions configured"],
        ),
    ],
    recommended_order=[
        "t1566-aws-guardduty-malware",
        "t1566-gcp-gmail-api",
        "t1566-aws-ses-analysis",
        "t1566-gcp-safe-browsing",
        "t1566-aws-workmail-rules",
    ],
    total_effort_hours=6.0,
    coverage_improvement="+30% improvement for Initial Access tactic",
)
