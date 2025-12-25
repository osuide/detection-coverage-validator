"""
T1534 - Internal Spearphishing

Adversaries use compromised accounts to send phishing messages internally,
exploiting trusted relationships for lateral movement. Used by Gamaredon,
HEXANE, Kimsuky, Leviathan, and Lazarus Group.
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
    technique_id="T1534",
    technique_name="Internal Spearphishing",
    tactic_ids=["TA0008"],
    mitre_url="https://attack.mitre.org/techniques/T1534/",
    threat_context=ThreatContext(
        description=(
            "After gaining initial access, adversaries leverage compromised legitimate "
            "accounts to send internal spearphishing messages. This technique exploits "
            "the inherent trust in internal communications to target additional users. "
            "Attackers may send messages via email, collaboration platforms like Microsoft "
            "Teams or Slack, or other internal communication tools. Messages often contain "
            "credential harvesting links, malicious attachments, or social engineering "
            "schemes designed to expand access within the organisation."
        ),
        attacker_goal="Exploit trusted internal accounts to expand access and move laterally within the organisation",
        why_technique=[
            "Bypasses external email security controls",
            "Leverages trust in internal communications",
            "Evades traditional phishing detection",
            "Enables rapid lateral movement",
            "Can access restricted internal resources",
            "Often combined with account impersonation",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="common",
        trend="increasing",
        severity_score=8,
        severity_reasoning=(
            "Internal spearphishing is particularly dangerous because it bypasses perimeter "
            "defences and exploits established trust relationships. Detection is challenging "
            "as messages originate from legitimate internal accounts. This technique often "
            "leads to rapid lateral movement and expanded compromise across the organisation."
        ),
        business_impact=[
            "Lateral movement and privilege escalation",
            "Additional credential compromise",
            "Expanded organisational access",
            "Data exfiltration and theft",
            "Deployment of additional malware",
            "Business disruption and trust erosion",
        ],
        typical_attack_phase="lateral_movement",
        often_precedes=["T1078.004", "T1114.003", "T1098", "T1136"],
        often_follows=["T1566", "T1078", "T1110", "T1528"],
    ),
    detection_strategies=[
        DetectionStrategy(
            strategy_id="t1534-aws-ses-internal",
            name="AWS SES/WorkMail Internal Email Anomaly Detection",
            description=(
                "Detect anomalous internal email patterns including unusual sending behaviour, "
                "suspicious attachments, and credential harvesting attempts from compromised accounts."
            ),
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, eventName, userIdentity.arn, requestParameters.destination, requestParameters.source
| filter eventSource = "ses.amazonaws.com" OR eventSource = "workmail.amazonaws.com"
| filter eventName in ["SendEmail", "SendRawEmail"]
| stats count(*) as email_count by userIdentity.arn, bin(5m)
| filter email_count > 10
| sort email_count desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: AWS SES/WorkMail internal spearphishing detection

Parameters:
  AlertEmail:
    Type: String
    Description: Email address for security alerts
  CloudTrailLogGroup:
    Type: String
    Description: CloudTrail log group name

Resources:
  # Step 1: Create SNS topic for internal phishing alerts
  InternalPhishingAlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      DisplayName: Internal Spearphishing Alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Create metric filter for unusual email sending patterns
  UnusualEmailVolumeFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ ($.eventSource = "ses.amazonaws.com" || $.eventSource = "workmail.amazonaws.com") && ($.eventName = "SendEmail" || $.eventName = "SendRawEmail") }'
      MetricTransformations:
        - MetricName: InternalEmailSendRate
          MetricNamespace: Security/T1534
          MetricValue: "1"
          DefaultValue: 0

  # Step 3: Create alarm for suspicious email volume
  UnusualEmailVolumeAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: T1534-InternalSpearphishing
      AlarmDescription: Detect unusual internal email sending patterns
      MetricName: InternalEmailSendRate
      Namespace: Security/T1534
      Statistic: Sum
      Period: 300
      EvaluationPeriods: 1
      Threshold: 20
      ComparisonOperator: GreaterThanThreshold
      AlarmActions:
        - !Ref InternalPhishingAlertTopic""",
                terraform_template="""# AWS SES/WorkMail internal spearphishing detection

variable "cloudtrail_log_group" {
  type        = string
  description = "CloudTrail log group name"
}

variable "alert_email" {
  type        = string
  description = "Email address for security alerts"
}

# Step 1: Create SNS topic for internal phishing alerts
resource "aws_sns_topic" "internal_phishing_alerts" {
  name         = "internal-spearphishing-alerts"
  kms_master_key_id = "alias/aws/sns"
  display_name = "Internal Spearphishing Alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.internal_phishing_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Create metric filter for unusual email sending patterns
resource "aws_cloudwatch_log_metric_filter" "unusual_email_volume" {
  name           = "internal-email-send-rate"
  log_group_name = var.cloudtrail_log_group

  pattern = "{ ($.eventSource = \"ses.amazonaws.com\" || $.eventSource = \"workmail.amazonaws.com\") && ($.eventName = \"SendEmail\" || $.eventName = \"SendRawEmail\") }"

  metric_transformation {
    name      = "InternalEmailSendRate"
    namespace = "Security/T1534"
    value     = "1"
  }
}

# Step 3: Create alarm for suspicious email volume
resource "aws_cloudwatch_metric_alarm" "unusual_email_volume" {
  alarm_name          = "T1534-InternalSpearphishing"
  alarm_description   = "Detect unusual internal email sending patterns"
  metric_name         = "InternalEmailSendRate"
  namespace           = "Security/T1534"
  statistic           = "Sum"
  period              = 300
  threshold           = 20
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  alarm_actions       = [aws_sns_topic.internal_phishing_alerts.arn]
}""",
                alert_severity="high",
                alert_title="AWS: Unusual Internal Email Sending Pattern Detected",
                alert_description_template=(
                    "Unusual internal email sending detected from {userIdentity.arn}. "
                    "Volume: {email_count} emails in 5 minutes. This may indicate "
                    "compromised account conducting internal spearphishing campaign."
                ),
                investigation_steps=[
                    "Review the sending account for signs of compromise",
                    "Check recent authentication logs for the user",
                    "Analyse email recipients and content if accessible",
                    "Verify if user reported account issues",
                    "Review email subject lines and attachment types",
                    "Check for suspicious login locations or devices",
                    "Look for related security events (failed MFA, password resets)",
                ],
                containment_actions=[
                    "Immediately disable the compromised account",
                    "Recall or delete sent emails if possible",
                    "Reset account credentials and revoke active sessions",
                    "Notify recipients of potential phishing attempt",
                    "Review and remove any email forwarding rules",
                    "Scan the account for malicious mailbox rules",
                    "Enable enhanced monitoring for the affected account",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Adjust threshold based on legitimate bulk email patterns; whitelist automated systems",
            detection_coverage="70% - covers SES and WorkMail email sending",
            evasion_considerations="Attackers may throttle sending to stay under threshold or use collaboration platforms instead",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$5-10",
            prerequisites=[
                "CloudTrail enabled for SES/WorkMail",
                "CloudWatch Logs configured",
            ],
        ),
        DetectionStrategy(
            strategy_id="t1534-aws-workmail-attachment",
            name="AWS WorkMail Suspicious Attachment Detection",
            description=(
                "Detect internal emails with suspicious attachments that may contain "
                "malware, macros, or credential harvesting tools sent from compromised accounts."
            ),
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, eventName, userIdentity.arn, requestParameters
| filter eventSource = "workmail.amazonaws.com"
| filter eventName = "SendRawEmail"
| filter requestParameters.rawMessage.data like /[.](exe|scr|vbs|js|jar|bat|cmd|ps1|zip|rar)/
| sort @timestamp desc""",
                terraform_template="""# Detect suspicious attachments in internal emails

variable "cloudtrail_log_group" { type = string }
variable "alert_email" { type = string }

# Step 1: Create SNS topic for attachment alerts
resource "aws_sns_topic" "attachment_alerts" {
  name = "suspicious-attachment-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.attachment_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Create metric filter for suspicious file types
resource "aws_cloudwatch_log_metric_filter" "suspicious_attachments" {
  name           = "workmail-suspicious-attachments"
  log_group_name = var.cloudtrail_log_group

  pattern = "{ ($.eventSource = \"workmail.amazonaws.com\") && ($.eventName = \"SendRawEmail\") }"

  metric_transformation {
    name      = "SuspiciousAttachments"
    namespace = "Security/T1534"
    value     = "1"
  }
}

# Step 3: Create alarm for suspicious attachment sending
resource "aws_cloudwatch_metric_alarm" "suspicious_attachments" {
  alarm_name          = "T1534-SuspiciousAttachments"
  alarm_description   = "Internal email with suspicious attachment detected"
  metric_name         = "SuspiciousAttachments"
  namespace           = "Security/T1534"
  statistic           = "Sum"
  period              = 300
  threshold           = 0
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  alarm_actions       = [aws_sns_topic.attachment_alerts.arn]
}""",
                alert_severity="high",
                alert_title="WorkMail: Suspicious Attachment in Internal Email",
                alert_description_template=(
                    "Internal email with suspicious attachment detected from {userIdentity.arn}. "
                    "This may indicate internal spearphishing with malicious payload."
                ),
                investigation_steps=[
                    "Quarantine the email and attachment immediately",
                    "Analyse attachment in sandboxed environment",
                    "Review sender account for compromise indicators",
                    "Check if recipients opened the attachment",
                    "Scan recipient systems if attachment was executed",
                    "Review sender's recent email activity",
                ],
                containment_actions=[
                    "Delete the email from all recipient mailboxes",
                    "Block attachment hash at email gateway",
                    "Disable sender account pending investigation",
                    "Reset sender credentials",
                    "Isolate systems that executed the attachment",
                    "Deploy EDR scans to affected endpoints",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Legitimate file transfers are rare via email; investigate all occurrences",
            detection_coverage="75% - covers WorkMail attachment patterns",
            evasion_considerations="Encrypted archives or renamed extensions may evade detection",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$5-10",
            prerequisites=["CloudTrail enabled for WorkMail"],
        ),
        DetectionStrategy(
            strategy_id="t1534-gcp-workspace-internal",
            name="Google Workspace Internal Email Anomaly Detection",
            description=(
                "Detect anomalous internal email activity in Google Workspace including "
                "unusual sending patterns, suspicious links, and potential credential phishing."
            ),
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""protoPayload.serviceName="gmail.googleapis.com"
AND protoPayload.methodName="gmail.send"
AND protoPayload.authenticationInfo.principalEmail=~"@yourdomain.com$"
AND (
  jsonPayload.message.suspicious=true
  OR jsonPayload.message.phishingVerdict!="NOT_PHISHING"
  OR jsonPayload.message.spamVerdict!="NOT_SPAM"
)""",
                gcp_terraform_template="""# GCP: Workspace internal spearphishing detection

variable "project_id" { type = string }
variable "alert_email" { type = string }
variable "organization_domain" {
  type        = string
  description = "Your organisation domain (e.g., example.com)"
}

# Step 1: Create notification channel for alerts
resource "google_monitoring_notification_channel" "email" {
  display_name = "Security Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Create log metric for internal spearphishing indicators
resource "google_logging_metric" "internal_phishing" {
  name   = "workspace-internal-spearphishing"
  filter = <<-EOT
    protoPayload.serviceName="gmail.googleapis.com"
    AND protoPayload.methodName="gmail.send"
    AND protoPayload.authenticationInfo.principalEmail=~"@${var.organization_domain}$"
    AND (
      jsonPayload.message.suspicious=true
      OR jsonPayload.message.phishingVerdict!="NOT_PHISHING"
      OR jsonPayload.message.spamVerdict!="NOT_SPAM"
    )
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Create alert policy for internal spearphishing
resource "google_monitoring_alert_policy" "internal_phishing_alert" {
  display_name = "Internal Spearphishing Detected"
  combiner     = "OR"

  conditions {
    display_name = "Suspicious internal email detected"

    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.internal_phishing.name}\""
      duration        = "60s"
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
                alert_title="GCP Workspace: Internal Spearphishing Detected",
                alert_description_template=(
                    "Suspicious internal email activity detected in Google Workspace. "
                    "Sender may be compromised account conducting internal phishing campaign."
                ),
                investigation_steps=[
                    "Review Gmail audit logs for the sending account",
                    "Check sender's recent login activity and locations",
                    "Analyse email content and embedded links",
                    "Verify if sender's account shows other compromise indicators",
                    "Review recipient list for targeted individuals",
                    "Check for recently created email filters or forwarding rules",
                    "Look for unusual delegation or sharing permissions",
                ],
                containment_actions=[
                    "Suspend the compromised sender account immediately",
                    "Recall emails using Gmail admin tools",
                    "Reset sender account password and revoke sessions",
                    "Remove malicious email filters and forwarding rules",
                    "Notify recipients to ignore the suspicious email",
                    "Enable 2FA for affected account if not already enabled",
                    "Review organisation-wide email security policies",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Google's built-in phishing detection is highly accurate",
            detection_coverage="85% - leverages Workspace native security verdicts",
            evasion_considerations="Sophisticated attacks may evade automated detection",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$10-15",
            prerequisites=["Google Workspace Enterprise", "Audit logging enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1534-gcp-workspace-teams",
            name="Google Chat/Teams Internal Message Monitoring",
            description=(
                "Detect suspicious internal messages sent via Google Chat that may contain "
                "credential harvesting links or malicious content from compromised accounts."
            ),
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""protoPayload.serviceName="chat.googleapis.com"
AND protoPayload.methodName="google.chat.v1.ChatService.CreateMessage"
AND (
  protoPayload.request.message.text=~"http[s]?://"
  OR protoPayload.request.message.cards!=""
)""",
                gcp_terraform_template="""# GCP: Google Chat internal phishing detection

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

# Step 2: Create log metric for suspicious Chat messages
resource "google_logging_metric" "chat_suspicious_links" {
  name   = "workspace-chat-suspicious-messages"
  filter = <<-EOT
    protoPayload.serviceName="chat.googleapis.com"
    AND protoPayload.methodName="google.chat.v1.ChatService.CreateMessage"
    AND (
      protoPayload.request.message.text=~"http[s]?://"
      OR protoPayload.request.message.cards!=""
    )
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "sender"
      value_type  = "STRING"
      description = "Message sender email"
    }
  }

  label_extractors = {
    "sender" = "EXTRACT(protoPayload.authenticationInfo.principalEmail)"
  }
}

# Step 3: Create alert policy for suspicious messages
resource "google_monitoring_alert_policy" "chat_phishing_alert" {
  display_name = "Google Chat Suspicious Messages"
  combiner     = "OR"

  conditions {
    display_name = "Message with suspicious link detected"

    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.chat_suspicious_links.name}\""
      duration        = "60s"
      comparison      = "COMPARISON_GT"
      threshold_value = 5
      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_RATE"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]
}""",
                alert_severity="medium",
                alert_title="GCP Workspace: Suspicious Links in Google Chat",
                alert_description_template=(
                    "Multiple messages with links detected in Google Chat. May indicate "
                    "internal spearphishing via collaboration platform."
                ),
                investigation_steps=[
                    "Review the Chat message content and links",
                    "Verify sender account for compromise indicators",
                    "Check if links lead to credential harvesting sites",
                    "Review sender's recent Chat activity patterns",
                    "Check for abnormal login activity for sender",
                    "Identify all recipients who may have clicked links",
                ],
                containment_actions=[
                    "Suspend sender account if compromised",
                    "Delete malicious messages from Chat rooms",
                    "Block malicious URLs at organisation firewall",
                    "Reset sender credentials and revoke sessions",
                    "Notify recipients of the phishing attempt",
                    "Enable enhanced security for affected users",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Legitimate links are common in Chat; focus on volume and patterns",
            detection_coverage="65% - covers Google Chat messages with links",
            evasion_considerations="Attackers may use URL shorteners or obfuscated links",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$10-20",
            prerequisites=[
                "Google Workspace with Chat enabled",
                "Audit logging configured",
            ],
        ),
        DetectionStrategy(
            strategy_id="t1534-gcp-safe-browsing-internal",
            name="GCP Web Risk API for Internal Link Validation",
            description=(
                "Validate URLs shared in internal communications against Google Web Risk "
                "database to detect malicious phishing links distributed via internal channels."
            ),
            detection_type=DetectionType.CLOUD_FUNCTIONS,
            aws_service="n/a",
            gcp_service="cloud_functions",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="cloud_function"
protoPayload.methodName="webrisk.uris.search"
jsonPayload.threat_types=~"SOCIAL_ENGINEERING|MALWARE"
jsonPayload.source="internal"''',
                gcp_terraform_template="""# GCP: Web Risk API for internal link validation

variable "project_id" { type = string }
variable "alert_email" { type = string }

# Step 1: Enable Web Risk API
resource "google_project_service" "webrisk" {
  service            = "webrisk.googleapis.com"
  disable_on_destroy = false
}

# Step 2: Create notification channel
resource "google_monitoring_notification_channel" "email" {
  display_name = "Security Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 3: Create alert for malicious internal URLs
resource "google_logging_metric" "malicious_internal_urls" {
  name   = "malicious-internal-link-detections"
  filter = <<-EOT
    resource.type="cloud_function"
    protoPayload.methodName="webrisk.uris.search"
    jsonPayload.threat_types=~"SOCIAL_ENGINEERING|MALWARE"
    jsonPayload.source="internal"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

resource "google_monitoring_alert_policy" "malicious_url_alert" {
  display_name = "Malicious URL in Internal Communications"
  combiner     = "OR"

  conditions {
    display_name = "Internal phishing link detected"

    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.malicious_internal_urls.name}\""
      duration        = "60s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]
}""",
                alert_severity="high",
                alert_title="GCP: Malicious URL Detected in Internal Communications",
                alert_description_template=(
                    "Web Risk API identified malicious URL shared internally. "
                    "Threat type: {threat_type}. Likely internal spearphishing attempt."
                ),
                investigation_steps=[
                    "Identify all internal communications containing the URL",
                    "Determine who shared the malicious link",
                    "Check if any users clicked the link",
                    "Review sender account for compromise indicators",
                    "Analyse the threat type (phishing, malware, etc.)",
                    "Search for similar URLs or domains",
                ],
                containment_actions=[
                    "Block the malicious URL at organisation firewall",
                    "Remove links from emails and chat messages",
                    "Suspend sender account if compromised",
                    "Notify all recipients of the threat",
                    "Scan systems of users who clicked the link",
                    "Update security awareness training",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Google Web Risk has high accuracy for known threats",
            detection_coverage="80% - covers known malicious URLs",
            evasion_considerations="Zero-day phishing sites not yet in database will evade",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2 hours",
            estimated_monthly_cost="$5-15",
            prerequisites=[
                "Web Risk API enabled",
                "Cloud Functions configured for URL scanning",
            ],
        ),
    ],
    recommended_order=[
        "t1534-gcp-workspace-internal",
        "t1534-aws-ses-internal",
        "t1534-gcp-safe-browsing-internal",
        "t1534-aws-workmail-attachment",
        "t1534-gcp-workspace-teams",
    ],
    total_effort_hours=7.5,
    coverage_improvement="+25% improvement for Lateral Movement tactic",
)
