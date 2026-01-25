"""
T1566.002 - Phishing: Spearphishing Link

Adversaries send spearphishing emails containing malicious links to compromise
victims. Links may download malware, exploit browsers, or steal credentials
through fake login pages and OAuth consent phishing.
Used by APT29, APT32, APT33, Lazarus Group, FIN4, FIN7, Emotet.
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
    technique_id="T1566.002",
    technique_name="Phishing: Spearphishing Link",
    tactic_ids=["TA0001"],
    mitre_url="https://attack.mitre.org/techniques/T1566/002/",
    threat_context=ThreatContext(
        description=(
            "Adversaries send spearphishing emails containing malicious links to "
            "gain initial access. Links may download malware, exploit browsers, "
            "redirect to credential harvesting pages, or perform OAuth consent "
            "phishing. Often uses domain spoofing, URL obfuscation, and social "
            "engineering to increase success rates."
        ),
        attacker_goal="Gain initial access through user interaction with malicious links",
        why_technique=[
            "Bypasses technical controls via user interaction",
            "Can steal credentials without malware",
            "OAuth consent phishing bypasses MFA",
            "Domain spoofing evades detection",
            "Scalable to many targets",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="very_common",
        trend="increasing",
        severity_score=8,
        severity_reasoning=(
            "Primary initial access vector for advanced persistent threats. OAuth "
            "consent phishing bypasses MFA. Can lead to full account compromise "
            "and lateral movement within cloud environments."
        ),
        business_impact=[
            "Account credential theft",
            "Malware infection",
            "OAuth token compromise",
            "Data exfiltration",
            "Business email compromise",
        ],
        typical_attack_phase="initial_access",
        often_precedes=["T1078", "T1110", "T1539", "T1114"],
        often_follows=[],
    ),
    detection_strategies=[
        DetectionStrategy(
            strategy_id="t1566-002-aws-ses",
            name="AWS SES Suspicious Link Detection",
            description="Detect suspicious URLs in inbound emails via SES.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, mail.source, mail.destination, receipt.action
| filter receipt.spfVerdict.status = "FAIL" or receipt.dkimVerdict.status = "FAIL" or receipt.dmarcVerdict.status = "FAIL"
| filter content.bodyPlainText like /http|hxxp|bit\\.ly|tinyurl|goo\\.gl/
| stats count(*) as suspicious_emails by mail.source, bin(1h)
| filter suspicious_emails > 3
| sort suspicious_emails desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect spearphishing links via SES logs

Parameters:
  SESLogGroup:
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

  PhishingLinkFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref SESLogGroup
      FilterPattern: '{ ($.receipt.spfVerdict.status = "FAIL" || $.receipt.dkimVerdict.status = "FAIL") && $.content.bodyPlainText = "*http*" }'
      MetricTransformations:
        - MetricName: PhishingLinks
          MetricNamespace: Security
          MetricValue: "1"

  PhishingLinkAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: SpearphishingLinkDetected
      MetricName: PhishingLinks
      Namespace: Security
      Statistic: Sum
      Period: 300
      Threshold: 5
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      TreatMissingData: notBreaching

      AlarmActions: [!Ref AlertTopic]""",
                terraform_template="""# Detect spearphishing links via SES logs

variable "ses_log_group" { type = string }
variable "alert_email" { type = string }

resource "aws_sns_topic" "alerts" {
  name = "spearphishing-link-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_cloudwatch_log_metric_filter" "phishing_links" {
  name           = "phishing-links"
  log_group_name = var.ses_log_group
  pattern        = "{ ($.receipt.spfVerdict.status = \"FAIL\" || $.receipt.dkimVerdict.status = \"FAIL\") && $.content.bodyPlainText = \"*http*\" }"

  metric_transformation {
    name      = "PhishingLinks"
    namespace = "Security"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "phishing_attempt" {
  alarm_name          = "SpearphishingLinkDetected"
  metric_name         = "PhishingLinks"
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
                alert_title="Spearphishing Link Detected",
                alert_description_template="Emails with suspicious links from {source} failing authentication checks.",
                investigation_steps=[
                    "Review email sender authentication (SPF/DKIM/DMARC)",
                    "Analyse URL patterns and destination domains",
                    "Check if users clicked the links",
                    "Review similar emails to other recipients",
                    "Identify compromised accounts",
                ],
                containment_actions=[
                    "Block sender domain and IP addresses",
                    "Delete phishing emails from all mailboxes",
                    "Reset credentials for users who clicked links",
                    "Block malicious domains at firewall/proxy",
                    "Notify affected users",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Legitimate emails may fail SPF/DKIM; correlate with URL reputation",
            detection_coverage="60% - catches authentication failures with links",
            evasion_considerations="Compromised legitimate accounts bypass authentication checks",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$10-20",
            prerequisites=["AWS SES with CloudWatch logging enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1566-002-aws-oauth",
            name="AWS IAM Identity Center OAuth Consent Monitoring",
            description="Detect suspicious OAuth consent grants following email clicks.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudtrail",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, userIdentity.principalId, eventName, sourceIPAddress, requestParameters.applicationId
| filter eventName = "CreateApplicationGrant" or eventName = "CreateTokenBinding"
| stats count(*) as consent_grants by userIdentity.principalId, requestParameters.applicationId, bin(5m)
| filter consent_grants > 0
| sort @timestamp desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect OAuth consent phishing attempts

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

  OAuthConsentFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ $.eventName = "CreateApplicationGrant" || $.eventName = "CreateTokenBinding" }'
      MetricTransformations:
        - MetricName: OAuthConsents
          MetricNamespace: Security
          MetricValue: "1"

  OAuthConsentAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: SuspiciousOAuthConsent
      MetricName: OAuthConsents
      Namespace: Security
      Statistic: Sum
      Period: 300
      Threshold: 3
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      TreatMissingData: notBreaching

      AlarmActions: [!Ref AlertTopic]""",
                terraform_template="""# Detect OAuth consent phishing

variable "cloudtrail_log_group" { type = string }
variable "alert_email" { type = string }

resource "aws_sns_topic" "alerts" {
  name = "oauth-consent-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_cloudwatch_log_metric_filter" "oauth_consents" {
  name           = "oauth-consents"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ $.eventName = \"CreateApplicationGrant\" || $.eventName = \"CreateTokenBinding\" }"

  metric_transformation {
    name      = "OAuthConsents"
    namespace = "Security"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "oauth_phishing" {
  alarm_name          = "SuspiciousOAuthConsent"
  metric_name         = "OAuthConsents"
  namespace           = "Security"
  statistic           = "Sum"
  period              = 300
  threshold           = 3
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.alerts.arn]
}""",
                alert_severity="critical",
                alert_title="OAuth Consent Phishing Detected",
                alert_description_template="User {principalId} granted consent to application {applicationId}.",
                investigation_steps=[
                    "Review application requesting consent",
                    "Check application permissions granted",
                    "Verify application publisher legitimacy",
                    "Review user's recent email activity",
                    "Check for similar consent grants organisation-wide",
                ],
                containment_actions=[
                    "Revoke malicious application consent",
                    "Block application organisation-wide",
                    "Reset user credentials and session tokens",
                    "Enable conditional access policies",
                    "Audit application permissions",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Legitimate app installs occur; focus on unknown publishers",
            detection_coverage="80% - catches OAuth consent activity",
            evasion_considerations="Low; OAuth grants are logged",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes - 1 hour",
            estimated_monthly_cost="$5-10",
            prerequisites=[
                "CloudTrail logging enabled",
                "IAM Identity Center configured",
            ],
        ),
        DetectionStrategy(
            strategy_id="t1566-002-aws-guardduty",
            name="AWS GuardDuty Credential Phishing Detection",
            description="Detect credential phishing via GuardDuty findings.",
            detection_type=DetectionType.GUARDDUTY,
            aws_service="guardduty",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, detail.type, detail.service.action.actionType
| filter detail.type = "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS"
    or detail.type = "CredentialAccess:IAMUser/AnomalousBehavior"
| sort @timestamp desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Alert on GuardDuty credential phishing findings

Parameters:
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

  GuardDutyPhishingRule:
    Type: AWS::Events::Rule
    Properties:
      EventPattern:
        source: [aws.guardduty]
        detail-type: [GuardDuty Finding]
        detail:
          type:
            - prefix: UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration
            - prefix: CredentialAccess:IAMUser/AnomalousCloudAccessUsed
      State: ENABLED
      Targets:
        - Arn: !Ref AlertTopic
          Id: PhishingAlertTarget""",
                terraform_template="""# Alert on GuardDuty credential phishing

variable "alert_email" { type = string }

resource "aws_sns_topic" "alerts" {
  name = "guardduty-phishing-alerts"
  kms_master_key_id = "alias/aws/sns"

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
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_cloudwatch_event_rule" "guardduty_phishing" {
  name        = "guardduty-credential-phishing"
  description = "Detect credential phishing via GuardDuty"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail = {
      type = [
        { prefix = "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS" },
        { prefix = "CredentialAccess:IAMUser/AnomalousBehavior" }
      ]
    }
  })
}

resource "aws_sqs_queue" "dlq" {
  name                      = "guardduty-phishing-dlq"
  message_retention_seconds = 1209600
}

resource "aws_cloudwatch_event_target" "sns" {
  rule      = aws_cloudwatch_event_rule.guardduty_phishing.name
  target_id = "PhishingAlertTarget"
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
          "aws:SourceArn" = aws_cloudwatch_event_rule.guardduty_phishing.arn
        }
      }
    }]
  })
}

# Allow EventBridge to publish to SNS
data "aws_caller_identity" "current" {}

resource "aws_sns_topic_policy" "allow_eventbridge" {
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
            "aws:SourceArn" = aws_cloudwatch_event_rule.guardduty_phishing.arn
          }
      }
    }]
  })
}""",
                alert_severity="critical",
                alert_title="Credential Phishing Detected by GuardDuty",
                alert_description_template="GuardDuty detected credential compromise: {finding_type}.",
                investigation_steps=[
                    "Review GuardDuty finding details",
                    "Identify compromised credentials",
                    "Check credential usage timeline",
                    "Review user's recent login activity",
                    "Analyse access patterns from suspicious IPs",
                ],
                containment_actions=[
                    "Disable compromised IAM credentials immediately",
                    "Invalidate all user sessions",
                    "Block suspicious IP addresses",
                    "Enable MFA if not enabled",
                    "Rotate all credentials",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="GuardDuty findings are high-fidelity",
            detection_coverage="85% - ML-based credential anomaly detection",
            evasion_considerations="Low; detects post-compromise activity",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$30-100 (GuardDuty pricing)",
            prerequisites=["AWS GuardDuty enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1566-002-gcp-gmail",
            name="GCP Gmail Phishing Link Detection",
            description="Detect phishing links via Gmail security logs.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="gmail_message"
protoPayload.metadata.event.type="PHISHING"
OR protoPayload.metadata.event.type="MALWARE"
OR protoPayload.metadata.event.type="SUSPICIOUS_LINK"''',
                gcp_terraform_template="""# GCP: Detect phishing links via Gmail logs

variable "project_id" { type = string }
variable "alert_email" { type = string }

resource "google_monitoring_notification_channel" "email_s1" {
  project      = var.project_id
  display_name = "Security Alerts"
  type         = "email"
  labels       = { email_address = var.alert_email }
}

resource "google_logging_metric" "phishing_links" {
  project = var.project_id
  name   = "gmail-phishing-links"
  filter = <<-EOT
    resource.type="gmail_message"
    (protoPayload.metadata.event.type="PHISHING"
    OR protoPayload.metadata.event.type="MALWARE"
    OR protoPayload.metadata.event.type="SUSPICIOUS_LINK")
  EOT
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

resource "google_monitoring_alert_policy" "phishing_alerts" {
  project      = var.project_id
  display_name = "Gmail Phishing Links"
  combiner     = "OR"
  conditions {
    display_name = "Phishing emails detected"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.phishing_links.name}\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 1
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
                alert_title="GCP: Phishing Link Detected in Gmail",
                alert_description_template="Gmail detected phishing or malicious links in emails.",
                investigation_steps=[
                    "Review detected phishing emails",
                    "Identify targeted users",
                    "Check if users interacted with links",
                    "Review sender information",
                    "Search for similar campaigns",
                ],
                containment_actions=[
                    "Remove phishing emails from all inboxes",
                    "Block sender domains",
                    "Reset credentials for affected users",
                    "Update email filtering rules",
                    "Notify users of phishing attempt",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Gmail's phishing detection is high-accuracy",
            detection_coverage="75% - Gmail built-in detection",
            evasion_considerations="Sophisticated phishing may evade initial detection",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes - 1 hour",
            estimated_monthly_cost="$5-10",
            prerequisites=["Google Workspace with Gmail logging enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1566-002-gcp-oauth",
            name="GCP OAuth Consent Phishing Detection",
            description="Detect suspicious OAuth consent grants in GCP/Workspace.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''protoPayload.serviceName="login.googleapis.com"
protoPayload.methodName="google.login.LoginService.oAuthApproval"
protoPayload.metadata.event.type="grant"''',
                gcp_terraform_template="""# GCP: Detect OAuth consent phishing

variable "project_id" { type = string }
variable "alert_email" { type = string }

resource "google_monitoring_notification_channel" "email_s2" {
  project      = var.project_id
  display_name = "Security Alerts"
  type         = "email"
  labels       = { email_address = var.alert_email }
}

resource "google_logging_metric" "oauth_consents" {
  project = var.project_id
  name   = "oauth-consent-grants"
  filter = <<-EOT
    protoPayload.serviceName="login.googleapis.com"
    protoPayload.methodName="google.login.LoginService.oAuthApproval"
    protoPayload.metadata.event.type="grant"
  EOT
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "app_name"
      value_type  = "STRING"
      description = "Application name"
    }
  }
  label_extractors = {
    "app_name" = "EXTRACT(protoPayload.metadata.event.parameter[0].value)"
  }
}

resource "google_monitoring_alert_policy" "oauth_phishing" {
  project      = var.project_id
  display_name = "OAuth Consent Phishing"
  combiner     = "OR"
  conditions {
    display_name = "Unusual OAuth consent grants"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.oauth_consents.name}\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 3
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
                alert_title="GCP: OAuth Consent Phishing Detected",
                alert_description_template="Suspicious OAuth consent grants detected for application {app_name}.",
                investigation_steps=[
                    "Review application requesting consent",
                    "Check application permissions and scopes",
                    "Verify application publisher",
                    "Review user's recent email and browsing",
                    "Check for organisation-wide consent patterns",
                ],
                containment_actions=[
                    "Revoke application access immediately",
                    "Block application organisation-wide",
                    "Reset user credentials and tokens",
                    "Configure OAuth app allowlist",
                    "Enable additional consent controls",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Legitimate app installs occur; baseline normal behaviour",
            detection_coverage="85% - captures OAuth grants",
            evasion_considerations="Low; OAuth activity is logged",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes - 1 hour",
            estimated_monthly_cost="$5-10",
            prerequisites=["Google Workspace Admin SDK logging enabled"],
        ),
        # Azure Strategy: Phishing: Spearphishing Link
        DetectionStrategy(
            strategy_id="t1566002-azure",
            name="Azure Phishing: Spearphishing Link Detection",
            description=(
                "Azure detection for Phishing: Spearphishing Link. "
                "Provides native Azure detection using Log Analytics and Defender for Cloud."
            ),
            detection_type=DetectionType.DEFENDER_ALERT,
            aws_service="n/a",
            azure_service="defender",
            cloud_provider=CloudProvider.AZURE,
            implementation=DetectionImplementation(
                defender_alert_types=["Suspicious activity detected"],
                azure_terraform_template="""# Microsoft Defender for Cloud Detection
# Phishing: Spearphishing Link (T1566.002)
# Microsoft Defender detects Phishing: Spearphishing Link activity

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
  name                = "defender-t1566-002-alerts"
  resource_group_name = var.resource_group_name
  short_name          = "DefAlerts"

  email_receiver {
    name          = "security-team"
    email_address = var.alert_email
  }
}

# Log Analytics query for Defender alerts
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "defender_detection" {
  name                = "defender-t1566-002"
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

  description = "Microsoft Defender detects Phishing: Spearphishing Link activity"
  display_name = "Defender: Phishing: Spearphishing Link"
  enabled      = true

  tags = {
    "mitre-technique" = "T1566.002"
    "detection-type"  = "security"
  }
}

output "alert_rule_id" {
  value = azurerm_monitor_scheduled_query_rules_alert_v2.defender_detection.id
}""",
                alert_severity="high",
                alert_title="Azure: Phishing: Spearphishing Link Detected",
                alert_description_template=(
                    "Phishing: Spearphishing Link activity detected. "
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
        "t1566-002-aws-guardduty",
        "t1566-002-gcp-gmail",
        "t1566-002-aws-oauth",
        "t1566-002-gcp-oauth",
        "t1566-002-aws-ses",
    ],
    total_effort_hours=4.5,
    coverage_improvement="+30% improvement for Initial Access tactic",
)
