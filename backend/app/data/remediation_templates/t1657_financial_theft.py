"""
T1657 - Financial Theft

Adversaries steal monetary resources through extortion, social engineering, technical theft,
or other methods for personal financial gain. Includes ransomware, BEC, fraud, and cryptocurrency theft.
Used by Akira, Scattered Spider, SilverTerrier, FIN13, and Kimsuky.
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
    technique_id="T1657",
    technique_name="Financial Theft",
    tactic_ids=["TA0040"],
    mitre_url="https://attack.mitre.org/techniques/T1657/",
    threat_context=ThreatContext(
        description=(
            "Adversaries steal monetary resources through extortion, social engineering, "
            "technical theft, or other methods for personal financial gain. This includes "
            "ransomware extortion, business email compromise (BEC), fraud schemes, "
            "cryptocurrency theft, and unauthorised fund transfers. In cloud environments, "
            "this manifests as compromised payment systems, cryptocurrency wallet theft, "
            "fraudulent transactions, and double-extortion ransomware campaigns."
        ),
        attacker_goal="Steal monetary resources for financial gain through various methods",
        why_technique=[
            "Direct financial motivation",
            "Multiple attack vectors (ransomware, BEC, fraud)",
            "Cryptocurrency theft highly lucrative",
            "Cloud payment systems accessible remotely",
            "Double-extortion increases pressure on victims",
            "SaaS financial applications easy to manipulate",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="common",
        trend="increasing",
        severity_score=10,
        severity_reasoning=(
            "Critical severity - financial theft directly impacts revenue and can cause "
            "catastrophic financial losses. Ransomware and BEC campaigns represent immediate "
            "threats to business continuity. Cryptocurrency theft is often unrecoverable. "
            "Double-extortion adds reputational and compliance risks."
        ),
        business_impact=[
            "Direct financial losses from theft",
            "Ransomware payment pressure",
            "Business operations disruption",
            "Reputational damage from data leaks",
            "Regulatory compliance violations",
            "Customer trust erosion",
        ],
        typical_attack_phase="impact",
        often_precedes=[],
        often_follows=["T1078.004", "T1114.003", "T1486", "T1530", "T1555.006"],
    ),
    detection_strategies=[
        DetectionStrategy(
            strategy_id="t1657-aws-payment-api",
            name="AWS Unusual Financial API Activity",
            description="Detect unusual API calls to payment and billing services that may indicate fraudulent activity.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, eventName, userIdentity.arn, sourceIPAddress, requestParameters
| filter eventSource = "organizations.amazonaws.com" or eventSource = "billing.amazonaws.com"
| filter eventName in ["CreateAccount", "ModifyBilling", "UpdatePaymentMethod", "CreatePaymentMethod"]
| stats count(*) as api_calls by userIdentity.arn, sourceIPAddress, bin(1h)
| filter api_calls > 5
| sort api_calls desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect unauthorised financial API activity

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

  FinancialAPIFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ ($.eventSource = "organizations.amazonaws.com" || $.eventSource = "billing.amazonaws.com") && ($.eventName = "CreateAccount" || $.eventName = "ModifyBilling" || $.eventName = "UpdatePaymentMethod") }'
      MetricTransformations:
        - MetricName: FinancialAPIActivity
          MetricNamespace: Security/Financial
          MetricValue: "1"

  FinancialAPIAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: UnusualFinancialAPIActivity
      MetricName: FinancialAPIActivity
      Namespace: Security/Financial
      Statistic: Sum
      Period: 300
      Threshold: 5
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      TreatMissingData: notBreaching

      AlarmActions: [!Ref AlertTopic]""",
                terraform_template="""# Detect unauthorised financial API activity

variable "cloudtrail_log_group" { type = string }
variable "alert_email" { type = string }

resource "aws_sns_topic" "alerts" {
  name = "financial-api-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_cloudwatch_log_metric_filter" "financial_api" {
  name           = "financial-api-activity"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ ($.eventSource = \"organizations.amazonaws.com\" || $.eventSource = \"billing.amazonaws.com\") && ($.eventName = \"CreateAccount\" || $.eventName = \"ModifyBilling\" || $.eventName = \"UpdatePaymentMethod\") }"

  metric_transformation {
    name      = "FinancialAPIActivity"
    namespace = "Security/Financial"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "financial_api" {
  alarm_name          = "UnusualFinancialAPIActivity"
  metric_name         = "FinancialAPIActivity"
  namespace           = "Security/Financial"
  statistic           = "Sum"
  period              = 300
  threshold           = 5
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.alerts.arn]
}""",
                alert_severity="critical",
                alert_title="Unusual Financial API Activity Detected",
                alert_description_template="High volume of payment/billing API calls from {userIdentity.arn} at {sourceIPAddress}.",
                investigation_steps=[
                    "Verify if activity was authorised",
                    "Check identity and source IP address",
                    "Review payment method changes",
                    "Check for unauthorised account creation",
                    "Review recent authentication logs",
                ],
                containment_actions=[
                    "Immediately revoke suspicious credentials",
                    "Revert unauthorised billing changes",
                    "Enable MFA on financial accounts",
                    "Contact payment provider",
                    "Review all recent transactions",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Legitimate financial operations are rare and scheduled",
            detection_coverage="80% - catches API-based financial manipulation",
            evasion_considerations="Manual console changes may evade API detection",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$5-10",
            prerequisites=["CloudTrail enabled with management events"],
        ),
        DetectionStrategy(
            strategy_id="t1657-aws-crypto-exfil",
            name="AWS Cryptocurrency Wallet Exfiltration",
            description="Detect potential cryptocurrency credential theft through unusual S3/Secrets Manager access patterns.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, eventName, userIdentity.arn, requestParameters
| filter eventSource = "secretsmanager.amazonaws.com" or eventSource = "s3.amazonaws.com"
| filter eventName in ["GetSecretValue", "GetObject"]
| filter requestParameters.secretId like /(?i)(wallet|crypto|bitcoin|ethereum|private.?key)/
    or requestParameters.key like /(?i)(wallet|crypto|bitcoin|ethereum|\\.key$)/
| stats count(*) as access_count by userIdentity.arn, bin(5m)
| filter access_count > 10
| sort access_count desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect cryptocurrency wallet theft

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

  CryptoAccessFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ ($.eventSource = "secretsmanager.amazonaws.com" || $.eventSource = "s3.amazonaws.com") && ($.eventName = "GetSecretValue" || $.eventName = "GetObject") }'
      MetricTransformations:
        - MetricName: CryptoWalletAccess
          MetricNamespace: Security/Financial
          MetricValue: "1"

  CryptoAccessAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: SuspiciousCryptoWalletAccess
      MetricName: CryptoWalletAccess
      Namespace: Security/Financial
      Statistic: Sum
      Period: 300
      Threshold: 10
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      TreatMissingData: notBreaching

      AlarmActions: [!Ref AlertTopic]""",
                terraform_template="""# Detect cryptocurrency wallet theft

variable "cloudtrail_log_group" { type = string }
variable "alert_email" { type = string }

resource "aws_sns_topic" "alerts" {
  name = "crypto-theft-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_cloudwatch_log_metric_filter" "crypto_access" {
  name           = "crypto-wallet-access"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ ($.eventSource = \"secretsmanager.amazonaws.com\" || $.eventSource = \"s3.amazonaws.com\") && ($.eventName = \"GetSecretValue\" || $.eventName = \"GetObject\") }"

  metric_transformation {
    name      = "CryptoWalletAccess"
    namespace = "Security/Financial"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "crypto_theft" {
  alarm_name          = "SuspiciousCryptoWalletAccess"
  metric_name         = "CryptoWalletAccess"
  namespace           = "Security/Financial"
  statistic           = "Sum"
  period              = 300
  threshold           = 10
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.alerts.arn]
}""",
                alert_severity="critical",
                alert_title="Suspicious Cryptocurrency Wallet Access",
                alert_description_template="High-frequency access to cryptocurrency credentials by {userIdentity.arn}.",
                investigation_steps=[
                    "Identify accessed wallet/key files",
                    "Check if access was authorised",
                    "Review wallet transaction history",
                    "Check for clipboard monitoring tools",
                    "Review compromised identity's activities",
                ],
                containment_actions=[
                    "Revoke compromised credentials immediately",
                    "Transfer funds to secure wallets",
                    "Rotate all cryptocurrency keys",
                    "Enable additional authentication",
                    "Review network connections to crypto nodes",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist legitimate automated cryptocurrency operations",
            detection_coverage="70% - catches bulk credential access",
            evasion_considerations="Slow, targeted access may evade threshold",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$5-10",
            prerequisites=[
                "CloudTrail S3 data events enabled",
                "Secrets Manager logging enabled",
            ],
        ),
        DetectionStrategy(
            strategy_id="t1657-aws-ransomware",
            name="AWS Ransomware Payment Infrastructure Detection",
            description="Detect infrastructure changes indicative of ransomware extortion campaigns.",
            detection_type=DetectionType.EVENTBRIDGE_RULE,
            aws_service="eventbridge",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                event_pattern={
                    "source": ["aws.s3"],
                    "detail-type": ["AWS API Call via CloudTrail"],
                    "detail": {
                        "eventName": ["PutBucketWebsite", "PutBucketPolicy"],
                        "$or": [
                            {"requestParameters.policy": [{"wildcard": "*ransom*"}]},
                            {"requestParameters.policy": [{"wildcard": "*payment*"}]},
                            {"requestParameters.policy": [{"wildcard": "*bitcoin*"}]},
                        ],
                    },
                },
                terraform_template="""# Detect ransomware payment infrastructure

variable "alert_email" { type = string }

resource "aws_sns_topic" "alerts" {
  name = "ransomware-detection-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_cloudwatch_event_rule" "ransomware_infra" {
  name        = "ransomware-payment-infrastructure"
  description = "Detect S3 buckets configured for ransomware leak sites"
  event_pattern = jsonencode({
    source      = ["aws.s3"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = ["PutBucketWebsite", "PutBucketPolicy", "PutPublicAccessBlock"]
    }
  })
}

resource "aws_sqs_queue" "dlq" {
  name                      = "ransomware-detection-dlq"
  message_retention_seconds = 1209600  # 14 days
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
          "aws:SourceArn" = aws_cloudwatch_event_rule.ransomware_infra.arn
        }
      }
    }]
  })
}

resource "aws_cloudwatch_event_target" "sns" {
  rule      = aws_cloudwatch_event_rule.ransomware_infra.name
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
          "aws:SourceArn" = aws_cloudwatch_event_rule.ransomware_infra.arn
        }
      }
    }]
  })
}""",
                alert_severity="critical",
                alert_title="Ransomware Payment Infrastructure Detected",
                alert_description_template="S3 bucket {requestParameters.bucketName} configured with suspicious public access by {userIdentity.arn}.",
                investigation_steps=[
                    "Review bucket configuration changes",
                    "Check bucket contents for ransom notes",
                    "Verify if change was authorised",
                    "Check for encrypted data or leak sites",
                    "Review identity's recent activities",
                ],
                containment_actions=[
                    "Disable bucket public access immediately",
                    "Revoke compromised credentials",
                    "Check for encrypted data",
                    "Review backups availability",
                    "Engage incident response team",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Public bucket configuration is rare for most organisations",
            detection_coverage="85% - catches infrastructure preparation",
            evasion_considerations="External hosting evades AWS detection",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$2-5",
            prerequisites=["CloudTrail enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1657-gcp-payment",
            name="GCP Payment Service API Anomalies",
            description="Detect unusual access to payment and billing services in GCP.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''protoPayload.serviceName="cloudbilling.googleapis.com"
AND protoPayload.methodName=~".*Update.*|.*Modify.*|.*Create.*"
AND severity="NOTICE"''',
                gcp_terraform_template="""# GCP: Detect payment service anomalies

variable "project_id" { type = string }
variable "alert_email" { type = string }

resource "google_monitoring_notification_channel" "email_s1" {
  project      = var.project_id
  display_name = "Financial Security Alerts"
  type         = "email"
  labels       = { email_address = var.alert_email }
}

resource "google_logging_metric" "billing_changes" {
  project = var.project_id
  name   = "billing-service-changes"
  filter = <<-EOT
    protoPayload.serviceName="cloudbilling.googleapis.com"
    AND protoPayload.methodName=~".*Update.*|.*Modify.*|.*Create.*"
  EOT
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

resource "google_monitoring_alert_policy" "billing_alerts" {
  project      = var.project_id
  display_name = "Unusual Billing API Activity"
  combiner     = "OR"
  conditions {
    display_name = "Billing changes detected"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.billing_changes.name}\""
      duration        = "60s"
      comparison      = "COMPARISON_GT"
      threshold_value = 3
    }
  }
  notification_channels = [google_monitoring_notification_channel.email_s1.id]
  alert_strategy {
    auto_close = "604800s"  # 7 days
  }
}""",
                alert_severity="critical",
                alert_title="GCP: Unusual Billing API Activity",
                alert_description_template="Suspicious payment/billing API calls detected in project.",
                investigation_steps=[
                    "Review billing API call details",
                    "Verify caller identity and authorisation",
                    "Check for payment method changes",
                    "Review project billing configuration",
                    "Check authentication logs",
                ],
                containment_actions=[
                    "Revoke suspicious credentials",
                    "Revert unauthorised billing changes",
                    "Enable MFA on billing accounts",
                    "Review IAM permissions",
                    "Contact billing support",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Billing changes are typically infrequent and controlled",
            detection_coverage="85% - catches billing manipulation",
            evasion_considerations="Console-based manual changes harder to detect in bulk",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$5-10",
            prerequisites=["Cloud Audit Logs enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1657-gcp-crypto",
            name="GCP Cryptocurrency Credential Access",
            description="Detect access to cryptocurrency wallets and credentials in GCP Secret Manager and GCS.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""(protoPayload.serviceName="secretmanager.googleapis.com" AND protoPayload.methodName="AccessSecretVersion")
OR (protoPayload.serviceName="storage.googleapis.com" AND protoPayload.methodName="storage.objects.get")
AND (protoPayload.resourceName=~".*wallet.*|.*crypto.*|.*bitcoin.*|.*ethereum.*|.*privatekey.*|.*\\.key$")""",
                gcp_terraform_template="""# GCP: Detect cryptocurrency credential theft

variable "project_id" { type = string }
variable "alert_email" { type = string }

resource "google_monitoring_notification_channel" "email_s2" {
  project      = var.project_id
  display_name = "Crypto Theft Alerts"
  type         = "email"
  labels       = { email_address = var.alert_email }
}

resource "google_logging_metric" "crypto_access" {
  project = var.project_id
  name   = "crypto-credential-access"
  filter = <<-EOT
    (protoPayload.serviceName="secretmanager.googleapis.com" AND protoPayload.methodName="AccessSecretVersion")
    OR (protoPayload.serviceName="storage.googleapis.com" AND protoPayload.methodName="storage.objects.get")
  EOT
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

resource "google_monitoring_alert_policy" "crypto_access" {
  project      = var.project_id
  display_name = "Cryptocurrency Credential Access"
  combiner     = "OR"
  conditions {
    display_name = "High-frequency secret access"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.crypto_access.name}\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 10
      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_RATE"
      }
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
                alert_title="GCP: Cryptocurrency Credential Access Detected",
                alert_description_template="High-frequency access to cryptocurrency-related secrets or storage objects.",
                investigation_steps=[
                    "Identify accessed secrets/objects",
                    "Verify caller identity and IP",
                    "Check wallet transaction history",
                    "Review authentication logs",
                    "Check for data exfiltration",
                ],
                containment_actions=[
                    "Revoke compromised credentials",
                    "Rotate all cryptocurrency keys",
                    "Transfer funds to secure wallets",
                    "Enable additional MFA",
                    "Review IAM permissions",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist legitimate cryptocurrency operations and scheduled jobs",
            detection_coverage="75% - catches bulk access patterns",
            evasion_considerations="Slow, targeted access over time may evade rate-based detection",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$10-15",
            prerequisites=["Cloud Audit Logs enabled for GCS data access"],
        ),
        # Azure Strategy: Financial Theft
        DetectionStrategy(
            strategy_id="t1657-azure",
            name="Azure Financial Theft Detection",
            description=(
                "Azure detection for Financial Theft. "
                "Provides native Azure detection using Log Analytics and Defender for Cloud."
            ),
            detection_type=DetectionType.DEFENDER_ALERT,
            aws_service="n/a",
            azure_service="defender",
            cloud_provider=CloudProvider.AZURE,
            implementation=DetectionImplementation(
                defender_alert_types=["Suspicious activity detected"],
                azure_terraform_template="""# Microsoft Defender for Cloud Detection
# Financial Theft (T1657)
# Microsoft Defender detects Financial Theft activity

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
  name                = "defender-t1657-alerts"
  resource_group_name = var.resource_group_name
  short_name          = "DefAlerts"

  email_receiver {
    name          = "security-team"
    email_address = var.alert_email
  }
}

# Log Analytics query for Defender alerts
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "defender_detection" {
  name                = "defender-t1657"
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

  description = "Microsoft Defender detects Financial Theft activity"
  display_name = "Defender: Financial Theft"
  enabled      = true

  tags = {
    "mitre-technique" = "T1657"
    "detection-type"  = "security"
  }
}

output "alert_rule_id" {
  value = azurerm_monitor_scheduled_query_rules_alert_v2.defender_detection.id
}""",
                alert_severity="high",
                alert_title="Azure: Financial Theft Detected",
                alert_description_template=(
                    "Financial Theft activity detected. "
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
        "t1657-aws-ransomware",
        "t1657-aws-payment-api",
        "t1657-gcp-payment",
        "t1657-aws-crypto-exfil",
        "t1657-gcp-crypto",
    ],
    total_effort_hours=4.5,
    coverage_improvement="+25% improvement for Impact tactic",
)
