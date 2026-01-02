"""
T1558 - Steal or Forge Kerberos Tickets

Adversaries exploit Kerberos authentication by stealing or forging tickets to enable unauthorised access.
Used by Akira. Includes Golden Ticket, Silver Ticket, Kerberoasting, and AS-REP Roasting sub-techniques.
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
    technique_id="T1558",
    technique_name="Steal or Forge Kerberos Tickets",
    tactic_ids=["TA0006"],  # Credential Access
    mitre_url="https://attack.mitre.org/techniques/T1558/",
    threat_context=ThreatContext(
        description=(
            "Adversaries exploit Kerberos authentication by stealing or forging tickets to enable "
            "unauthorised access. This includes Golden Tickets (forged TGTs using KRBTGT hash), "
            "Silver Tickets (forged service tickets), Kerberoasting (cracking service account "
            "passwords), AS-REP Roasting (targeting accounts without pre-authentication), and "
            "stealing cached Kerberos tickets. In cloud environments, this primarily affects "
            "hybrid deployments with Active Directory integration (AWS Directory Service, "
            "GCP Managed Service for Microsoft AD)."
        ),
        attacker_goal="Obtain unauthorised access by stealing or forging Kerberos authentication tickets",
        why_technique=[
            "Forged tickets bypass authentication entirely",
            "Golden tickets persist until KRBTGT password reset",
            "Silver tickets grant service access without domain controller contact",
            "Kerberoasting enables offline password cracking",
            "Difficult to detect without proper logging",
            "Valid tickets appear as legitimate authentication",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="moderate",
        trend="stable",
        severity_score=9,
        severity_reasoning=(
            "Critical technique that enables complete domain compromise via Golden Tickets. "
            "Forged tickets bypass MFA and grant persistent unauthorised access until KRBTGT "
            "password is reset. Kerberoasting enables offline cracking of service accounts."
        ),
        business_impact=[
            "Complete domain compromise possible",
            "Persistent unauthorised access",
            "MFA and authentication bypass",
            "Lateral movement enablement",
            "Difficult remediation requiring KRBTGT rotation",
        ],
        typical_attack_phase="credential_access",
        often_precedes=["T1550", "T1078", "T1021.002"],
        often_follows=["T1003", "T1558.003"],
    ),
    detection_strategies=[
        DetectionStrategy(
            strategy_id="t1558-aws-ad-auth",
            name="AWS Managed AD Authentication Anomalies",
            description="Detect suspicious Kerberos authentication patterns in AWS Directory Service logs.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, eventName, userIdentity.principalId, sourceIPAddress, errorCode
| filter eventSource = "ds.amazonaws.com"
| filter eventName like /AuthenticateDirectory|DescribeDirectories|CreateTrust/
| stats count(*) as auth_attempts by userIdentity.principalId, sourceIPAddress, bin(5m)
| filter auth_attempts > 10
| sort auth_attempts desc""",
                terraform_template="""# AWS: Detect Kerberos ticket anomalies in Managed AD
# Step 1: Create SNS topic for alerts
# Step 2: Set up CloudWatch log group filter for suspicious AD authentication
# Step 3: Configure EventBridge rule for authentication anomalies

variable "directory_id" {
  description = "AWS Directory Service Managed AD directory ID"
  type        = string
}

variable "cloudtrail_log_group" {
  description = "CloudTrail log group name"
  type        = string
}

variable "alert_email" {
  description = "Email address for security alerts"
  type        = string
}

# SNS topic for alerts
resource "aws_sns_topic" "kerberos_alerts" {
  name = "kerberos-ticket-anomaly-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.kerberos_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# CloudWatch log metric filter for RC4 encryption (indicator of Golden Ticket)
resource "aws_cloudwatch_log_metric_filter" "rc4_tickets" {
  name           = "rc4-kerberos-tickets"
  log_group_name = var.cloudtrail_log_group

  # Detect RC4-encrypted TGTs (Golden Ticket indicator)
  pattern = "[timestamp, request_id, event_type = EventType, event_data]"

  metric_transformation {
    name      = "RC4KerberosTickets"
    namespace = "Security/Kerberos"
    value     = "1"
  }
}

# Alarm for suspicious Kerberos activity
resource "aws_cloudwatch_metric_alarm" "kerberos_anomaly" {
  alarm_name          = "kerberos-ticket-anomaly"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "1"
  metric_name         = "RC4KerberosTickets"
  namespace           = "Security/Kerberos"
  period              = "300"
  statistic           = "Sum"
  threshold           = "5"
  alarm_description   = "Detects potential Golden Ticket or Kerberos ticket forgery"
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.kerberos_alerts.arn]
}

# EventBridge rule for Directory Service authentication failures
resource "aws_cloudwatch_event_rule" "ad_auth_failures" {
  name        = "directory-service-auth-failures"
  description = "Detect authentication failures in AWS Managed AD"

  event_pattern = jsonencode({
    source      = ["aws.ds"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = [
        "AuthenticateDirectory",
        "DescribeDirectories"
      ]
      errorCode = [
        { exists = true }
      ]
    }
  })
}

# Dead Letter Queue for failed events
resource "aws_sqs_queue" "dlq" {
  name                      = "kerberos-ticket-anomaly-dlq"
  message_retention_seconds = 1209600  # 14 days
}

resource "aws_cloudwatch_event_target" "sns_target" {
  rule      = aws_cloudwatch_event_rule.ad_auth_failures.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.kerberos_alerts.arn

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

# SNS topic policy to allow EventBridge to publish
data "aws_caller_identity" "current" {}

resource "aws_sns_topic_policy" "allow_eventbridge" {
  arn = aws_sns_topic.kerberos_alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.kerberos_alerts.arn
      Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
        ArnEquals = {
          "aws:SourceArn" = aws_cloudwatch_event_rule.ad_auth_failures.arn
        }
      }
    }]
  })
}

# SQS queue policy to allow EventBridge to send to DLQ
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
          "aws:SourceArn" = aws_cloudwatch_event_rule.ad_auth_failures.arn
        }
      }
    }]
  })
}""",
                cloudformation_template="""# AWS CloudFormation: Detect Kerberos ticket anomalies
# Step 1: Create SNS topic for security alerts
# Step 2: Configure CloudWatch alarms for suspicious AD authentication patterns
# Step 3: Set up EventBridge rules for authentication anomalies

AWSTemplateFormatVersion: '2010-09-09'
Description: 'Kerberos ticket anomaly detection for AWS Managed AD'

Parameters:
  DirectoryId:
    Type: String
    Description: AWS Directory Service Managed AD directory ID

  CloudTrailLogGroup:
    Type: String
    Description: CloudTrail log group name

  AlertEmail:
    Type: String
    Description: Email address for security alerts

Resources:
  # SNS Topic for alerts
  KerberosAlertsTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      TopicName: kerberos-ticket-anomaly-alerts
      Subscription:
        - Endpoint: !Ref AlertEmail
          Protocol: email

  # CloudWatch Log Metric Filter for RC4 encryption
  RC4TicketsMetricFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      FilterPattern: '[timestamp, request_id, event_type = EventType, event_data]'
      LogGroupName: !Ref CloudTrailLogGroup
      MetricTransformations:
        - MetricName: RC4KerberosTickets
          MetricNamespace: Security/Kerberos
          MetricValue: '1'

  # CloudWatch Alarm for suspicious Kerberos activity
  KerberosAnomalyAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: kerberos-ticket-anomaly
      AlarmDescription: Detects potential Golden Ticket or Kerberos ticket forgery
      MetricName: RC4KerberosTickets
      Namespace: Security/Kerberos
      Statistic: Sum
      Period: 300
      EvaluationPeriods: 1
      Threshold: 5
      ComparisonOperator: GreaterThanThreshold
      TreatMissingData: notBreaching

      AlarmActions:
        - !Ref KerberosAlertsTopic

  # EventBridge Rule for AD authentication failures
  ADAuthFailuresRule:
    Type: AWS::Events::Rule
    Properties:
      Name: directory-service-auth-failures
      Description: Detect authentication failures in AWS Managed AD
      EventPattern:
        source:
          - aws.ds
        detail-type:
          - AWS API Call via CloudTrail
        detail:
          eventName:
            - AuthenticateDirectory
            - DescribeDirectories
          errorCode:
            - exists: true
      State: ENABLED
      Targets:
        - Arn: !Ref KerberosAlertsTopic
          Id: SendToSNS

  # SNS Topic Policy
  SNSTopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics:
        - !Ref KerberosAlertsTopic
      PolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              Service: events.amazonaws.com
            Action: sns:Publish
            Resource: !Ref KerberosAlertsTopic
            Condition:
              StringEquals:
                AWS:SourceAccount: !Ref AWS::AccountId
              ArnEquals:
                aws:SourceArn: !GetAtt ADAuthFailuresRule.Arn

Outputs:
  TopicArn:
    Description: SNS Topic ARN for Kerberos alerts
    Value: !Ref KerberosAlertsTopic""",
                alert_severity="critical",
                alert_title="Kerberos Ticket Anomaly Detected",
                alert_description_template="Suspicious Kerberos authentication detected in Directory Service: {eventName}.",
                investigation_steps=[
                    "Review Directory Service CloudWatch logs for authentication patterns",
                    "Check for RC4-encrypted tickets (Golden Ticket indicator)",
                    "Identify source IP addresses and user accounts involved",
                    "Look for TGS requests without corresponding TGT requests (Silver Ticket)",
                    "Review security event logs for Event ID 4768 (TGT requests) and 4769 (TGS requests)",
                    "Check for Kerberoasting indicators (multiple SPN service ticket requests)",
                    "Review domain controller logs for unusual KRBTGT account activity",
                ],
                containment_actions=[
                    "Reset KRBTGT account password twice (renders Golden Tickets invalid)",
                    "Disable compromised user accounts immediately",
                    "Force password reset for affected service accounts",
                    "Revoke all active Kerberos tickets for compromised accounts",
                    "Enable AES encryption and disable RC4 if possible",
                    "Review and strengthen service account passwords (25+ characters)",
                    "Enable advanced AD auditing for Kerberos events",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Baseline normal authentication patterns for AD-integrated workloads",
            detection_coverage="60% - Detects anomalous patterns in AWS Managed AD environments",
            evasion_considerations="Attackers using AES encryption or staying within normal usage patterns may evade detection",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2-3 hours",
            estimated_monthly_cost="$10-25",
            prerequisites=[
                "AWS Managed AD or AD Connector",
                "CloudTrail enabled",
                "CloudWatch Logs configured",
            ],
        ),
        DetectionStrategy(
            strategy_id="t1558-aws-kerberoasting",
            name="AWS Kerberoasting Detection",
            description="Detect Kerberoasting attacks targeting service account credentials in hybrid environments.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, eventName, userIdentity.principalId, sourceIPAddress, requestParameters
| filter eventSource = "ds.amazonaws.com"
| filter eventName = "AuthenticateDirectory"
| stats count(*) as service_ticket_requests by userIdentity.principalId, bin(1h)
| filter service_ticket_requests > 20
| sort service_ticket_requests desc""",
                terraform_template="""# AWS: Detect Kerberoasting attacks
# Step 1: Create CloudWatch log metric for excessive SPN ticket requests
# Step 2: Configure alarm threshold based on baseline
# Step 3: Set up SNS notifications for security team

variable "cloudtrail_log_group" {
  description = "CloudTrail log group name"
  type        = string
}

variable "alert_email" {
  description = "Email address for security alerts"
  type        = string
}

# SNS topic for Kerberoasting alerts
resource "aws_sns_topic" "kerberoasting_alerts" {
  name = "kerberoasting-detection-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.kerberoasting_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# CloudWatch log metric for excessive service ticket requests
resource "aws_cloudwatch_log_metric_filter" "excessive_spn_requests" {
  name           = "kerberoasting-spn-requests"
  log_group_name = var.cloudtrail_log_group

  # Detect multiple service ticket requests (Kerberoasting indicator)
  pattern = "{ ($.eventName = AuthenticateDirectory) && ($.requestParameters.servicePrincipalName = *) }"

  metric_transformation {
    name      = "KerberoastingAttempts"
    namespace = "Security/Kerberos"
    value     = "1"
  }
}

# Alarm for Kerberoasting activity
resource "aws_cloudwatch_metric_alarm" "kerberoasting_detected" {
  alarm_name          = "kerberoasting-attack-detected"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "1"
  metric_name         = "KerberoastingAttempts"
  namespace           = "Security/Kerberos"
  period              = "3600"  # 1 hour window
  statistic           = "Sum"
  threshold           = "20"    # Adjust based on environment
  alarm_description   = "Detects potential Kerberoasting attack - excessive SPN ticket requests"
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.kerberoasting_alerts.arn]
}

# Additional metric for AS-REP Roasting detection
resource "aws_cloudwatch_log_metric_filter" "asrep_roasting" {
  name           = "asrep-roasting-attempts"
  log_group_name = var.cloudtrail_log_group

  # Detect AS-REQ requests for accounts without pre-authentication
  pattern = "{ ($.eventName = AuthenticateDirectory) && ($.errorCode = KDC_ERR_PREAUTH_REQUIRED) }"

  metric_transformation {
    name      = "ASREPRoastingAttempts"
    namespace = "Security/Kerberos"
    value     = "1"
  }
}

# Alarm for AS-REP Roasting
resource "aws_cloudwatch_metric_alarm" "asrep_roasting_detected" {
  alarm_name          = "asrep-roasting-detected"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "1"
  metric_name         = "ASREPRoastingAttempts"
  namespace           = "Security/Kerberos"
  period              = "1800"  # 30 minute window
  statistic           = "Sum"
  threshold           = "10"
  alarm_description   = "Detects potential AS-REP Roasting attack"
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.kerberoasting_alerts.arn]
}""",
                cloudformation_template="""# AWS CloudFormation: Detect Kerberoasting attacks
# Step 1: Create metric filters for excessive SPN ticket requests
# Step 2: Configure alarms with appropriate thresholds
# Step 3: Set up SNS notifications

AWSTemplateFormatVersion: '2010-09-09'
Description: 'Kerberoasting attack detection for AWS environments'

Parameters:
  CloudTrailLogGroup:
    Type: String
    Description: CloudTrail log group name

  AlertEmail:
    Type: String
    Description: Email address for security alerts

Resources:
  # SNS Topic
  KerberoastingAlertsTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      TopicName: kerberoasting-detection-alerts
      Subscription:
        - Endpoint: !Ref AlertEmail
          Protocol: email

  # Metric Filter for excessive SPN requests
  ExcessiveSPNRequestsFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      FilterPattern: '{ ($.eventName = AuthenticateDirectory) && ($.requestParameters.servicePrincipalName = *) }'
      LogGroupName: !Ref CloudTrailLogGroup
      MetricTransformations:
        - MetricName: KerberoastingAttempts
          MetricNamespace: Security/Kerberos
          MetricValue: '1'

  # Alarm for Kerberoasting
  KerberoastingAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: kerberoasting-attack-detected
      AlarmDescription: Detects potential Kerberoasting attack - excessive SPN ticket requests
      MetricName: KerberoastingAttempts
      Namespace: Security/Kerberos
      Statistic: Sum
      Period: 300
      EvaluationPeriods: 1
      Threshold: 20
      ComparisonOperator: GreaterThanThreshold
      TreatMissingData: notBreaching

      AlarmActions:
        - !Ref KerberoastingAlertsTopic

  # Metric Filter for AS-REP Roasting
  ASREPRoastingFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      FilterPattern: '{ ($.eventName = AuthenticateDirectory) && ($.errorCode = KDC_ERR_PREAUTH_REQUIRED) }'
      LogGroupName: !Ref CloudTrailLogGroup
      MetricTransformations:
        - MetricName: ASREPRoastingAttempts
          MetricNamespace: Security/Kerberos
          MetricValue: '1'

  # Alarm for AS-REP Roasting
  ASREPRoastingAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: asrep-roasting-detected
      AlarmDescription: Detects potential AS-REP Roasting attack
      MetricName: ASREPRoastingAttempts
      Namespace: Security/Kerberos
      Statistic: Sum
      Period: 1800
      EvaluationPeriods: 1
      Threshold: 10
      ComparisonOperator: GreaterThanThreshold
      TreatMissingData: notBreaching

      AlarmActions:
        - !Ref KerberoastingAlertsTopic

Outputs:
  TopicArn:
    Description: SNS Topic ARN for Kerberoasting alerts
    Value: !Ref KerberoastingAlertsTopic""",
                alert_severity="high",
                alert_title="Kerberoasting Attack Detected",
                alert_description_template="Excessive service ticket requests detected from {principalId}.",
                investigation_steps=[
                    "Review the requesting user account and source IP",
                    "Check for multiple SPN ticket requests in short timeframe",
                    "Identify which service accounts were targeted",
                    "Review security logs for Event ID 4769 (TGS requests)",
                    "Check if targeted service accounts have weak passwords",
                    "Look for offline password cracking attempts",
                    "Review account privileges and access patterns",
                ],
                containment_actions=[
                    "Disable compromised user account making requests",
                    "Force password reset for targeted service accounts",
                    "Implement strong passwords (25+ characters) for service accounts",
                    "Use Group Managed Service Accounts (gMSA) where possible",
                    "Enable 'Account is sensitive and cannot be delegated' for privileged accounts",
                    "Monitor for subsequent authentication attempts with cracked credentials",
                    "Review and reduce service account privileges",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Adjust threshold based on legitimate service ticket request patterns",
            detection_coverage="75% - Detects bulk Kerberoasting attempts",
            evasion_considerations="Slow, stealthy requests over extended periods may evade threshold-based detection",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$5-15",
            prerequisites=[
                "AWS Managed AD",
                "CloudTrail enabled",
                "Advanced AD auditing enabled",
            ],
        ),
        DetectionStrategy(
            strategy_id="t1558-gcp-ad-monitoring",
            name="GCP Managed AD Authentication Monitoring",
            description="Monitor authentication anomalies in GCP Managed Service for Microsoft AD.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""resource.type="microsoft_ad_domain"
(protoPayload.methodName="AuthenticateUser" OR protoPayload.methodName="DescribeDomain")
(protoPayload.status.code!=0 OR protoPayload.status.message=~".*authentication.*failed.*")""",
                gcp_terraform_template="""# GCP: Monitor Kerberos authentication in Managed AD
# Step 1: Create log-based metric for authentication anomalies
# Step 2: Set up alerting policy with notification channel
# Step 3: Configure Cloud Logging sink for long-term retention

variable "project_id" {
  description = "GCP project ID"
  type        = string
}

variable "alert_email" {
  description = "Email address for security alerts"
  type        = string
}

variable "managed_ad_domain" {
  description = "Managed AD domain name"
  type        = string
}

# Notification channel for alerts
resource "google_monitoring_notification_channel" "security_email" {
  display_name = "Security Team Email"
  type         = "email"
  project      = var.project_id

  labels = {
    email_address = var.alert_email
  }
}

# Log-based metric for authentication failures
resource "google_logging_metric" "ad_auth_failures" {
  name    = "managed-ad-auth-failures"
  project = var.project_id

  filter = <<-EOT
    resource.type="microsoft_ad_domain"
    resource.labels.domain_name="${var.managed_ad_domain}"
    (protoPayload.methodName="AuthenticateUser" OR protoPayload.methodName="DescribeDomain")
    protoPayload.status.code!=0
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    unit        = "1"

    labels {
      key         = "source_ip"
      value_type  = "STRING"
      description = "Source IP address of authentication attempt"
    }
  }

  label_extractors = {
    "source_ip" = "EXTRACT(protoPayload.requestMetadata.callerIp)"
  }
}

# Log-based metric for Kerberoasting indicators
resource "google_logging_metric" "kerberoasting_attempts" {
  name    = "kerberoasting-attempts"
  project = var.project_id

  filter = <<-EOT
    resource.type="microsoft_ad_domain"
    resource.labels.domain_name="${var.managed_ad_domain}"
    protoPayload.methodName="AuthenticateUser"
    jsonPayload.servicePrincipalName:*
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    unit        = "1"
  }
}

# Alert policy for authentication failures
resource "google_monitoring_alert_policy" "auth_failure_alert" {
  project      = var.project_id
  display_name = "Managed AD Authentication Failures"
  combiner     = "OR"

  conditions {
    display_name = "High authentication failure rate"

    condition_threshold {
      filter          = "resource.type=\"microsoft_ad_domain\" AND metric.type=\"logging.googleapis.com/user/${google_logging_metric.ad_auth_failures.name}\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 10

      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_RATE"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.security_email.id]

  alert_strategy {
    auto_close = "86400s"  # 24 hours
  }

  documentation {
    content   = "Potential Kerberos authentication attack detected in Managed AD. Investigate source IPs and user accounts immediately."
    mime_type = "text/markdown"
  }
}

# Alert policy for Kerberoasting
resource "google_monitoring_alert_policy" "kerberoasting_alert" {
  project      = var.project_id
  display_name = "Kerberoasting Attack Detection"
  combiner     = "OR"

  conditions {
    display_name = "Excessive service ticket requests"

    condition_threshold {
      filter          = "resource.type=\"microsoft_ad_domain\" AND metric.type=\"logging.googleapis.com/user/${google_logging_metric.kerberoasting_attempts.name}\""
      duration        = "3600s"  # 1 hour
      comparison      = "COMPARISON_GT"
      threshold_value = 20

      aggregations {
        alignment_period   = "3600s"
        per_series_aligner = "ALIGN_SUM"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.security_email.id]

  alert_strategy {
    auto_close = "86400s"
    notification_rate_limit {
      period = "300s"
    }
  }

  documentation {
    content   = "Potential Kerberoasting attack detected. Review service account security and password strength."
    mime_type = "text/markdown"
  }
}

# Log sink for long-term retention and analysis
resource "google_logging_project_sink" "ad_auth_logs" {
  name        = "managed-ad-authentication-logs"
  project     = var.project_id
  destination = "storage.googleapis.com/${google_storage_bucket.ad_logs.name}"

  filter = <<-EOT
    resource.type="microsoft_ad_domain"
    resource.labels.domain_name="${var.managed_ad_domain}"
    (protoPayload.methodName="AuthenticateUser" OR protoPayload.methodName="DescribeDomain")
  EOT

  unique_writer_identity = true
}

# Storage bucket for log retention
resource "google_storage_bucket" "ad_logs" {
  name          = "${var.project_id}-managed-ad-logs"
  project       = var.project_id
  location      = "US"
  force_destroy = false

  lifecycle_rule {
    condition {
      age = 90  # Retain for 90 days
    }
    action {
      type = "Delete"
    }
  }

  uniform_bucket_level_access = true
}

# IAM binding for log sink
resource "google_storage_bucket_iam_member" "log_writer" {
  bucket = google_storage_bucket.ad_logs.name
  role   = "roles/storage.objectCreator"
  member = google_logging_project_sink.ad_auth_logs.writer_identity
}""",
                alert_severity="high",
                alert_title="GCP Managed AD Authentication Anomaly",
                alert_description_template="Suspicious Kerberos authentication activity detected in Managed AD domain.",
                investigation_steps=[
                    "Review Cloud Logging for Managed AD authentication events",
                    "Check source IP addresses and geographic locations",
                    "Identify user accounts and service principals involved",
                    "Look for patterns indicating Golden Ticket (RC4 encryption)",
                    "Review for Kerberoasting (multiple SPN requests)",
                    "Check for AS-REP Roasting attempts",
                    "Correlate with Windows Security Event logs if available",
                ],
                containment_actions=[
                    "Reset KRBTGT account password twice to invalidate Golden Tickets",
                    "Disable compromised user accounts",
                    "Force password resets for affected service accounts",
                    "Enable AES encryption, disable RC4 if not already done",
                    "Strengthen service account passwords (25+ characters)",
                    "Enable 'Do not require Kerberos pre-authentication' flag review",
                    "Implement Group Managed Service Accounts where possible",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Baseline normal AD authentication patterns; exclude legitimate batch processes",
            detection_coverage="65% - Covers common Kerberos attack patterns in GCP Managed AD",
            evasion_considerations="Sophisticated attackers using AES and mimicking normal patterns may evade detection",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2-3 hours",
            estimated_monthly_cost="$15-30",
            prerequisites=[
                "GCP Managed Service for Microsoft AD",
                "Cloud Logging enabled",
                "Cloud Monitoring configured",
            ],
        ),
    ],
    recommended_order=[
        "t1558-aws-ad-auth",
        "t1558-aws-kerberoasting",
        "t1558-gcp-ad-monitoring",
    ],
    total_effort_hours=6.0,
    coverage_improvement="+15% improvement for Credential Access tactic in hybrid cloud environments",
)
