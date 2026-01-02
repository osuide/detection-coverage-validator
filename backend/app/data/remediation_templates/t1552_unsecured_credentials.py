"""
T1552 - Unsecured Credentials

Adversaries search compromised systems to find insecurely stored credentials in
plaintext files, registry entries, shell history, private keys, and cloud metadata APIs.
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
    technique_id="T1552",
    technique_name="Unsecured Credentials",
    tactic_ids=["TA0006"],
    mitre_url="https://attack.mitre.org/techniques/T1552/",
    threat_context=ThreatContext(
        description=(
            "Adversaries search compromised systems to locate insecurely stored credentials "
            "found in plaintext files, operating system repositories, application-specific storage, "
            "and specialised files such as shell history, registry entries, private keys, and cloud "
            "instance metadata APIs. In cloud environments, credentials are often exposed through "
            "misconfigured storage, hardcoded secrets in code, container environment variables, "
            "and accessible metadata services."
        ),
        attacker_goal="Obtain valid credentials to escalate privileges and move laterally without deploying additional malware",
        why_technique=[
            "Developers frequently hardcode credentials in source code and configuration files",
            "Cloud metadata APIs provide instant access to temporary credentials",
            "Shell history files often contain credentials from command-line operations",
            "Private keys and service account credentials stored without encryption",
            "Credentials found here typically have elevated permissions",
            "No authentication required if files are world-readable or exposed",
            "Automated scanning tools make discovery at scale trivial",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="common",
        trend="increasing",
        severity_score=9,
        severity_reasoning=(
            "Unsecured credentials remain the #1 cloud attack vector in 2024. Discovery requires "
            "minimal sophistication, credentials often have excessive permissions, and successful "
            "exploitation enables complete environment compromise. The attack surface continues to "
            "expand with containers, serverless functions, and multi-cloud deployments."
        ),
        business_impact=[
            "Complete cloud environment compromise",
            "Unauthorised access to sensitive data and customer information",
            "Lateral movement to production systems",
            "Cryptomining and resource abuse resulting in unexpected costs",
            "Regulatory fines for inadequate credential protection (GDPR, PCI-DSS, HIPAA)",
            "Reputational damage and loss of customer trust",
            "Ransomware deployment using compromised administrative credentials",
        ],
        typical_attack_phase="credential_access",
        often_precedes=["T1078.004", "T1087.004", "T1530", "T1098"],
        often_follows=["T1190", "T1595", "T1609", "T1611"],
    ),
    detection_strategies=[
        # Strategy 1: AWS - GuardDuty for credential exposure and exfiltration
        DetectionStrategy(
            strategy_id="t1552-aws-guardduty",
            name="GuardDuty Credential Exposure Detection",
            description="Detect when credentials are exfiltrated or used from unexpected locations, indicating they may have been obtained from insecure storage.",
            detection_type=DetectionType.GUARDDUTY,
            aws_service="guardduty",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                guardduty_finding_types=[
                    "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS",
                    "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.InsideAWS",
                    "CredentialAccess:IAMUser/AnomalousBehavior",
                    "UnauthorizedAccess:EC2/MetadataDNSRebind",
                    "UnauthorizedAccess:EC2/RDPBruteForce",
                ],
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect credential exfiltration and exposure via GuardDuty

Parameters:
  AlertEmail:
    Type: String
    Description: Email address for security alerts

Resources:
  # Step 1: Enable GuardDuty to detect credential exfiltration
  GuardDutyDetector:
    Type: AWS::GuardDuty::Detector
    Properties:
      Enable: true
      FindingPublishingFrequency: FIFTEEN_MINUTES

  # Step 2: SNS topic for alerts
  CredentialAlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      DisplayName: Credential Exposure Alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 3: Dead Letter Queue for failed deliveries
  DeadLetterQueue:
    Type: AWS::SQS::Queue
    Properties:
      QueueName: credential-exposure-alerts-dlq
      MessageRetentionPeriod: 1209600

  # Step 4: Route credential exposure findings to alerts
  CredentialExposureRule:
    Type: AWS::Events::Rule
    Properties:
      Name: T1552-CredentialExposure
      Description: Alert on credential exposure and exfiltration
      EventPattern:
        source: [aws.guardduty]
        detail-type:
          - GuardDuty Finding
        detail:
          type:
            - prefix: "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS"
            - prefix: "CredentialAccess:IAMUser"
            - prefix: "UnauthorizedAccess:EC2/MetadataDNSRebind"
      State: ENABLED
      Targets:
        - Id: SNSTarget
          Arn: !Ref CredentialAlertTopic
          RetryPolicy:
            MaximumEventAgeInSeconds: 3600
            MaximumRetryAttempts: 8
          DeadLetterConfig:
            Arn: !GetAtt DeadLetterQueue.Arn
          InputTransformer:
            InputPathsMap:
              account: $.account
              region: $.region
              time: $.time
              type: $.detail.type
              severity: $.detail.severity
              description: $.detail.description
            InputTemplate: |
              "CRITICAL: Credential Exposure Alert (T1552)"
              "Time: <time>"
              "Account: <account> | Region: <region>"
              "Finding Type: <type>"
              "Severity: <severity>"
              "Description: <description>"
              "Action: Rotate credentials and investigate immediately"

  TopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics: [!Ref CredentialAlertTopic]
      PolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Sid: AllowEventBridgePublishScoped
            Effect: Allow
            Principal:
              Service: events.amazonaws.com
            Action: sns:Publish
            Resource: !Ref CredentialAlertTopic
            Condition:
              StringEquals:
                AWS:SourceAccount: !Ref AWS::AccountId
              ArnEquals:
                aws:SourceArn: !GetAtt CredentialExposureRule.Arn

  DLQPolicy:
    Type: AWS::SQS::QueuePolicy
    Properties:
      Queues:
        - !Ref DeadLetterQueue
      PolicyDocument:
        Statement:
          - Effect: Allow
            Principal:
              Service: events.amazonaws.com
            Action: sqs:SendMessage
            Resource: !GetAtt DeadLetterQueue.Arn
            Condition:
              StringEquals:
                AWS:SourceAccount: !Ref AWS::AccountId
              ArnEquals:
                aws:SourceArn: !GetAtt CredentialExposureRule.Arn""",
                terraform_template="""# Detect credential exfiltration and exposure via GuardDuty

variable "alert_email" {
  type        = string
  description = "Email address for security alerts"
}

data "aws_caller_identity" "current" {}

# Step 1: Enable GuardDuty to detect credential exfiltration
resource "aws_guardduty_detector" "main" {
  enable                       = true
  finding_publishing_frequency = "FIFTEEN_MINUTES"
}

# Step 2: SNS topic for alerts
resource "aws_sns_topic" "credential_alerts" {
  name              = "credential-exposure-alerts"
  kms_master_key_id = "alias/aws/sns"
  display_name      = "Credential Exposure Alerts"
}

resource "aws_sns_topic_subscription" "email_subscription" {
  topic_arn = aws_sns_topic.credential_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 3: Dead Letter Queue for failed deliveries
resource "aws_sqs_queue" "dlq" {
  name                      = "credential-exposure-alerts-dlq"
  message_retention_seconds = 1209600
}

# Step 4: Route credential exposure findings to alerts
resource "aws_cloudwatch_event_rule" "credential_exposure" {
  name        = "T1552-CredentialExposure"
  description = "Alert on credential exposure and exfiltration"

  event_pattern = jsonencode({
    source        = ["aws.guardduty"]
    "detail-type" = ["GuardDuty Finding"]
    detail = {
      type = [
        { prefix = "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS" },
        { prefix = "CredentialAccess:IAMUser" },
        { prefix = "UnauthorizedAccess:EC2/MetadataDNSRebind" }
      ]
    }
  })
}

resource "aws_cloudwatch_event_target" "sns_target" {
  rule      = aws_cloudwatch_event_rule.credential_exposure.name
  target_id = "SNSTarget"
  arn       = aws_sns_topic.credential_alerts.arn

  retry_policy {
    maximum_event_age_in_seconds = 3600
    maximum_retry_attempts       = 8
  }

  dead_letter_config {
    arn = aws_sqs_queue.dlq.arn
  }

  input_transformer {
    input_paths = {
      account     = "$.account"
      region      = "$.region"
      time        = "$.time"
      type        = "$.detail.type"
      severity    = "$.detail.severity"
      description = "$.detail.description"
    }

    input_template = <<-EOT
"CRITICAL: Credential Exposure Alert (T1552)
Time: <time>
Account: <account> | Region: <region>
Finding Type: <type>
Severity: <severity>
Description: <description>
Action: Rotate credentials and investigate immediately"
EOT
  }
}

resource "aws_sns_topic_policy" "credential_alerts_policy" {
  arn = aws_sns_topic.credential_alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowEventBridgePublishScoped"
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.credential_alerts.arn
      Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
        ArnEquals = {
          "aws:SourceArn" = aws_cloudwatch_event_rule.credential_exposure.arn
        }
      }
    }]
  })
}

resource "aws_sqs_queue_policy" "dlq" {
  queue_url = aws_sqs_queue.dlq.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sqs:SendMessage"
      Resource  = aws_sqs_queue.dlq.arn
    }]
  })
}""",
                alert_severity="critical",
                alert_title="Credential Exfiltration or Exposure Detected",
                alert_description_template="GuardDuty detected credential exfiltration or unusual credential usage. Finding: {finding_type}. Principal: {principal}. Source IP: {source_ip}.",
                investigation_steps=[
                    "Review the GuardDuty finding details to identify which credentials were affected",
                    "Check CloudTrail for all API calls made using the compromised credentials",
                    "Identify the source of the credentials (instance metadata, file, environment variable)",
                    "Determine the time window of potential exposure",
                    "Review what resources were accessed or modified",
                    "Check for lateral movement to other accounts or services",
                ],
                containment_actions=[
                    "Immediately rotate the compromised credentials",
                    "Revoke all active sessions for the affected principal",
                    "Block the source IP if identified as malicious",
                    "Disable EC2 instance or container if it's the source",
                    "Scan all systems for exposed credential files",
                    "Enable IMDSv2 on EC2 instances to prevent metadata abuse",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Whitelist known CI/CD systems and deployment automation tools. Create trusted IP lists for expected locations.",
            detection_coverage="70% - catches credential use from unexpected locations and metadata API abuse",
            evasion_considerations="Attackers using credentials from expected regions/IPs or accessing metadata via SSRF may evade detection",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$4/million events analysed",
            prerequisites=["GuardDuty service quota available"],
        ),
        # Strategy 2: AWS - Detect access to credential storage locations
        DetectionStrategy(
            strategy_id="t1552-aws-secret-access",
            name="Monitor Access to Secret Storage Services",
            description="Detect unusual or bulk access to AWS Secrets Manager, Parameter Store, and KMS, which may indicate credential harvesting.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, userIdentity.arn, eventName, requestParameters.secretId, requestParameters.name, sourceIPAddress
| filter eventSource in ["secretsmanager.amazonaws.com", "ssm.amazonaws.com", "kms.amazonaws.com"]
| filter eventName in ["GetSecretValue", "BatchGetSecretValue", "GetParameter", "GetParameters", "GetParametersByPath", "Decrypt"]
| stats count(*) as access_count by userIdentity.arn, eventName, bin(5m)
| filter access_count > 10
| sort access_count desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Alert on unusual access to credential storage services

Parameters:
  CloudTrailLogGroup:
    Type: String
    Description: CloudTrail log group name
  AlertEmail:
    Type: String
    Description: Email for alerts

Resources:
  # Step 1: SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      DisplayName: Secret Access Alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Metric filter for secret access
  SecretAccessMetricFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ ($.eventSource = "secretsmanager.amazonaws.com" && $.eventName = "GetSecretValue") || ($.eventSource = "ssm.amazonaws.com" && $.eventName = "GetParameter*") }'
      MetricTransformations:
        - MetricName: SecretAccessCount
          MetricNamespace: Security/T1552
          MetricValue: "1"
          DefaultValue: 0

  # Step 3: Alarm on excessive access
  SecretAccessAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: T1552-ExcessiveSecretAccess
      AlarmDescription: High volume of secret retrieval detected
      MetricName: SecretAccessCount
      Namespace: Security/T1552
      Statistic: Sum
      Period: 300
      Threshold: 20
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      TreatMissingData: notBreaching

      AlarmActions: [!Ref AlertTopic]""",
                terraform_template="""# Alert on unusual access to credential storage services

variable "cloudtrail_log_group" {
  type        = string
  description = "CloudTrail log group name"
}

variable "alert_email" {
  type        = string
  description = "Email for alerts"
}

# Step 1: SNS topic for alerts
resource "aws_sns_topic" "secret_access_alerts" {
  name         = "secret-access-alerts"
  kms_master_key_id = "alias/aws/sns"
  display_name = "Secret Access Alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.secret_access_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Metric filter for secret access
resource "aws_cloudwatch_log_metric_filter" "secret_access" {
  name           = "T1552-SecretAccess"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ ($.eventSource = \"secretsmanager.amazonaws.com\" && $.eventName = \"GetSecretValue\") || ($.eventSource = \"ssm.amazonaws.com\" && $.eventName = \"GetParameter*\") }"

  metric_transformation {
    name          = "SecretAccessCount"
    namespace     = "Security/T1552"
    value         = "1"
    default_value = 0
  }
}

# Step 3: Alarm on excessive access
resource "aws_cloudwatch_metric_alarm" "secret_access" {
  alarm_name          = "T1552-ExcessiveSecretAccess"
  alarm_description   = "High volume of secret retrieval detected"
  metric_name         = "SecretAccessCount"
  namespace           = "Security/T1552"
  statistic           = "Sum"
  period              = 300
  threshold           = 20
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.secret_access_alerts.arn]
}""",
                alert_severity="high",
                alert_title="Unusual Access to Secret Storage",
                alert_description_template="High volume of secret retrieval detected. {access_count} accesses by {principal} in 5 minutes.",
                investigation_steps=[
                    "Identify which IAM principal is accessing secrets",
                    "Review which specific secrets were accessed",
                    "Check if access pattern matches normal application behaviour",
                    "Verify the source IP and user agent",
                    "Look for other suspicious activity from the same principal",
                    "Review IAM permissions to assess if they're excessive",
                ],
                containment_actions=[
                    "Rotate all accessed secrets immediately",
                    "Restrict IAM permissions for the accessing principal",
                    "Enable automatic secret rotation if not already enabled",
                    "Review and update resource policies on secrets",
                    "Enable AWS Config rules for secret manager compliance",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Baseline normal access patterns over 30 days. Exclude known batch processes and CI/CD pipelines.",
            detection_coverage="75% - catches bulk credential harvesting attempts",
            evasion_considerations="Slow, distributed access below threshold may evade detection. Adjust thresholds based on environment.",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$10-20 depending on log volume",
            prerequisites=["CloudTrail enabled and logging to CloudWatch Logs"],
        ),
        # Strategy 3: GCP - Detect secret access via Cloud Logging
        DetectionStrategy(
            strategy_id="t1552-gcp-secret-access",
            name="GCP Secret Manager Access Monitoring",
            description="Monitor for unusual access to GCP Secret Manager and service account keys, indicating potential credential harvesting.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""resource.type="audited_resource"
protoPayload.serviceName="secretmanager.googleapis.com"
protoPayload.methodName=~"google.cloud.secretmanager.v1.SecretManagerService.(AccessSecretVersion|GetSecretVersion)"
OR (protoPayload.serviceName="iam.googleapis.com"
    AND protoPayload.methodName=~"google.iam.admin.v1.CreateServiceAccountKey")""",
                gcp_terraform_template="""# GCP: Monitor Secret Manager and service account key access

variable "project_id" {
  type        = string
  description = "GCP project ID"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

# Step 1: Create notification channel
resource "google_monitoring_notification_channel" "email_s1" {
  display_name = "Security Alert Email"
  type         = "email"
  project      = var.project_id

  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Log-based metric for secret access
resource "google_logging_metric" "secret_access" {
  name    = "t1552-secret-access"
  project = var.project_id

  filter = <<-EOT
    resource.type="audited_resource"
    (protoPayload.serviceName="secretmanager.googleapis.com"
     AND protoPayload.methodName=~"google.cloud.secretmanager.v1.SecretManagerService.(AccessSecretVersion|GetSecretVersion)")
    OR (protoPayload.serviceName="iam.googleapis.com"
        AND protoPayload.methodName=~"google.iam.admin.v1.CreateServiceAccountKey")
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    unit        = "1"
  }
}

# Step 3: Alert policy for unusual access
resource "google_monitoring_alert_policy" "secret_access_alert" {
  project      = var.project_id
  display_name = "T1552 - Unusual Secret Access"
  combiner     = "OR"

  conditions {
    display_name = "High volume of secret access"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.secret_access.name}\" AND resource.type=\"audited_resource\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 15
      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_RATE"
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

  documentation {
    content   = "High volume of Secret Manager or service account key access detected, indicating potential credential harvesting (MITRE T1552)."
    mime_type = "text/markdown"
  }
}""",
                alert_severity="high",
                alert_title="GCP: Unusual Secret Access Detected",
                alert_description_template="High volume of Secret Manager or service account key access detected, potentially indicating credential harvesting.",
                investigation_steps=[
                    "Review Cloud Audit Logs to identify the principal accessing secrets",
                    "Check which secrets or service account keys were accessed",
                    "Verify the source IP and determine if it's expected",
                    "Review IAM permissions for the accessing principal",
                    "Check for other suspicious activity from the same identity",
                    "Determine if access pattern matches legitimate application behaviour",
                ],
                containment_actions=[
                    "Rotate all accessed secrets and service account keys",
                    "Disable compromised service accounts",
                    "Restrict IAM permissions using least privilege principle",
                    "Enable VPC Service Controls to restrict Secret Manager access",
                    "Implement automatic secret rotation policies",
                    "Review and update secret version access policies",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Baseline normal access patterns. Exclude known CI/CD service accounts and deployment automation.",
            detection_coverage="75% - catches bulk secret access and service account key creation",
            evasion_considerations="Attackers may spread access over time to stay below thresholds. Use behaviour analysis for better detection.",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$15-25",
            prerequisites=["Cloud Audit Logs enabled", "Secret Manager API enabled"],
        ),
        # Strategy 4: AWS - Detect EC2 instance metadata service abuse
        DetectionStrategy(
            strategy_id="t1552-aws-metadata-abuse",
            name="EC2 Instance Metadata Service Abuse Detection",
            description="Detect potential abuse of EC2 instance metadata service to obtain temporary credentials (T1552.005).",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, @message
| filter @message like /169.254.169.254/
| filter @message like /latest\\/meta-data\\/iam\\/security-credentials/
| stats count(*) as metadata_requests by bin(5m)
| filter metadata_requests > 100
| sort metadata_requests desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect EC2 metadata service abuse for T1552.005

Parameters:
  VPCFlowLogGroup:
    Type: String
    Description: VPC Flow Logs log group name
  AlertEmail:
    Type: String

Resources:
  # Step 1: SNS topic
  MetadataAbuseTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      DisplayName: Metadata Service Abuse Alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Metric filter for metadata access
  MetadataAccessFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref VPCFlowLogGroup
      FilterPattern: '[version, account, eni, source, destination="169.254.169.254", ...]'
      MetricTransformations:
        - MetricName: MetadataServiceAccess
          MetricNamespace: Security/T1552
          MetricValue: "1"

  # Step 3: Alarm on excessive metadata access
  MetadataAccessAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: T1552-MetadataServiceAbuse
      AlarmDescription: Excessive EC2 metadata service access detected
      MetricName: MetadataServiceAccess
      Namespace: Security/T1552
      Statistic: Sum
      Period: 300
      Threshold: 100
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      TreatMissingData: notBreaching

      AlarmActions: [!Ref MetadataAbuseTopic]""",
                terraform_template="""# Detect EC2 metadata service abuse for T1552.005

variable "vpc_flow_log_group" {
  type        = string
  description = "VPC Flow Logs log group name"
}

variable "alert_email" {
  type = string
}

# Step 1: SNS topic
resource "aws_sns_topic" "metadata_abuse" {
  name         = "metadata-abuse-alerts"
  kms_master_key_id = "alias/aws/sns"
  display_name = "Metadata Service Abuse Alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.metadata_abuse.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Metric filter for metadata access
resource "aws_cloudwatch_log_metric_filter" "metadata_access" {
  name           = "T1552-MetadataAccess"
  log_group_name = var.vpc_flow_log_group
  pattern        = "[version, account, eni, source, destination=\"169.254.169.254\", ...]"

  metric_transformation {
    name      = "MetadataServiceAccess"
    namespace = "Security/T1552"
    value     = "1"
  }
}

# Step 3: Alarm on excessive metadata access
resource "aws_cloudwatch_metric_alarm" "metadata_abuse" {
  alarm_name          = "T1552-MetadataServiceAbuse"
  alarm_description   = "Excessive EC2 metadata service access detected"
  metric_name         = "MetadataServiceAccess"
  namespace           = "Security/T1552"
  statistic           = "Sum"
  period              = 300
  threshold           = 100
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.metadata_abuse.arn]
}""",
                alert_severity="high",
                alert_title="EC2 Metadata Service Abuse Detected",
                alert_description_template="Excessive metadata service requests detected: {metadata_requests} requests in 5 minutes. Possible SSRF or credential harvesting.",
                investigation_steps=[
                    "Identify which EC2 instance(s) are making excessive metadata requests",
                    "Check application logs for SSRF vulnerabilities",
                    "Review if IMDSv2 (session-oriented) is enforced on instances",
                    "Investigate network traffic from affected instances",
                    "Check CloudTrail for any API calls made using instance credentials",
                    "Review instance role permissions for excessive privileges",
                ],
                containment_actions=[
                    "Enforce IMDSv2 on all EC2 instances to prevent SSRF abuse",
                    "Rotate instance role credentials if compromise is suspected",
                    "Implement hop limit of 1 for metadata service",
                    "Review and restrict instance role permissions",
                    "Patch applications vulnerable to SSRF",
                    "Consider isolating affected instances for forensic analysis",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Adjust threshold based on normal instance metadata usage patterns. Some applications legitimately query metadata frequently.",
            detection_coverage="60% - catches SSRF-based metadata abuse and excessive harvesting attempts",
            evasion_considerations="Attackers using low-and-slow techniques or already having IMDSv2 tokens may evade detection",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2 hours",
            estimated_monthly_cost="$10-15",
            prerequisites=["VPC Flow Logs enabled and logging to CloudWatch"],
        ),
    ],
    recommended_order=[
        "t1552-aws-guardduty",
        "t1552-aws-secret-access",
        "t1552-gcp-secret-access",
        "t1552-aws-metadata-abuse",
    ],
    total_effort_hours=6.0,
    coverage_improvement="+30% improvement for Credential Access tactic",
)
