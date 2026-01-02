"""
T1552.005 - Unsecured Credentials: Cloud Instance Metadata API

Adversaries access cloud instance metadata services to retrieve
temporary credentials. IMDS attacks are a key vector for lateral movement.
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
    technique_id="T1552.005",
    technique_name="Unsecured Credentials: Cloud Instance Metadata API",
    tactic_ids=["TA0006"],
    mitre_url="https://attack.mitre.org/techniques/T1552/005/",
    threat_context=ThreatContext(
        description=(
            "Cloud instances expose metadata services (AWS IMDS, GCP metadata server) "
            "that provide instance credentials. SSRF vulnerabilities or compromised "
            "applications can be exploited to steal these credentials."
        ),
        attacker_goal="Steal IAM role credentials via instance metadata service",
        why_technique=[
            "Metadata service accessible at known IP (169.254.169.254)",
            "No authentication required by default (IMDSv1)",
            "Credentials can have significant permissions",
            "SSRF vulnerabilities make exploitation easy",
            "Credentials valid for hours after theft",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="common",
        trend="stable",
        severity_score=8,
        severity_reasoning=(
            "IMDS credential theft provides immediate access to cloud resources. "
            "IMDSv1 is still common and easily exploitable. Credentials often have "
            "more permissions than needed."
        ),
        business_impact=[
            "Credential theft leading to data breaches",
            "Lateral movement across cloud resources",
            "Resource abuse for cryptomining",
            "Privilege escalation if role is overpermissioned",
        ],
        typical_attack_phase="credential_access",
        often_precedes=["T1078.004", "T1530", "T1537"],
        often_follows=["T1190", "T1059"],
    ),
    detection_strategies=[
        # Strategy 1: AWS - GuardDuty IMDS exfiltration
        DetectionStrategy(
            strategy_id="t1552005-aws-guardduty",
            name="GuardDuty Instance Credential Exfiltration",
            description="Detect when instance role credentials are used from outside AWS.",
            detection_type=DetectionType.GUARDDUTY,
            aws_service="guardduty",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                guardduty_finding_types=[
                    "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS",
                    "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.InsideAWS",
                ],
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect IMDS credential exfiltration

Parameters:
  AlertEmail:
    Type: String

Resources:
  # Step 1: Enable GuardDuty
  Detector:
    Type: AWS::GuardDuty::Detector
    Properties:
      Enable: true

  # Step 2: SNS topic
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 3: Route IMDS exfil findings
  IMDSExfilRule:
    Type: AWS::Events::Rule
    Properties:
      EventPattern:
        source: [aws.guardduty]
        detail-type:
          - GuardDuty Finding
        detail:
          type:
            - prefix: "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS"
      Targets:
        - Id: Alert
          Arn: !Ref AlertTopic

  DeadLetterQueue:
    Type: AWS::SQS::Queue
    Properties:
      QueueName: imds-exfil-dlq
      MessageRetentionPeriod: 1209600

  TopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics:
        - !Ref AlertTopic
      PolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Sid: AllowEventBridgePublishScoped
            Effect: Allow
            Principal:
              Service: events.amazonaws.com
            Action: sns:Publish
            Resource: !Ref AlertTopic
            Condition:
              StringEquals:
                AWS:SourceAccount: !Ref AWS::AccountId
              ArnEquals:
                aws:SourceArn: !GetAtt IMDSExfilRule.Arn""",
                terraform_template="""# Detect IMDS credential exfiltration

variable "alert_email" {
  type = string
}

# Step 1: Enable GuardDuty
resource "aws_guardduty_detector" "main" {
  enable = true
}

# Step 2: SNS topic
resource "aws_sns_topic" "alerts" {
  name = "imds-exfil-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 3: Route IMDS exfil findings
resource "aws_cloudwatch_event_rule" "imds_exfil" {
  name = "imds-exfil-alerts"
  event_pattern = jsonencode({
    source = ["aws.guardduty"]
    "detail-type" = ["GuardDuty Finding"]
    detail = {
      type = [{ prefix = "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS" }]
    }
  })
}

data "aws_caller_identity" "current" {}

# DLQ for failed deliveries
resource "aws_sqs_queue" "dlq" {
  name                      = "imds-exfil-dlq"
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
      values   = [aws_cloudwatch_event_rule.imds_exfil.arn]
    }
  }
}

resource "aws_sqs_queue_policy" "event_dlq" {
  queue_url = aws_sqs_queue.dlq.url
  policy    = data.aws_iam_policy_document.eventbridge_dlq_policy.json
}

resource "aws_cloudwatch_event_target" "sns" {
  rule      = aws_cloudwatch_event_rule.imds_exfil.name
  target_id = "SNSTarget"
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
      account  = "$.account"
      region   = "$.region"
      time     = "$.time"
      type     = "$.detail.type"
      severity = "$.detail.severity"
      instance = "$.detail.resource.instanceDetails.instanceId"
      role     = "$.detail.resource.accessKeyDetails.userName"
    }

    input_template = <<-EOT
"IMDS Credential Exfiltration Alert (T1552.005)
time=<time> account=<account> region=<region>
type=<type> severity=<severity>
instance=<instance> role=<role>
Action: Revoke instance credentials immediately"
EOT
  }
}

resource "aws_sns_topic_policy" "allow_events" {
  arn = aws_sns_topic.alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowEventBridgePublishScoped"
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.alerts.arn
      Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
        ArnEquals = {
          "aws:SourceArn" = aws_cloudwatch_event_rule.imds_exfil.arn
        }
      }
    }]
  })
}""",
                alert_severity="critical",
                alert_title="IMDS Credential Exfiltration Detected",
                alert_description_template="Instance credentials used from external location. This indicates credential theft via IMDS.",
                investigation_steps=[
                    "Identify which EC2 instance's credentials were stolen",
                    "Check VPC flow logs for connections to 169.254.169.254",
                    "Review application logs for SSRF patterns",
                    "List all API calls made with the stolen credentials",
                ],
                containment_actions=[
                    "Terminate or isolate the affected instance",
                    "Revoke the instance role's sessions",
                    "Enable IMDSv2 requirement on the instance",
                    "Review and restrict the IAM role permissions",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Whitelist known hybrid/on-prem services that use instance credentials",
            detection_coverage="90% - catches external credential use",
            evasion_considerations="Attacker using credentials from within AWS",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$4/million events",
            prerequisites=["GuardDuty enabled"],
        ),
        # Strategy 2: AWS - Enforce IMDSv2
        DetectionStrategy(
            strategy_id="t1552005-aws-imdsv2",
            name="Enforce IMDSv2 (Prevention + Detection)",
            description="Require IMDSv2 which blocks simple SSRF attacks and monitor compliance.",
            detection_type=DetectionType.CONFIG_RULE,
            aws_service="config",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                config_rule_identifier="ec2-imdsv2-check",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Enforce IMDSv2 on EC2 instances

Parameters:
  AlertEmail:
    Type: String

Resources:
  # Step 1: SNS topic for non-compliant notifications
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Config rule to check IMDSv2
  IMDSv2Rule:
    Type: AWS::Config::ConfigRule
    Properties:
      ConfigRuleName: ec2-imdsv2-check
      Description: Check that EC2 instances require IMDSv2
      Source:
        Owner: AWS
        SourceIdentifier: EC2_IMDSV2_CHECK

  # Step 3: EventBridge to alert on non-compliance
  NonComplianceRule:
    Type: AWS::Events::Rule
    Properties:
      EventPattern:
        source: [aws.config]
        detail-type: [Config Rules Compliance Change]
        detail:
          configRuleName: [ec2-imdsv2-check]
          newEvaluationResult:
            complianceType: [NON_COMPLIANT]
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
                aws:SourceArn: !GetAtt NonComplianceRule.Arn""",
                terraform_template="""# Enforce IMDSv2 on EC2 instances

variable "alert_email" {
  type = string
}

# Step 1: SNS topic
resource "aws_sns_topic" "alerts" {
  name = "imdsv2-compliance-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Config rule
resource "aws_config_config_rule" "imdsv2" {
  name = "ec2-imdsv2-check"

  source {
    owner             = "AWS"
    source_identifier = "EC2_IMDSV2_CHECK"
  }

  depends_on = [aws_config_configuration_recorder.main]
}

# Step 3: Alert on non-compliance
resource "aws_cloudwatch_event_rule" "non_compliant" {
  name = "imdsv2-non-compliant"
  event_pattern = jsonencode({
    source      = ["aws.config"]
    detail-type = ["Config Rules Compliance Change"]
    detail = {
      configRuleName = ["ec2-imdsv2-check"]
      newEvaluationResult = {
        complianceType = ["NON_COMPLIANT"]
      }
    }
  })
}

resource "aws_cloudwatch_event_target" "sns" {
  rule = aws_cloudwatch_event_rule.non_compliant.name
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
              aws_cloudwatch_event_rule.imds_exfil.arn,
              aws_cloudwatch_event_rule.non_compliant.arn,
            ]
          }
      }
    }]
  })
}""",
                alert_severity="high",
                alert_title="EC2 Instance Not Using IMDSv2",
                alert_description_template="Instance {instance_id} is not configured to require IMDSv2, making it vulnerable to SSRF credential theft.",
                investigation_steps=[
                    "Identify which instances are non-compliant",
                    "Check if instances are internet-facing",
                    "Review applications running for SSRF vulnerabilities",
                    "Plan migration to IMDSv2",
                ],
                containment_actions=[
                    "Enable IMDSv2 requirement on non-compliant instances",
                    "Update launch templates to require IMDSv2",
                    "Set account-level default for IMDSv2",
                    "Review IAM role permissions on instances",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Some legacy applications may require IMDSv1",
            detection_coverage="100% - identifies all non-compliant instances",
            evasion_considerations="IMDSv2 requires hop limit bypass for advanced attacks",
            implementation_effort=EffortLevel.LOW,
            implementation_time="1 hour",
            estimated_monthly_cost="$1-5",
            prerequisites=["AWS Config enabled"],
        ),
        # Strategy 3: GCP - Service Account Token Exfiltration Detection
        # NOTE: GCP metadata server access (169.254.169.254) is NOT logged in Cloud Audit Logs
        # because it's internal instance traffic. Detection must focus on CONSEQUENCES of theft.
        DetectionStrategy(
            strategy_id="t1552005-gcp-token-exfil",
            name="GCP Service Account Token Exfiltration Detection",
            description=(
                "Detect when service account credentials stolen via metadata server are used "
                "from unusual locations. Since metadata server access itself is NOT logged, "
                "we detect the consequences: token usage from external IPs or unusual patterns."
            ),
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""-- Detect service account token usage from unusual locations
-- Metadata server access is NOT logged; detect consequences instead
-- 1. SA activity from public IPs (token may have been exfiltrated)
protoPayload.authenticationInfo.principalEmail=~".*@.*\\.iam\\.gserviceaccount\\.com$"
protoPayload.requestMetadata.callerIp!~"^(10\\.|172\\.(1[6-9]|2[0-9]|3[01])\\.|192\\.168\\.|private|gce-internal-ip)"
severity>=NOTICE

-- For detecting SA creating key for itself (highly unusual, indicates compromise)
-- OR (
--   protoPayload.methodName="google.iam.admin.v1.CreateServiceAccountKey"
--   protoPayload.authenticationInfo.principalEmail=protoPayload.request.name
-- )""",
                gcp_terraform_template="""# GCP: Detect service account token exfiltration
# NOTE: Metadata server (169.254.169.254) access is NOT logged in Cloud Audit Logs
# This detection focuses on CONSEQUENCES of credential theft

variable "project_id" {
  type = string
}

variable "alert_email" {
  type = string
}

# Step 1: Notification channel
resource "google_monitoring_notification_channel" "imds_exfil" {
  project      = var.project_id
  display_name = "IMDS Exfiltration Alerts - T1552.005"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Log-based metric for SA activity from external IPs
# When a token is stolen via metadata server and used externally,
# the callerIp will be the external IP, not internal or "private"
resource "google_logging_metric" "sa_external_usage" {
  project = var.project_id
  name    = "t1552005-sa-external-ip-usage"
  filter  = <<-EOT
    protoPayload.authenticationInfo.principalEmail=~".*@.*\\.iam\\.gserviceaccount\\.com$"
    protoPayload.requestMetadata.callerIp!~"^(10\\.|172\\.(1[6-9]|2[0-9]|3[01])\\.|192\\.168\\.|private|gce-internal-ip)"
    severity>=NOTICE
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "principal"
      value_type  = "STRING"
      description = "Service account email"
    }
    labels {
      key         = "caller_ip"
      value_type  = "STRING"
      description = "External caller IP"
    }
  }

  label_extractors = {
    "principal"  = "EXTRACT(protoPayload.authenticationInfo.principalEmail)"
    "caller_ip"  = "EXTRACT(protoPayload.requestMetadata.callerIp)"
  }
}

# Step 3: Log-based metric for SA self-key-creation (highly unusual)
resource "google_logging_metric" "sa_self_key_creation" {
  project = var.project_id
  name    = "t1552005-sa-self-key-creation"
  filter  = <<-EOT
    protoPayload.methodName="google.iam.admin.v1.CreateServiceAccountKey"
    protoPayload.authenticationInfo.principalEmail=~".*@.*\\.iam\\.gserviceaccount\\.com$"
    severity>=NOTICE
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "principal"
      value_type  = "STRING"
      description = "Service account creating the key"
    }
  }

  label_extractors = {
    "principal" = "EXTRACT(protoPayload.authenticationInfo.principalEmail)"
  }
}

# Step 4: Alert policy for external SA usage
resource "google_monitoring_alert_policy" "sa_external_usage" {
  project      = var.project_id
  display_name = "T1552.005: Service Account Used from External IP"
  combiner     = "OR"

  conditions {
    display_name = "SA activity from non-GCP IP (potential token theft)"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.sa_external_usage.name}\""
      duration        = "0s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0

      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_SUM"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.imds_exfil.id]

  documentation {
    content   = <<-EOT
      ## Service Account Token Potentially Exfiltrated (T1552.005)

      A service account made API calls from an external IP address.
      This may indicate the token was stolen via metadata server (IMDS) access.

      ### Investigation Steps
      1. Identify the source IP and geolocate it
      2. Check if the SA is attached to a GCE instance
      3. Review instance for SSRF vulnerabilities
      4. List all API calls made by this SA from this IP

      ### Immediate Actions
      1. Rotate the service account key
      2. Review and restrict SA permissions
      3. Check for lateral movement or data exfiltration
    EOT
    mime_type = "text/markdown"
  }

  alert_strategy {
    auto_close = "1800s"
    notification_rate_limit {
      period = "300s"
    }
  }
}

# Step 5: Alert policy for SA self-key-creation
resource "google_monitoring_alert_policy" "sa_self_key" {
  project      = var.project_id
  display_name = "T1552.005: SA Creating Key for Itself (Persistence)"
  combiner     = "OR"

  conditions {
    display_name = "Service account created key for itself"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.sa_self_key_creation.name}\""
      duration        = "0s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0

      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_SUM"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.imds_exfil.id]

  documentation {
    content   = <<-EOT
      ## Service Account Self-Key Creation (T1552.005 + T1098)

      A service account created an API key for itself.
      This is HIGHLY UNUSUAL - normally keys are created by admins.
      This indicates the SA is compromised and attacker is establishing persistence.

      ### Investigation Steps
      1. Identify when the SA was compromised
      2. Check for prior SSRF or metadata access
      3. List all keys for this SA and their creation times
      4. Review all activity from this SA

      ### Immediate Actions
      1. Delete ALL keys for this service account
      2. Disable the service account temporarily
      3. Rotate credentials for any accessed resources
      4. Review instance security configurations
    EOT
    mime_type = "text/markdown"
  }

  alert_strategy {
    auto_close = "1800s"
    notification_rate_limit {
      period = "300s"
    }
  }
}

# Step 6: VPC Service Controls recommendation (prevention)
# Implement IP-based access policies to block token use from untrusted IPs
# See: https://cloud.google.com/vpc-service-controls/docs/overview""",
                alert_severity="critical",
                alert_title="GCP: Service Account Token Exfiltration Detected",
                alert_description_template=(
                    "Service account {principal} made API calls from external IP {caller_ip}. "
                    "This may indicate credentials stolen via metadata server (IMDS) access."
                ),
                investigation_steps=[
                    "Identify the external IP and geolocate it",
                    "Check if the SA is attached to a GCE instance",
                    "Review the instance for SSRF vulnerabilities",
                    "List all API calls made by this SA from this IP",
                    "Check for data exfiltration or privilege escalation",
                ],
                containment_actions=[
                    "Rotate the service account key immediately",
                    "Review and restrict service account permissions",
                    "Enable VPC Service Controls with IP restrictions",
                    "Check for lateral movement using delegation chain",
                    "Disable service account if compromise confirmed",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning=(
                "Whitelist known external IPs for hybrid/on-prem services. "
                "Exclude SAs legitimately used from CI/CD systems."
            ),
            detection_coverage=(
                "85% - detects token usage from external IPs. Cannot detect "
                "usage from within GCP (attacker lateral movement)."
            ),
            evasion_considerations=(
                "Attacker using token from within GCP shows as 'private' or "
                "'gce-internal-ip'. Combine with SCC Premium for better coverage."
            ),
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$10-20",
            prerequisites=[
                "Cloud Audit Logs enabled (Data Access logs for IAM)",
                "VPC Service Controls recommended for prevention",
            ],
        ),
        # Strategy 4: AWS - VPC Flow Logs IMDS detection
        DetectionStrategy(
            strategy_id="t1552005-aws-flowlogs",
            name="VPC Flow Logs IMDS Access Monitoring",
            description="Detect unusual traffic to IMDS IP address.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, srcAddr, dstAddr, dstPort, bytes
| filter dstAddr = "169.254.169.254"
| stats count(*) as imds_calls, sum(bytes) as total_bytes by srcAddr, bin(1h)
| filter imds_calls > 100
| sort imds_calls desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Monitor IMDS access via VPC Flow Logs

Parameters:
  VPCFlowLogGroup:
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

  # Step 2: Metric filter for IMDS access
  IMDSAccessFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref VPCFlowLogGroup
      FilterPattern: '[..., dstaddr="169.254.169.254", ...]'
      MetricTransformations:
        - MetricName: IMDSAccess
          MetricNamespace: Security
          MetricValue: "1"

  # Step 3: Alarm
  IMDSAccessAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: HighIMDSAccess
      MetricName: IMDSAccess
      Namespace: Security
      Statistic: Sum
      Period: 300
      Threshold: 1000
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      TreatMissingData: notBreaching

      AlarmActions: [!Ref AlertTopic]""",
                terraform_template="""# Monitor IMDS access via VPC Flow Logs

variable "vpc_flow_log_group" {
  type = string
}

variable "alert_email" {
  type = string
}

# Step 1: SNS topic
resource "aws_sns_topic" "alerts" {
  name = "imds-access-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Metric filter
resource "aws_cloudwatch_log_metric_filter" "imds_access" {
  name           = "imds-access"
  log_group_name = var.vpc_flow_log_group
  pattern        = "[..., dstaddr=\"169.254.169.254\", ...]"

  metric_transformation {
    name      = "IMDSAccess"
    namespace = "Security"
    value     = "1"
  }
}

# Step 3: Alarm
resource "aws_cloudwatch_metric_alarm" "imds_access" {
  alarm_name          = "HighIMDSAccess"
  metric_name         = "IMDSAccess"
  namespace           = "Security"
  statistic           = "Sum"
  period              = 300
  threshold           = 1000
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.alerts.arn]
}""",
                alert_severity="medium",
                alert_title="High IMDS Access Volume",
                alert_description_template="Instance {srcAddr} made {imds_calls} calls to IMDS in 1 hour. Normal is <100.",
                investigation_steps=[
                    "Identify which instances have high IMDS access",
                    "Check if application legitimately uses IMDS",
                    "Review for SSRF vulnerabilities",
                    "Check if credentials were subsequently used",
                ],
                containment_actions=[
                    "Enable IMDSv2 with hop limit 1",
                    "Review application code for SSRF",
                    "Restrict IMDS access via iptables if needed",
                    "Add IMDS hop count limit",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Adjust threshold based on normal application IMDS usage",
            detection_coverage="60% - volume-based detection",
            evasion_considerations="Low-and-slow attacks may evade threshold",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$10-30",
            prerequisites=["VPC Flow Logs enabled to CloudWatch"],
        ),
    ],
    recommended_order=[
        "t1552005-aws-guardduty",
        "t1552005-aws-imdsv2",
        "t1552005-gcp-token-exfil",
        "t1552005-aws-flowlogs",
    ],
    total_effort_hours=4.5,
    coverage_improvement="+20% improvement for Credential Access tactic",
)
