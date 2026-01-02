"""
T1592 - Gather Victim Host Information

Adversaries collect details about victim hosts before attacking, including
administrative data (names, IP addresses, functionality) and configuration specifics
(operating systems, language settings, hardware, firmware).
Used by Volt Typhoon.
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
    technique_id="T1592",
    technique_name="Gather Victim Host Information",
    tactic_ids=["TA0043"],
    mitre_url="https://attack.mitre.org/techniques/T1592/",
    threat_context=ThreatContext(
        description=(
            "Adversaries collect information about victim hosts during the reconnaissance "
            "phase, including administrative details (hostnames, IP addresses, functionality), "
            "configuration specifics (OS versions, language settings), hardware specifications, "
            "firmware versions, and client configurations. This reconnaissance occurs before "
            "initial access and helps attackers tailor their approach."
        ),
        attacker_goal="Gather host information to plan and customise attacks before initial access",
        why_technique=[
            "Identify vulnerable systems and software",
            "Determine appropriate malware variants",
            "Select exploits matching target OS/software",
            "Identify high-value targets",
            "Plan evasion techniques based on defences",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="common",
        trend="stable",
        severity_score=4,
        severity_reasoning=(
            "Reconnaissance technique that occurs outside enterprise defences. "
            "While not directly harmful, enables more targeted and effective attacks. "
            "Detection is challenging but provides early warning of potential attacks."
        ),
        business_impact=[
            "Enables targeted attack planning",
            "Identifies vulnerable assets",
            "Facilitates exploit selection",
            "Supports social engineering",
            "Early warning of potential attack",
        ],
        typical_attack_phase="reconnaissance",
        often_precedes=["T1190", "T1566", "T1189", "T1078"],
        often_follows=[],
    ),
    detection_strategies=[
        DetectionStrategy(
            strategy_id="t1592-aws-public-exposure",
            name="AWS Public Asset Exposure Monitoring",
            description="Monitor for publicly exposed AWS resources that leak host information.",
            detection_type=DetectionType.CONFIG_RULE,
            aws_service="config",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Monitor public asset exposure that may leak host information

Parameters:
  AlertEmail:
    Type: String
    Description: Email address for security alerts

Resources:
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      DisplayName: Public Exposure Alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Monitor public EC2 instances
  PublicEC2Rule:
    Type: AWS::Config::ConfigRule
    Properties:
      ConfigRuleName: detect-public-ec2-instances
      Description: Detects EC2 instances with public IP addresses
      Source:
        Owner: AWS
        SourceIdentifier: ec2-instance-no-public-ip

  # Monitor public S3 buckets
  PublicS3Rule:
    Type: AWS::Config::ConfigRule
    Properties:
      ConfigRuleName: s3-bucket-public-read-prohibited
      Description: Detects S3 buckets with public read access
      Source:
        Owner: AWS
        SourceIdentifier: s3-bucket-public-read-prohibited

  # Remediation notification
  ComplianceEventRule:
    Type: AWS::Events::Rule
    Properties:
      Description: Alert on non-compliant public exposure
      EventPattern:
        source:
          - aws.config
        detail-type:
          - Config Rules Compliance Change
        detail:
          messageType:
            - ComplianceChangeNotification
          newEvaluationResult:
            complianceType:
              - NON_COMPLIANT
      State: ENABLED
      Targets:
        - Arn: !Ref AlertTopic
          Id: ComplianceAlertTarget""",
                terraform_template="""# Monitor public asset exposure in AWS

variable "alert_email" { type = string }

resource "aws_sns_topic" "alerts" {
  name = "public-exposure-alerts"
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

# Monitor public EC2 instances
resource "aws_config_config_rule" "public_ec2" {
  name = "detect-public-ec2-instances"
  description = "Detects EC2 instances with public IP addresses"

  source {
    owner             = "AWS"
    source_identifier = "ec2-instance-no-public-ip"
  }

  depends_on = [aws_config_configuration_recorder.main]
}

# Monitor public S3 buckets
resource "aws_config_config_rule" "public_s3" {
  name = "s3-bucket-public-read-prohibited"
  description = "Detects S3 buckets with public read access"

  source {
    owner             = "AWS"
    source_identifier = "s3-bucket-public-read-prohibited"
  }

  depends_on = [aws_config_configuration_recorder.main]
}

# Alert on non-compliant resources
resource "aws_cloudwatch_event_rule" "config_compliance" {
  name        = "config-compliance-changes"
  description = "Alert on non-compliant public exposure"

  event_pattern = jsonencode({
    source      = ["aws.config"]
    detail-type = ["Config Rules Compliance Change"]
    detail = {
      messageType = ["ComplianceChangeNotification"]
      newEvaluationResult = {
        complianceType = ["NON_COMPLIANT"]
      }
    }
  })
}

# Dead Letter Queue for config compliance events
resource "aws_sqs_queue" "config_dlq" {
  name                      = "config-compliance-dlq"
  message_retention_seconds = 1209600  # 14 days
}

resource "aws_cloudwatch_event_target" "sns" {
  rule      = aws_cloudwatch_event_rule.config_compliance.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.alerts.arn

  retry_policy {
    maximum_event_age_in_seconds = 3600
    maximum_retry_attempts       = 8
  }

  dead_letter_config {
    arn = aws_sqs_queue.config_dlq.arn
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
          "aws:SourceArn" = aws_cloudwatch_event_rule.config_compliance.arn
        }
      }
    }]
  })
}

# SQS queue policy for config compliance DLQ
resource "aws_sqs_queue_policy" "config_dlq_policy" {
  queue_url = aws_sqs_queue.config_dlq.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sqs:SendMessage"
      Resource  = aws_sqs_queue.config_dlq.arn
      Condition = {
        ArnEquals = {
          "aws:SourceArn" = aws_cloudwatch_event_rule.config_compliance.arn
        }
      }
    }]
  })
}""",
                alert_severity="medium",
                alert_title="Public Asset Exposure Detected",
                alert_description_template="Publicly exposed resource may leak host information: {resourceId}",
                investigation_steps=[
                    "Review publicly exposed resources",
                    "Check for sensitive metadata exposure",
                    "Review CloudTrail for unusual access patterns",
                    "Assess information disclosure risk",
                    "Check for reconnaissance scanning activity",
                ],
                containment_actions=[
                    "Remove unnecessary public exposure",
                    "Implement security groups restrictions",
                    "Review and sanitise public metadata",
                    "Enable VPC Flow Logs for monitoring",
                    "Document legitimate public assets",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Exclude intentionally public resources (websites, APIs)",
            detection_coverage="50% - detects exposure but not active reconnaissance",
            evasion_considerations="Does not detect passive collection or third-party sources",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=["AWS Config enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1592-aws-metadata-access",
            name="AWS EC2 Metadata Service Access",
            description="Detect unusual metadata service access patterns that may indicate reconnaissance.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, sourceIPAddress, userAgent, requestParameters
| filter eventName = "DescribeInstances" or eventName = "DescribeImages" or eventName = "GetConsoleOutput"
| stats count(*) as requests by sourceIPAddress, userAgent, bin(1h)
| filter requests > 50
| sort requests desc""",
                terraform_template="""# Detect metadata and instance enumeration in AWS

variable "cloudtrail_log_group" { type = string }
variable "alert_email" { type = string }

resource "aws_sns_topic" "alerts" {
  name = "metadata-access-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_cloudwatch_log_metric_filter" "instance_enumeration" {
  name           = "instance-enumeration"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ ($.eventName = DescribeInstances) || ($.eventName = DescribeImages) || ($.eventName = GetConsoleOutput) }"

  metric_transformation {
    name      = "InstanceEnumeration"
    namespace = "Security/Reconnaissance"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "excessive_enumeration" {
  alarm_name          = "ExcessiveInstanceEnumeration"
  metric_name         = "InstanceEnumeration"
  namespace           = "Security/Reconnaissance"
  statistic           = "Sum"
  period              = 300
  threshold           = 50
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  alarm_description   = "Detects excessive instance enumeration activity"
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.alerts.arn]
}""",
                alert_severity="medium",
                alert_title="Excessive Instance Enumeration Detected",
                alert_description_template="High volume of instance enumeration from {sourceIPAddress}",
                investigation_steps=[
                    "Review CloudTrail logs for enumeration activity",
                    "Identify source IP and user agent",
                    "Check for authorised security scanning",
                    "Review compromised credentials possibility",
                    "Correlate with other suspicious activity",
                ],
                containment_actions=[
                    "Review IAM permissions for least privilege",
                    "Enable MFA for sensitive operations",
                    "Rotate potentially compromised credentials",
                    "Implement SCPs to restrict enumeration",
                    "Enable CloudTrail Insights",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Exclude authorised security scanning and monitoring tools",
            detection_coverage="40% - detects post-compromise enumeration",
            evasion_considerations="Slow enumeration and use of legitimate tools may evade",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$10-20",
            prerequisites=["CloudTrail enabled with CloudWatch Logs integration"],
        ),
        DetectionStrategy(
            strategy_id="t1592-gcp-asset-enumeration",
            name="GCP Asset Enumeration Detection",
            description="Detect reconnaissance via GCP asset and instance enumeration.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""resource.type="gce_instance"
(protoPayload.methodName="v1.compute.instances.list" OR
 protoPayload.methodName="v1.compute.instances.get" OR
 protoPayload.methodName="beta.compute.instances.getSerialPortOutput")""",
                gcp_terraform_template="""# GCP: Detect instance and asset enumeration

variable "project_id" { type = string }
variable "alert_email" { type = string }

resource "google_monitoring_notification_channel" "email" {
  project      = var.project_id
  display_name = "Reconnaissance Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

resource "google_logging_metric" "instance_enumeration" {
  project = var.project_id
  name   = "instance-enumeration"
  filter = <<-EOT
    resource.type="gce_instance"
    (protoPayload.methodName="v1.compute.instances.list" OR
     protoPayload.methodName="v1.compute.instances.get" OR
     protoPayload.methodName="beta.compute.instances.getSerialPortOutput")
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "principal_email"
      value_type  = "STRING"
      description = "User performing enumeration"
    }
  }

  label_extractors = {
    "principal_email" = "EXTRACT(protoPayload.authenticationInfo.principalEmail)"
  }
}

resource "google_monitoring_alert_policy" "excessive_enumeration" {
  project      = var.project_id
  display_name = "Excessive GCE Instance Enumeration"
  combiner     = "OR"

  conditions {
    display_name = "High enumeration rate"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.instance_enumeration.name}\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 50
      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_RATE"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]

  alert_strategy {
    auto_close = "1800s"
    notification_rate_limit {
      period = "300s"
    }
  }
}

# Monitor public IP assignments
resource "google_logging_metric" "public_ip_assignments" {
  project = var.project_id
  name   = "public-ip-assignments"
  filter = <<-EOT
    resource.type="gce_instance"
    protoPayload.methodName="v1.compute.instances.insert"
    protoPayload.request.networkInterfaces.accessConfigs.type="ONE_TO_ONE_NAT"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

resource "google_monitoring_alert_policy" "public_instance_creation" {
  project      = var.project_id
  display_name = "Public GCE Instance Created"
  combiner     = "OR"

  conditions {
    display_name = "New public instance"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.public_ip_assignments.name}\""
      duration        = "60s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]

  alert_strategy {
    auto_close = "1800s"
    notification_rate_limit {
      period = "300s"
    }
  }
}""",
                alert_severity="medium",
                alert_title="GCP: Asset Enumeration Detected",
                alert_description_template="Excessive instance enumeration activity detected",
                investigation_steps=[
                    "Review Cloud Audit Logs for enumeration patterns",
                    "Identify principal performing enumeration",
                    "Check for authorised security scanning",
                    "Review service account permissions",
                    "Correlate with authentication logs",
                ],
                containment_actions=[
                    "Review IAM bindings for least privilege",
                    "Require MFA for sensitive operations",
                    "Rotate compromised service account keys",
                    "Implement organisation policies",
                    "Enable VPC Service Controls",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Exclude monitoring tools, GKE, and automation",
            detection_coverage="40% - detects post-compromise enumeration",
            evasion_considerations="Slow enumeration and legitimate service accounts may evade",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$15-25",
            prerequisites=["Cloud Audit Logs enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1592-aws-guardduty",
            name="AWS GuardDuty Reconnaissance Findings",
            description="Leverage GuardDuty to detect reconnaissance activities.",
            detection_type=DetectionType.GUARDDUTY,
            aws_service="guardduty",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                guardduty_finding_types=[
                    "Recon:EC2/PortProbeUnprotectedPort",
                    "Recon:EC2/PortProbeEMRUnprotectedPort",
                    "Recon:EC2/Portscan",
                    "Discovery:S3/MaliciousIPCaller",
                    "Discovery:S3/TorIPCaller",
                ],
                terraform_template="""# Enable GuardDuty reconnaissance detection

variable "alert_email" { type = string }

resource "aws_guardduty_detector" "main" {
  enable = true

  datasources {
    s3_logs {
      enable = true
    }
    kubernetes {
      audit_logs {
        enable = true
      }
    }
  }
}

resource "aws_sns_topic" "guardduty_alerts" {
  name = "guardduty-recon-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.guardduty_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_cloudwatch_event_rule" "guardduty_recon" {
  name        = "guardduty-reconnaissance"
  description = "Capture GuardDuty reconnaissance findings"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail = {
      type = [
        "Recon:EC2/PortProbeUnprotectedPort",
        "Recon:EC2/PortProbeEMRUnprotectedPort",
        "Recon:EC2/Portscan",
        "Discovery:S3/MaliciousIPCaller",
        "Discovery:S3/TorIPCaller"
      ]
    }
  })
}

# Dead Letter Queue for GuardDuty recon events
resource "aws_sqs_queue" "guardduty_dlq" {
  name                      = "guardduty-recon-dlq"
  message_retention_seconds = 1209600  # 14 days
}

resource "aws_cloudwatch_event_target" "sns" {
  rule      = aws_cloudwatch_event_rule.guardduty_recon.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.guardduty_alerts.arn

  retry_policy {
    maximum_event_age_in_seconds = 3600
    maximum_retry_attempts       = 8
  }

  dead_letter_config {
    arn = aws_sqs_queue.guardduty_dlq.arn
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

# SNS topic policy for GuardDuty alerts
resource "aws_sns_topic_policy" "guardduty_publish" {
  arn = aws_sns_topic.guardduty_alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "SNS:Publish"
      Resource  = aws_sns_topic.guardduty_alerts.arn
      Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
        ArnEquals = {
          "aws:SourceArn" = aws_cloudwatch_event_rule.guardduty_recon.arn
        }
      }
    }]
  })
}

# SQS queue policy for GuardDuty DLQ
resource "aws_sqs_queue_policy" "guardduty_dlq_policy" {
  queue_url = aws_sqs_queue.guardduty_dlq.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sqs:SendMessage"
      Resource  = aws_sqs_queue.guardduty_dlq.arn
      Condition = {
        ArnEquals = {
          "aws:SourceArn" = aws_cloudwatch_event_rule.guardduty_recon.arn
        }
      }
    }]
  })
}""",
                alert_severity="high",
                alert_title="Reconnaissance Activity Detected",
                alert_description_template="GuardDuty detected reconnaissance: {findingType}",
                investigation_steps=[
                    "Review GuardDuty finding details",
                    "Identify targeted resources",
                    "Check VPC Flow Logs for activity",
                    "Review Security Group configurations",
                    "Assess potential vulnerability exposure",
                ],
                containment_actions=[
                    "Block malicious IPs via NACL/Security Groups",
                    "Review and harden security groups",
                    "Enable VPC Flow Logs if not present",
                    "Patch identified vulnerabilities",
                    "Consider AWS Shield if DDoS concerns",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="GuardDuty findings are generally accurate",
            detection_coverage="60% - detects network-based reconnaissance",
            evasion_considerations="Does not detect passive or third-party reconnaissance",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$30-50 for GuardDuty",
            prerequisites=["AWS GuardDuty enabled"],
        ),
    ],
    recommended_order=[
        "t1592-aws-guardduty",
        "t1592-aws-public-exposure",
        "t1592-aws-metadata-access",
        "t1592-gcp-asset-enumeration",
    ],
    total_effort_hours=3.0,
    coverage_improvement="+15% improvement for Reconnaissance tactic detection",
)
