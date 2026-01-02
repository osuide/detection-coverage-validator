"""
T1583 - Acquire Infrastructure

Adversaries acquire infrastructure such as domains, servers, VPNs, and cloud resources
to support operations. Includes VPS, serverless, botnets, and web services.
Used by Kimsuky, Sandworm Team, Ember Bear, Indrik Spider.
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
    technique_id="T1583",
    technique_name="Acquire Infrastructure",
    tactic_ids=["TA0042"],
    mitre_url="https://attack.mitre.org/techniques/T1583/",
    threat_context=ThreatContext(
        description=(
            "Adversaries acquire various types of infrastructure including domains, "
            "servers, VPNs, cloud resources, and web services to support operations. "
            "This infrastructure enables staging, launching attacks, and maintaining "
            "command and control whilst blending with legitimate traffic patterns."
        ),
        attacker_goal="Acquire infrastructure to support targeting and operational activities",
        why_technique=[
            "Provides anonymity and operational security",
            "Enables staging of malicious payloads",
            "Supports command and control infrastructure",
            "Cloud providers offer free trials reducing costs",
            "Blends with legitimate traffic patterns",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="common",
        trend="increasing",
        severity_score=6,
        severity_reasoning=(
            "Pre-compromise technique that enables subsequent attack phases. "
            "Detection focuses on identifying abuse of acquired infrastructure "
            "and anomalous resource provisioning patterns."
        ),
        business_impact=[
            "Indicator of targeting",
            "Precursor to attacks",
            "Resource abuse",
            "Unauthorised cloud spend",
        ],
        typical_attack_phase="resource_development",
        often_precedes=["T1566", "T1071", "T1608"],
        often_follows=[],
    ),
    detection_strategies=[
        DetectionStrategy(
            strategy_id="t1583-aws-unauthorized-resources",
            name="AWS Unauthorised Resource Provisioning",
            description="Detect unexpected EC2, Lambda, or infrastructure provisioning.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, userIdentity.principalId, eventName, sourceIPAddress, userAgent
| filter eventName like /RunInstances|CreateFunction|CreateLoadBalancer|RegisterDomain/
| filter userIdentity.principalId not like /expected-principals/
| stats count(*) as events by userIdentity.principalId, sourceIPAddress, bin(1h)
| filter events > 3
| sort events desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect unauthorised infrastructure provisioning

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

  TopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics: [!Ref AlertTopic]
      PolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Sid: AllowCloudWatchPublish
            Effect: Allow
            Principal:
              Service: cloudwatch.amazonaws.com
            Action: sns:Publish
            Resource: !Ref AlertTopic
            Condition:
              StringEquals:
                AWS:SourceAccount: !Ref AWS::AccountId

  # Detect EC2 instance launches
  EC2LaunchFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ $.eventName = "RunInstances" }'
      MetricTransformations:
        - MetricName: UnauthorisedEC2Launch
          MetricNamespace: Security
          MetricValue: "1"

  EC2LaunchAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: UnauthorisedEC2Provisioning
      MetricName: UnauthorisedEC2Launch
      Namespace: Security
      Statistic: Sum
      Period: 300
      Threshold: 5
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      TreatMissingData: notBreaching

      AlarmActions: [!Ref AlertTopic]

  # Detect Lambda function creation
  LambdaCreateFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ $.eventName = "CreateFunction" }'
      MetricTransformations:
        - MetricName: UnauthorisedLambdaCreate
          MetricNamespace: Security
          MetricValue: "1"

  LambdaCreateAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: UnauthorisedLambdaProvisioning
      MetricName: UnauthorisedLambdaCreate
      Namespace: Security
      Statistic: Sum
      Period: 300
      Threshold: 3
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      TreatMissingData: notBreaching

      AlarmActions: [!Ref AlertTopic]""",
                terraform_template="""# Detect unauthorised infrastructure provisioning in AWS

variable "cloudtrail_log_group" { type = string }
variable "alert_email" { type = string }

data "aws_caller_identity" "current" {}

resource "aws_sns_topic" "alerts" {
  name = "infrastructure-provisioning-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_policy" "allow_cloudwatch" {
  arn = aws_sns_topic.alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowCloudWatchPublish"
      Effect    = "Allow"
      Principal = { Service = "cloudwatch.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.alerts.arn
      Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
      }
    }]
  })
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Detect EC2 instance launches
resource "aws_cloudwatch_log_metric_filter" "ec2_launches" {
  name           = "unauthorised-ec2-launch"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ $.eventName = \"RunInstances\" }"

  metric_transformation {
    name      = "UnauthorisedEC2Launch"
    namespace = "Security"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "ec2_provisioning" {
  alarm_name          = "UnauthorisedEC2Provisioning"
  metric_name         = "UnauthorisedEC2Launch"
  namespace           = "Security"
  statistic           = "Sum"
  period              = 300
  threshold           = 5
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.alerts.arn]
}

# Detect Lambda function creation
resource "aws_cloudwatch_log_metric_filter" "lambda_create" {
  name           = "unauthorised-lambda-create"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ $.eventName = \"CreateFunction\" }"

  metric_transformation {
    name      = "UnauthorisedLambdaCreate"
    namespace = "Security"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "lambda_provisioning" {
  alarm_name          = "UnauthorisedLambdaProvisioning"
  metric_name         = "UnauthorisedLambdaCreate"
  namespace           = "Security"
  statistic           = "Sum"
  period              = 300
  threshold           = 3
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.alerts.arn]
}""",
                alert_severity="medium",
                alert_title="Unauthorised Infrastructure Provisioning Detected",
                alert_description_template="Unexpected resource provisioning by {principalId} from {sourceIPAddress}.",
                investigation_steps=[
                    "Verify principal identity and authorisation",
                    "Review source IP address and location",
                    "Check resources provisioned (type, region, configuration)",
                    "Correlate with legitimate change requests",
                    "Review IAM permissions and access patterns",
                ],
                containment_actions=[
                    "Terminate unauthorised resources immediately",
                    "Revoke compromised credentials",
                    "Review and restrict IAM policies",
                    "Enable MFA for privileged accounts",
                    "Audit all recent infrastructure changes",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Exclude known automation principals and approved provisioning patterns",
            detection_coverage="65% - catches unauthorised provisioning",
            evasion_considerations="Attackers may use compromised legitimate credentials",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=["CloudTrail enabled with CloudWatch integration"],
        ),
        DetectionStrategy(
            strategy_id="t1583-aws-vpc-external-access",
            name="AWS VPC Suspicious External Connectivity",
            description="Detect unusual VPC external connections that may indicate C2 infrastructure.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, srcAddr, dstAddr, dstPort, bytes
| filter dstAddr not like /^10\\.|^172\\.(1[6-9]|2[0-9]|3[0-1])\\.|^192\\.168\\./
| filter action = "ACCEPT"
| stats sum(bytes) as total_bytes, count(*) as connections by srcAddr, dstAddr, dstPort, bin(5m)
| filter connections > 50 or total_bytes > 10000000
| sort total_bytes desc""",
                terraform_template="""# Detect suspicious VPC external connectivity

variable "vpc_flow_log_group" { type = string }
variable "alert_email" { type = string }

data "aws_caller_identity" "current" {}

resource "aws_sns_topic" "alerts" {
  name = "vpc-external-connectivity-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_policy" "allow_cloudwatch" {
  arn = aws_sns_topic.alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowCloudWatchPublish"
      Effect    = "Allow"
      Principal = { Service = "cloudwatch.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.alerts.arn
      Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
      }
    }]
  })
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Detect high-volume external connections
resource "aws_cloudwatch_log_metric_filter" "external_connections" {
  name           = "high-external-connections"
  log_group_name = var.vpc_flow_log_group
  pattern        = "[version, account, eni, source, destination != 10.*, destinationport, protocol, packets, bytes > 1000000, windowstart, windowend, action = \"ACCEPT\", flowlogstatus]"

  metric_transformation {
    name      = "HighExternalTraffic"
    namespace = "Security"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "suspicious_connectivity" {
  alarm_name          = "SuspiciousExternalConnectivity"
  metric_name         = "HighExternalTraffic"
  namespace           = "Security"
  statistic           = "Sum"
  period              = 300
  threshold           = 10
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.alerts.arn]
}""",
                alert_severity="medium",
                alert_title="Suspicious VPC External Connectivity",
                alert_description_template="High volume external connections from {srcAddr} to {dstAddr}.",
                investigation_steps=[
                    "Identify source instance and owner",
                    "Check destination IP reputation",
                    "Review connection patterns and volume",
                    "Correlate with known C2 infrastructure",
                    "Analyse payload if traffic capture available",
                ],
                containment_actions=[
                    "Block destination IP at security group/NACL",
                    "Isolate compromised instance",
                    "Capture memory and disk forensics",
                    "Review security group rules",
                    "Update threat intelligence feeds",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Exclude known external services (CDNs, SaaS platforms, backup services)",
            detection_coverage="60% - pattern-based detection of C2 traffic",
            evasion_considerations="Attackers may use encrypted channels and blend with legitimate traffic",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$10-20",
            prerequisites=["VPC Flow Logs enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1583-gcp-compute-provisioning",
            name="GCP Unauthorised Compute Provisioning",
            description="Detect unexpected GCE instance or Cloud Function creation.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''protoPayload.methodName=~"compute.instances.insert|cloudfunctions.functions.create|run.services.create"
protoPayload.authenticationInfo.principalEmail!~"expected-service-accounts@.*"''',
                gcp_terraform_template="""# GCP: Detect unauthorised compute resource provisioning

variable "project_id" { type = string }
variable "alert_email" { type = string }

resource "google_monitoring_notification_channel" "email_s1" {
  project      = var.project_id
  display_name = "Infrastructure Security Alerts"
  type         = "email"
  labels       = { email_address = var.alert_email }
}

# Detect GCE instance creation
resource "google_logging_metric" "gce_creation" {
  project = var.project_id
  name   = "unauthorised-gce-creation"
  filter = <<-EOT
    protoPayload.methodName="v1.compute.instances.insert"
    protoPayload.authenticationInfo.principalEmail!~"expected-service-account@.*"
  EOT
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

resource "google_monitoring_alert_policy" "gce_provisioning" {
  project      = var.project_id
  display_name = "Unauthorised GCE Provisioning"
  combiner     = "OR"
  conditions {
    display_name = "Unexpected instance creation"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.gce_creation.name}\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 3
    }
  }
  notification_channels = [google_monitoring_notification_channel.email_s1.id]

  alert_strategy {
    auto_close = "1800s"
    notification_rate_limit {
      period = "300s"
    }
  }
}

# Detect Cloud Function creation
resource "google_logging_metric" "function_creation" {
  project = var.project_id
  name   = "unauthorised-function-creation"
  filter = <<-EOT
    protoPayload.methodName="google.cloud.functions.v1.CloudFunctionsService.CreateFunction"
    protoPayload.authenticationInfo.principalEmail!~"expected-service-account@.*"
  EOT
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

resource "google_monitoring_alert_policy" "function_provisioning" {
  project      = var.project_id
  display_name = "Unauthorised Cloud Function Provisioning"
  combiner     = "OR"
  conditions {
    display_name = "Unexpected function creation"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.function_creation.name}\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 2
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
                alert_title="GCP: Unauthorised Compute Provisioning",
                alert_description_template="Unexpected compute resource creation detected.",
                investigation_steps=[
                    "Verify principal identity and permissions",
                    "Review resource configuration and location",
                    "Check for compromised credentials",
                    "Correlate with approved changes",
                    "Analyse resource purpose and network connectivity",
                ],
                containment_actions=[
                    "Delete unauthorised resources",
                    "Revoke compromised credentials",
                    "Review IAM bindings and permissions",
                    "Enable organisation policy constraints",
                    "Implement resource quotas",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Exclude known automation service accounts and CI/CD pipelines",
            detection_coverage="65% - catches unauthorised provisioning",
            evasion_considerations="Attackers may use compromised legitimate accounts",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=["Cloud Audit Logs enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1583-gcp-vpc-suspicious-egress",
            name="GCP VPC Suspicious Egress Traffic",
            description="Detect unusual VPC egress patterns indicating C2 communication.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""resource.type="gce_subnetwork"
jsonPayload.connection.dest_ip!~"^10\\.|^172\\.(1[6-9]|2[0-9]|3[0-1])\\.|^192\\.168\\."
jsonPayload.bytes_sent>10000000""",
                gcp_terraform_template="""# GCP: Detect suspicious VPC egress traffic

variable "project_id" { type = string }
variable "alert_email" { type = string }

resource "google_monitoring_notification_channel" "email_s2" {
  project      = var.project_id
  display_name = "VPC Security Alerts"
  type         = "email"
  labels       = { email_address = var.alert_email }
}

resource "google_logging_metric" "high_egress" {
  project = var.project_id
  name   = "high-vpc-egress"
  filter = <<-EOT
    resource.type="gce_subnetwork"
    jsonPayload.bytes_sent>10000000
  EOT
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

resource "google_monitoring_alert_policy" "suspicious_egress" {
  project      = var.project_id
  display_name = "Suspicious VPC Egress Traffic"
  combiner     = "OR"
  conditions {
    display_name = "High volume external traffic"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.high_egress.name}\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 5
      aggregations {
        alignment_period   = "300s"
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
                alert_severity="medium",
                alert_title="GCP: Suspicious VPC Egress Traffic",
                alert_description_template="High volume egress traffic detected from VPC.",
                investigation_steps=[
                    "Identify source instance and project",
                    "Check destination IP reputation",
                    "Review traffic patterns and protocols",
                    "Correlate with threat intelligence",
                    "Analyse application logs",
                ],
                containment_actions=[
                    "Block destination via firewall rules",
                    "Isolate affected instances",
                    "Capture forensic evidence",
                    "Review VPC firewall rules",
                    "Update Cloud Armor policies",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Exclude known external services and CDN endpoints",
            detection_coverage="55% - volume-based detection",
            evasion_considerations="Low-and-slow traffic may evade volume thresholds",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$10-20",
            prerequisites=["VPC Flow Logs enabled"],
        ),
    ],
    recommended_order=[
        "t1583-aws-unauthorized-resources",
        "t1583-gcp-compute-provisioning",
        "t1583-aws-vpc-external-access",
        "t1583-gcp-vpc-suspicious-egress",
    ],
    total_effort_hours=3.0,
    coverage_improvement="+15% improvement for Resource Development tactic",
)
