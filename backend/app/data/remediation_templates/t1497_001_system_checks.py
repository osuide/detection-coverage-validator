"""
T1497.001 - Virtualisation/Sandbox Evasion: System Checks

Adversaries employ system inspection methods to identify and evade virtualisation
and analysis environments in cloud infrastructure.
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
    technique_id="T1497.001",
    technique_name="Virtualisation/Sandbox Evasion: System Checks",
    tactic_ids=["TA0005", "TA0007"],
    mitre_url="https://attack.mitre.org/techniques/T1497/001/",
    threat_context=ThreatContext(
        description=(
            "Adversaries employ system inspection methods to identify virtualisation "
            "and analysis environments. In cloud environments, this includes checking "
            "instance metadata, CPU/memory characteristics, and running processes to "
            "determine if the environment is legitimate before deploying additional payloads."
        ),
        attacker_goal="Identify virtualisation or analysis environments to evade detection",
        why_technique=[
            "Avoids triggering analysis in sandbox environments",
            "Ensures malware only executes on intended targets",
            "Reduces likelihood of detection by security tools",
            "Helps identify security research environments",
            "Enables conditional payload deployment",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="common",
        trend="increasing",
        severity_score=6,
        severity_reasoning=(
            "System checks indicate sophisticated malware employing evasion techniques. "
            "Whilst not directly harmful, this behaviour often precedes payload deployment. "
            "Provides early warning of advanced threats."
        ),
        business_impact=[
            "Indicates presence of sophisticated malware",
            "Precursor to ransomware or cryptomining deployment",
            "Early warning signal for targeted attacks",
            "May indicate compromised workloads",
            "Risk of undetected payload execution",
        ],
        typical_attack_phase="defence_evasion",
        often_precedes=["T1486", "T1496.001", "T1562.001"],
        often_follows=["T1078.004", "T1190", "T1204.003"],
    ),
    detection_strategies=[
        # Strategy 1: AWS - EC2 Instance Metadata Enumeration
        DetectionStrategy(
            strategy_id="t1497001-aws-metadata",
            name="EC2 Instance Metadata Service Enumeration",
            description=(
                "Detect excessive or suspicious access to EC2 instance metadata service, "
                "which attackers use to profile the environment."
            ),
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, @message
| filter @message like /169.254.169.254/
| stats count(*) as metadata_requests by bin(5m)
| filter metadata_requests > 50
| sort @timestamp desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect EC2 metadata enumeration for sandbox evasion

Parameters:
  VPCFlowLogGroup:
    Type: String
    Description: CloudWatch Log Group for VPC Flow Logs
  AlertEmail:
    Type: String

Resources:
  # Step 1: SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Metric filter for metadata access
  MetadataEnumFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref VPCFlowLogGroup
      FilterPattern: '[version, account, eni, source, destination="169.254.169.254", ...]'
      MetricTransformations:
        - MetricName: MetadataEnumeration
          MetricNamespace: Security/T1497
          MetricValue: "1"

  # Step 3: Alarm for excessive metadata access
  MetadataEnumAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: T1497-MetadataEnumeration
      AlarmDescription: Excessive EC2 metadata service access detected
      MetricName: MetadataEnumeration
      Namespace: Security/T1497
      Statistic: Sum
      Period: 300
      EvaluationPeriods: 1
      Threshold: 100
      ComparisonOperator: GreaterThanOrEqualToThreshold
      TreatMissingData: notBreaching

      AlarmActions:
        - !Ref AlertTopic""",
                terraform_template="""# Detect EC2 metadata enumeration for sandbox evasion

variable "vpc_flow_log_group" {
  type        = string
  description = "CloudWatch Log Group for VPC Flow Logs"
}

variable "alert_email" {
  type = string
}

# Step 1: SNS topic for alerts
resource "aws_sns_topic" "alerts" {
  name = "metadata-enumeration-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Metric filter for metadata access
resource "aws_cloudwatch_log_metric_filter" "metadata_enum" {
  name           = "metadata-enumeration"
  log_group_name = var.vpc_flow_log_group
  pattern        = "[version, account, eni, source, destination=\"169.254.169.254\", ...]"

  metric_transformation {
    name      = "MetadataEnumeration"
    namespace = "Security/T1497"
    value     = "1"
  }
}

# Step 3: Alarm for excessive metadata access
resource "aws_cloudwatch_metric_alarm" "metadata_enum" {
  alarm_name          = "T1497-MetadataEnumeration"
  alarm_description   = "Excessive EC2 metadata service access detected"
  metric_name         = "MetadataEnumeration"
  namespace           = "Security/T1497"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 100
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.alerts.arn]
}

data "aws_caller_identity" "current" {}

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
}""",
                alert_severity="medium",
                alert_title="EC2 Instance Metadata Enumeration Detected",
                alert_description_template=(
                    "Excessive access to EC2 instance metadata service (169.254.169.254) detected. "
                    "This may indicate malware profiling the environment for sandbox evasion."
                ),
                investigation_steps=[
                    "Identify the EC2 instance making excessive metadata requests",
                    "Review running processes on the instance",
                    "Check for unauthorised applications or scripts",
                    "Examine CloudTrail logs for related suspicious activity",
                    "Review instance launch configuration and AMI source",
                ],
                containment_actions=[
                    "Isolate the affected EC2 instance",
                    "Capture instance snapshot for forensic analysis",
                    "Review and terminate suspicious processes",
                    "Consider blocking metadata service access via iptables",
                    "Deploy endpoint detection and response (EDR) tools",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Tune threshold based on legitimate application behaviour; whitelist known infrastructure tools",
            detection_coverage="70% - detects high-volume metadata enumeration",
            evasion_considerations="Slow, throttled enumeration may evade volume-based detection",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1.5 hours",
            estimated_monthly_cost="$10-20",
            prerequisites=["VPC Flow Logs enabled", "Flow logs sent to CloudWatch"],
        ),
        # Strategy 2: AWS - Rapid System Discovery Commands
        DetectionStrategy(
            strategy_id="t1497001-aws-syscommands",
            name="Rapid System Discovery Command Execution",
            description=(
                "Detect rapid sequences of system discovery commands (CPU checks, "
                "memory checks, process enumeration) indicative of sandbox detection."
            ),
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, eventName, userIdentity.arn, requestParameters
| filter eventName in ["DescribeInstances", "DescribeInstanceTypes", "DescribeVolumes", "DescribeSecurityGroups"]
| stats count(*) as discovery_count by userIdentity.sessionContext.sessionIssuer.arn, bin(1m)
| filter discovery_count > 20
| sort discovery_count desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect rapid system discovery for sandbox evasion

Parameters:
  CloudTrailLogGroup:
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

  # Step 2: Metric filter for rapid discovery
  RapidDiscoveryFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ $.eventSource = "ec2.amazonaws.com" && ($.eventName = "DescribeInstances" || $.eventName = "DescribeInstanceTypes" || $.eventName = "DescribeVolumes") }'
      MetricTransformations:
        - MetricName: SystemDiscovery
          MetricNamespace: Security/T1497
          MetricValue: "1"

  # Step 3: Alarm for burst discovery
  RapidDiscoveryAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: T1497-RapidSystemDiscovery
      AlarmDescription: Rapid system discovery commands detected
      MetricName: SystemDiscovery
      Namespace: Security/T1497
      Statistic: Sum
      Period: 60
      EvaluationPeriods: 1
      Threshold: 30
      ComparisonOperator: GreaterThanOrEqualToThreshold
      TreatMissingData: notBreaching

      AlarmActions:
        - !Ref AlertTopic""",
                terraform_template="""# Detect rapid system discovery for sandbox evasion

variable "cloudtrail_log_group" {
  type = string
}

variable "alert_email" {
  type = string
}

# Step 1: SNS topic
resource "aws_sns_topic" "alerts" {
  name = "rapid-discovery-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Metric filter for rapid discovery
resource "aws_cloudwatch_log_metric_filter" "rapid_discovery" {
  name           = "rapid-system-discovery"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ $.eventSource = \"ec2.amazonaws.com\" && ($.eventName = \"DescribeInstances\" || $.eventName = \"DescribeInstanceTypes\") }"

  metric_transformation {
    name      = "SystemDiscovery"
    namespace = "Security/T1497"
    value     = "1"
  }
}

# Step 3: Alarm for burst discovery
resource "aws_cloudwatch_metric_alarm" "rapid_discovery" {
  alarm_name          = "T1497-RapidSystemDiscovery"
  alarm_description   = "Rapid system discovery commands detected"
  metric_name         = "SystemDiscovery"
  namespace           = "Security/T1497"
  statistic           = "Sum"
  period              = 60
  evaluation_periods  = 1
  threshold           = 30
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.alerts.arn]
}

data "aws_caller_identity" "current" {}

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
}""",
                alert_severity="medium",
                alert_title="Rapid System Discovery Detected",
                alert_description_template=(
                    "Rapid sequence of system discovery commands from {userIdentity.arn}. "
                    "This pattern is consistent with sandbox evasion techniques."
                ),
                investigation_steps=[
                    "Identify the principal performing rapid discovery",
                    "Review if this is automated tooling or manual reconnaissance",
                    "Check for subsequent suspicious activity",
                    "Examine the timing and pattern of API calls",
                    "Look for signs of malware or compromised credentials",
                ],
                containment_actions=[
                    "Review and restrict IAM permissions if necessary",
                    "Monitor for follow-on malicious activity",
                    "Consider rate limiting for discovery APIs",
                    "Enable GuardDuty for behavioural detection",
                    "Implement SCPs to restrict rapid enumeration",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.HIGH,
            false_positive_tuning="Whitelist automation tools, CI/CD pipelines, and infrastructure management tools",
            detection_coverage="65% - detects burst patterns",
            evasion_considerations="Slow, distributed discovery evades burst detection",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$5-10",
            prerequisites=["CloudTrail logging to CloudWatch"],
        ),
        # Strategy 3: GCP - Compute Engine Metadata Enumeration
        DetectionStrategy(
            strategy_id="t1497001-gcp-metadata",
            name="GCP Compute Metadata Server Enumeration",
            description=(
                "Detect excessive access to GCP Compute Engine metadata server, "
                "which attackers use to profile virtual machine environments."
            ),
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="gce_instance"
httpRequest.requestUrl=~"metadata.google.internal"
httpRequest.requestUrl=~"(instance/|project/)"''',
                gcp_terraform_template="""# GCP: Detect Compute Engine metadata enumeration

variable "project_id" {
  type = string
}

variable "alert_email" {
  type = string
}

# Step 1: Notification channel
resource "google_monitoring_notification_channel" "email_s1" {
  project      = var.project_id
  display_name = "Security Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Log-based metric for metadata access
resource "google_logging_metric" "metadata_enum" {
  project = var.project_id
  name   = "compute-metadata-enumeration"
  filter = <<-EOT
    resource.type="gce_instance"
    httpRequest.requestUrl=~"metadata.google.internal"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Alert policy for excessive metadata access
resource "google_monitoring_alert_policy" "metadata_enum" {
  project      = var.project_id
  display_name = "Compute Metadata Enumeration"
  combiner     = "OR"

  conditions {
    display_name = "Excessive metadata service access"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.metadata_enum.name}\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 100
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
    content   = "Excessive access to Compute Engine metadata service detected. This may indicate malware profiling the environment for sandbox evasion."
    mime_type = "text/markdown"
  }
}""",
                alert_severity="medium",
                alert_title="GCP: Compute Metadata Enumeration Detected",
                alert_description_template="Excessive access to Compute Engine metadata service detected on instance.",
                investigation_steps=[
                    "Identify the GCE instance making excessive requests",
                    "Review running processes and applications",
                    "Check for unauthorised software or scripts",
                    "Examine Cloud Audit Logs for related activity",
                    "Review instance creation and configuration",
                ],
                containment_actions=[
                    "Isolate the affected GCE instance",
                    "Create disk snapshot for forensic analysis",
                    "Review and terminate suspicious processes",
                    "Consider restricting metadata server access",
                    "Deploy security agents or EDR tools",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Adjust threshold based on normal application behaviour; whitelist known infrastructure services",
            detection_coverage="70% - detects high-volume access patterns",
            evasion_considerations="Throttled access may evade detection",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$10-15",
            prerequisites=["Cloud Logging enabled on GCE instances"],
        ),
        # Strategy 4: GCP - System Property Enumeration
        DetectionStrategy(
            strategy_id="t1497001-gcp-sysprofile",
            name="GCP System Profiling Detection",
            description=(
                "Detect rapid sequences of Compute Engine API calls used to profile "
                "instance characteristics (CPU, memory, network) for sandbox detection."
            ),
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''protoPayload.serviceName="compute.googleapis.com"
protoPayload.methodName=~"(instances.get|instances.list|machineTypes.get|zones.list)"''',
                gcp_terraform_template="""# GCP: Detect system profiling for sandbox evasion

variable "project_id" {
  type = string
}

variable "alert_email" {
  type = string
}

# Step 1: Notification channel
resource "google_monitoring_notification_channel" "email_s2" {
  project      = var.project_id
  display_name = "Security Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Log-based metric for system profiling
resource "google_logging_metric" "system_profile" {
  project = var.project_id
  name   = "system-profiling"
  filter = <<-EOT
    protoPayload.serviceName="compute.googleapis.com"
    protoPayload.methodName=~"(instances.get|instances.list|machineTypes.get)"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Alert policy for rapid profiling
resource "google_monitoring_alert_policy" "system_profile" {
  project      = var.project_id
  display_name = "System Profiling for Sandbox Evasion"
  combiner     = "OR"

  conditions {
    display_name = "Rapid system profiling detected"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.system_profile.name}\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 50
    }
  }

  notification_channels = [google_monitoring_notification_channel.email_s2.id]

  alert_strategy {
    auto_close = "1800s"
    notification_rate_limit {
      period = "300s"
    }
  }

  documentation {
    content   = "Rapid sequence of system profiling API calls detected. This pattern is consistent with sandbox evasion techniques."
    mime_type = "text/markdown"
  }
}""",
                alert_severity="medium",
                alert_title="GCP: System Profiling Detected",
                alert_description_template="Rapid sequence of system profiling API calls detected.",
                investigation_steps=[
                    "Identify the principal performing system profiling",
                    "Check if this is legitimate automation or tooling",
                    "Review subsequent API calls for malicious patterns",
                    "Examine timing and frequency of requests",
                    "Look for signs of compromised service accounts",
                ],
                containment_actions=[
                    "Review and restrict IAM permissions",
                    "Monitor for follow-on malicious activity",
                    "Consider IAM Conditions to limit API access",
                    "Enable Security Command Centre detections",
                    "Implement rate limiting via IAM policies",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.HIGH,
            false_positive_tuning="Whitelist infrastructure automation, monitoring tools, and CI/CD pipelines",
            detection_coverage="65% - detects burst patterns",
            evasion_considerations="Slow enumeration avoids burst detection",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$10-15",
            prerequisites=["Cloud Audit Logs enabled"],
        ),
    ],
    recommended_order=[
        "t1497001-aws-metadata",
        "t1497001-gcp-metadata",
        "t1497001-aws-syscommands",
        "t1497001-gcp-sysprofile",
    ],
    total_effort_hours=4.5,
    coverage_improvement="+12% improvement for Defence Evasion and Discovery tactics",
)
