"""
T1033 - System Owner/User Discovery

Adversaries attempt to identify the primary user, currently logged in user, or set
of users that commonly use a system to gather intelligence about privilege levels
and determine whether to proceed with full compromise.
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
    technique_id="T1033",
    technique_name="System Owner/User Discovery",
    tactic_ids=["TA0007"],  # Discovery
    mitre_url="https://attack.mitre.org/techniques/T1033/",
    threat_context=ThreatContext(
        description=(
            "Adversaries identify the primary user, currently logged in user, or set of users "
            "that commonly use a system to gather intelligence about privilege levels and targets. "
            "In cloud environments, this includes discovering which IAM users or service accounts "
            "are actively performing operations, their permission levels, and usage patterns. "
            "This reconnaissance helps attackers assess whether to proceed with full compromise "
            "or selective actions against high-value accounts."
        ),
        attacker_goal="Identify system users and their privilege levels to determine valuable targets",
        why_technique=[
            "Determines if high-privilege accounts are active",
            "Identifies administrative users for targeted attacks",
            "Reveals usage patterns and active sessions",
            "Assesses system value based on user activity",
            "Required for planning privilege escalation paths",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="common",
        trend="stable",
        severity_score=4,
        severity_reasoning=(
            "User discovery is a low-impact reconnaissance activity but indicates active threat actor presence. "
            "This technique is difficult to prevent as it leverages legitimate system features. "
            "It typically precedes more serious attacks like credential harvesting or privilege escalation. "
            "Important as an early warning signal but cannot be easily mitigated with preventive controls."
        ),
        business_impact=[
            "Indicates active reconnaissance in environment",
            "Precursor to targeted credential attacks",
            "Mapping of administrative accounts",
            "Early warning opportunity for defence",
        ],
        typical_attack_phase="discovery",
        often_precedes=["T1078.004", "T1087.004", "T1069.003", "T1110"],
        often_follows=["T1078.004", "T1190", "T1133"],
    ),
    detection_strategies=[
        # Strategy 1: AWS - IAM User Activity Enumeration
        DetectionStrategy(
            strategy_id="t1033-aws-user-enum",
            name="AWS IAM User Activity Discovery Detection",
            description="Detect when attackers enumerate IAM user activity and session information through CloudTrail queries.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, userIdentity.arn, eventName, sourceIPAddress
| filter eventSource = "sts.amazonaws.com" and eventName = "GetCallerIdentity"
| stats count(*) as call_count by userIdentity.arn, sourceIPAddress, bin(5m)
| filter call_count > 20
| sort call_count desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect IAM user activity enumeration

Parameters:
  CloudTrailLogGroup:
    Type: String
    Description: CloudTrail log group name
  AlertEmail:
    Type: String
    Description: Email address for alerts

Resources:
  # Step 1: SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Metric filter for GetCallerIdentity enumeration
  UserEnumFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ $.eventSource = "sts.amazonaws.com" && $.eventName = "GetCallerIdentity" }'
      MetricTransformations:
        - MetricName: UserIdentityEnumeration
          MetricNamespace: Security
          MetricValue: "1"

  # Step 3: Alarm for high-frequency calls
  UserEnumAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: UserIdentityEnumeration
      MetricName: UserIdentityEnumeration
      Namespace: Security
      Statistic: Sum
      Period: 300
      Threshold: 50
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      TreatMissingData: notBreaching

      AlarmActions: [!Ref AlertTopic]

  # Step 4: SNS topic policy (scoped)
  TopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics: [!Ref AlertTopic]
      PolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Sid: AllowCloudWatchAlarms
            Effect: Allow
            Principal:
              Service: cloudwatch.amazonaws.com
            Action: sns:Publish
            Resource: !Ref AlertTopic
            Condition:
              StringEquals:
                AWS:SourceAccount: !Ref AWS::AccountId""",
                terraform_template="""# Detect IAM user activity enumeration

variable "cloudtrail_log_group" {
  type        = string
  description = "CloudTrail log group name"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

# Step 1: SNS topic for alerts
resource "aws_sns_topic" "alerts" {
  name = "user-enumeration-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Metric filter for user enumeration
resource "aws_cloudwatch_log_metric_filter" "user_enum" {
  name           = "user-identity-enumeration"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ $.eventSource = \"sts.amazonaws.com\" && $.eventName = \"GetCallerIdentity\" }"

  metric_transformation {
    name      = "UserIdentityEnumeration"
    namespace = "Security"
    value     = "1"
  }
}

# Step 3: Alarm for high-frequency enumeration
resource "aws_cloudwatch_metric_alarm" "user_enum" {
  alarm_name          = "UserIdentityEnumeration"
  metric_name         = "UserIdentityEnumeration"
  namespace           = "Security"
  statistic           = "Sum"
  period              = 300
  threshold           = 50
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.alerts.arn]
}

# Step 4: SNS topic policy (scoped)
data "aws_caller_identity" "current" {}

resource "aws_sns_topic_policy" "allow_cloudwatch" {
  arn = aws_sns_topic.alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowCloudWatchAlarms"
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
                alert_title="AWS: User Identity Enumeration Detected",
                alert_description_template="High-frequency GetCallerIdentity calls from {userIdentity.arn} may indicate user discovery activity.",
                investigation_steps=[
                    "Identify the principal making repeated calls",
                    "Check if this matches normal application behaviour",
                    "Review the source IP address and geographic location",
                    "Examine what other API calls were made by this principal",
                    "Check for follow-on reconnaissance or privilege escalation",
                ],
                containment_actions=[
                    "Review the principal's permissions and recent activity",
                    "Check for unauthorised access or compromised credentials",
                    "Monitor for privilege escalation attempts",
                    "Consider rate limiting or IAM Conditions",
                    "Enable MFA if not already configured",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist automated tools and health check systems that legitimately call GetCallerIdentity",
            detection_coverage="75% - volume-based detection may miss slow enumeration",
            evasion_considerations="Slow, low-volume enumeration spread over time may evade thresholds",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$5-10",
            prerequisites=["CloudTrail logging to CloudWatch Logs"],
        ),
        # Strategy 2: AWS - EC2 Instance User Discovery
        DetectionStrategy(
            strategy_id="t1033-aws-instance-user",
            name="AWS EC2 Instance User Discovery Detection",
            description="Detect enumeration of EC2 instances to discover which users or applications are running workloads.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, userIdentity.arn, eventName, requestParameters.instancesSet.items
| filter eventSource = "ec2.amazonaws.com"
| filter eventName in ["DescribeInstances", "DescribeInstanceAttribute", "GetConsoleOutput"]
| stats count(*) as query_count by userIdentity.arn, bin(10m)
| filter query_count > 30
| sort query_count desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect EC2 instance user discovery

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

  # Step 2: Metric filter for instance enumeration
  InstanceEnumFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ ($.eventSource = "ec2.amazonaws.com") && ($.eventName = "DescribeInstances" || $.eventName = "GetConsoleOutput") }'
      MetricTransformations:
        - MetricName: EC2UserDiscovery
          MetricNamespace: Security
          MetricValue: "1"

  # Step 3: Alarm
  InstanceEnumAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: EC2UserDiscovery
      MetricName: EC2UserDiscovery
      Namespace: Security
      Statistic: Sum
      Period: 600
      Threshold: 40
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      TreatMissingData: notBreaching

      AlarmActions: [!Ref AlertTopic]

  # Step 4: SNS topic policy (scoped)
  TopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics: [!Ref AlertTopic]
      PolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Sid: AllowCloudWatchAlarms
            Effect: Allow
            Principal:
              Service: cloudwatch.amazonaws.com
            Action: sns:Publish
            Resource: !Ref AlertTopic
            Condition:
              StringEquals:
                AWS:SourceAccount: !Ref AWS::AccountId""",
                terraform_template="""# Detect EC2 instance user discovery

variable "cloudtrail_log_group" {
  type = string
}

variable "alert_email" {
  type = string
}

# Step 1: SNS topic
resource "aws_sns_topic" "alerts" {
  name = "ec2-user-discovery-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Metric filter
resource "aws_cloudwatch_log_metric_filter" "instance_enum" {
  name           = "ec2-user-discovery"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ ($.eventSource = \"ec2.amazonaws.com\") && ($.eventName = \"DescribeInstances\" || $.eventName = \"GetConsoleOutput\") }"

  metric_transformation {
    name      = "EC2UserDiscovery"
    namespace = "Security"
    value     = "1"
  }
}

# Step 3: Alarm
resource "aws_cloudwatch_metric_alarm" "instance_enum" {
  alarm_name          = "EC2UserDiscovery"
  metric_name         = "EC2UserDiscovery"
  namespace           = "Security"
  statistic           = "Sum"
  period              = 600
  threshold           = 40
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.alerts.arn]
}

# Step 4: SNS topic policy (scoped)
data "aws_caller_identity" "current" {}

resource "aws_sns_topic_policy" "allow_cloudwatch" {
  arn = aws_sns_topic.alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowCloudWatchAlarms"
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
                alert_title="AWS: EC2 Instance User Discovery",
                alert_description_template="High volume of EC2 instance queries from {userIdentity.arn}. May indicate reconnaissance.",
                investigation_steps=[
                    "Identify who is performing the enumeration",
                    "Check if this is normal monitoring or DevOps activity",
                    "Review what instance metadata was accessed",
                    "Look for GetConsoleOutput calls (reveals user data)",
                    "Check for follow-on lateral movement or access attempts",
                ],
                containment_actions=[
                    "Review the principal's permissions",
                    "Monitor for unauthorised instance access",
                    "Check instance metadata service access logs",
                    "Consider restricting EC2 describe permissions",
                    "Enable Session Manager logging",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist monitoring tools, CSPM platforms, and automated DevOps systems",
            detection_coverage="70% - behavioural detection based on volume",
            evasion_considerations="Slow enumeration or use of existing monitoring tools may evade detection",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$5-10",
            prerequisites=["CloudTrail enabled", "CloudWatch Logs"],
        ),
        # Strategy 3: GCP - User Activity Discovery
        DetectionStrategy(
            strategy_id="t1033-gcp-user-activity",
            name="GCP User Activity Discovery Detection",
            description="Detect enumeration of GCP user activity and session information through Cloud Audit Logs queries.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''protoPayload.serviceName="cloudresourcemanager.googleapis.com"
protoPayload.methodName=~"(getIamPolicy|testIamPermissions|getAncestry)"''',
                gcp_terraform_template="""# GCP: Detect user activity discovery

variable "project_id" {
  type        = string
  description = "GCP project ID"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
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

# Step 2: Log-based metric for user discovery
resource "google_logging_metric" "user_discovery" {
  project = var.project_id
  name   = "user-activity-discovery"
  filter = <<-EOT
    protoPayload.serviceName="cloudresourcemanager.googleapis.com"
    (protoPayload.methodName=~"getIamPolicy" OR
     protoPayload.methodName=~"testIamPermissions" OR
     protoPayload.methodName=~"getAncestry")
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Alert policy
resource "google_monitoring_alert_policy" "user_discovery" {
  project      = var.project_id
  display_name = "User Activity Discovery Detected"
  combiner     = "OR"

  conditions {
    display_name = "High volume user queries"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.user_discovery.name}\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 50
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
                alert_title="GCP: User Activity Discovery Detected",
                alert_description_template="High volume of user activity queries detected. May indicate reconnaissance.",
                investigation_steps=[
                    "Identify the principal performing the queries",
                    "Check if this is authorised security scanning",
                    "Review what resources were queried",
                    "Look for patterns indicating automated enumeration",
                    "Check for follow-on privilege escalation attempts",
                ],
                containment_actions=[
                    "Review the principal's IAM permissions",
                    "Monitor for unauthorised access attempts",
                    "Consider IAM Conditions to restrict access",
                    "Enable detailed audit logging",
                    "Review service account usage patterns",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist security tools, CSPM platforms, and authorised monitoring services",
            detection_coverage="75% - volume-based detection",
            evasion_considerations="Slow enumeration spread over time may evade thresholds",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$10-15",
            prerequisites=["Cloud Audit Logs enabled"],
        ),
        # Strategy 4: GCP - Compute Instance User Discovery
        DetectionStrategy(
            strategy_id="t1033-gcp-instance-user",
            name="GCP Compute Instance User Discovery",
            description="Detect enumeration of GCP Compute Engine instances to identify active users and workloads.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''protoPayload.serviceName="compute.googleapis.com"
protoPayload.methodName=~"(instances.list|instances.get|instances.getSerialPortOutput)"''',
                gcp_terraform_template="""# GCP: Detect compute instance user discovery

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

# Step 2: Log-based metric
resource "google_logging_metric" "instance_discovery" {
  project = var.project_id
  name   = "compute-instance-discovery"
  filter = <<-EOT
    protoPayload.serviceName="compute.googleapis.com"
    (protoPayload.methodName=~"instances.list" OR
     protoPayload.methodName=~"instances.get" OR
     protoPayload.methodName=~"instances.getSerialPortOutput")
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Alert policy
resource "google_monitoring_alert_policy" "instance_discovery" {
  project      = var.project_id
  display_name = "Compute Instance Discovery Detected"
  combiner     = "OR"

  conditions {
    display_name = "High volume instance queries"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.instance_discovery.name}\""
      duration        = "600s"
      comparison      = "COMPARISON_GT"
      threshold_value = 100
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
                alert_title="GCP: Compute Instance Discovery",
                alert_description_template="High volume of compute instance queries. May indicate user discovery reconnaissance.",
                investigation_steps=[
                    "Identify who is performing instance enumeration",
                    "Check if this is normal DevOps or monitoring activity",
                    "Review what instance metadata was accessed",
                    "Look for getSerialPortOutput calls (reveals boot logs)",
                    "Check for follow-on SSH or RDP access attempts",
                ],
                containment_actions=[
                    "Review the principal's compute permissions",
                    "Monitor for unauthorised instance access",
                    "Consider restricting compute.instances.* permissions",
                    "Enable OS Login for instance access control",
                    "Review firewall rules for SSH/RDP access",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist monitoring tools, infrastructure management platforms, and DevOps automation",
            detection_coverage="70% - behavioural detection based on query volume",
            evasion_considerations="Slow enumeration or use of legitimate monitoring tools may evade detection",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$10-15",
            prerequisites=["Cloud Audit Logs enabled"],
        ),
    ],
    recommended_order=[
        "t1033-aws-user-enum",
        "t1033-gcp-user-activity",
        "t1033-aws-instance-user",
        "t1033-gcp-instance-user",
    ],
    total_effort_hours=4.0,
    coverage_improvement="+12% improvement for Discovery tactic",
)
