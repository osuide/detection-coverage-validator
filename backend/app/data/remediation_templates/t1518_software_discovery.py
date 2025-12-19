"""
T1518 - Software Discovery

Adversaries enumerate installed software and versions on cloud systems
to identify security tools, vulnerabilities, and plan their attack strategy.
"""

from .template_loader import (
    RemediationTemplate,
    ThreatContext,
    DetectionStrategy,
    DetectionImplementation,
    Campaign,
    DetectionType,
    EffortLevel,
    FalsePositiveRate,
    CloudProvider,
)

TEMPLATE = RemediationTemplate(
    technique_id="T1518",
    technique_name="Software Discovery",
    tactic_ids=["TA0007"],
    mitre_url="https://attack.mitre.org/techniques/T1518/",

    threat_context=ThreatContext(
        description=(
            "Adversaries enumerate installed software, versions, and patches on systems "
            "and cloud environments. This reconnaissance identifies security tools, reveals "
            "vulnerable software versions, and informs attack strategy before exploitation."
        ),
        attacker_goal="Discover installed software to identify defences, vulnerabilities, and system capabilities",
        why_technique=[
            "Identifies installed security software",
            "Reveals vulnerable application versions",
            "Discovers system management tools",
            "Informs exploitation strategy",
            "Detects monitoring and backup solutions"
        ],
        known_threat_actors=["APT35", "Volt Typhoon", "Lazarus Group", "MuddyWater", "Mustang Panda", "OilRig"],
        recent_campaigns=[
            Campaign(
                name="Software Inventory Reconnaissance",
                year=2024,
                description="Threat actors systematically enumerate installed software to identify security tools and vulnerable applications before launching attacks",
                reference_url="https://attack.mitre.org/techniques/T1518/"
            ),
            Campaign(
                name="Cloud Environment Profiling",
                year=2024,
                description="Enumeration of cloud-based software inventories via Systems Manager and metadata services to identify attack surface",
                reference_url="https://unit42.paloaltonetworks.com/2025-cloud-security-alert-trends/"
            )
        ],
        prevalence="common",
        trend="stable",
        severity_score=4,
        severity_reasoning=(
            "Discovery technique with low direct impact but high strategic value. "
            "Indicates active reconnaissance and typically precedes targeted exploitation. "
            "Critical early warning signal for defensive operations."
        ),
        business_impact=[
            "Reveals defensive capabilities to adversaries",
            "Enables targeted vulnerability exploitation",
            "Identifies valuable software assets",
            "Indicates pre-attack reconnaissance phase"
        ],
        typical_attack_phase="discovery",
        often_precedes=["T1203", "T1210", "T1562.001"],
        often_follows=["T1078.004", "T1651"]
    ),

    detection_strategies=[
        # Strategy 1: AWS - Systems Manager Inventory Enumeration
        DetectionStrategy(
            strategy_id="t1518-aws-ssm-inventory",
            name="AWS Systems Manager Inventory Enumeration",
            description="Detect queries to Systems Manager Inventory revealing installed software.",
            detection_type=DetectionType.EVENTBRIDGE_RULE,
            aws_service="eventbridge",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                event_pattern={
                    "source": ["aws.ssm"],
                    "detail-type": ["AWS API Call via CloudTrail"],
                    "detail": {
                        "eventName": ["GetInventory", "ListInventoryEntries", "DescribeInstanceInformation"]
                    }
                },
                cloudformation_template='''AWSTemplateFormatVersion: '2010-09-09'
Description: Detect Systems Manager inventory enumeration

Parameters:
  AlertEmail:
    Type: String

Resources:
  # Step 1: SNS topic
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: EventBridge rule for SSM inventory queries
  SSMInventoryRule:
    Type: AWS::Events::Rule
    Properties:
      EventPattern:
        source: [aws.ssm]
        detail-type: [AWS API Call via CloudTrail]
        detail:
          eventName: [GetInventory, ListInventoryEntries, DescribeInstanceInformation]
      Targets:
        - Id: Alert
          Arn: !Ref AlertTopic

  # Step 3: Topic policy
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
            Resource: !Ref AlertTopic''',
                terraform_template='''# Detect Systems Manager inventory enumeration

variable "alert_email" {
  type = string
}

# Step 1: SNS topic
resource "aws_sns_topic" "alerts" {
  name = "ssm-inventory-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: EventBridge rule
resource "aws_cloudwatch_event_rule" "ssm_inventory" {
  name = "ssm-inventory-enumeration"
  event_pattern = jsonencode({
    source      = ["aws.ssm"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = ["GetInventory", "ListInventoryEntries", "DescribeInstanceInformation"]
    }
  })
}

# Step 3: EventBridge target
resource "aws_cloudwatch_event_target" "sns" {
  rule = aws_cloudwatch_event_rule.ssm_inventory.name
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
    }]
  })
}''',
                alert_severity="medium",
                alert_title="Systems Manager Inventory Enumeration Detected",
                alert_description_template="SSM inventory queries performed by {userIdentity.arn}.",
                investigation_steps=[
                    "Identify the user performing inventory queries",
                    "Check if this is authorised security scanning or patching activity",
                    "Review what instance information was accessed",
                    "Look for follow-on exploitation attempts"
                ],
                containment_actions=[
                    "Review user's permissions and recent activity",
                    "Monitor for targeted attacks on identified software",
                    "Check for vulnerability exploitation attempts",
                    "Consider restricting SSM inventory read access"
                ]
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist patch management, CSPM tools, and systems administrators",
            detection_coverage="85% - catches SSM inventory queries",
            evasion_considerations="Direct instance access or alternative discovery methods may bypass",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$2-5",
            prerequisites=["CloudTrail enabled", "Systems Manager Inventory configured"]
        ),

        # Strategy 2: AWS - EC2 Instance Details Enumeration
        DetectionStrategy(
            strategy_id="t1518-aws-ec2-describe",
            name="EC2 Software Details Enumeration",
            description="Detect bulk EC2 describe operations that reveal instance software configurations.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query='''fields @timestamp, eventName, userIdentity.arn, sourceIPAddress
| filter eventSource = "ec2.amazonaws.com"
| filter eventName in ["DescribeInstanceAttribute", "GetConsoleOutput", "DescribeImages"]
| stats count(*) as describe_count by userIdentity.arn, bin(1h)
| filter describe_count > 20
| sort describe_count desc''',
                cloudformation_template='''AWSTemplateFormatVersion: '2010-09-09'
Description: Detect EC2 software enumeration

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
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Metric filter for EC2 describe operations
  EC2DescribeFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ $.eventSource = "ec2.amazonaws.com" && ($.eventName = "DescribeInstanceAttribute" || $.eventName = "GetConsoleOutput" || $.eventName = "DescribeImages") }'
      MetricTransformations:
        - MetricName: EC2SoftwareEnum
          MetricNamespace: Security
          MetricValue: "1"

  # Step 3: Alarm for bulk enumeration
  EC2EnumAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: EC2SoftwareEnumeration
      MetricName: EC2SoftwareEnum
      Namespace: Security
      Statistic: Sum
      Period: 3600
      Threshold: 50
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      AlarmActions: [!Ref AlertTopic]''',
                terraform_template='''# Detect EC2 software enumeration

variable "cloudtrail_log_group" {
  type = string
}

variable "alert_email" {
  type = string
}

# Step 1: SNS topic
resource "aws_sns_topic" "alerts" {
  name = "ec2-software-enum-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Metric filter
resource "aws_cloudwatch_log_metric_filter" "ec2_describe" {
  name           = "ec2-software-enumeration"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ $.eventSource = \"ec2.amazonaws.com\" && ($.eventName = \"DescribeInstanceAttribute\" || $.eventName = \"GetConsoleOutput\") }"

  metric_transformation {
    name      = "EC2SoftwareEnum"
    namespace = "Security"
    value     = "1"
  }
}

# Step 3: Alarm
resource "aws_cloudwatch_metric_alarm" "ec2_enum" {
  alarm_name          = "EC2SoftwareEnumeration"
  metric_name         = "EC2SoftwareEnum"
  namespace           = "Security"
  statistic           = "Sum"
  period              = 3600
  threshold           = 50
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  alarm_actions       = [aws_sns_topic.alerts.arn]
}''',
                alert_severity="medium",
                alert_title="EC2 Software Enumeration Detected",
                alert_description_template="High volume of EC2 describe operations from {userIdentity.arn}.",
                investigation_steps=[
                    "Identify who is performing EC2 enumeration",
                    "Determine if this is normal operational behaviour",
                    "Review what instance details were accessed",
                    "Check for targeted exploitation attempts"
                ],
                containment_actions=[
                    "Review user's permissions and activity history",
                    "Monitor for exploitation of identified software",
                    "Consider implementing SCPs for describe limits",
                    "Audit instances for vulnerable software"
                ]
            ),
            estimated_false_positive_rate=FalsePositiveRate.HIGH,
            false_positive_tuning="Whitelist automation tools, monitoring systems, and infrastructure management platforms",
            detection_coverage="70% - volume-based detection",
            evasion_considerations="Slow enumeration over time may evade thresholds",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$5-10",
            prerequisites=["CloudTrail logging to CloudWatch"]
        ),

        # Strategy 3: GCP - Compute Instance Software Enumeration
        DetectionStrategy(
            strategy_id="t1518-gcp-compute-describe",
            name="GCP Compute Instance Software Enumeration",
            description="Detect queries to enumerate software on GCP Compute instances.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''protoPayload.methodName=~"(compute.instances.get|osconfig.patchDeployments.list|osconfig.patchJobs.list)"''',
                gcp_terraform_template='''# GCP: Detect instance software enumeration

variable "project_id" {
  type = string
}

variable "alert_email" {
  type = string
}

# Step 1: Notification channel
resource "google_monitoring_notification_channel" "email" {
  display_name = "Security Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Log-based metric for software enumeration
resource "google_logging_metric" "software_enum" {
  name   = "instance-software-enumeration"
  filter = <<-EOT
    protoPayload.methodName=~"(compute.instances.get|osconfig.patchDeployments.list|osconfig.patchJobs.list)"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Alert policy
resource "google_monitoring_alert_policy" "software_enum" {
  display_name = "Instance Software Enumeration"
  combiner     = "OR"

  conditions {
    display_name = "High volume software queries"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.software_enum.name}\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 50
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]
}''',
                alert_severity="medium",
                alert_title="GCP: Instance Software Enumeration Detected",
                alert_description_template="High volume of instance software queries detected.",
                investigation_steps=[
                    "Identify the principal performing software enumeration",
                    "Check if this is authorised security scanning",
                    "Review which instances were queried",
                    "Look for follow-on exploitation attempts"
                ],
                containment_actions=[
                    "Review principal's permissions and recent activity",
                    "Monitor for targeted attacks on vulnerable software",
                    "Consider IAM Conditions to restrict access",
                    "Audit instances for vulnerable applications"
                ]
            ),
            estimated_false_positive_rate=FalsePositiveRate.HIGH,
            false_positive_tuning="Whitelist patch management, monitoring tools, and operations teams",
            detection_coverage="75% - volume-based detection",
            evasion_considerations="Slow enumeration or direct SSH access may evade",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$10-15",
            prerequisites=["Cloud Audit Logs enabled"]
        ),

        # Strategy 4: GCP - OS Inventory Service Enumeration
        DetectionStrategy(
            strategy_id="t1518-gcp-os-inventory",
            name="GCP OS Inventory Data Enumeration",
            description="Detect queries to GCP OS Inventory service revealing installed packages.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''protoPayload.methodName=~"osconfig.*Inventory|compute.instances.getGuestAttributes"''',
                gcp_terraform_template='''# GCP: Detect OS inventory enumeration

variable "project_id" {
  type = string
}

variable "alert_email" {
  type = string
}

# Step 1: Notification channel
resource "google_monitoring_notification_channel" "email" {
  display_name = "Security Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Log-based metric
resource "google_logging_metric" "os_inventory" {
  name   = "os-inventory-enumeration"
  filter = <<-EOT
    protoPayload.methodName=~"osconfig.*Inventory|compute.instances.getGuestAttributes"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Alert policy
resource "google_monitoring_alert_policy" "os_inventory" {
  display_name = "OS Inventory Enumeration"
  combiner     = "OR"

  conditions {
    display_name = "OS inventory queries detected"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.os_inventory.name}\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 20
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]
}''',
                alert_severity="medium",
                alert_title="GCP: OS Inventory Enumeration Detected",
                alert_description_template="OS inventory queries detected - software enumeration in progress.",
                investigation_steps=[
                    "Identify who is accessing OS inventory data",
                    "Verify if this is authorised patching or scanning",
                    "Review which instances were targeted",
                    "Check for subsequent exploitation activity"
                ],
                containment_actions=[
                    "Review principal's permissions",
                    "Monitor for targeted exploitation",
                    "Consider restricting inventory access",
                    "Audit vulnerable software on instances"
                ]
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist vulnerability scanners and patch management systems",
            detection_coverage="80% - catches OS inventory queries",
            evasion_considerations="Metadata service queries or direct access may bypass",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=["Cloud Audit Logs enabled", "OS Inventory configured"]
        )
    ],

    recommended_order=[
        "t1518-aws-ssm-inventory",
        "t1518-aws-ec2-describe",
        "t1518-gcp-os-inventory",
        "t1518-gcp-compute-describe"
    ],
    total_effort_hours=3.0,
    coverage_improvement="+12% improvement for Discovery tactic"
)
