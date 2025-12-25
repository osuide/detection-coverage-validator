"""
T1578.002 - Modify Cloud Compute Infrastructure: Create Cloud Instance

Adversaries create new VM instances to bypass security controls on existing instances.
Used by Scattered Spider and LAPSUS$ for cryptomining and data staging.
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
    technique_id="T1578.002",
    technique_name="Modify Cloud Compute Infrastructure: Create Cloud Instance",
    tactic_ids=["TA0005"],
    mitre_url="https://attack.mitre.org/techniques/T1578/002/",
    threat_context=ThreatContext(
        description=(
            "Adversaries create new virtual machine instances to bypass firewall rules "
            "and permissions on existing instances. New instances can be used for "
            "cryptomining, data staging, or as attack infrastructure."
        ),
        attacker_goal="Create new instances to bypass controls or abuse resources",
        why_technique=[
            "Bypasses security controls on existing instances",
            "Enables cryptomining on victim infrastructure",
            "Provides clean environment for data staging",
            "Avoids detection on monitored systems",
            "Can use large instance types for compute abuse",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="common",
        trend="stable",
        severity_score=7,
        severity_reasoning=(
            "Direct resource abuse and defence evasion. New instances can incur "
            "significant costs and bypass existing security controls."
        ),
        business_impact=[
            "Significant cloud cost increases",
            "Cryptomining resource abuse",
            "Bypassed security controls",
            "Potential data staging for exfil",
        ],
        typical_attack_phase="defence_evasion",
        often_precedes=["T1496.001", "T1530"],
        often_follows=["T1078.004", "T1098.003"],
    ),
    detection_strategies=[
        # =====================================================================
        # STRATEGY 1: GuardDuty EC2 Runtime Monitoring (Recommended)
        # =====================================================================
        DetectionStrategy(
            strategy_id="t1578002-aws-guardduty",
            name="AWS GuardDuty EC2 Cryptomining Detection",
            description=(
                "Leverage GuardDuty EC2 Runtime Monitoring to detect cryptomining "
                "and malicious activity on newly created instances. "
                "See: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-ec2.html"
            ),
            detection_type=DetectionType.GUARDDUTY,
            aws_service="guardduty",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                guardduty_finding_types=[
                    "CryptoCurrency:EC2/BitcoinTool.B!DNS",
                    "CryptoCurrency:Runtime/BitcoinTool.B",
                    "Impact:Runtime/CryptoMinerExecuted",
                    "Backdoor:EC2/C&CActivity.B!DNS",
                    "UnauthorizedAccess:EC2/TorClient",
                ],
                terraform_template="""# AWS GuardDuty EC2 Runtime Monitoring
# Detects: CryptoCurrency, Backdoor, UnauthorizedAccess on EC2
# See: https://docs.aws.amazon.com/guardduty/latest/ug/findings-runtime-monitoring.html

variable "alert_email" {
  type        = string
  description = "Email for EC2 security alerts"
}

# Step 1: Create encrypted SNS topic
resource "aws_sns_topic" "ec2_alerts" {
  name              = "guardduty-ec2-runtime-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "alert_email" {
  topic_arn = aws_sns_topic.ec2_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Enable GuardDuty with Runtime Monitoring
resource "aws_guardduty_detector" "main" {
  enable = true
}

resource "aws_guardduty_detector_feature" "runtime_monitoring" {
  detector_id = aws_guardduty_detector.main.id
  name        = "RUNTIME_MONITORING"
  status      = "ENABLED"

  additional_configuration {
    name   = "ECS_FARGATE_AGENT_MANAGEMENT"
    status = "ENABLED"
  }
}

# Step 3: Route EC2 findings to SNS
resource "aws_cloudwatch_event_rule" "ec2_findings" {
  name        = "guardduty-ec2-findings"
  description = "Detect cryptomining and malicious EC2 activity"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail = {
      type = [
        { prefix = "CryptoCurrency:EC2/" },
        { prefix = "CryptoCurrency:Runtime/" },
        { prefix = "Impact:Runtime/" },
        { prefix = "Backdoor:EC2/" },
        { prefix = "Backdoor:Runtime/" }
      ]
    }
  })
}

resource "aws_cloudwatch_event_target" "to_sns" {
  rule      = aws_cloudwatch_event_rule.ec2_findings.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.ec2_alerts.arn

  input_transformer {
    input_paths = {
      findingType = "$.detail.type"
      severity    = "$.detail.severity"
      instanceId  = "$.detail.resource.instanceDetails.instanceId"
      accountId   = "$.account"
    }
    input_template = <<-EOF
      "CRITICAL: GuardDuty EC2 Runtime Alert"
      "Type: <findingType>"
      "Severity: <severity>"
      "Instance: <instanceId>"
      "Account: <accountId>"
      "Action: Immediately investigate instance for cryptomining or compromise"
    EOF
  }
}

resource "aws_sns_topic_policy" "allow_eventbridge" {
  arn = aws_sns_topic.ec2_alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowEventBridgePublish"
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.ec2_alerts.arn
    }]
  })
}""",
                alert_severity="critical",
                alert_title="GuardDuty: EC2 Malicious Activity Detected",
                alert_description_template=(
                    "GuardDuty detected malicious activity on EC2 instance {instanceId}: {type}. "
                    "This may indicate cryptomining, backdoor, or C&C communication."
                ),
                investigation_steps=[
                    "Review the specific GuardDuty finding for full context",
                    "Check instance CPU/network utilisation for mining indicators",
                    "Review when the instance was created and by whom",
                    "Check the instance's security groups and IAM role",
                    "Look for associated billing spikes",
                ],
                containment_actions=[
                    "Immediately stop or terminate the instance",
                    "Preserve the EBS volume for forensics if needed",
                    "Revoke credentials used to create the instance",
                    "Review RunInstances permissions in the account",
                    "Check for other instances created by the same principal",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning=(
                "GuardDuty's ML minimises false positives. "
                "Suppress findings for legitimate blockchain workloads. "
                "Use trusted IP lists for known mining pools (if authorised)."
            ),
            detection_coverage="90% - runtime monitoring of EC2 processes",
            evasion_considerations="Encrypted or obfuscated mining traffic may evade",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost=(
                "Runtime Monitoring: ~$1.50/instance/month. "
                "See: https://aws.amazon.com/guardduty/pricing/"
            ),
            prerequisites=["GuardDuty enabled", "SSM Agent installed on instances"],
        ),
        # =====================================================================
        # STRATEGY 2: AWS - EC2 Instance Creation
        # =====================================================================
        DetectionStrategy(
            strategy_id="t1578002-aws-ec2",
            name="EC2 Instance Creation Detection",
            description="Detect when new EC2 instances are created.",
            detection_type=DetectionType.EVENTBRIDGE_RULE,
            aws_service="eventbridge",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                event_pattern={
                    "source": ["aws.ec2"],
                    "detail-type": ["AWS API Call via CloudTrail"],
                    "detail": {"eventName": ["RunInstances"]},
                },
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect EC2 instance creation

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

  EC2CreateRule:
    Type: AWS::Events::Rule
    Properties:
      EventPattern:
        source: [aws.ec2]
        detail-type: [AWS API Call via CloudTrail]
        detail:
          eventName: [RunInstances]
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
            Resource: !Ref AlertTopic""",
                terraform_template="""# Detect EC2 instance creation

variable "alert_email" { type = string }

resource "aws_sns_topic" "alerts" {
  name = "ec2-creation-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_cloudwatch_event_rule" "ec2_create" {
  name = "ec2-instance-creation"
  event_pattern = jsonencode({
    source      = ["aws.ec2"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail      = { eventName = ["RunInstances"] }
  })
}

resource "aws_cloudwatch_event_target" "sns" {
  rule = aws_cloudwatch_event_rule.ec2_create.name
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
}""",
                alert_severity="medium",
                alert_title="EC2 Instance Created",
                alert_description_template="New EC2 instance created by {userIdentity.arn}.",
                investigation_steps=[
                    "Verify instance creation was authorised",
                    "Check instance type for cryptomining (large GPU/compute)",
                    "Review who created the instance",
                    "Check instance security groups and IAM role",
                ],
                containment_actions=[
                    "Terminate unauthorised instances",
                    "Review EC2 launch permissions",
                    "Check for associated costs",
                    "Review instance for malicious activity",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist auto-scaling and deployment automation",
            detection_coverage="95% - catches all RunInstances",
            evasion_considerations="Cannot evade this detection",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$2-5",
            prerequisites=["CloudTrail enabled"],
        ),
        # Strategy 2: AWS - Large Instance Type Detection
        DetectionStrategy(
            strategy_id="t1578002-aws-largeinstance",
            name="Large/GPU Instance Creation Detection",
            description="Detect creation of large or GPU instances often used for cryptomining.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, userIdentity.arn, requestParameters.instanceType
| filter eventSource = "ec2.amazonaws.com"
| filter eventName = "RunInstances"
| filter requestParameters.instanceType like /p3|p4|g4|g5|x1|x2|c5.18|c5.24|c6|m5.24/
| sort @timestamp desc""",
                terraform_template="""# Detect large/GPU instance creation (cryptomining indicator)

variable "cloudtrail_log_group" { type = string }
variable "alert_email" { type = string }

resource "aws_sns_topic" "alerts" {
  name = "large-instance-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_cloudwatch_log_metric_filter" "large_instance" {
  name           = "large-instance-creation"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ $.eventName = \"RunInstances\" && ($.requestParameters.instanceType = \"p3*\" || $.requestParameters.instanceType = \"p4*\" || $.requestParameters.instanceType = \"g4*\") }"

  metric_transformation {
    name      = "LargeInstanceCreated"
    namespace = "Security"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "large_instance" {
  alarm_name          = "LargeInstanceCreated"
  metric_name         = "LargeInstanceCreated"
  namespace           = "Security"
  statistic           = "Sum"
  period              = 300
  threshold           = 0
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  alarm_actions       = [aws_sns_topic.alerts.arn]
}""",
                alert_severity="high",
                alert_title="Large/GPU Instance Created",
                alert_description_template="Large or GPU instance {instanceType} created - potential cryptomining.",
                investigation_steps=[
                    "Verify large instance was authorised",
                    "Check for legitimate ML/HPC workload",
                    "Review instance activity",
                    "Check CPU/GPU utilisation patterns",
                ],
                containment_actions=[
                    "Terminate if unauthorised",
                    "Review who has RunInstances permission",
                    "Set Service Control Policies for instance types",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Whitelist ML teams and approved workloads",
            detection_coverage="95% - catches specific instance types",
            evasion_considerations="Attacker may use many small instances instead",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$5-10",
            prerequisites=["CloudTrail logging to CloudWatch"],
        ),
        # Strategy 3: GCP - GCE Instance Creation
        DetectionStrategy(
            strategy_id="t1578002-gcp-gce",
            name="GCE Instance Creation Detection",
            description="Detect when new GCE instances are created.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''protoPayload.methodName="compute.instances.insert"''',
                gcp_terraform_template="""# GCP: Detect GCE instance creation

variable "project_id" { type = string }
variable "alert_email" { type = string }

resource "google_monitoring_notification_channel" "email" {
  display_name = "Security Alerts"
  type         = "email"
  labels       = { email_address = var.alert_email }
}

resource "google_logging_metric" "gce_create" {
  name   = "gce-instance-creation"
  filter = "protoPayload.methodName=\"compute.instances.insert\""
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

resource "google_monitoring_alert_policy" "gce_create" {
  display_name = "GCE Instance Created"
  combiner     = "OR"

  conditions {
    display_name = "Instance creation"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.gce_create.name}\""
      duration        = "0s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]
}""",
                alert_severity="medium",
                alert_title="GCP: GCE Instance Created",
                alert_description_template="New GCE instance was created.",
                investigation_steps=[
                    "Verify instance creation was authorised",
                    "Check machine type for cryptomining indicators",
                    "Review who created the instance",
                    "Check instance for malicious activity",
                ],
                containment_actions=[
                    "Delete unauthorised instances",
                    "Review compute permissions",
                    "Set organisation policy constraints",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist auto-scaling and deployment",
            detection_coverage="95% - catches all instance creation",
            evasion_considerations="Cannot evade",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=["Cloud Audit Logs enabled"],
        ),
    ],
    recommended_order=[
        "t1578002-aws-guardduty",
        "t1578002-aws-ec2",
        "t1578002-aws-largeinstance",
        "t1578002-gcp-gce",
    ],
    total_effort_hours=3.0,
    coverage_improvement="+15% improvement for Defence Evasion tactic",
)
