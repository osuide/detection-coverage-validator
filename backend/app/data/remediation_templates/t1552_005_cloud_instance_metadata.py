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
    Campaign,
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
        recent_campaigns=[
            Campaign(
                name="Capital One Breach",
                year=2019,
                description="SSRF exploit used to access IMDS and steal IAM credentials, exfiltrating 100M+ records",
                reference_url="https://krebsonsecurity.com/2019/08/what-we-can-learn-from-the-capital-one-hack/",
            ),
            Campaign(
                name="TeamTNT IMDS Attacks",
                year=2024,
                description="Cryptomining group targeting misconfigured IMDS to steal credentials across cloud providers",
                reference_url="https://www.cadosecurity.com/blog/teamtnt-reemerges-with-new-aggressive-cloud-campaign",
            ),
        ],
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
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 3: Route IMDS exfil findings
  IMDSExfilRule:
    Type: AWS::Events::Rule
    Properties:
      EventPattern:
        source: [aws.guardduty]
        detail:
          type:
            - prefix: "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration"
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
    detail = {
      type = [{ prefix = "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration" }]
    }
  })
}

resource "aws_cloudwatch_event_target" "sns" {
  rule = aws_cloudwatch_event_rule.imds_exfil.name
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
            Resource: !Ref AlertTopic""",
                terraform_template="""# Enforce IMDSv2 on EC2 instances

variable "alert_email" {
  type = string
}

# Step 1: SNS topic
resource "aws_sns_topic" "alerts" {
  name = "imdsv2-compliance-alerts"
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
        # Strategy 3: GCP - Metadata server access monitoring
        DetectionStrategy(
            strategy_id="t1552005-gcp-metadata",
            name="GCP Metadata Server Access Detection",
            description="Monitor for unusual access to GCP metadata server.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="gce_instance"
protoPayload.methodName="compute.instances.getSerialPortOutput"
OR protoPayload.requestMetadata.callerSuppliedUserAgent=~".*metadata.*"''',
                gcp_terraform_template="""# GCP: Detect metadata server abuse

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

# Step 2: Log-based metric for metadata access
resource "google_logging_metric" "metadata_access" {
  name   = "suspicious-metadata-access"
  filter = <<-EOT
    resource.type="gce_instance"
    protoPayload.methodName=~"compute.instances.get.*"
    severity>=WARNING
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Alert policy
resource "google_monitoring_alert_policy" "metadata_alert" {
  display_name = "Suspicious Metadata Access"
  combiner     = "OR"

  conditions {
    display_name = "High volume of metadata queries"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.metadata_access.name}\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 50
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]
}

# Step 4: Enforce metadata concealment (prevention)
# Add this to GCE instance configs:
# metadata = {
#   enable-oslogin = "TRUE"
# }
# shielded_instance_config {
#   enable_secure_boot = true
# }""",
                alert_severity="high",
                alert_title="GCP: Suspicious Metadata Access",
                alert_description_template="Unusual metadata server access pattern detected on GCE instances.",
                investigation_steps=[
                    "Check Cloud Audit Logs for metadata API calls",
                    "Review which service accounts accessed metadata",
                    "Look for SSRF patterns in application logs",
                    "Verify instance security configurations",
                ],
                containment_actions=[
                    "Enable metadata concealment on instances",
                    "Rotate service account keys",
                    "Review and restrict service account permissions",
                    "Enable OS Login for instance access",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Baseline normal metadata access patterns",
            detection_coverage="70% - depends on logging configuration",
            evasion_considerations="Direct metadata access may not log",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$10-20",
            prerequisites=["Cloud Audit Logs enabled"],
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
      Period: 3600
      Threshold: 1000
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
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
  period              = 3600
  threshold           = 1000
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
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
        "t1552005-gcp-metadata",
        "t1552005-aws-flowlogs",
    ],
    total_effort_hours=4.5,
    coverage_improvement="+20% improvement for Credential Access tactic",
)
