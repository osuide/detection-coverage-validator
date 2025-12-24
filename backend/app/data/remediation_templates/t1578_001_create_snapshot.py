"""
T1578.001 - Modify Cloud Compute Infrastructure: Create Snapshot

Adversaries create snapshots of cloud compute resources to exfiltrate data.
45% increase in snapshot-based exfiltration observed in late 2024.
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
    technique_id="T1578.001",
    technique_name="Modify Cloud Compute Infrastructure: Create Snapshot",
    tactic_ids=["TA0005", "TA0010"],
    mitre_url="https://attack.mitre.org/techniques/T1578/001/",
    threat_context=ThreatContext(
        description=(
            "Adversaries create snapshots of EBS volumes, RDS databases, or GCE disks "
            "to exfiltrate data. Snapshots can be shared to external accounts or "
            "used to create new instances for data extraction."
        ),
        attacker_goal="Create snapshots to exfiltrate data or preserve access",
        why_technique=[
            "Complete copy of disk data",
            "Faster than downloading individual files",
            "Can be shared cross-account easily",
            "Often overlooked in monitoring",
            "45% increase in attacks in late 2024",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="common",
        trend="increasing",
        severity_score=8,
        severity_reasoning=(
            "Direct data theft technique. Snapshots contain complete disk data "
            "and can be quickly shared externally. Often missed by traditional monitoring."
        ),
        business_impact=[
            "Complete data exfiltration",
            "Intellectual property theft",
            "Compliance violations",
            "Evidence for further attacks",
        ],
        typical_attack_phase="exfiltration",
        often_precedes=["T1537"],
        often_follows=["T1078.004", "T1530"],
    ),
    detection_strategies=[
        # Strategy 1: AWS - EBS Snapshot Creation
        DetectionStrategy(
            strategy_id="t1578001-aws-ebs",
            name="EBS Snapshot Creation Detection",
            description="Detect when EBS snapshots are created.",
            detection_type=DetectionType.EVENTBRIDGE_RULE,
            aws_service="eventbridge",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                event_pattern={
                    "source": ["aws.ec2"],
                    "detail-type": ["AWS API Call via CloudTrail"],
                    "detail": {"eventName": ["CreateSnapshot", "CreateSnapshots"]},
                },
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect EBS snapshot creation

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

  # Step 2: EventBridge for snapshot creation
  SnapshotRule:
    Type: AWS::Events::Rule
    Properties:
      EventPattern:
        source: [aws.ec2]
        detail-type: [AWS API Call via CloudTrail]
        detail:
          eventName: [CreateSnapshot, CreateSnapshots]
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
                terraform_template="""# Detect EBS snapshot creation

variable "alert_email" {
  type = string
}

# Step 1: SNS topic
resource "aws_sns_topic" "alerts" {
  name = "snapshot-creation-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: EventBridge rule
resource "aws_cloudwatch_event_rule" "snapshot_create" {
  name = "ebs-snapshot-creation"
  event_pattern = jsonencode({
    source      = ["aws.ec2"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = ["CreateSnapshot", "CreateSnapshots"]
    }
  })
}

resource "aws_cloudwatch_event_target" "sns" {
  rule = aws_cloudwatch_event_rule.snapshot_create.name
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
                alert_title="EBS Snapshot Created",
                alert_description_template="EBS snapshot created for volume {volumeId}.",
                investigation_steps=[
                    "Verify snapshot creation was authorised",
                    "Check who created the snapshot",
                    "Review if snapshot is shared externally",
                    "Check for data sensitivity of the volume",
                ],
                containment_actions=[
                    "Delete unauthorised snapshots",
                    "Remove external sharing permissions",
                    "Review snapshot creation permissions",
                    "Enable AWS Backup with restrictions",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist backup automation and DR processes",
            detection_coverage="95% - catches all snapshot creation",
            evasion_considerations="Cannot evade this detection",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$2-5",
            prerequisites=["CloudTrail enabled"],
        ),
        # Strategy 2: AWS - RDS Snapshot Creation
        DetectionStrategy(
            strategy_id="t1578001-aws-rds",
            name="RDS Snapshot Creation Detection",
            description="Detect when RDS snapshots are created.",
            detection_type=DetectionType.EVENTBRIDGE_RULE,
            aws_service="eventbridge",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                event_pattern={
                    "source": ["aws.rds"],
                    "detail-type": ["AWS API Call via CloudTrail"],
                    "detail": {
                        "eventName": ["CreateDBSnapshot", "CreateDBClusterSnapshot"]
                    },
                },
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect RDS snapshot creation

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

  # Step 2: EventBridge for RDS snapshots
  RDSSnapshotRule:
    Type: AWS::Events::Rule
    Properties:
      EventPattern:
        source: [aws.rds]
        detail-type: [AWS API Call via CloudTrail]
        detail:
          eventName: [CreateDBSnapshot, CreateDBClusterSnapshot]
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
                terraform_template="""# Detect RDS snapshot creation

variable "alert_email" {
  type = string
}

# Step 1: SNS topic
resource "aws_sns_topic" "alerts" {
  name = "rds-snapshot-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: EventBridge rule
resource "aws_cloudwatch_event_rule" "rds_snapshot" {
  name = "rds-snapshot-creation"
  event_pattern = jsonencode({
    source      = ["aws.rds"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = ["CreateDBSnapshot", "CreateDBClusterSnapshot"]
    }
  })
}

resource "aws_cloudwatch_event_target" "sns" {
  rule = aws_cloudwatch_event_rule.rds_snapshot.name
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
                alert_title="RDS Snapshot Created",
                alert_description_template="RDS snapshot created for database {dBInstanceIdentifier}.",
                investigation_steps=[
                    "Verify snapshot was authorised",
                    "Check who created the snapshot",
                    "Review if shared externally",
                    "Check database data sensitivity",
                ],
                containment_actions=[
                    "Delete unauthorised snapshots",
                    "Remove external sharing",
                    "Review RDS permissions",
                    "Enable RDS encryption",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist backup and DR automation",
            detection_coverage="95% - catches all RDS snapshot creation",
            evasion_considerations="Cannot evade",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$2-5",
            prerequisites=["CloudTrail enabled"],
        ),
        # Strategy 3: GCP - Disk Snapshot Creation
        DetectionStrategy(
            strategy_id="t1578001-gcp-snapshot",
            name="GCP Disk Snapshot Creation",
            description="Detect when GCE disk snapshots are created.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''protoPayload.methodName="compute.disks.createSnapshot"
OR protoPayload.methodName="compute.snapshots.insert"''',
                gcp_terraform_template="""# GCP: Detect disk snapshot creation

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
resource "google_logging_metric" "snapshot_create" {
  name   = "disk-snapshot-creation"
  filter = <<-EOT
    protoPayload.methodName=~"(compute.disks.createSnapshot|compute.snapshots.insert)"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Alert policy
resource "google_monitoring_alert_policy" "snapshot_create" {
  display_name = "Disk Snapshot Created"
  combiner     = "OR"

  conditions {
    display_name = "Snapshot creation"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.snapshot_create.name}\""
      duration        = "0s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]
}""",
                alert_severity="high",
                alert_title="GCP: Disk Snapshot Created",
                alert_description_template="GCE disk snapshot was created.",
                investigation_steps=[
                    "Verify snapshot was authorised",
                    "Check who created the snapshot",
                    "Review if shared externally",
                    "Check disk data sensitivity",
                ],
                containment_actions=[
                    "Delete unauthorised snapshots",
                    "Remove external IAM bindings",
                    "Review snapshot permissions",
                    "Enable organisation policies",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist backup automation",
            detection_coverage="95% - catches all snapshot creation",
            evasion_considerations="Cannot evade",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=["Cloud Audit Logs enabled"],
        ),
    ],
    recommended_order=["t1578001-aws-ebs", "t1578001-aws-rds", "t1578001-gcp-snapshot"],
    total_effort_hours=2.0,
    coverage_improvement="+18% improvement for Exfiltration tactic",
)
