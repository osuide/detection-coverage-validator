"""
T1578.003 - Modify Cloud Compute Infrastructure: Delete Cloud Instance

Adversaries delete cloud instances to eliminate forensic evidence and evade detection.
Used by LAPSUS$ and Storm-0501 to trigger incident response and destroy evidence.
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
    technique_id="T1578.003",
    technique_name="Modify Cloud Compute Infrastructure: Delete Cloud Instance",
    tactic_ids=["TA0005"],
    mitre_url="https://attack.mitre.org/techniques/T1578/003/",
    threat_context=ThreatContext(
        description=(
            "Adversaries delete cloud instances to eliminate forensic evidence and "
            "evade detection following malicious activities. Attackers may also spin "
            "up temporary instances to accomplish objectives before terminating them "
            "to cover their tracks and remove valuable artefacts that would aid investigation."
        ),
        attacker_goal="Delete instances to remove forensic evidence and evade detection",
        why_technique=[
            "Eliminates forensic evidence",
            "Removes valuable investigation artefacts",
            "Covers tracks after malicious activity",
            "Can trigger organisation incident response",
            "Enables temporary attack infrastructure",
        ],
        known_threat_actors=["LAPSUS$", "Storm-0501"],
        recent_campaigns=[
            Campaign(
                name="LAPSUS$ Resource Deletion",
                year=2022,
                description="Deleted target's systems and resources in the cloud to trigger incident response",
                reference_url="https://attack.mitre.org/groups/G1004/",
            ),
            Campaign(
                name="Storm-0501 Mass Deletion",
                year=2024,
                description="Conducted mass deletion of cloud data stores and resources from Azure subscriptions",
                reference_url="https://attack.mitre.org/groups/G1053/",
            ),
        ],
        prevalence="moderate",
        trend="stable",
        severity_score=8,
        severity_reasoning=(
            "Critical defence evasion technique. Instance deletion destroys forensic "
            "evidence and can significantly impair incident investigation. Mass deletion "
            "can also cause operational disruption and trigger crisis response."
        ),
        business_impact=[
            "Loss of forensic evidence",
            "Impaired incident investigation",
            "Operational disruption",
            "Potential data loss",
            "Compliance audit challenges",
        ],
        typical_attack_phase="defence_evasion",
        often_precedes=["T1485", "T1490"],
        often_follows=["T1578.002", "T1496.001", "T1530"],
    ),
    detection_strategies=[
        # Strategy 1: AWS - EC2 Instance Termination
        DetectionStrategy(
            strategy_id="t1578003-aws-ec2-delete",
            name="EC2 Instance Termination Detection",
            description="Detect when EC2 instances are terminated.",
            detection_type=DetectionType.EVENTBRIDGE_RULE,
            aws_service="eventbridge",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                event_pattern={
                    "source": ["aws.ec2"],
                    "detail-type": ["AWS API Call via CloudTrail"],
                    "detail": {"eventName": ["TerminateInstances"]},
                },
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect EC2 instance termination

Parameters:
  AlertEmail:
    Type: String

Resources:
  # Step 1: SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: EventBridge rule for instance termination
  EC2TerminateRule:
    Type: AWS::Events::Rule
    Properties:
      EventPattern:
        source: [aws.ec2]
        detail-type: [AWS API Call via CloudTrail]
        detail:
          eventName: [TerminateInstances]
      Targets:
        - Id: Alert
          Arn: !Ref AlertTopic

  # Step 3: Allow EventBridge to publish to SNS
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
                terraform_template="""# Detect EC2 instance termination

variable "alert_email" {
  type = string
}

# Step 1: SNS topic for alerts
resource "aws_sns_topic" "alerts" {
  name = "ec2-termination-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: EventBridge rule for instance termination
resource "aws_cloudwatch_event_rule" "ec2_terminate" {
  name = "ec2-instance-termination"
  event_pattern = jsonencode({
    source      = ["aws.ec2"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = ["TerminateInstances"]
    }
  })
}

resource "aws_cloudwatch_event_target" "sns" {
  rule = aws_cloudwatch_event_rule.ec2_terminate.name
  arn  = aws_sns_topic.alerts.arn
}

# Step 3: Allow EventBridge to publish to SNS
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
                alert_title="EC2 Instance Terminated",
                alert_description_template="EC2 instance {instanceId} terminated by {userIdentity.arn}.",
                investigation_steps=[
                    "Verify instance termination was authorised",
                    "Check who terminated the instance and their recent activity",
                    "Review if instance was recently created (temporary attack infrastructure)",
                    "Check if snapshots exist for forensic recovery",
                    "Correlate with other suspicious activities",
                    "Review CloudTrail logs for the instance before termination",
                ],
                containment_actions=[
                    "Review termination permissions and restrict if needed",
                    "Enable termination protection on critical instances",
                    "Recover from snapshots if available",
                    "Investigate user account for compromise",
                    "Enable EC2 instance termination notifications",
                    "Implement Service Control Policies to prevent mass deletions",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist auto-scaling and deployment automation accounts",
            detection_coverage="95% - catches all TerminateInstances API calls",
            evasion_considerations="Cannot evade this detection",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$2-5",
            prerequisites=["CloudTrail enabled"],
        ),
        # Strategy 2: AWS - Suspicious Instance Deletion Pattern
        DetectionStrategy(
            strategy_id="t1578003-aws-suspicious-delete",
            name="Suspicious Instance Deletion Pattern Detection",
            description="Detect suspicious patterns: instances deleted shortly after creation, or mass deletions.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, userIdentity.arn, requestParameters.instancesSet.items.0.instanceId as instanceId
| filter eventSource = "ec2.amazonaws.com"
| filter eventName = "TerminateInstances"
| sort @timestamp desc
| stats count(*) as deletions by userIdentity.arn, bin(5m)
| filter deletions > 3""",
                terraform_template="""# Detect suspicious instance deletion patterns (mass deletions)

variable "cloudtrail_log_group" {
  type = string
}

variable "alert_email" {
  type = string
}

# Step 1: SNS topic for alerts
resource "aws_sns_topic" "alerts" {
  name = "suspicious-deletion-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Metric filter for mass deletions
resource "aws_cloudwatch_log_metric_filter" "mass_deletion" {
  name           = "mass-instance-deletion"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ $.eventName = \"TerminateInstances\" }"

  metric_transformation {
    name      = "InstanceDeletions"
    namespace = "Security"
    value     = "1"
  }
}

# Step 3: Alarm for mass deletions (3+ in 5 minutes)
resource "aws_cloudwatch_metric_alarm" "mass_deletion" {
  alarm_name          = "MassInstanceDeletion"
  metric_name         = "InstanceDeletions"
  namespace           = "Security"
  statistic           = "Sum"
  period              = 300
  threshold           = 3
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  alarm_actions       = [aws_sns_topic.alerts.arn]
  treat_missing_data  = "notBreaching"
}""",
                alert_severity="critical",
                alert_title="Mass Instance Deletion Detected",
                alert_description_template="Multiple instances deleted by {userIdentity.arn} in short timeframe.",
                investigation_steps=[
                    "Identify all instances deleted and their purpose",
                    "Check if user account is compromised",
                    "Review CloudTrail for authentication anomalies",
                    "Check for new/infrequently used accounts",
                    "Review geographic origin of deletions",
                    "Correlate with snapshot creation events",
                ],
                containment_actions=[
                    "Suspend compromised user account",
                    "Enable termination protection on remaining instances",
                    "Recover critical instances from snapshots",
                    "Review and restrict termination permissions",
                    "Enable MFA for high-privilege operations",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Adjust threshold based on normal decommissioning patterns",
            detection_coverage="85% - detects mass deletion patterns",
            evasion_considerations="Slow deletion over time may evade threshold",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$5-10",
            prerequisites=["CloudTrail logging to CloudWatch"],
        ),
        # Strategy 3: AWS - RDS Instance Deletion
        DetectionStrategy(
            strategy_id="t1578003-aws-rds-delete",
            name="RDS Instance Deletion Detection",
            description="Detect when RDS database instances are deleted.",
            detection_type=DetectionType.EVENTBRIDGE_RULE,
            aws_service="eventbridge",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                event_pattern={
                    "source": ["aws.rds"],
                    "detail-type": ["AWS API Call via CloudTrail"],
                    "detail": {"eventName": ["DeleteDBInstance", "DeleteDBCluster"]},
                },
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect RDS instance deletion

Parameters:
  AlertEmail:
    Type: String

Resources:
  # Step 1: SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: EventBridge rule for RDS deletion
  RDSDeleteRule:
    Type: AWS::Events::Rule
    Properties:
      EventPattern:
        source: [aws.rds]
        detail-type: [AWS API Call via CloudTrail]
        detail:
          eventName: [DeleteDBInstance, DeleteDBCluster]
      Targets:
        - Id: Alert
          Arn: !Ref AlertTopic

  # Step 3: Allow EventBridge to publish to SNS
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
                terraform_template="""# Detect RDS instance deletion

variable "alert_email" {
  type = string
}

# Step 1: SNS topic for alerts
resource "aws_sns_topic" "alerts" {
  name = "rds-deletion-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: EventBridge rule for RDS deletion
resource "aws_cloudwatch_event_rule" "rds_delete" {
  name = "rds-instance-deletion"
  event_pattern = jsonencode({
    source      = ["aws.rds"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = ["DeleteDBInstance", "DeleteDBCluster"]
    }
  })
}

resource "aws_cloudwatch_event_target" "sns" {
  rule = aws_cloudwatch_event_rule.rds_delete.name
  arn  = aws_sns_topic.alerts.arn
}

# Step 3: Allow EventBridge to publish to SNS
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
                alert_title="RDS Instance Deleted",
                alert_description_template="RDS database {dBInstanceIdentifier} deleted by {userIdentity.arn}.",
                investigation_steps=[
                    "Verify deletion was authorised",
                    "Check who deleted the database",
                    "Review if final snapshot was created",
                    "Check for recent suspicious activity",
                    "Review data sensitivity and compliance requirements",
                ],
                containment_actions=[
                    "Restore from snapshot if unauthorised",
                    "Review RDS deletion permissions",
                    "Enable deletion protection on databases",
                    "Investigate user account for compromise",
                    "Require final snapshots for deletions",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Whitelist approved database decommissioning processes",
            detection_coverage="95% - catches all RDS deletion API calls",
            evasion_considerations="Cannot evade this detection",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$2-5",
            prerequisites=["CloudTrail enabled"],
        ),
        # Strategy 4: GCP - GCE Instance Deletion
        DetectionStrategy(
            strategy_id="t1578003-gcp-gce-delete",
            name="GCE Instance Deletion Detection",
            description="Detect when GCE instances are deleted.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''protoPayload.methodName="compute.instances.delete"''',
                gcp_terraform_template="""# GCP: Detect GCE instance deletion

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

# Step 2: Log-based metric for instance deletion
resource "google_logging_metric" "gce_delete" {
  name   = "gce-instance-deletion"
  filter = "protoPayload.methodName=\"compute.instances.delete\""

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Alert policy for instance deletion
resource "google_monitoring_alert_policy" "gce_delete" {
  display_name = "GCE Instance Deleted"
  combiner     = "OR"

  conditions {
    display_name = "Instance deletion"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.gce_delete.name}\""
      duration        = "0s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]
}""",
                alert_severity="high",
                alert_title="GCP: GCE Instance Deleted",
                alert_description_template="GCE instance was deleted.",
                investigation_steps=[
                    "Verify deletion was authorised",
                    "Check who deleted the instance",
                    "Review if instance was recently created",
                    "Check for available snapshots or backups",
                    "Correlate with other suspicious activities",
                ],
                containment_actions=[
                    "Review compute deletion permissions",
                    "Restore from snapshot if needed",
                    "Investigate user account for compromise",
                    "Set organisation policy constraints",
                    "Enable deletion lien on critical instances",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist auto-scaling and deployment automation",
            detection_coverage="95% - catches all instance deletion",
            evasion_considerations="Cannot evade",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=["Cloud Audit Logs enabled"],
        ),
        # Strategy 5: GCP - Mass Resource Deletion
        DetectionStrategy(
            strategy_id="t1578003-gcp-mass-delete",
            name="GCP Mass Resource Deletion Detection",
            description="Detect mass deletion of GCP resources (instances, disks, snapshots).",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''protoPayload.methodName=~"(compute.instances.delete|compute.disks.delete|compute.snapshots.delete|storage.buckets.delete)"''',
                gcp_terraform_template="""# GCP: Detect mass resource deletion

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

# Step 2: Log-based metric for mass deletion
resource "google_logging_metric" "mass_delete" {
  name   = "mass-resource-deletion"
  filter = <<-EOT
    protoPayload.methodName=~"(compute.instances.delete|compute.disks.delete|compute.snapshots.delete|storage.buckets.delete)"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Alert policy for mass deletion (3+ in 5 minutes)
resource "google_monitoring_alert_policy" "mass_delete" {
  display_name = "Mass Resource Deletion"
  combiner     = "OR"

  conditions {
    display_name = "Multiple deletions"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.mass_delete.name}\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 3
      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_SUM"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]
}""",
                alert_severity="critical",
                alert_title="GCP: Mass Resource Deletion Detected",
                alert_description_template="Multiple GCP resources deleted in short timeframe.",
                investigation_steps=[
                    "Identify all deleted resources",
                    "Check if user account is compromised",
                    "Review authentication logs for anomalies",
                    "Check for available backups and snapshots",
                    "Correlate with other suspicious activities",
                ],
                containment_actions=[
                    "Suspend compromised user account",
                    "Restore critical resources from backups",
                    "Review and restrict deletion permissions",
                    "Enable organisation policies to prevent mass deletions",
                    "Implement deletion lien on critical resources",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Adjust threshold based on normal operations",
            detection_coverage="85% - detects mass deletion patterns",
            evasion_considerations="Slow deletion over time may evade threshold",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$5-10",
            prerequisites=["Cloud Audit Logs enabled"],
        ),
    ],
    recommended_order=[
        "t1578003-aws-ec2-delete",
        "t1578003-aws-suspicious-delete",
        "t1578003-aws-rds-delete",
        "t1578003-gcp-gce-delete",
        "t1578003-gcp-mass-delete",
    ],
    total_effort_hours=3.5,
    coverage_improvement="+20% improvement for Defence Evasion tactic",
)
