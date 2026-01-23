"""
T1578 - Modify Cloud Compute Infrastructure

Adversaries modify cloud compute infrastructure to evade defences.
86% of cloud incidents in 2024 involved business disruption.
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
    technique_id="T1578",
    technique_name="Modify Cloud Compute Infrastructure",
    tactic_ids=["TA0005"],
    mitre_url="https://attack.mitre.org/techniques/T1578/",
    threat_context=ThreatContext(
        description=(
            "Adversaries may alter cloud compute service infrastructure to circumvent "
            "security controls. This involves creating, deleting, or modifying components "
            "like compute instances, virtual machines, and snapshots. Such modifications "
            "bypass restrictions that prevent access to existing infrastructure and facilitate "
            "detection evasion and evidence removal."
        ),
        attacker_goal="Modify cloud infrastructure to evade defences and maintain persistence",
        why_technique=[
            "Creates new instances to bypass security controls",
            "Deletes instances to remove evidence of compromise",
            "Modifies configurations to disable logging",
            "Reverts instances to vulnerable states",
            "Creates snapshots for data exfiltration",
            "86% of cloud incidents involved business disruption",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="common",
        trend="increasing",
        severity_score=8,
        severity_reasoning=(
            "Critical defence evasion technique with 86% of cloud incidents causing "
            "business disruption in 2024. Enables attackers to bypass security controls, "
            "remove evidence, and maintain persistent access. Often missed by traditional monitoring."
        ),
        business_impact=[
            "Operational downtime from infrastructure changes",
            "Evidence destruction hampering forensics",
            "Bypassed security controls",
            "Compliance violations for unauthorised changes",
            "Data exfiltration via snapshot creation",
            "Reputational damage from security breaches",
        ],
        typical_attack_phase="defence-evasion",
        often_precedes=["T1537", "T1530"],
        often_follows=["T1078.004", "T1098.003"],
    ),
    detection_strategies=[
        # Strategy 1: AWS - EC2 Instance Lifecycle Changes
        DetectionStrategy(
            strategy_id="t1578-aws-ec2-lifecycle",
            name="EC2 Instance Lifecycle Detection",
            description="Detect when EC2 instances are created, modified, or terminated.",
            detection_type=DetectionType.EVENTBRIDGE_RULE,
            aws_service="eventbridge",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                event_pattern={
                    "source": ["aws.ec2"],
                    "detail-type": ["AWS API Call via CloudTrail"],
                    "detail": {
                        "eventName": [
                            "RunInstances",
                            "TerminateInstances",
                            "StopInstances",
                            "ModifyInstanceAttribute",
                            "ModifyInstanceMetadataOptions",
                        ]
                    },
                },
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect EC2 instance lifecycle changes

Parameters:
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

  # Step 2: EventBridge for instance changes
  EC2LifecycleRule:
    Type: AWS::Events::Rule
    Properties:
      EventPattern:
        source: [aws.ec2]
        detail-type: [AWS API Call via CloudTrail]
        detail:
          eventName:
            - RunInstances
            - TerminateInstances
            - StopInstances
            - ModifyInstanceAttribute
            - ModifyInstanceMetadataOptions
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
            Resource: !Ref AlertTopic
            Condition:
              StringEquals:
                AWS:SourceAccount: !Ref AWS::AccountId
              ArnEquals:
                aws:SourceArn: !GetAtt EC2LifecycleRule.Arn""",
                terraform_template="""# Detect EC2 instance lifecycle changes

variable "alert_email" {
  type = string
}

# Step 1: SNS topic
resource "aws_sns_topic" "alerts" {
  name = "ec2-lifecycle-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: EventBridge rule
resource "aws_cloudwatch_event_rule" "ec2_lifecycle" {
  name = "ec2-lifecycle-changes"
  event_pattern = jsonencode({
    source      = ["aws.ec2"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = [
        "RunInstances",
        "TerminateInstances",
        "StopInstances",
        "ModifyInstanceAttribute",
        "ModifyInstanceMetadataOptions"
      ]
    }
  })
}

# Step 3: EventBridge target
resource "aws_sqs_queue" "ec2_lifecycle_dlq" {
  name                      = "ec2-lifecycle-dlq"
  message_retention_seconds = 1209600
}

resource "aws_cloudwatch_event_target" "sns" {
  rule      = aws_cloudwatch_event_rule.ec2_lifecycle.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.alerts.arn

  retry_policy {
    maximum_event_age_in_seconds = 3600
    maximum_retry_attempts       = 8
  }

  dead_letter_config {
    arn = aws_sqs_queue.ec2_lifecycle_dlq.arn
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

resource "aws_sqs_queue_policy" "ec2_lifecycle_dlq_policy" {
  queue_url = aws_sqs_queue.ec2_lifecycle_dlq.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sqs:SendMessage"
      Resource  = aws_sqs_queue.ec2_lifecycle_dlq.arn
      Condition = {
        ArnEquals = {
          "aws:SourceArn" = aws_cloudwatch_event_rule.ec2_lifecycle.arn
        }
      }
    }]
  })
}

data "aws_caller_identity" "current" {}

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
              aws_cloudwatch_event_rule.ec2_lifecycle.arn,
              aws_cloudwatch_event_rule.volume_snapshot.arn,
              aws_cloudwatch_event_rule.defence_evasion.arn,
            ]
          }
      }
    }]
  })
}""",
                alert_severity="high",
                alert_title="EC2 Instance Lifecycle Change Detected",
                alert_description_template="EC2 instance {instanceId} action: {eventName} by {userArn}.",
                investigation_steps=[
                    "Verify the change was authorised",
                    "Check who initiated the action",
                    "Review instance configuration changes",
                    "Check for unusual instance types or AMIs",
                    "Look for patterns of rapid create/delete cycles",
                ],
                containment_actions=[
                    "Terminate unauthorised instances",
                    "Restore deleted instances from snapshots if needed",
                    "Review EC2 launch permissions",
                    "Enable AWS Config for configuration tracking",
                    "Implement SCPs to restrict instance actions",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist auto-scaling groups and deployment automation",
            detection_coverage="90% - catches instance lifecycle events",
            evasion_considerations="Very slow changes spread over time",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$2-5",
            prerequisites=["CloudTrail enabled"],
        ),
        # Strategy 2: AWS - Volume and Snapshot Manipulation
        DetectionStrategy(
            strategy_id="t1578-aws-volume-snapshot",
            name="Volume and Snapshot Manipulation Detection",
            description="Detect when EBS volumes and snapshots are created, modified, or deleted.",
            detection_type=DetectionType.EVENTBRIDGE_RULE,
            aws_service="eventbridge",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                event_pattern={
                    "source": ["aws.ec2"],
                    "detail-type": ["AWS API Call via CloudTrail"],
                    "detail": {
                        "eventName": [
                            "CreateVolume",
                            "DeleteVolume",
                            "ModifyVolume",
                            "DeleteSnapshot",
                            "ModifySnapshotAttribute",
                        ]
                    },
                },
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect volume and snapshot manipulation

Parameters:
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

  # Step 2: EventBridge for volume/snapshot changes
  VolumeSnapshotRule:
    Type: AWS::Events::Rule
    Properties:
      EventPattern:
        source: [aws.ec2]
        detail-type: [AWS API Call via CloudTrail]
        detail:
          eventName:
            - CreateVolume
            - DeleteVolume
            - ModifyVolume
            - DeleteSnapshot
            - ModifySnapshotAttribute
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
            Resource: !Ref AlertTopic
            Condition:
              StringEquals:
                AWS:SourceAccount: !Ref AWS::AccountId
              ArnEquals:
                aws:SourceArn: !GetAtt VolumeSnapshotRule.Arn""",
                terraform_template="""# Detect volume and snapshot manipulation

variable "alert_email" {
  type = string
}

# Step 1: SNS topic
resource "aws_sns_topic" "alerts" {
  name = "volume-snapshot-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: EventBridge rule
resource "aws_cloudwatch_event_rule" "volume_snapshot" {
  name = "volume-snapshot-changes"
  event_pattern = jsonencode({
    source      = ["aws.ec2"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = [
        "CreateVolume",
        "DeleteVolume",
        "ModifyVolume",
        "DeleteSnapshot",
        "ModifySnapshotAttribute"
      ]
    }
  })
}

# Step 3: EventBridge target
resource "aws_sqs_queue" "volume_snapshot_dlq" {
  name                      = "volume-snapshot-dlq"
  message_retention_seconds = 1209600
}

resource "aws_cloudwatch_event_target" "sns" {
  rule      = aws_cloudwatch_event_rule.volume_snapshot.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.alerts.arn

  retry_policy {
    maximum_event_age_in_seconds = 3600
    maximum_retry_attempts       = 8
  }

  dead_letter_config {
    arn = aws_sqs_queue.volume_snapshot_dlq.arn
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

resource "aws_sqs_queue_policy" "volume_snapshot_dlq_policy" {
  queue_url = aws_sqs_queue.volume_snapshot_dlq.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sqs:SendMessage"
      Resource  = aws_sqs_queue.volume_snapshot_dlq.arn
      Condition = {
        ArnEquals = {
          "aws:SourceArn" = aws_cloudwatch_event_rule.volume_snapshot.arn
        }
      }
    }]
  })
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
              aws_cloudwatch_event_rule.ec2_lifecycle.arn,
              aws_cloudwatch_event_rule.volume_snapshot.arn,
              aws_cloudwatch_event_rule.defence_evasion.arn,
            ]
          }
      }
    }]
  })
}""",
                alert_severity="high",
                alert_title="Volume/Snapshot Manipulation Detected",
                alert_description_template="Volume/snapshot {resourceId} action: {eventName} by {userArn}.",
                investigation_steps=[
                    "Verify the action was authorised",
                    "Check who performed the operation",
                    "Review if snapshots were shared externally",
                    "Check for evidence destruction (deletions)",
                    "Look for data exfiltration patterns",
                ],
                containment_actions=[
                    "Block unauthorised volume/snapshot operations",
                    "Remove external sharing permissions",
                    "Enable snapshot deletion protection",
                    "Review EBS encryption settings",
                    "Implement resource tagging for tracking",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist backup automation and storage management",
            detection_coverage="90% - catches volume and snapshot operations",
            evasion_considerations="Cannot easily evade this detection",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$2-5",
            prerequisites=["CloudTrail enabled"],
        ),
        # Strategy 3: AWS - GuardDuty Defence Evasion
        DetectionStrategy(
            strategy_id="t1578-aws-guardduty",
            name="GuardDuty Defence Evasion Detection",
            description="AWS GuardDuty detects anomalous compute infrastructure changes.",
            detection_type=DetectionType.GUARDDUTY,
            aws_service="guardduty",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                guardduty_finding_types=[
                    "DefenseEvasion:EC2/UnusualDNSResolver",
                    "DefenseEvasion:EC2/UnusualDoHActivity",
                    "Behavior:EC2/NetworkPortUnusual",
                    "Impact:EC2/WinRMBruteForce",
                ],
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: GuardDuty defence evasion detection

Parameters:
  AlertEmail:
    Type: String

Resources:
  # Step 1: Enable GuardDuty
  GuardDutyDetector:
    Type: AWS::GuardDuty::Detector
    Properties:
      Enable: true

  # Step 2: Create SNS topic
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 3: Route defence evasion findings
  DefenceEvasionRule:
    Type: AWS::Events::Rule
    Properties:
      EventPattern:
        source: [aws.guardduty]
        detail-type:
          - GuardDuty Finding
        detail:
          type:
            - prefix: "DefenseEvasion:EC2"
            - prefix: "Stealth:EC2"
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
                aws:SourceArn: !GetAtt DefenceEvasionRule.Arn""",
                terraform_template="""# GuardDuty defence evasion detection

variable "alert_email" {
  type = string
}

# Step 1: Enable GuardDuty
resource "aws_guardduty_detector" "main" {
  enable = true
}

# Step 2: Create SNS topic
resource "aws_sns_topic" "alerts" {
  name = "guardduty-defence-evasion-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 3: Route defence evasion findings
resource "aws_cloudwatch_event_rule" "defence_evasion" {
  name = "guardduty-defence-evasion"
  event_pattern = jsonencode({
    source = ["aws.guardduty"]
    "detail-type" = ["GuardDuty Finding"]
    detail = {
      type = [
        { prefix = "DefenseEvasion:EC2" },
        { prefix = "Stealth:EC2" }
      ]
    }
  })
}

resource "aws_sqs_queue" "defence_evasion_dlq" {
  name                      = "defence-evasion-dlq"
  message_retention_seconds = 1209600
}

resource "aws_cloudwatch_event_target" "sns" {
  rule      = aws_cloudwatch_event_rule.defence_evasion.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.alerts.arn

  retry_policy {
    maximum_event_age_in_seconds = 3600
    maximum_retry_attempts       = 8
  }

  dead_letter_config {
    arn = aws_sqs_queue.defence_evasion_dlq.arn
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

resource "aws_sqs_queue_policy" "defence_evasion_dlq_policy" {
  queue_url = aws_sqs_queue.defence_evasion_dlq.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sqs:SendMessage"
      Resource  = aws_sqs_queue.defence_evasion_dlq.arn
      Condition = {
        ArnEquals = {
          "aws:SourceArn" = aws_cloudwatch_event_rule.defence_evasion.arn
        }
      }
    }]
  })
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
              aws_cloudwatch_event_rule.ec2_lifecycle.arn,
              aws_cloudwatch_event_rule.volume_snapshot.arn,
              aws_cloudwatch_event_rule.defence_evasion.arn,
            ]
          }
      }
    }]
  })
}""",
                alert_severity="high",
                alert_title="GuardDuty: Defence Evasion Detected",
                alert_description_template="GuardDuty detected {findingType} on {instanceId}.",
                investigation_steps=[
                    "Review the specific GuardDuty finding details",
                    "Check instance security group changes",
                    "Review network configuration modifications",
                    "Verify instance metadata service access",
                    "Check for evidence destruction attempts",
                ],
                containment_actions=[
                    "Isolate the affected instance",
                    "Revert unauthorised configuration changes",
                    "Enable instance termination protection",
                    "Review and restrict EC2 permissions",
                    "Enable VPC Flow Logs for network monitoring",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Whitelist known maintenance windows",
            detection_coverage="70% - covers anomalous behaviour patterns",
            evasion_considerations="Very slow, gradual changes may evade ML detection",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$4 per million events",
            prerequisites=["AWS account with GuardDuty permissions"],
        ),
        # Strategy 4: GCP - Compute Instance Modification
        DetectionStrategy(
            strategy_id="t1578-gcp-compute",
            name="GCP Compute Instance Modification Detection",
            description="Detect when GCE instances are created, modified, or deleted.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''protoPayload.methodName=~"(compute.instances.insert|compute.instances.delete|compute.instances.stop|compute.instances.setMetadata|compute.instances.setMachineType)"''',
                gcp_terraform_template="""# GCP: Detect compute instance modifications

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

# Step 2: Log-based metric
resource "google_logging_metric" "instance_modification" {
  project = var.project_id
  name   = "compute-instance-modifications"
  filter = <<-EOT
    protoPayload.methodName=~"(compute.instances.insert|compute.instances.delete|compute.instances.stop|compute.instances.setMetadata|compute.instances.setMachineType)"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Alert policy
resource "google_monitoring_alert_policy" "instance_modification" {
  project      = var.project_id
  display_name = "Compute Instance Modification"
  combiner     = "OR"

  conditions {
    display_name = "Instance modification detected"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.instance_modification.name}\""
      duration        = "0s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0
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
                alert_severity="high",
                alert_title="GCP: Compute Instance Modified",
                alert_description_template="GCE instance modified: {methodName}.",
                investigation_steps=[
                    "Verify the change was authorised",
                    "Check who performed the modification",
                    "Review instance metadata changes",
                    "Check for unusual machine types",
                    "Look for evidence destruction patterns",
                ],
                containment_actions=[
                    "Delete unauthorised instances",
                    "Revert configuration changes",
                    "Review IAM permissions for Compute Engine",
                    "Enable organisation policies for restrictions",
                    "Implement resource labels for tracking",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist auto-scaling and deployment automation",
            detection_coverage="90% - catches compute instance changes",
            evasion_considerations="Cannot easily evade",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=["Cloud Audit Logs enabled"],
        ),
        # Strategy 5: Pattern Analysis - Suspicious Sequences
        DetectionStrategy(
            strategy_id="t1578-pattern-analysis",
            name="Suspicious Infrastructure Change Patterns",
            description="Detect suspicious sequences of infrastructure changes.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, userIdentity.arn as user, eventName,
       requestParameters.instancesSet.items.0.instanceId as instanceId,
       sourceIPAddress
| filter eventSource = "ec2.amazonaws.com"
| filter eventName in ["RunInstances", "TerminateInstances", "CreateSnapshot",
    "DeleteSnapshot", "ModifyInstanceAttribute", "StopInstances"]
| stats count(*) as action_count, count_distinct(eventName) as unique_actions
  by user, sourceIPAddress, bin(1h) as hour_window
| filter action_count >= 10 or unique_actions >= 4
| sort action_count desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Suspicious infrastructure change pattern detection

Parameters:
  CloudTrailLogGroup:
    Type: String
  SNSTopicArn:
    Type: String

Resources:
  # Step 1: Metric filter for rapid changes
  InfraChangeMetricFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ $.eventSource = "ec2.amazonaws.com" && ($.eventName = "RunInstances" || $.eventName = "TerminateInstances" || $.eventName = "CreateSnapshot" || $.eventName = "DeleteSnapshot") }'
      MetricTransformations:
        - MetricName: InfrastructureChanges
          MetricNamespace: Security/T1578
          MetricValue: "1"

  # Step 2: Alarm for excessive changes
  InfraChangeAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: T1578-ExcessiveInfraChanges
      AlarmDescription: Suspicious infrastructure change pattern
      MetricName: InfrastructureChanges
      Namespace: Security/T1578
      Statistic: Sum
      Period: 300
      EvaluationPeriods: 1
      Threshold: 10
      ComparisonOperator: GreaterThanOrEqualToThreshold
      TreatMissingData: notBreaching

      AlarmActions:
        - !Ref SNSTopicArn

  # Step 3: Metric filter for snapshot deletion
  SnapshotDeletionFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ $.eventName = "DeleteSnapshot" }'
      MetricTransformations:
        - MetricName: SnapshotDeletions
          MetricNamespace: Security/T1578
          MetricValue: "1"

  SnapshotDeletionAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: T1578-SnapshotDeletion
      AlarmDescription: Snapshot deletion detected (possible evidence removal)
      MetricName: SnapshotDeletions
      Namespace: Security/T1578
      Statistic: Sum
      Period: 300
      EvaluationPeriods: 1
      Threshold: 1
      ComparisonOperator: GreaterThanOrEqualToThreshold
      TreatMissingData: notBreaching

      AlarmActions:
        - !Ref SNSTopicArn""",
                terraform_template="""# Suspicious infrastructure change pattern detection

variable "cloudtrail_log_group" {
  type = string
}

variable "sns_topic_arn" {
  type = string
}

# Step 1: Metric filter for rapid changes
resource "aws_cloudwatch_log_metric_filter" "infra_changes" {
  name           = "infrastructure-changes"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ $.eventSource = \"ec2.amazonaws.com\" && ($.eventName = \"RunInstances\" || $.eventName = \"TerminateInstances\" || $.eventName = \"CreateSnapshot\" || $.eventName = \"DeleteSnapshot\") }"

  metric_transformation {
    name      = "InfrastructureChanges"
    namespace = "Security/T1578"
    value     = "1"
  }
}

# Step 2: Alarm for excessive changes
resource "aws_cloudwatch_metric_alarm" "infra_changes" {
  alarm_name          = "T1578-ExcessiveInfraChanges"
  alarm_description   = "Suspicious infrastructure change pattern"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "InfrastructureChanges"
  namespace           = "Security/T1578"
  period              = 300
  statistic           = "Sum"
  threshold           = 10
  treat_missing_data  = "notBreaching"

  alarm_actions       = [var.sns_topic_arn]
}

# Step 3: Metric filter for snapshot deletion
resource "aws_cloudwatch_log_metric_filter" "snapshot_deletion" {
  name           = "snapshot-deletions"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ $.eventName = \"DeleteSnapshot\" }"

  metric_transformation {
    name      = "SnapshotDeletions"
    namespace = "Security/T1578"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "snapshot_deletion" {
  alarm_name          = "T1578-SnapshotDeletion"
  alarm_description   = "Snapshot deletion detected (possible evidence removal)"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "SnapshotDeletions"
  namespace           = "Security/T1578"
  period              = 300
  statistic           = "Sum"
  threshold           = 1
  treat_missing_data  = "notBreaching"

  alarm_actions       = [var.sns_topic_arn]
}""",
                alert_severity="high",
                alert_title="Suspicious Infrastructure Change Pattern",
                alert_description_template=(
                    "User {user} made {action_count} infrastructure changes ({unique_actions} unique actions) "
                    "in 1 hour from {sourceIPAddress}. This may indicate defence evasion."
                ),
                investigation_steps=[
                    "List all infrastructure changes in the time window",
                    "Check for create/delete cycles (evidence destruction)",
                    "Review snapshot operations for data exfiltration",
                    "Verify the source IP and user identity",
                    "Look for patterns indicating automated attacks",
                    "Check if changes correlate with other alerts",
                ],
                containment_actions=[
                    "Temporarily restrict the user's EC2 permissions",
                    "Enable termination protection on critical instances",
                    "Review and revert unauthorised changes",
                    "Enable AWS Config for change tracking",
                    "Implement SCPs for infrastructure restrictions",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Baseline normal change patterns; exclude deployment windows",
            detection_coverage="80% - catches suspicious change patterns",
            evasion_considerations="Very slow, distributed changes over time",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2 hours",
            estimated_monthly_cost="$10-20",
            prerequisites=["CloudTrail enabled", "CloudTrail logs in CloudWatch"],
        ),
        # Azure Strategy: Modify Cloud Compute Infrastructure
        DetectionStrategy(
            strategy_id="t1578-azure",
            name="Azure Modify Cloud Compute Infrastructure Detection",
            description=(
                "Azure detection for Modify Cloud Compute Infrastructure. "
                "Provides native Azure detection using Log Analytics and Defender for Cloud."
            ),
            detection_type=DetectionType.SENTINEL_RULE,
            aws_service="n/a",
            azure_service="sentinel",
            cloud_provider=CloudProvider.AZURE,
            implementation=DetectionImplementation(
                sentinel_rule_query="""// Sentinel Analytics Rule: Modify Cloud Compute Infrastructure
// MITRE ATT&CK: T1578
let lookback = 24h;
let threshold = 5;
AzureActivity
| where TimeGenerated > ago(lookback)
| where CategoryValue == "Administrative"
| where ActivityStatusValue in ("Success", "Succeeded")
| summarize
    EventCount = count(),
    DistinctOperations = dcount(OperationNameValue),
    Operations = make_set(OperationNameValue, 20),
    Resources = make_set(Resource, 10),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by Caller, CallerIpAddress, SubscriptionId
| where EventCount > threshold
| extend
    AccountName = tostring(split(Caller, "@")[0]),
    AccountDomain = tostring(split(Caller, "@")[1])
| project
    TimeGenerated = LastSeen,
    AccountName,
    AccountDomain,
    Caller,
    CallerIpAddress,
    SubscriptionId,
    EventCount,
    DistinctOperations,
    Operations,
    Resources""",
                azure_terraform_template="""# Azure Detection for Modify Cloud Compute Infrastructure
# MITRE ATT&CK: T1578

terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = ">= 3.0"
    }
  }
}

variable "resource_group_name" {
  type        = string
  description = "Resource group for Log Analytics workspace"
}

variable "log_analytics_workspace_id" {
  type        = string
  description = "Log Analytics workspace resource ID"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

# Action Group for alerts
resource "azurerm_monitor_action_group" "security_alerts" {
  name                = "modify-cloud-compute-infrastructure-alerts"
  resource_group_name = var.resource_group_name
  short_name          = "SecAlerts"

  email_receiver {
    name          = "security-team"
    email_address = var.alert_email
  }
}

# Scheduled Query Rule for detection
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "detection" {
  name                = "modify-cloud-compute-infrastructure-detection"
  resource_group_name = var.resource_group_name
  location            = "uksouth"

  evaluation_frequency = "PT5M"
  window_duration      = "PT1H"
  scopes               = [var.log_analytics_workspace_id]
  severity             = 2

  criteria {
    query = <<-QUERY
// Sentinel Analytics Rule: Modify Cloud Compute Infrastructure
// MITRE ATT&CK: T1578
let lookback = 24h;
let threshold = 5;
AzureActivity
| where TimeGenerated > ago(lookback)
| where CategoryValue == "Administrative"
| where ActivityStatusValue in ("Success", "Succeeded")
| summarize
    EventCount = count(),
    DistinctOperations = dcount(OperationNameValue),
    Operations = make_set(OperationNameValue, 20),
    Resources = make_set(Resource, 10),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by Caller, CallerIpAddress, SubscriptionId
| where EventCount > threshold
| extend
    AccountName = tostring(split(Caller, "@")[0]),
    AccountDomain = tostring(split(Caller, "@")[1])
| project
    TimeGenerated = LastSeen,
    AccountName,
    AccountDomain,
    Caller,
    CallerIpAddress,
    SubscriptionId,
    EventCount,
    DistinctOperations,
    Operations,
    Resources
    QUERY

    time_aggregation_method = "Count"
    threshold               = 1
    operator                = "GreaterThanOrEqual"

    failing_periods {
      minimum_failing_periods_to_trigger_alert = 1
      number_of_evaluation_periods             = 1
    }
  }

  auto_mitigation_enabled = false

  action {
    action_groups = [azurerm_monitor_action_group.security_alerts.id]
  }

  description = "Detects Modify Cloud Compute Infrastructure (T1578) activity in Azure environment"
  display_name = "Modify Cloud Compute Infrastructure Detection"
  enabled      = true

  tags = {
    "mitre-technique" = "T1578"
    "detection-type"  = "security"
  }
}

output "alert_rule_id" {
  value = azurerm_monitor_scheduled_query_rules_alert_v2.detection.id
}""",
                alert_severity="high",
                alert_title="Azure: Modify Cloud Compute Infrastructure Detected",
                alert_description_template=(
                    "Modify Cloud Compute Infrastructure activity detected. "
                    "Caller: {Caller}. Resource: {Resource}."
                ),
                investigation_steps=[
                    "Review Azure Activity Log for full operation details",
                    "Check caller identity and verify if authorised",
                    "Review affected resources and assess impact",
                    "Check for related activities in the same time window",
                    "Verify against change management records",
                ],
                containment_actions=[
                    "Disable compromised user/service principal if unauthorised",
                    "Revoke active sessions using Entra ID",
                    "Review and restrict Azure RBAC permissions",
                    "Enable additional Defender for Cloud protections",
                    "Implement Azure Policy to prevent recurrence",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning=(
                "Allowlist known automation accounts and CI/CD service principals. "
                "Use Azure Policy to define expected behaviour baselines."
            ),
            detection_coverage="70% - Azure-native detection for cloud operations",
            evasion_considerations=(
                "Attackers may use legitimate credentials from expected locations. "
                "Combine with Defender for Cloud for ML-based anomaly detection."
            ),
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$10-50 (Log Analytics + Defender)",
            prerequisites=[
                "Azure subscription with Log Analytics workspace",
                "Defender for Cloud enabled (recommended)",
                "Appropriate Azure RBAC permissions for deployment",
            ],
        ),
    ],
    recommended_order=[
        "t1578-aws-guardduty",
        "t1578-aws-ec2-lifecycle",
        "t1578-aws-volume-snapshot",
        "t1578-gcp-compute",
        "t1578-pattern-analysis",
    ],
    total_effort_hours=5.0,
    coverage_improvement="+25% improvement for Defence Evasion tactic",
)
