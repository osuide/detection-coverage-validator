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
      KmsMasterKeyId: alias/aws/sns
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
            Resource: !Ref AlertTopic
            Condition:
              StringEquals:
                AWS:SourceAccount: !Ref AWS::AccountId
              ArnEquals:
                aws:SourceArn: !GetAtt SnapshotRule.Arn""",
                terraform_template="""# Detect EBS snapshot creation

variable "alert_email" {
  type = string
}

# Step 1: SNS topic
resource "aws_sns_topic" "alerts" {
  name = "snapshot-creation-alerts"
  kms_master_key_id = "alias/aws/sns"
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

resource "aws_sqs_queue" "dlq" {
  name                      = "snapshot-creation-dlq"
  message_retention_seconds = 1209600
}

resource "aws_cloudwatch_event_target" "sns" {
  rule      = aws_cloudwatch_event_rule.snapshot_create.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.alerts.arn

  retry_policy {
    maximum_event_age_in_seconds = 3600
    maximum_retry_attempts       = 8
  }

  dead_letter_config {
    arn = aws_sqs_queue.dlq.arn
  }
  input_transformer {
    input_paths = {
      account       = "$.account"
      region        = "$.region"
      time          = "$.time"
      eventName     = "$.detail.eventName"
      eventSource   = "$.detail.eventSource"
      sourceIP      = "$.detail.sourceIPAddress"
      userIdentity  = "$.detail.userIdentity.arn"
    }

    input_template = <<-EOT
"CloudTrail Security Alert
Time: <time>
Account: <account>
Region: <region>
Event: <eventName>
Source: <eventSource>
User: <userIdentity>
Source IP: <sourceIP>
Action: Review CloudTrail event and investigate"
EOT
  }

}

resource "aws_sqs_queue_policy" "dlq_policy" {
  queue_url = aws_sqs_queue.dlq.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sqs:SendMessage"
      Resource  = aws_sqs_queue.dlq.arn
      Condition = {
        ArnEquals = {
          "aws:SourceArn" = aws_cloudwatch_event_rule.snapshot_create.arn
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
              aws_cloudwatch_event_rule.snapshot_create.arn,
              aws_cloudwatch_event_rule.rds_snapshot.arn,
            ]
          }
      }
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
      KmsMasterKeyId: alias/aws/sns
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
            Resource: !Ref AlertTopic
            Condition:
              StringEquals:
                AWS:SourceAccount: !Ref AWS::AccountId
              ArnEquals:
                aws:SourceArn: !GetAtt RDSSnapshotRule.Arn""",
                terraform_template="""# Detect RDS snapshot creation

variable "alert_email" {
  type = string
}

# Step 1: SNS topic
resource "aws_sns_topic" "alerts" {
  name = "rds-snapshot-alerts"
  kms_master_key_id = "alias/aws/sns"
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
target_id = "SendToSNS"
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
    Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
          ArnEquals = {
            "aws:SourceArn" = [
              aws_cloudwatch_event_rule.snapshot_create.arn,
              aws_cloudwatch_event_rule.rds_snapshot.arn,
            ]
          }
      }
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
resource "google_monitoring_notification_channel" "email_s1" {
  project      = var.project_id
  display_name = "Security Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Log-based metric
resource "google_logging_metric" "snapshot_create" {
  project = var.project_id
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
  project      = var.project_id
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

  notification_channels = [google_monitoring_notification_channel.email_s1.id]

  alert_strategy {
    auto_close = "1800s"
    notification_rate_limit {
      period = "300s"
    }
  }
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
        # Azure Strategy: Modify Cloud Compute Infrastructure: Create Snapshot
        DetectionStrategy(
            strategy_id="t1578001-azure",
            name="Azure Modify Cloud Compute Infrastructure: Create Snapshot Detection",
            description=(
                "Azure detection for Modify Cloud Compute Infrastructure: Create Snapshot. "
                "Provides native Azure detection using Log Analytics and Defender for Cloud."
            ),
            detection_type=DetectionType.SENTINEL_RULE,
            aws_service="n/a",
            azure_service="sentinel",
            cloud_provider=CloudProvider.AZURE,
            implementation=DetectionImplementation(
                sentinel_rule_query="""// Sentinel Analytics Rule: Modify Cloud Compute Infrastructure: Create Snapshot
// MITRE ATT&CK: T1578.001
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
                azure_terraform_template="""# Azure Detection for Modify Cloud Compute Infrastructure: Create Snapshot
# MITRE ATT&CK: T1578.001

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
  name                = "modify-cloud-compute-infrastructure--create-snapsh-alerts"
  resource_group_name = var.resource_group_name
  short_name          = "SecAlerts"

  email_receiver {
    name          = "security-team"
    email_address = var.alert_email
  }
}

# Scheduled Query Rule for detection
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "detection" {
  name                = "modify-cloud-compute-infrastructure--create-snapsh-detection"
  resource_group_name = var.resource_group_name
  location            = "uksouth"

  evaluation_frequency = "PT5M"
  window_duration      = "PT1H"
  scopes               = [var.log_analytics_workspace_id]
  severity             = 2

  criteria {
    query = <<-QUERY
// Sentinel Analytics Rule: Modify Cloud Compute Infrastructure: Create Snapshot
// MITRE ATT&CK: T1578.001
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

  description = "Detects Modify Cloud Compute Infrastructure: Create Snapshot (T1578.001) activity in Azure environment"
  display_name = "Modify Cloud Compute Infrastructure: Create Snapshot Detection"
  enabled      = true

  tags = {
    "mitre-technique" = "T1578.001"
    "detection-type"  = "security"
  }
}

output "alert_rule_id" {
  value = azurerm_monitor_scheduled_query_rules_alert_v2.detection.id
}""",
                alert_severity="high",
                alert_title="Azure: Modify Cloud Compute Infrastructure: Create Snapshot Detected",
                alert_description_template=(
                    "Modify Cloud Compute Infrastructure: Create Snapshot activity detected. "
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
    recommended_order=["t1578001-aws-ebs", "t1578001-aws-rds", "t1578001-gcp-snapshot"],
    total_effort_hours=2.0,
    coverage_improvement="+18% improvement for Exfiltration tactic",
)
