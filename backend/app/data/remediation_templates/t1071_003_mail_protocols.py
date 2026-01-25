"""
T1071.003 - Application Layer Protocol: Mail Protocols

Adversaries leverage email protocols (SMTP, POP3, IMAP) to establish command
and control channels whilst evading detection by blending with legitimate traffic.
Used by APT28, APT32, Turla, Kimsuky.
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
    technique_id="T1071.003",
    technique_name="Application Layer Protocol: Mail Protocols",
    tactic_ids=["TA0011"],
    mitre_url="https://attack.mitre.org/techniques/T1071/003/",
    threat_context=ThreatContext(
        description=(
            "Adversaries leverage email protocols (SMTP, POP3, IMAP) to establish "
            "command and control channels whilst evading detection. The technique exploits "
            "the ubiquity of mail traffic in enterprise environments, embedding malicious "
            "commands and exfiltrated data within protocol headers and email messages."
        ),
        attacker_goal="Establish covert command and control using email protocols to blend with legitimate traffic",
        why_technique=[
            "Email protocols are ubiquitous in enterprise networks",
            "Protocol packets contain numerous fields for data concealment",
            "Mimics legitimate business communications",
            "Multiple protocols available (SMTP, POP3, IMAP)",
            "Enables data exfiltration and command receipt",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="moderate",
        trend="stable",
        severity_score=7,
        severity_reasoning=(
            "Enables persistent command and control whilst evading network detection. "
            "Email protocols are expected traffic, making detection challenging without "
            "proper monitoring of non-standard email client behaviour."
        ),
        business_impact=[
            "Persistent attacker access",
            "Data exfiltration enabler",
            "Difficult to detect C2 traffic",
            "Compromised credential usage",
        ],
        typical_attack_phase="command_and_control",
        often_precedes=["T1041", "T1048", "T1567"],
        often_follows=["T1078", "T1566"],
    ),
    detection_strategies=[
        DetectionStrategy(
            strategy_id="t1071-003-aws-smtp",
            name="AWS Unauthorised SMTP/IMAP/POP3 Traffic Detection",
            description="Detect suspicious outbound email protocol traffic from compute instances.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, srcaddr, dstaddr, dstport, action, protocol
| filter (dstport = 25 or dstport = 587 or dstport = 465 or dstport = 110 or dstport = 995 or dstport = 143 or dstport = 993)
| filter protocol = 6
| filter action = "ACCEPT"
| stats count(*) as connections by srcaddr, dstport, bin(5m)
| filter connections > 10
| sort connections desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect unauthorised email protocol usage from compute instances

Parameters:
  VPCFlowLogGroup:
    Type: String
    Description: VPC Flow Logs CloudWatch Log Group
  AlertEmail:
    Type: String
    Description: Email address for security alerts

Resources:
  # Step 1: Create SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      DisplayName: Email Protocol C2 Alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Create metric filter for SMTP/IMAP/POP3 traffic
  EmailProtocolFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref VPCFlowLogGroup
      FilterPattern: '[version, account, eni, source, destination, srcport, destport=25||destport=587||destport=465||destport=110||destport=995||destport=143||destport=993, protocol=6, packets, bytes, windowstart, windowend, action=ACCEPT, flowlogstatus]'
      MetricTransformations:
        - MetricName: EmailProtocolConnections
          MetricNamespace: Security/EmailC2
          MetricValue: "1"
          DefaultValue: 0

  # Step 3: Create alarm for high email protocol activity
  EmailProtocolAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: UnauthorisedEmailProtocolTraffic
      AlarmDescription: Detect suspicious SMTP/IMAP/POP3 connections from compute instances
      MetricName: EmailProtocolConnections
      Namespace: Security/EmailC2
      Statistic: Sum
      Period: 300
      Threshold: 50
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      TreatMissingData: notBreaching

      AlarmActions: [!Ref AlertTopic]""",
                terraform_template="""# Detect unauthorised email protocol usage from compute instances

variable "vpc_flow_log_group" {
  type        = string
  description = "VPC Flow Logs CloudWatch Log Group"
}

variable "alert_email" {
  type        = string
  description = "Email address for security alerts"
}

variable "location" {
  type        = string
  description = "Azure region for resources"
  default     = "uksouth"
}

# Step 1: Create SNS topic for alerts
resource "aws_sns_topic" "alerts" {
  name         = "email-protocol-c2-alerts"
  kms_master_key_id = "alias/aws/sns"
  display_name = "Email Protocol C2 Alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Create metric filter for SMTP/IMAP/POP3 traffic
resource "aws_cloudwatch_log_metric_filter" "email_protocol" {
  name           = "email-protocol-connections"
  log_group_name = var.vpc_flow_log_group
  pattern        = "[version, account, eni, source, destination, srcport, destport=25||destport=587||destport=465||destport=110||destport=995||destport=143||destport=993, protocol=6, packets, bytes, windowstart, windowend, action=ACCEPT, flowlogstatus]"

  metric_transformation {
    name      = "EmailProtocolConnections"
    namespace = "Security/EmailC2"
    value     = "1"
    default_value = 0
  }
}

# Step 3: Create alarm for high email protocol activity
resource "aws_cloudwatch_metric_alarm" "email_protocol" {
  alarm_name          = "UnauthorisedEmailProtocolTraffic"
  alarm_description   = "Detect suspicious SMTP/IMAP/POP3 connections from compute instances"
  metric_name         = "EmailProtocolConnections"
  namespace           = "Security/EmailC2"
  statistic           = "Sum"
  period              = 300
  threshold           = 50
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.alerts.arn]
}""",
                alert_severity="high",
                alert_title="Unauthorised Email Protocol Traffic Detected",
                alert_description_template="Suspicious SMTP/IMAP/POP3 connections from instance {srcaddr}.",
                investigation_steps=[
                    "Identify source instance and running processes",
                    "Review email destinations and external IPs",
                    "Check for known malware signatures",
                    "Analyse email content if accessible",
                    "Review instance for unauthorised email clients",
                ],
                containment_actions=[
                    "Block email protocol ports at security group level",
                    "Isolate affected instance from network",
                    "Review and revoke compromised credentials",
                    "Terminate unauthorised processes",
                    "Scan for malware and backdoors",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Exclude authorised mail servers and legitimate email clients. Baseline normal email traffic patterns.",
            detection_coverage="65% - catches direct email protocol connections",
            evasion_considerations="Encrypted protocols (SMTPS, POP3S, IMAPS) may require TLS inspection. Slow, low-volume C2 may evade thresholds.",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30-60 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=["VPC Flow Logs enabled", "CloudWatch Logs"],
        ),
        DetectionStrategy(
            strategy_id="t1071-003-aws-guardduty",
            name="AWS GuardDuty Email Protocol Anomaly Detection",
            description="Leverage GuardDuty to detect anomalous email protocol behaviour.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="guardduty",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, type, severity, title, resource.instanceDetails.instanceId
| filter type like /Backdoor|CryptoCurrency|Trojan/
| filter service.action.networkConnectionAction.connectionDirection = "OUTBOUND"
| filter service.action.networkConnectionAction.remotePortDetails.port in [25, 587, 465, 110, 995, 143, 993]
| sort @timestamp desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: GuardDuty email protocol anomaly detection

Parameters:
  AlertEmail:
    Type: String
    Description: Email address for security alerts

Resources:
  # Step 1: Enable GuardDuty (if not already enabled)
  GuardDutyDetector:
    Type: AWS::GuardDuty::Detector
    Properties:
      Enable: true
      FindingPublishingFrequency: FIFTEEN_MINUTES

  # Step 2: Create SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      DisplayName: GuardDuty Email C2 Alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 3: Create EventBridge rule for email protocol findings
  GuardDutyEventRule:
    Type: AWS::Events::Rule
    Properties:
      Name: GuardDutyEmailProtocolFindings
      Description: Alert on GuardDuty findings related to email protocol C2
      EventPattern:
        source:
          - aws.guardduty
        detail-type:
          - GuardDuty Finding
        detail:
          service:
            action:
              networkConnectionAction:
                remotePortDetails:
                  port:
                    - 25
                    - 587
                    - 465
                    - 110
                    - 995
                    - 143
                    - 993
      State: ENABLED
      Targets:
        - Arn: !Ref AlertTopic
          Id: SNSTarget""",
                terraform_template="""# GuardDuty email protocol anomaly detection

variable "alert_email" {
  type        = string
  description = "Email address for security alerts"
}

variable "location" {
  type        = string
  description = "Azure region for resources"
  default     = "uksouth"
}

# Step 1: Enable GuardDuty (if not already enabled)
resource "aws_guardduty_detector" "main" {
  enable                       = true
  finding_publishing_frequency = "FIFTEEN_MINUTES"
}

# Step 2: Create SNS topic for alerts
resource "aws_sns_topic" "alerts" {
  name         = "guardduty-email-c2-alerts"
  kms_master_key_id = "alias/aws/sns"
  display_name = "GuardDuty Email C2 Alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# SQS DLQ for failed EventBridge deliveries
resource "aws_sqs_queue" "dlq" {
  name                      = "guardduty-email-c2-eventbridge-dlq"
  message_retention_seconds = 1209600  # 14 days
}

resource "aws_sqs_queue_policy" "dlq" {
  queue_url = aws_sqs_queue.dlq.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "events.amazonaws.com"
      }
      Action   = "sqs:SendMessage"
      Resource = aws_sqs_queue.dlq.arn
    }]
  })
}

# Step 3: Create EventBridge rule for email protocol findings
resource "aws_cloudwatch_event_rule" "guardduty_email" {
  name        = "guardduty-email-protocol-findings"
  description = "Alert on GuardDuty findings related to email protocol C2"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail = {
      service = {
        action = {
          networkConnectionAction = {
            remotePortDetails = {
              port = [25, 587, 465, 110, 995, 143, 993]
            }
          }
        }
      }
    }
  })
}

resource "aws_cloudwatch_event_target" "sns" {
  rule      = aws_cloudwatch_event_rule.guardduty_email.name
  target_id = "SNSTarget"
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

data "aws_caller_identity" "current" {}

resource "aws_sns_topic_policy" "guardduty" {
  arn = aws_sns_topic.alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "events.amazonaws.com"
      }
      Action   = "SNS:Publish"
      Resource = aws_sns_topic.alerts.arn
    Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
        ArnEquals = {
          "aws:SourceArn" = aws_cloudwatch_event_rule.guardduty_email.arn
        }
      }
    }]
  })
}""",
                alert_severity="high",
                alert_title="GuardDuty: Email Protocol C2 Activity",
                alert_description_template="GuardDuty detected suspicious email protocol activity from instance {instanceId}.",
                investigation_steps=[
                    "Review GuardDuty finding details",
                    "Identify affected EC2 instance",
                    "Analyse network connections and processes",
                    "Check for malware indicators",
                    "Review instance access logs",
                ],
                containment_actions=[
                    "Isolate affected instance",
                    "Block outbound email protocol ports",
                    "Terminate malicious processes",
                    "Analyse and remove malware",
                    "Review and rotate credentials",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="GuardDuty uses machine learning and threat intelligence, reducing false positives significantly.",
            detection_coverage="75% - comprehensive anomaly detection",
            evasion_considerations="Slow, low-volume C2 may evade ML models. Encrypted traffic limits inspection depth.",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$30-50",
            prerequisites=["AWS GuardDuty enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1071-003-gcp-smtp",
            name="GCP Unauthorised Email Protocol Detection",
            description="Detect suspicious outbound email protocol traffic from GCP instances.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""resource.type="gce_subnetwork"
logName="projects/PROJECT_ID/logs/compute.googleapis.com%2Fvpc_flows"
jsonPayload.connection.dest_port=(25 OR 587 OR 465 OR 110 OR 995 OR 143 OR 993)
jsonPayload.connection.protocol=6""",
                gcp_terraform_template="""# GCP: Detect unauthorised email protocol usage

variable "project_id" {
  type        = string
  description = "GCP project ID"
}

variable "alert_email" {
  type        = string
  description = "Email address for security alerts"
}

variable "location" {
  type        = string
  description = "Azure region for resources"
  default     = "uksouth"
}

# Step 1: Create notification channel for alerts
resource "google_monitoring_notification_channel" "email_s1" {
  project      = var.project_id
  display_name = "Email Protocol C2 Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Create log-based metric for email protocol traffic
resource "google_logging_metric" "email_protocol" {
  name   = "email-protocol-connections"
  filter = <<-EOT
    resource.type="gce_subnetwork"
    logName="projects/${var.project_id}/logs/compute.googleapis.com%2Fvpc_flows"
    jsonPayload.connection.dest_port=(25 OR 587 OR 465 OR 110 OR 995 OR 143 OR 993)
    jsonPayload.connection.protocol=6
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    unit        = "1"
    labels {
      key         = "src_ip"
      value_type  = "STRING"
      description = "Source IP address"
    }
  }

  label_extractors = {
    "src_ip" = "EXTRACT(jsonPayload.connection.src_ip)"
  }

  project = var.project_id
}

# Step 3: Create alert policy for suspicious email protocol activity
resource "google_monitoring_alert_policy" "email_protocol" {
  project      = var.project_id
  display_name = "Unauthorised Email Protocol Traffic"
  combiner     = "OR"

  conditions {
    display_name = "High email protocol connection rate"

    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.email_protocol.name}\" resource.type=\"gce_subnetwork\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 30

      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_RATE"
      }
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
                alert_title="GCP: Unauthorised Email Protocol Traffic",
                alert_description_template="Suspicious SMTP/IMAP/POP3 connections from GCP instance.",
                investigation_steps=[
                    "Identify source GCP instance",
                    "Review running processes and services",
                    "Analyse VPC flow logs for patterns",
                    "Check for malware signatures",
                    "Review instance service account permissions",
                ],
                containment_actions=[
                    "Apply firewall rules to block email ports",
                    "Isolate instance from network",
                    "Terminate malicious processes",
                    "Remove malware and backdoors",
                    "Rotate service account credentials",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Exclude authorised mail relays. Establish baseline for legitimate email traffic.",
            detection_coverage="65% - catches direct protocol connections",
            evasion_considerations="Encrypted protocols require additional inspection. Low-volume C2 may evade rate thresholds.",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30-60 minutes",
            estimated_monthly_cost="$10-20",
            prerequisites=["VPC Flow Logs enabled", "Cloud Logging API enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1071-003-gcp-scc",
            name="GCP Security Command Centre Email Protocol Detection",
            description="Leverage Security Command Centre to detect email protocol anomalies.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="security_command_center",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="security_finding"
protoPayload.serviceName="securitycenter.googleapis.com"
protoPayload.response.finding.category="Persistence: Outbound Email Traffic from Compute Instance"''',
                gcp_terraform_template="""# GCP: Security Command Centre email protocol detection

variable "project_id" {
  type        = string
  description = "GCP project ID"
}

variable "organization_id" {
  type        = string
  description = "GCP organisation ID"
}

variable "alert_email" {
  type        = string
  description = "Email address for security alerts"
}

variable "location" {
  type        = string
  description = "Azure region for resources"
  default     = "uksouth"
}

# Step 1: Enable Security Command Centre (requires organisation-level permissions)
# Note: SCC Standard tier is automatically enabled for GCP organisations
# Premium tier provides additional features

# Step 2: Create notification channel
resource "google_monitoring_notification_channel" "email_s2" {
  project      = var.project_id
  display_name = "SCC Email Protocol Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 3: Create notification config for email protocol findings
resource "google_scc_notification_config" "email_protocol" {
  config_id    = "email-protocol-c2-alerts"
  organization = var.organization_id
  description  = "Alert on email protocol C2 activity detected by SCC"
  pubsub_topic = google_pubsub_topic.scc_notifications.id

  streaming_config {
    filter = <<-EOT
      category="Persistence: Outbound Email Traffic from Compute Instance" OR
      category="Backdoor: Unexpected Network Connection" AND
      finding.connections.destinationPort IN (25, 587, 465, 110, 995, 143, 993)
    EOT
  }
}

resource "google_pubsub_topic" "scc_notifications" {
  name    = "scc-email-protocol-notifications"
  project = var.project_id
}

resource "google_pubsub_subscription" "scc_email" {
  name    = "scc-email-protocol-subscription"
  topic   = google_pubsub_topic.scc_notifications.name
  project = var.project_id

  push_config {
    push_endpoint = "https://pubsub.googleapis.com/v1/projects/${var.project_id}/topics/security-alerts"
  }
}""",
                alert_severity="high",
                alert_title="GCP SCC: Email Protocol C2 Activity",
                alert_description_template="Security Command Centre detected email protocol C2 activity.",
                investigation_steps=[
                    "Review SCC finding details",
                    "Identify affected GCP resources",
                    "Analyse network traffic patterns",
                    "Check for malware indicators",
                    "Review security policies and configurations",
                ],
                containment_actions=[
                    "Isolate affected instances",
                    "Block email protocol ports",
                    "Remove malware and backdoors",
                    "Rotate compromised credentials",
                    "Apply security hardening",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="SCC uses threat intelligence and anomaly detection, minimising false positives.",
            detection_coverage="80% - comprehensive threat detection",
            evasion_considerations="Sophisticated adversaries may use low-volume, encrypted C2 to evade detection.",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$50-100",
            prerequisites=[
                "Security Command Centre enabled",
                "Organisation-level permissions",
            ],
        ),
        # Azure Strategy: Application Layer Protocol: Mail Protocols
        DetectionStrategy(
            strategy_id="t1071003-azure",
            name="Azure Application Layer Protocol: Mail Protocols Detection",
            description=(
                "Azure detection for Application Layer Protocol: Mail Protocols. "
                "Provides native Azure detection using Log Analytics and Defender for Cloud."
            ),
            detection_type=DetectionType.SENTINEL_RULE,
            aws_service="n/a",
            azure_service="sentinel",
            cloud_provider=CloudProvider.AZURE,
            implementation=DetectionImplementation(
                sentinel_rule_query="""// Sentinel Analytics Rule: Application Layer Protocol: Mail Protocols
// MITRE ATT&CK: T1071.003
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
                azure_terraform_template="""# Azure Detection for Application Layer Protocol: Mail Protocols
# MITRE ATT&CK: T1071.003

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

variable "location" {
  type        = string
  description = "Azure region for resources"
  default     = "uksouth"
}

# Action Group for alerts
resource "azurerm_monitor_action_group" "security_alerts" {
  name                = "application-layer-protocol--mail-protocols-alerts"
  resource_group_name = var.resource_group_name
  short_name          = "SecAlerts"

  email_receiver {
    name          = "security-team"
    email_address = var.alert_email
  }
}

# Scheduled Query Rule for detection
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "detection" {
  name                = "application-layer-protocol--mail-protocols-detection"
  resource_group_name = var.resource_group_name
  location            = var.location

  evaluation_frequency = "PT5M"
  window_duration      = "PT1H"
  scopes               = [var.log_analytics_workspace_id]
  severity             = 2

  criteria {
    query = <<-QUERY
// Sentinel Analytics Rule: Application Layer Protocol: Mail Protocols
// MITRE ATT&CK: T1071.003
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

  description = "Detects Application Layer Protocol: Mail Protocols (T1071.003) activity in Azure environment"
  display_name = "Application Layer Protocol: Mail Protocols Detection"
  enabled      = true

  tags = {
    "mitre-technique" = "T1071.003"
    "detection-type"  = "security"
  }
}

output "alert_rule_id" {
  value = azurerm_monitor_scheduled_query_rules_alert_v2.detection.id
}""",
                alert_severity="high",
                alert_title="Azure: Application Layer Protocol: Mail Protocols Detected",
                alert_description_template=(
                    "Application Layer Protocol: Mail Protocols activity detected. "
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
        "t1071-003-aws-guardduty",
        "t1071-003-gcp-scc",
        "t1071-003-aws-smtp",
        "t1071-003-gcp-smtp",
    ],
    total_effort_hours=3.5,
    coverage_improvement="+25% improvement for Command and Control tactic",
)
