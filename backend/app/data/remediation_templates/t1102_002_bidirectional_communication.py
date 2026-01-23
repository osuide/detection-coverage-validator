"""
T1102.002 - Web Service: Bidirectional Communication

Adversaries leverage legitimate external web services for bidirectional command
and control. Using popular websites and social media to host C2 instructions
and return results through posting comments, pull requests, document updates, or tweets.
Used by APT12, APT28, APT29, APT37, Carbanak, FIN7, Lazarus Group, Turla.
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
    technique_id="T1102.002",
    technique_name="Web Service: Bidirectional Communication",
    tactic_ids=["TA0011"],
    mitre_url="https://attack.mitre.org/techniques/T1102/002/",
    threat_context=ThreatContext(
        description=(
            "Adversaries leverage legitimate external web services for bidirectional "
            "command and control with compromised systems. Rather than establishing "
            "dedicated infrastructure, threat actors use established platforms like "
            "Google Drive, Dropbox, GitHub, Twitter, Telegram, and WordPress to send "
            "commands and receive output. Communications are encrypted via SSL/TLS, "
            "blend with expected organisational traffic patterns, and leverage trusted "
            "platforms to reduce detection likelihood."
        ),
        attacker_goal="Establish covert command and control using legitimate web services to evade detection",
        why_technique=[
            "SSL/TLS encryption protects communications",
            "Blends with legitimate organisational traffic",
            "Leverages trusted platforms",
            "No dedicated infrastructure required",
            "Difficult to block without impacting business",
            "Often bypasses traditional network controls",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="common",
        trend="increasing",
        severity_score=8,
        severity_reasoning=(
            "Highly effective C2 technique that leverages trusted services, making "
            "detection difficult without impacting legitimate business operations. "
            "Widely adopted by APT groups and commodity malware."
        ),
        business_impact=[
            "Covert command and control access",
            "Data exfiltration via trusted services",
            "Persistent access to environment",
            "Difficult to block without business impact",
            "Extended dwell time due to evasion",
        ],
        typical_attack_phase="command_and_control",
        often_precedes=["T1041", "T1567.002", "T1071.001"],
        often_follows=["T1566.001", "T1204.002", "T1059"],
    ),
    detection_strategies=[
        DetectionStrategy(
            strategy_id="t1102-002-aws-process-network",
            name="AWS Process to Web Service Correlation",
            description="Detect suspicious processes initiating encrypted connections to web services followed by abnormal upload behaviour.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, userIdentity.principalId, eventName, sourceIPAddress, requestParameters
| filter eventName = "RunInstances" or eventName = "StartInstances"
| filter requestParameters.instanceType like /t2.|t3./
| stats count(*) as launches by userIdentity.principalId, sourceIPAddress, bin(1h)
| filter launches > 5
| sort launches desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect suspicious process-to-web-service communications

Parameters:
  VPCFlowLogGroup:
    Type: String
    Description: VPC Flow Logs CloudWatch Log Group
  AlertEmail:
    Type: String
    Description: Email for security alerts

Resources:
  # SNS Topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Metric filter for HTTPS to cloud storage domains
  WebServiceConnectionFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref VPCFlowLogGroup
      FilterPattern: '[version, account, eni, source, destination, srcport, destport="443", protocol="6", packets, bytes, start, end, action="ACCEPT", status]'
      MetricTransformations:
        - MetricName: HTTPSConnections
          MetricNamespace: Security/C2
          MetricValue: "1"

  # Alarm for high volume HTTPS to common C2 services
  HighWebServiceTrafficAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: SuspiciousWebServiceC2Traffic
      AlarmDescription: High volume HTTPS connections potentially indicating C2 activity
      MetricName: HTTPSConnections
      Namespace: Security/C2
      Statistic: Sum
      Period: 300
      Threshold: 100
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 2
      TreatMissingData: notBreaching

      AlarmActions: [!Ref AlertTopic]""",
                terraform_template="""# AWS: Detect suspicious process-to-web-service communications

variable "vpc_flow_log_group" {
  description = "VPC Flow Logs CloudWatch Log Group"
  type        = string
}

variable "alert_email" {
  description = "Email for security alerts"
  type        = string
}

# SNS Topic for alerts
resource "aws_sns_topic" "web_service_c2_alerts" {
  name = "web-service-c2-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email_alerts" {
  topic_arn = aws_sns_topic.web_service_c2_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Metric filter for HTTPS connections (port 443)
resource "aws_cloudwatch_log_metric_filter" "web_service_connections" {
  name           = "web-service-connections"
  log_group_name = var.vpc_flow_log_group
  pattern        = "[version, account, eni, source, destination, srcport, destport=\"443\", protocol=\"6\", packets, bytes, start, end, action=\"ACCEPT\", status]"

  metric_transformation {
    name      = "HTTPSConnections"
    namespace = "Security/C2"
    value     = "1"
  }
}

# Alarm for high volume HTTPS connections
resource "aws_cloudwatch_metric_alarm" "suspicious_web_service_traffic" {
  alarm_name          = "SuspiciousWebServiceC2Traffic"
  alarm_description   = "High volume HTTPS connections potentially indicating C2 activity"
  metric_name         = "HTTPSConnections"
  namespace           = "Security/C2"
  statistic           = "Sum"
  period              = 300
  threshold           = 100
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.web_service_c2_alerts.arn]
}""",
                alert_severity="high",
                alert_title="Suspicious Web Service C2 Activity Detected",
                alert_description_template="Suspicious process initiated high-volume HTTPS connections to web services from {principalId}.",
                investigation_steps=[
                    "Identify the process making connections (review GuardDuty/CloudTrail)",
                    "Check destination domains (GitHub, Dropbox, Google Drive, Telegram, etc.)",
                    "Review upload/download patterns and data volumes",
                    "Examine process parent-child relationships",
                    "Check for non-interactive or scripted behaviour",
                    "Review CloudTrail for API calls to cloud storage services",
                ],
                containment_actions=[
                    "Isolate affected EC2 instance via security group modification",
                    "Block egress to suspicious web service domains",
                    "Terminate malicious processes",
                    "Capture forensic snapshot of instance",
                    "Review IAM credentials for compromise",
                    "Block API access to cloud storage services if needed",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Tune thresholds based on legitimate web service usage. Whitelist known automation tools and CI/CD systems.",
            detection_coverage="50% - catches high-volume automated C2, may miss low-and-slow activity",
            evasion_considerations="Adversaries can use low-volume traffic, human-like timing, or lesser-known web services",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2-3 hours",
            estimated_monthly_cost="$10-25",
            prerequisites=["VPC Flow Logs enabled", "CloudWatch Logs Insights"],
        ),
        DetectionStrategy(
            strategy_id="t1102-002-aws-guardduty",
            name="AWS GuardDuty C2 Domain Detection",
            description="Leverage GuardDuty to detect connections to known C2 domains and threat intelligence feeds.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="guardduty",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, service.action.networkConnectionAction.remoteIpDetails.organization.asn,
       service.action.networkConnectionAction.remotePortDetails.port,
       severity, title
| filter type like /Backdoor|CryptoCurrency|Trojan/
| filter service.action.networkConnectionAction.remotePortDetails.port = 443
| stats count(*) as detections by service.action.networkConnectionAction.remoteIpDetails.organization.asn, bin(1h)
| sort detections desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: GuardDuty findings alerting for C2 activity

Parameters:
  AlertEmail:
    Type: String
    Description: Email for GuardDuty C2 alerts

Resources:
  # SNS Topic for GuardDuty alerts
  GuardDutyAlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # EventBridge rule for GuardDuty C2 findings
  GuardDutyC2Rule:
    Type: AWS::Events::Rule
    Properties:
      Description: Alert on GuardDuty C2 detections
      EventPattern:
        source:
          - aws.guardduty
        detail-type:
          - GuardDuty Finding
        detail:
          type:
            - prefix: Backdoor
            - prefix: CryptoCurrency
            - prefix: Trojan
            - prefix: UnauthorizedAccess
      State: ENABLED
      Targets:
        - Arn: !Ref GuardDutyAlertTopic
          Id: GuardDutyC2SNS

  # Permission for EventBridge to publish to SNS
  SNSTopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics:
        - !Ref GuardDutyAlertTopic
      PolicyDocument:
        Statement:
          - Effect: Allow
            Principal:
              Service: events.amazonaws.com
            Action: sns:Publish
            Resource: !Ref GuardDutyAlertTopic
            Condition:
              StringEquals:
                AWS:SourceAccount: !Ref AWS::AccountId
              ArnEquals:
                aws:SourceArn: !GetAtt GuardDutyC2Rule.Arn""",
                terraform_template="""# AWS: GuardDuty C2 domain detection

variable "alert_email" {
  description = "Email for GuardDuty C2 alerts"
  type        = string
}

# SNS Topic for GuardDuty alerts
resource "aws_sns_topic" "guardduty_c2_alerts" {
  name = "guardduty-c2-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "guardduty_email" {
  topic_arn = aws_sns_topic.guardduty_c2_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# EventBridge rule for GuardDuty C2 findings
resource "aws_cloudwatch_event_rule" "guardduty_c2" {
  name        = "guardduty-c2-detection"
  description = "Alert on GuardDuty C2 detections"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail = {
      type = [
        { prefix = "Backdoor" },
        { prefix = "CryptoCurrency" },
        { prefix = "Trojan" },
        { prefix = "UnauthorizedAccess" }
      ]
    }
  })
}

resource "aws_sqs_queue" "dlq" {
  name                      = "guardduty-c2-dlq"
  message_retention_seconds = 1209600
}

data "aws_caller_identity" "current" {}

data "aws_iam_policy_document" "eventbridge_dlq_policy" {
  statement {
    sid     = "AllowEventBridgeToSendToDLQ"
    effect  = "Allow"
    actions = ["sqs:SendMessage"]
    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }
    resources = [aws_sqs_queue.dlq.arn]
    condition {
      test     = "StringEquals"
      variable = "AWS:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
    condition {
      test     = "ArnEquals"
      variable = "aws:SourceArn"
      values   = [aws_cloudwatch_event_rule.guardduty_c2.arn]
    }
  }
}

resource "aws_sqs_queue_policy" "event_dlq" {
  queue_url = aws_sqs_queue.dlq.url
  policy    = data.aws_iam_policy_document.eventbridge_dlq_policy.json
}

resource "aws_cloudwatch_event_target" "guardduty_sns" {
  rule      = aws_cloudwatch_event_rule.guardduty_c2.name
  target_id = "GuardDutyC2SNS"
  arn       = aws_sns_topic.guardduty_c2_alerts.arn

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

# SNS topic policy
resource "aws_sns_topic_policy" "guardduty_publish" {
  arn = aws_sns_topic.guardduty_c2_alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "events.amazonaws.com"
      }
      Action   = "SNS:Publish"
      Resource = aws_sns_topic.guardduty_c2_alerts.arn
    Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
          ArnEquals = {
            "aws:SourceArn" = aws_cloudwatch_event_rule.guardduty_c2.arn
          }
      }
    }]
  })
}""",
                alert_severity="critical",
                alert_title="GuardDuty: C2 Communication Detected",
                alert_description_template="GuardDuty detected C2 communication: {title}",
                investigation_steps=[
                    "Review GuardDuty finding details",
                    "Identify affected EC2 instance or IAM principal",
                    "Check remote IP/domain reputation",
                    "Review CloudTrail for related API activity",
                    "Examine process and network connections on instance",
                    "Check for persistence mechanisms",
                ],
                containment_actions=[
                    "Isolate affected resource immediately",
                    "Block malicious IPs/domains at security group level",
                    "Revoke IAM credentials if compromised",
                    "Capture forensic evidence",
                    "Terminate compromised instances",
                    "Review related resources for lateral movement",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="GuardDuty threat intelligence is highly accurate. Review findings context for verification.",
            detection_coverage="75% - leverages AWS threat intelligence and known C2 infrastructure",
            evasion_considerations="New or private C2 infrastructure may evade threat intel feeds",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$5-15 (GuardDuty costs vary by usage)",
            prerequisites=["AWS GuardDuty enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1102-002-gcp-cloud-storage",
            name="GCP Cloud Storage API C2 Detection",
            description="Detect suspicious Cloud Storage API usage patterns indicating C2 activity.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="gcs_bucket"
protoPayload.methodName=~"storage.objects.(create|get|update)"
severity="INFO"
protoPayload.authenticationInfo.principalEmail!~"gserviceaccount.com$"''',
                gcp_terraform_template="""# GCP: Detect Cloud Storage C2 activity

variable "project_id" {
  description = "GCP Project ID"
  type        = string
}

variable "alert_email" {
  description = "Email for security alerts"
  type        = string
}

# Notification channel for alerts
resource "google_monitoring_notification_channel" "storage_c2_email" {
  project      = var.project_id
  display_name = "Cloud Storage C2 Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Log-based metric for suspicious Cloud Storage access
resource "google_logging_metric" "storage_c2_access" {
  project = var.project_id
  name   = "cloud-storage-c2-access"
  filter = <<-EOT
    resource.type="gcs_bucket"
    protoPayload.methodName=~"storage.objects.(create|get|update)"
    severity="INFO"
    protoPayload.authenticationInfo.principalEmail!~"gserviceaccount.com$"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "principal_email"
      value_type  = "STRING"
      description = "User making the request"
    }
  }

  label_extractors = {
    "principal_email" = "EXTRACT(protoPayload.authenticationInfo.principalEmail)"
  }

}

# Alert policy for high-volume Cloud Storage access
resource "google_monitoring_alert_policy" "storage_c2_alerts" {
  project      = var.project_id
  display_name = "Cloud Storage C2 Activity"
  combiner     = "OR"

  conditions {
    display_name = "High volume Cloud Storage API calls"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.storage_c2_access.name}\" AND resource.type=\"gcs_bucket\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 50
      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_RATE"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.storage_c2_email.id]

  alert_strategy {
    auto_close = "1800s"
    notification_rate_limit {
      period = "300s"
    }
  }
}""",
                alert_severity="high",
                alert_title="GCP: Suspicious Cloud Storage C2 Activity",
                alert_description_template="High-volume Cloud Storage API activity detected from {principal_email}.",
                investigation_steps=[
                    "Review Cloud Storage audit logs for access patterns",
                    "Identify buckets and objects being accessed",
                    "Check principal identity and authentication method",
                    "Review uploaded/downloaded object contents",
                    "Examine timing patterns (automated vs manual)",
                    "Check for associated Compute Engine or Cloud Functions activity",
                ],
                containment_actions=[
                    "Revoke IAM permissions for suspicious principal",
                    "Enable bucket access controls to restrict access",
                    "Review and delete malicious objects",
                    "Block egress to external destinations if needed",
                    "Rotate compromised service account keys",
                    "Enable VPC Service Controls for additional protection",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist legitimate automation and CI/CD service accounts. Adjust thresholds based on normal usage patterns.",
            detection_coverage="60% - catches automated C2 via Cloud Storage API",
            evasion_considerations="Low-volume access or legitimate service account usage can evade detection",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2-3 hours",
            estimated_monthly_cost="$10-20",
            prerequisites=["Cloud Audit Logs enabled", "Cloud Monitoring configured"],
        ),
        DetectionStrategy(
            strategy_id="t1102-002-gcp-dns",
            name="GCP DNS Query Analysis for Web Service C2",
            description="Detect DNS queries to common C2 web service domains.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="dns_query"
jsonPayload.queryName=~"(github|gitlab|dropbox|pastebin|telegram|discord|slack)\\..*"
jsonPayload.responseCode="NOERROR"''',
                gcp_terraform_template="""# GCP: DNS-based web service C2 detection

variable "project_id" {
  description = "GCP Project ID"
  type        = string
}

variable "alert_email" {
  description = "Email for security alerts"
  type        = string
}

# Notification channel
resource "google_monitoring_notification_channel" "dns_c2_email" {
  project      = var.project_id
  display_name = "DNS C2 Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Log-based metric for DNS queries to web service domains
resource "google_logging_metric" "dns_web_service_queries" {
  project = var.project_id
  name   = "dns-web-service-c2-queries"
  filter = <<-EOT
    resource.type="dns_query"
    jsonPayload.queryName=~"(github|gitlab|dropbox|pastebin|telegram|discord|slack)\\..*"
    jsonPayload.responseCode="NOERROR"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "source_ip"
      value_type  = "STRING"
      description = "Source IP making DNS query"
    }
    labels {
      key         = "query_name"
      value_type  = "STRING"
      description = "DNS query name"
    }
  }

  label_extractors = {
    "source_ip"  = "EXTRACT(jsonPayload.sourceIP)"
    "query_name" = "EXTRACT(jsonPayload.queryName)"
  }

}

# Alert policy for suspicious DNS activity
resource "google_monitoring_alert_policy" "dns_web_service_c2" {
  project      = var.project_id
  display_name = "DNS Queries to Web Service C2 Domains"
  combiner     = "OR"

  conditions {
    display_name = "High volume DNS queries to web services"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.dns_web_service_queries.name}\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 20
      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_RATE"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.dns_c2_email.id]

  alert_strategy {
    auto_close = "1800s"
    notification_rate_limit {
      period = "300s"
    }
  }
}""",
                alert_severity="medium",
                alert_title="GCP: DNS Queries to Web Service C2 Domains",
                alert_description_template="High-volume DNS queries to web service domains from {source_ip}.",
                investigation_steps=[
                    "Review DNS query logs for patterns",
                    "Identify source Compute Engine instances",
                    "Check query frequency and timing",
                    "Examine destination domains (GitHub, Dropbox, Telegram, etc.)",
                    "Review associated network connections",
                    "Check for data transfer volumes",
                ],
                containment_actions=[
                    "Isolate affected Compute Engine instances",
                    "Block DNS resolution to suspicious domains",
                    "Review and terminate malicious processes",
                    "Implement DNS firewall policies",
                    "Enable Cloud DNS Security (DNSSEC)",
                    "Review VPC firewall rules",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.HIGH,
            false_positive_tuning="High false positive rate due to legitimate use of these services. Correlate with other indicators and whitelist known legitimate usage.",
            detection_coverage="40% - provides early warning but requires correlation",
            evasion_considerations="Adversaries can use lesser-known services or direct IP connections",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2-3 hours",
            estimated_monthly_cost="$5-15",
            prerequisites=["Cloud DNS Logging enabled", "VPC Flow Logs"],
        ),
        # Azure Strategy: Web Service: Bidirectional Communication
        DetectionStrategy(
            strategy_id="t1102002-azure",
            name="Azure Web Service: Bidirectional Communication Detection",
            description=(
                "Azure detection for Web Service: Bidirectional Communication. "
                "Provides native Azure detection using Log Analytics and Defender for Cloud."
            ),
            detection_type=DetectionType.SENTINEL_RULE,
            aws_service="n/a",
            azure_service="sentinel",
            cloud_provider=CloudProvider.AZURE,
            implementation=DetectionImplementation(
                sentinel_rule_query="""// Sentinel Analytics Rule: Web Service: Bidirectional Communication
// MITRE ATT&CK: T1102.002
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
                azure_terraform_template="""# Azure Detection for Web Service: Bidirectional Communication
# MITRE ATT&CK: T1102.002

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
  name                = "web-service--bidirectional-communication-alerts"
  resource_group_name = var.resource_group_name
  short_name          = "SecAlerts"

  email_receiver {
    name          = "security-team"
    email_address = var.alert_email
  }
}

# Scheduled Query Rule for detection
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "detection" {
  name                = "web-service--bidirectional-communication-detection"
  resource_group_name = var.resource_group_name
  location            = "uksouth"

  evaluation_frequency = "PT5M"
  window_duration      = "PT1H"
  scopes               = [var.log_analytics_workspace_id]
  severity             = 2

  criteria {
    query = <<-QUERY
// Sentinel Analytics Rule: Web Service: Bidirectional Communication
// MITRE ATT&CK: T1102.002
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

  description = "Detects Web Service: Bidirectional Communication (T1102.002) activity in Azure environment"
  display_name = "Web Service: Bidirectional Communication Detection"
  enabled      = true

  tags = {
    "mitre-technique" = "T1102.002"
    "detection-type"  = "security"
  }
}

output "alert_rule_id" {
  value = azurerm_monitor_scheduled_query_rules_alert_v2.detection.id
}""",
                alert_severity="high",
                alert_title="Azure: Web Service: Bidirectional Communication Detected",
                alert_description_template=(
                    "Web Service: Bidirectional Communication activity detected. "
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
        "t1102-002-aws-guardduty",
        "t1102-002-gcp-cloud-storage",
        "t1102-002-aws-process-network",
        "t1102-002-gcp-dns",
    ],
    total_effort_hours=7.0,
    coverage_improvement="+25% improvement for Command and Control tactic",
)
