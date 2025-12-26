"""
T1568.002 - Dynamic Resolution: Domain Generation Algorithms

Adversaries use Domain Generation Algorithms (DGAs) to dynamically identify
command and control destinations rather than relying on static IP addresses
or domains. Used by APT41, Aria-body, Astaroth, Bazar, Conficker, QakBot.
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
    technique_id="T1568.002",
    technique_name="Dynamic Resolution: Domain Generation Algorithms",
    tactic_ids=["TA0011"],
    mitre_url="https://attack.mitre.org/techniques/T1568/002/",
    threat_context=ThreatContext(
        description=(
            "Adversaries use Domain Generation Algorithms (DGAs) to dynamically generate "
            "domain names for command and control (C2) communication. DGAs create apparent "
            "gibberish strings or concatenate complete words together, often incorporating "
            "time-based or seed values. This makes it significantly harder for defenders to "
            "block, track, or take over the C2 channel as potentially thousands of domains "
            "can be generated."
        ),
        attacker_goal="Establish resilient command and control channels that are difficult to block or detect",
        why_technique=[
            "Evades static blocklists and DNS-based blocking",
            "Provides fallback C2 when primary channels fail",
            "Makes takedown efforts impractical",
            "Complicates network forensics and tracking",
            "Enables automated C2 rotation",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="common",
        trend="stable",
        severity_score=7,
        severity_reasoning=(
            "DGAs enable persistent C2 communication despite defensive measures. "
            "Detection requires advanced DNS monitoring capabilities, but successful "
            "identification can reveal malware presence before data exfiltration occurs."
        ),
        business_impact=[
            "Persistent C2 communication",
            "Difficult to block or contain",
            "Enables data exfiltration",
            "Complicates incident response",
            "Indicator of active malware infection",
        ],
        typical_attack_phase="command_and_control",
        often_precedes=["T1041", "T1030", "T1048"],
        often_follows=["T1203", "T1204", "T1566"],
    ),
    detection_strategies=[
        # AWS GuardDuty Detection (Recommended)
        DetectionStrategy(
            strategy_id="t1568.002-aws-guardduty",
            name="AWS GuardDuty Anomaly Detection",
            description=(
                "AWS GuardDuty uses ML to detect domain generation algorithm (DGA) communications. These findings fire when EC2 instances query domains that match DGA patterns, indicating potential C2 communication."
            ),
            detection_type=DetectionType.GUARDDUTY,
            aws_service="guardduty",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                guardduty_finding_types=[
                    "Trojan:EC2/DGADomainRequest.B",
                    "Trojan:EC2/DGADomainRequest.C!DNS",
                ],
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: GuardDuty alerts for T1568.002

Parameters:
  AlertEmail:
    Type: String
    Description: Email for security alerts

Resources:
  # Step 1: SNS Topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      DisplayName: GuardDuty-T1568.002-Alerts
      KmsMasterKeyId: alias/aws/sns

  AlertSubscription:
    Type: AWS::SNS::Subscription
    Properties:
      TopicArn: !Ref AlertTopic
      Protocol: email
      Endpoint: !Ref AlertEmail

  # Step 2: EventBridge rule for GuardDuty findings
  GuardDutyRule:
    Type: AWS::Events::Rule
    Properties:
      Description: Capture GuardDuty findings for T1568.002
      EventPattern:
        source:
          - aws.guardduty
        detail-type:
          - GuardDuty Finding
        detail:
          type:
            - prefix: "Trojan:EC2/"
      State: ENABLED
      Targets:
        - Id: SNSTarget
          Arn: !Ref AlertTopic

  # Step 3: Allow EventBridge to publish to SNS
  TopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics:
        - !Ref AlertTopic
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
                aws:SourceArn: !GetAtt GuardDutyRule.Arn""",
                terraform_template="""# GuardDuty alerts for T1568.002

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

data "aws_caller_identity" "current" {}

# Step 1: SNS Topic
resource "aws_sns_topic" "guardduty_alerts" {
  name              = "guardduty-t1568.002-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.guardduty_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: EventBridge rule for findings
resource "aws_cloudwatch_event_rule" "guardduty" {
  name        = "guardduty-t1568.002"
  description = "Capture GuardDuty findings for T1568.002"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail = {
      type = [{ prefix = "Trojan:EC2/" }]
    }
  })
}

# Step 3: Target with DLQ and retry
resource "aws_sqs_queue" "dlq" {
  name                      = "guardduty-t1568.002-dlq"
  message_retention_seconds = 1209600
}

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
      values   = [aws_cloudwatch_event_rule.guardduty.arn]
    }
  }
}

resource "aws_sqs_queue_policy" "eventbridge_dlq" {
  queue_url = aws_sqs_queue.dlq.url
  policy    = data.aws_iam_policy_document.eventbridge_dlq_policy.json
}

resource "aws_cloudwatch_event_target" "sns" {
  rule      = aws_cloudwatch_event_rule.guardduty.name
  target_id = "SNSTarget"
  arn       = aws_sns_topic.guardduty_alerts.arn

  retry_policy {
    maximum_event_age_in_seconds = 3600
    maximum_retry_attempts       = 8
  }

  dead_letter_config {
    arn = aws_sqs_queue.dlq.arn
  }
}

# Step 4: SNS topic policy
resource "aws_sns_topic_policy" "allow_eventbridge" {
  arn = aws_sns_topic.guardduty_alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.guardduty_alerts.arn
      Condition = {
        StringEquals = { "AWS:SourceAccount" = data.aws_caller_identity.current.account_id }
        ArnEquals    = { "aws:SourceArn" = aws_cloudwatch_event_rule.guardduty.arn }
      }
    }]
  })
}""",
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="GuardDuty uses ML baselines; tune suppression rules for known benign patterns",
            detection_coverage="70% - detects anomalous behaviour but may miss attacks that blend with normal activity",
            evasion_considerations="Using legitimate-looking domains, low query frequency, blending with normal DNS traffic",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$4-10 per million events",
            prerequisites=[
                "AWS GuardDuty enabled",
                "CloudTrail logging active",
            ],
        ),
        DetectionStrategy(
            strategy_id="t1568.002-aws-dns-entropy",
            name="AWS Route 53 High Entropy DNS Query Detection",
            description="Detect DGA activity via Route 53 query logs analysing high entropy domains and NXDOMAIN responses.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, query_name, srcaddr, query_type, rcode
| filter rcode = "NXDOMAIN"
| stats count(*) as nxdomain_count by srcaddr, bin(5m)
| filter nxdomain_count > 50
| sort nxdomain_count desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect DGA activity via Route 53 DNS query logs

Parameters:
  Route53LogGroup:
    Type: String
    Description: Route 53 query log group name
  AlertEmail:
    Type: String
    Description: Email address for security alerts

Resources:
  # Step 1: Create SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      DisplayName: DGA Detection Alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  TopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics: [!Ref AlertTopic]
      PolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Sid: AllowCloudWatchPublish
            Effect: Allow
            Principal:
              Service: cloudwatch.amazonaws.com
            Action: sns:Publish
            Resource: !Ref AlertTopic
            Condition:
              StringEquals:
                AWS:SourceAccount: !Ref AWS::AccountId

  # Step 2: Create metric filter for high NXDOMAIN rates
  NXDomainFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref Route53LogGroup
      FilterPattern: '{ $.rcode = "NXDOMAIN" }'
      MetricTransformations:
        - MetricName: NXDomainResponses
          MetricNamespace: Security/DNS
          MetricValue: "1"

  # Step 3: Create CloudWatch alarm for DGA detection
  DGADetectionAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: HighNXDomainRate-PossibleDGA
      AlarmDescription: Detects high NXDOMAIN rates indicating possible DGA activity
      MetricName: NXDomainResponses
      Namespace: Security/DNS
      Statistic: Sum
      Period: 300
      EvaluationPeriods: 1
      Threshold: 100
      ComparisonOperator: GreaterThanThreshold
      TreatMissingData: notBreaching

      AlarmActions: [!Ref AlertTopic]""",
                terraform_template="""# Detect DGA activity via Route 53 DNS query logs

variable "route53_log_group" {
  type        = string
  description = "Route 53 query log group name"
}

variable "alert_email" {
  type        = string
  description = "Email address for security alerts"
}

data "aws_caller_identity" "current" {}

# Step 1: Create SNS topic for alerts
resource "aws_sns_topic" "dga_alerts" {
  name         = "dga-detection-alerts"
  kms_master_key_id = "alias/aws/sns"
  display_name = "DGA Detection Alerts"
}

resource "aws_sns_topic_policy" "allow_cloudwatch" {
  arn = aws_sns_topic.dga_alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowCloudWatchPublish"
      Effect    = "Allow"
      Principal = { Service = "cloudwatch.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.dga_alerts.arn
      Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
      }
    }]
  })
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.dga_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Create metric filter for high NXDOMAIN rates
resource "aws_cloudwatch_log_metric_filter" "nxdomain_rate" {
  name           = "nxdomain-responses"
  log_group_name = var.route53_log_group
  pattern        = "{ $.rcode = \"NXDOMAIN\" }"

  metric_transformation {
    name      = "NXDomainResponses"
    namespace = "Security/DNS"
    value     = "1"
  }
}

# Step 3: Create CloudWatch alarm for DGA detection
resource "aws_cloudwatch_metric_alarm" "dga_detection" {
  alarm_name          = "HighNXDomainRate-PossibleDGA"
  alarm_description   = "Detects high NXDOMAIN rates indicating possible DGA activity"
  metric_name         = "NXDomainResponses"
  namespace           = "Security/DNS"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 100
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.dga_alerts.arn]
}""",
                alert_severity="high",
                alert_title="Possible DGA Activity Detected",
                alert_description_template="High volume of NXDOMAIN responses from {srcaddr} indicates potential DGA activity.",
                investigation_steps=[
                    "Review DNS query patterns from source IP",
                    "Analyse domain names for randomness/entropy",
                    "Check for known DGA patterns or families",
                    "Identify affected host and review running processes",
                    "Check for concurrent suspicious network activity",
                    "Search for matching malware indicators",
                ],
                containment_actions=[
                    "Isolate affected host from network",
                    "Block identified C2 domains at DNS resolver",
                    "Terminate suspicious processes",
                    "Deploy DNS sinkhole for identified DGA pattern",
                    "Scan host for malware and remediate",
                    "Review other hosts for similar activity",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Tune threshold based on environment size. Exclude legitimate DNS-intensive applications.",
            detection_coverage="65% - catches high-volume DGA activity with many NXDOMAIN failures",
            evasion_considerations="Low-frequency DGAs or those with high success rates may evade detection",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$15-40",
            prerequisites=[
                "Route 53 Resolver Query Logging enabled",
                "VPC DNS query logging enabled",
            ],
        ),
        DetectionStrategy(
            strategy_id="t1568.002-aws-vpc-dns",
            name="AWS VPC DNS Pattern Analysis",
            description="Detect DGA-generated domains via VPC DNS query log pattern analysis.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, query_name, srcids.instance as instance_id, answers.Rdata as resolved_ip
| filter query_name like /^[a-z]{15,}\\./ or query_name like /^[0-9a-z]{20,}\\./
| stats count(*) as suspicious_queries by srcids.instance, bin(10m)
| filter suspicious_queries > 20
| sort suspicious_queries desc""",
                terraform_template="""# Detect DGA patterns via VPC DNS logs

variable "vpc_dns_log_group" {
  type        = string
  description = "VPC DNS query log group name"
}

variable "alert_email" {
  type        = string
  description = "Email address for security alerts"
}

data "aws_caller_identity" "current" {}

# Step 1: Create SNS topic for alerts
resource "aws_sns_topic" "dga_pattern_alerts" {
  name         = "dga-pattern-alerts"
  kms_master_key_id = "alias/aws/sns"
  display_name = "DGA Pattern Detection"
}

resource "aws_sns_topic_policy" "allow_cloudwatch" {
  arn = aws_sns_topic.dga_pattern_alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowCloudWatchPublish"
      Effect    = "Allow"
      Principal = { Service = "cloudwatch.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.dga_pattern_alerts.arn
      Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
      }
    }]
  })
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.dga_pattern_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Create metric filter for suspicious domain patterns
resource "aws_cloudwatch_log_metric_filter" "suspicious_domains" {
  name           = "suspicious-domain-patterns"
  log_group_name = var.vpc_dns_log_group
  # Pattern matches long random-looking domains
  pattern        = "[timestamp, query_type, instance, query_name = *????????????????*.*, ...]"

  metric_transformation {
    name      = "SuspiciousDomainQueries"
    namespace = "Security/DNS"
    value     = "1"
  }
}

# Step 3: Create CloudWatch alarm for pattern-based DGA detection
resource "aws_cloudwatch_metric_alarm" "dga_pattern_detection" {
  alarm_name          = "SuspiciousDomainPatterns-PossibleDGA"
  alarm_description   = "Detects suspicious domain query patterns indicating DGA"
  metric_name         = "SuspiciousDomainQueries"
  namespace           = "Security/DNS"
  statistic           = "Sum"
  period              = 600
  evaluation_periods  = 1
  threshold           = 50
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.dga_pattern_alerts.arn]
}""",
                alert_severity="high",
                alert_title="Suspicious Domain Pattern Detected",
                alert_description_template="Instance {instance_id} querying domains with DGA-like characteristics.",
                investigation_steps=[
                    "Review all DNS queries from affected instance",
                    "Analyse domain entropy and lexical patterns",
                    "Check instance for running malware",
                    "Review instance CloudTrail/VPC Flow logs",
                    "Identify process making DNS queries",
                    "Compare against known DGA families",
                ],
                containment_actions=[
                    "Isolate affected EC2 instance",
                    "Block identified domains at DNS level",
                    "Take memory dump for forensic analysis",
                    "Terminate instance if confirmed compromised",
                    "Deploy network IDS signatures",
                    "Review security group rules",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Exclude known domains with long random-looking subdomains (CDNs, analytics). Adjust pattern matching.",
            detection_coverage="55% - pattern-based detection catches typical DGA formats",
            evasion_considerations="Word-based DGAs or those mimicking legitimate domains may evade",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2-3 hours",
            estimated_monthly_cost="$20-50",
            prerequisites=["VPC DNS query logging enabled", "Enhanced VPC Flow Logs"],
        ),
        DetectionStrategy(
            strategy_id="t1568.002-gcp-dns-entropy",
            name="GCP Cloud DNS High Entropy Query Detection",
            description="Detect DGA activity via Cloud DNS query logs analysing entropy and NXDOMAIN rates.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""resource.type="dns_query"
protoPayload.responseCode="NXDOMAIN"
severity>=WARNING""",
                gcp_terraform_template="""# GCP: Detect DGA activity via Cloud DNS logs

variable "project_id" {
  type        = string
  description = "GCP project ID"
}

variable "alert_email" {
  type        = string
  description = "Email address for security alerts"
}

# Step 1: Create notification channel for alerts
resource "google_monitoring_notification_channel" "email" {
  project      = var.project_id
  display_name = "DGA Detection Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Create log-based metric for NXDOMAIN responses
resource "google_logging_metric" "nxdomain_rate" {
  project = var.project_id
  name    = "dns-nxdomain-rate"
  filter  = <<-EOT
    resource.type="dns_query"
    protoPayload.responseCode="NXDOMAIN"
  EOT
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    unit        = "1"
  }
}

# Step 3: Create alert policy for high NXDOMAIN rates
resource "google_monitoring_alert_policy" "dga_detection" {
  project      = var.project_id
  display_name = "High NXDOMAIN Rate - Possible DGA"
  combiner     = "OR"

  conditions {
    display_name = "High NXDOMAIN rate detected"
    condition_threshold {
      filter          = "resource.type=\"dns_query\" AND metric.type=\"logging.googleapis.com/user/${google_logging_metric.nxdomain_rate.name}\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 100
      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_RATE"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]

  alert_strategy {
    auto_close = "86400s"
  }
}""",
                alert_severity="high",
                alert_title="GCP: Possible DGA Activity Detected",
                alert_description_template="High NXDOMAIN rate detected in Cloud DNS queries indicating potential DGA activity.",
                investigation_steps=[
                    "Review Cloud DNS query logs for patterns",
                    "Identify source VM instances or services",
                    "Analyse domain names for entropy characteristics",
                    "Check VPC Flow Logs for related activity",
                    "Review VM instance processes and connections",
                    "Check for known malware signatures",
                ],
                containment_actions=[
                    "Isolate affected GCE instances",
                    "Implement Cloud DNS policies to block domains",
                    "Deploy firewall rules to restrict outbound DNS",
                    "Terminate compromised instances",
                    "Deploy DNS sinkhole configuration",
                    "Review and update security policies",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Adjust threshold based on environment DNS traffic. Exclude known high-query applications.",
            detection_coverage="65% - effective for high-volume DGA activity",
            evasion_considerations="Slow DGAs with low query rates may evade detection",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$20-45",
            prerequisites=["Cloud DNS logging enabled", "Cloud Logging API enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1568.002-gcp-vpc-dns",
            name="GCP VPC DNS Query Pattern Analysis",
            description="Detect DGA patterns via VPC DNS query log analysis for suspicious domain characteristics.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="gce_instance"
logName=~"logs/dns"
jsonPayload.queryName=~"^[a-z0-9]{15,}\\."''',
                gcp_terraform_template="""# GCP: Detect DGA via VPC DNS pattern analysis

variable "project_id" {
  type        = string
  description = "GCP project ID"
}

variable "alert_email" {
  type        = string
  description = "Email address for security alerts"
}

# Step 1: Create notification channel
resource "google_monitoring_notification_channel" "email" {
  project      = var.project_id
  display_name = "DGA Pattern Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Create log-based metric for suspicious patterns
resource "google_logging_metric" "suspicious_dns_patterns" {
  project = var.project_id
  name    = "suspicious-dns-query-patterns"
  filter  = <<-EOT
    resource.type="gce_instance"
    logName=~"logs/dns"
    jsonPayload.queryName=~"^[a-z0-9]{15,}\\."
  EOT
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    unit        = "1"
    labels {
      key         = "instance_id"
      value_type  = "STRING"
      description = "GCE instance ID"
    }
  }
  label_extractors = {
    "instance_id" = "EXTRACT(resource.labels.instance_id)"
  }
}

# Step 3: Create alert for suspicious DNS patterns
resource "google_monitoring_alert_policy" "dga_pattern_alert" {
  project      = var.project_id
  display_name = "Suspicious DNS Patterns - Possible DGA"
  combiner     = "OR"

  conditions {
    display_name = "High rate of suspicious DNS queries"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.suspicious_dns_patterns.name}\""
      duration        = "600s"
      comparison      = "COMPARISON_GT"
      threshold_value = 50
      aggregations {
        alignment_period   = "600s"
        per_series_aligner = "ALIGN_RATE"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]
}""",
                alert_severity="high",
                alert_title="GCP: Suspicious DNS Query Patterns",
                alert_description_template="GCE instance exhibiting DNS query patterns consistent with DGA activity.",
                investigation_steps=[
                    "Review VPC DNS logs for affected instance",
                    "Analyse domain structure and entropy",
                    "Check instance metadata and processes",
                    "Review VPC Flow Logs for C2 connections",
                    "Compare against threat intelligence feeds",
                    "Check for lateral movement indicators",
                ],
                containment_actions=[
                    "Isolate GCE instance from network",
                    "Create VPC firewall rules to block outbound C2",
                    "Implement Cloud DNS response policies",
                    "Take disk snapshot for forensics",
                    "Terminate and rebuild instance if confirmed",
                    "Update security monitoring rules",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Refine regex patterns to exclude legitimate services. Whitelist known CDN/cloud service domains.",
            detection_coverage="55% - pattern-based detection effective for common DGA formats",
            evasion_considerations="Dictionary-based or word-concatenation DGAs may appear more legitimate",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2-3 hours",
            estimated_monthly_cost="$25-50",
            prerequisites=["VPC Flow Logs enabled", "Cloud DNS logging enabled"],
        ),
    ],
    recommended_order=[
        "t1568.002-aws-dns-entropy",
        "t1568.002-gcp-dns-entropy",
        "t1568.002-aws-vpc-dns",
        "t1568.002-gcp-vpc-dns",
    ],
    total_effort_hours=8.0,
    coverage_improvement="+15% improvement for Command and Control tactic",
)
