"""
T1567.003 - Exfiltration to Text Storage Sites

Adversaries exfiltrate data to text storage and paste sites like Pastebin and Hastebin.
These services provide anonymous, encrypted data storage that appears as legitimate web traffic.
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
    technique_id="T1567.003",
    technique_name="Exfiltration to Text Storage Sites",
    tactic_ids=["TA0010"],
    mitre_url="https://attack.mitre.org/techniques/T1567/003/",
    threat_context=ThreatContext(
        description=(
            "Adversaries leverage text storage and paste sites (Pastebin, Hastebin, etc.) "
            "to exfiltrate stolen data. These platforms are designed for code and text sharing, "
            "making malicious uploads blend with legitimate developer activity. Many services "
            "offer paid encryption features to further conceal exfiltrated data."
        ),
        attacker_goal="Exfiltrate sensitive data using text storage sites to evade detection",
        why_technique=[
            "Appears as normal developer/IT activity",
            "HTTPS encryption hides payload content",
            "Services often allow anonymous posting",
            "Paid features provide additional encryption",
            "Bypasses traditional DLP solutions",
            "Widely accessible from corporate networks",
        ],
        known_threat_actors=[],  # MITRE page did not identify specific actors
        recent_campaigns=[
            Campaign(
                name="PowerShell Pastebin Exfiltration",
                year=2024,
                description="PowerShell scripts uploading sensitive data to Pastebin via HTTPS POST",
                reference_url="https://attack.mitre.org/techniques/T1567/003/",
            ),
            Campaign(
                name="ESXi Hastebin Upload",
                year=2024,
                description="Compromised ESXi hosts generating outbound traffic to Hastebin for data exfiltration",
                reference_url="https://attack.mitre.org/techniques/T1567/003/",
            ),
        ],
        prevalence="moderate",
        trend="stable",
        severity_score=7,
        severity_reasoning=(
            "Text storage sites provide easy, anonymous exfiltration with encryption. "
            "Difficult to distinguish from legitimate developer activity. Lower severity "
            "than cloud-to-cloud transfers due to size limitations and manual upload process."
        ),
        business_impact=[
            "Data breach and intellectual property theft",
            "Regulatory compliance violations",
            "Credential exposure",
            "Source code exfiltration",
        ],
        typical_attack_phase="exfiltration",
        often_precedes=["T1486"],
        often_follows=["T1552.001", "T1530", "T1119", "T1074"],
    ),
    detection_strategies=[
        # Strategy 1: AWS - CloudWatch DNS Query Detection
        DetectionStrategy(
            strategy_id="t1567-003-aws-dns",
            name="AWS DNS Queries to Text Storage Sites",
            description="Detect DNS queries to known text storage/paste sites from EC2/VPC.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="route53",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, query_name, srcaddr, query_type
| filter query_name like /pastebin|hastebin|paste\\.ee|dpaste|privatebin|justpaste|rentry|telegra\\.ph/
| stats count() as query_count by srcaddr, query_name, bin(5m)
| filter query_count > 0
| sort @timestamp desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect DNS queries to text storage sites

Parameters:
  Route53LogGroup:
    Type: String
    Description: Route53 Resolver Query Log Group
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

  # Step 2: CloudWatch Logs metric filter
  TextStorageDnsFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref Route53LogGroup
      FilterPattern: '[query_type, timestamp, vpc_id, query_name="*pastebin*" || query_name="*hastebin*" || query_name="*paste.ee*" || query_name="*dpaste*", ...]'
      MetricTransformations:
        - MetricName: TextStorageDnsQueries
          MetricNamespace: Security
          MetricValue: '1'
          DefaultValue: 0

  # Step 3: CloudWatch alarm
  TextStorageAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: TextStorageSiteDnsQueries
      MetricName: TextStorageDnsQueries
      Namespace: Security
      Statistic: Sum
      Period: 300
      EvaluationPeriods: 1
      Threshold: 1
      ComparisonOperator: GreaterThanThreshold
      AlarmActions:
        - !Ref AlertTopic

  TopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics: [!Ref AlertTopic]
      PolicyDocument:
        Statement:
          - Effect: Allow
            Principal:
              Service: cloudwatch.amazonaws.com
            Action: sns:Publish
            Resource: !Ref AlertTopic""",
                terraform_template="""# Detect DNS queries to text storage sites

variable "route53_log_group" {
  type        = string
  description = "Route53 Resolver Query Log Group"
}

variable "alert_email" {
  type = string
}

# Step 1: SNS topic for alerts
resource "aws_sns_topic" "alerts" {
  name = "text-storage-dns-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: CloudWatch Logs metric filter
resource "aws_cloudwatch_log_metric_filter" "text_storage_dns" {
  name           = "text-storage-dns-queries"
  log_group_name = var.route53_log_group
  pattern        = "[query_type, timestamp, vpc_id, query_name=\"*pastebin*\" || query_name=\"*hastebin*\" || query_name=\"*paste.ee*\" || query_name=\"*dpaste*\", ...]"

  metric_transformation {
    name      = "TextStorageDnsQueries"
    namespace = "Security"
    value     = "1"
  }
}

# Step 3: CloudWatch alarm
resource "aws_cloudwatch_metric_alarm" "text_storage" {
  alarm_name          = "TextStorageSiteDnsQueries"
  metric_name         = "TextStorageDnsQueries"
  namespace           = "Security"
  statistic           = "Sum"
  period              = 300
  threshold           = 1
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  alarm_actions       = [aws_sns_topic.alerts.arn]
}

resource "aws_sns_topic_policy" "allow_cloudwatch" {
  arn = aws_sns_topic.alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "cloudwatch.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.alerts.arn
    }]
  })
}""",
                alert_severity="high",
                alert_title="DNS Query to Text Storage Site",
                alert_description_template="Instance {srcaddr} queried text storage domain {query_name}.",
                investigation_steps=[
                    "Identify the source instance/container making DNS queries",
                    "Review process activity on the source system",
                    "Check for outbound HTTPS connections to the domain",
                    "Examine recent file access patterns for sensitive data",
                    "Review CloudTrail for recent API activity by associated IAM role",
                ],
                containment_actions=[
                    "Block text storage domains via security groups/NACLs",
                    "Isolate the affected instance for forensic analysis",
                    "Revoke IAM credentials for the instance role",
                    "Enable VPC Flow Logs if not already enabled",
                    "Implement DNS firewall rules for paste site domains",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Monitor during business hours; legitimate developer use is typically manual/infrequent",
            detection_coverage="75% - catches DNS-based reconnaissance and access",
            evasion_considerations="Direct IP connections or lesser-known paste sites bypass DNS detection",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=[
                "Route53 Resolver Query Logging enabled",
                "CloudWatch Logs configured",
            ],
        ),
        # Strategy 2: AWS - VPC Flow Logs for HTTPS POST to Paste Sites
        DetectionStrategy(
            strategy_id="t1567-003-aws-vpc",
            name="AWS VPC HTTPS Traffic to Text Storage IPs",
            description="Detect outbound HTTPS connections to text storage site IP addresses.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="vpc",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, srcAddr, dstAddr, dstPort, bytes, packets
| filter dstPort = 443
| filter action = "ACCEPT"
| filter bytes > 10000
| stats sum(bytes) as total_bytes, count() as conn_count by srcAddr, dstAddr, bin(10m)
| filter total_bytes > 50000
| sort total_bytes desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect HTTPS traffic patterns to text storage sites

Parameters:
  VpcFlowLogGroup:
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

  # Step 2: Metric filter for large HTTPS uploads
  LargeHttpsUploadFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref VpcFlowLogGroup
      FilterPattern: '[version, account, eni, source, destination, srcport, dstport="443", protocol="6", packets, bytes > 50000, ...]'
      MetricTransformations:
        - MetricName: LargeHttpsUpload
          MetricNamespace: Security
          MetricValue: '$bytes'
          DefaultValue: 0

  # Step 3: Alarm for suspicious uploads
  HttpsUploadAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: LargeHttpsUploadDetected
      MetricName: LargeHttpsUpload
      Namespace: Security
      Statistic: Sum
      Period: 600
      EvaluationPeriods: 1
      Threshold: 100000
      ComparisonOperator: GreaterThanThreshold
      AlarmActions:
        - !Ref AlertTopic

  TopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics: [!Ref AlertTopic]
      PolicyDocument:
        Statement:
          - Effect: Allow
            Principal:
              Service: cloudwatch.amazonaws.com
            Action: sns:Publish
            Resource: !Ref AlertTopic""",
                terraform_template="""# Detect HTTPS traffic patterns to text storage sites

variable "vpc_flow_log_group" {
  type = string
}

variable "alert_email" {
  type = string
}

# Step 1: SNS topic
resource "aws_sns_topic" "alerts" {
  name = "https-upload-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Metric filter for large HTTPS uploads
resource "aws_cloudwatch_log_metric_filter" "https_upload" {
  name           = "large-https-upload"
  log_group_name = var.vpc_flow_log_group
  pattern        = "[version, account, eni, source, destination, srcport, dstport=\"443\", protocol=\"6\", packets, bytes > 50000, ...]"

  metric_transformation {
    name      = "LargeHttpsUpload"
    namespace = "Security"
    value     = "$bytes"
  }
}

# Step 3: Alarm for suspicious uploads
resource "aws_cloudwatch_metric_alarm" "https_upload" {
  alarm_name          = "LargeHttpsUploadDetected"
  metric_name         = "LargeHttpsUpload"
  namespace           = "Security"
  statistic           = "Sum"
  period              = 600
  threshold           = 100000
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  alarm_actions       = [aws_sns_topic.alerts.arn]
}

resource "aws_sns_topic_policy" "allow_cloudwatch" {
  arn = aws_sns_topic.alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "cloudwatch.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.alerts.arn
    }]
  })
}""",
                alert_severity="medium",
                alert_title="Large HTTPS Upload Detected",
                alert_description_template="Instance {srcAddr} uploaded {total_bytes} bytes via HTTPS to {dstAddr}.",
                investigation_steps=[
                    "Correlate with DNS logs to identify destination domain",
                    "Review CloudWatch Logs for application/system logs from source",
                    "Identify processes making network connections",
                    "Check for file staging or compression activity",
                    "Review IAM CloudTrail activity for the instance role",
                ],
                containment_actions=[
                    "Block destination IP via security groups",
                    "Quarantine affected instance",
                    "Analyse network packet captures if available",
                    "Review and rotate credentials for affected workloads",
                    "Implement egress filtering for paste site domains",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Baseline normal HTTPS upload patterns; exclude CDN/backup destinations",
            detection_coverage="60% - network-level detection of upload activity",
            evasion_considerations="Low-and-slow exfiltration or fragmented uploads may evade thresholds",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$10-25",
            prerequisites=["VPC Flow Logs enabled and sent to CloudWatch"],
        ),
        # Strategy 3: AWS - GuardDuty for Unusual Outbound Activity
        DetectionStrategy(
            strategy_id="t1567-003-aws-guardduty",
            name="AWS GuardDuty Unusual Outbound Activity",
            description="Leverage GuardDuty findings for unusual outbound network activity patterns.",
            detection_type=DetectionType.GUARDDUTY,
            aws_service="guardduty",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                guardduty_finding_types=[
                    "Behavior:EC2/NetworkPortUnusual",
                    "Behavior:EC2/TrafficVolumeUnusual",
                    "UnauthorizedAccess:EC2/TorClient",
                ],
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Route GuardDuty exfiltration findings to SNS

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

  # Step 2: EventBridge rule for GuardDuty findings
  GuardDutyExfilRule:
    Type: AWS::Events::Rule
    Properties:
      Description: Alert on GuardDuty exfiltration-related findings
      EventPattern:
        source: [aws.guardduty]
        detail-type: [GuardDuty Finding]
        detail:
          type:
            - prefix: Behavior:EC2/NetworkPortUnusual
            - prefix: Behavior:EC2/TrafficVolumeUnusual
            - prefix: Exfiltration:
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
                terraform_template="""# Route GuardDuty exfiltration findings to SNS

variable "alert_email" {
  type = string
}

# Step 1: SNS topic
resource "aws_sns_topic" "alerts" {
  name = "guardduty-exfil-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: EventBridge rule for GuardDuty findings
resource "aws_cloudwatch_event_rule" "guardduty_exfil" {
  name        = "guardduty-exfiltration-findings"
  description = "Alert on GuardDuty exfiltration-related findings"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail = {
      type = [
        { prefix = "Behavior:EC2/NetworkPortUnusual" },
        { prefix = "Behavior:EC2/TrafficVolumeUnusual" },
        { prefix = "Exfiltration:" }
      ]
    }
  })
}

resource "aws_cloudwatch_event_target" "sns" {
  rule = aws_cloudwatch_event_rule.guardduty_exfil.name
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
                alert_title="GuardDuty: Unusual Network Activity Detected",
                alert_description_template="GuardDuty detected unusual outbound activity from {resource.instanceDetails.instanceId}.",
                investigation_steps=[
                    "Review the full GuardDuty finding details",
                    "Identify the affected EC2 instance and its role",
                    "Examine CloudTrail logs for the instance's IAM role",
                    "Review Systems Manager Session Manager logs if applicable",
                    "Check for recently deployed applications or scripts",
                ],
                containment_actions=[
                    "Isolate the instance using security group changes",
                    "Take an EBS snapshot for forensic analysis",
                    "Terminate the instance if confirmed malicious",
                    "Review and rotate all credentials accessible to the instance",
                    "Enable GuardDuty malware protection if available",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="GuardDuty uses ML baselines; tune suppression rules for known batch jobs",
            detection_coverage="70% - broad anomaly detection for unusual patterns",
            evasion_considerations="Gradual exfiltration within normal traffic patterns may not trigger anomaly detection",
            implementation_effort=EffortLevel.LOW,
            implementation_time="20 minutes",
            estimated_monthly_cost="$3-8 (assumes GuardDuty already enabled)",
            prerequisites=["GuardDuty enabled in the region"],
        ),
        # Strategy 4: GCP - Cloud Logging for Text Storage Site Access
        DetectionStrategy(
            strategy_id="t1567-003-gcp-dns",
            name="GCP Cloud DNS Query Logs for Paste Sites",
            description="Detect DNS queries to text storage sites from GCP resources.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""resource.type="dns_query"
(protoPayload.queryName=~"pastebin|hastebin|paste\\.ee|dpaste|privatebin|justpaste|rentry")""",
                gcp_terraform_template="""# GCP: Detect DNS queries to text storage sites

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

# Step 2: Log-based metric for text storage DNS queries
resource "google_logging_metric" "text_storage_dns" {
  name   = "text-storage-dns-queries"
  filter = <<-EOT
    resource.type="dns_query"
    (protoPayload.queryName=~"pastebin|hastebin|paste\\.ee|dpaste|privatebin|justpaste|rentry")
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Alert policy
resource "google_monitoring_alert_policy" "text_storage_dns" {
  display_name = "Text Storage Site DNS Queries"
  combiner     = "OR"

  conditions {
    display_name = "DNS queries to paste sites"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.text_storage_dns.name}\""
      duration        = "60s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]

  alert_strategy {
    notification_rate_limit {
      period = "300s"
    }
  }
}""",
                alert_severity="high",
                alert_title="GCP: DNS Query to Text Storage Site",
                alert_description_template="GCP resource queried text storage domain.",
                investigation_steps=[
                    "Identify the source GCE instance or service making queries",
                    "Review VPC Flow Logs for corresponding HTTPS connections",
                    "Examine Cloud Logging for application logs from the source",
                    "Check recent IAM activity for the service account",
                    "Review file access patterns on the instance",
                ],
                containment_actions=[
                    "Block text storage domains using Cloud DNS policies",
                    "Isolate the affected GCE instance",
                    "Revoke service account credentials",
                    "Enable VPC Flow Logs if not already configured",
                    "Implement VPC Service Controls for perimeter security",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Exclude known developer workstations during code review periods",
            detection_coverage="75% - catches DNS-based access attempts",
            evasion_considerations="Direct IP connections or use of alternative DNS resolvers bypass detection",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$5-12",
            prerequisites=["Cloud DNS logging enabled", "Cloud Logging API enabled"],
        ),
        # Strategy 5: GCP - VPC Flow Logs for HTTPS to Paste Sites
        DetectionStrategy(
            strategy_id="t1567-003-gcp-vpc",
            name="GCP VPC Flow Logs HTTPS Upload Detection",
            description="Detect large HTTPS uploads from GCP VPC resources.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="vpc",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""resource.type="gce_subnetwork"
logName="projects/PROJECT_ID/logs/compute.googleapis.com%2Fvpc_flows"
jsonPayload.connection.dest_port=443
jsonPayload.bytes_sent > 50000""",
                gcp_terraform_template="""# GCP: Detect large HTTPS uploads via VPC Flow Logs

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

# Step 2: Log-based metric for large HTTPS uploads
resource "google_logging_metric" "large_https_upload" {
  name   = "large-https-uploads"
  filter = <<-EOT
    resource.type="gce_subnetwork"
    logName="projects/${var.project_id}/logs/compute.googleapis.com%2Fvpc_flows"
    jsonPayload.connection.dest_port=443
    jsonPayload.bytes_sent > 50000
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }

  value_extractor = "EXTRACT(jsonPayload.bytes_sent)"
}

# Step 3: Alert policy
resource "google_monitoring_alert_policy" "large_https_upload" {
  display_name = "Large HTTPS Upload Detected"
  combiner     = "OR"

  conditions {
    display_name = "Unusual HTTPS upload volume"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.large_https_upload.name}\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 100000
      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_SUM"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]
}""",
                alert_severity="medium",
                alert_title="GCP: Large HTTPS Upload Detected",
                alert_description_template="GCE instance uploaded significant data via HTTPS.",
                investigation_steps=[
                    "Correlate VPC Flow Logs with DNS logs for destination domain",
                    "Review Cloud Logging for application activity on source instance",
                    "Identify processes with network activity using OS logs",
                    "Check for recent file staging or archive creation",
                    "Review Cloud Audit Logs for IAM and API activity",
                ],
                containment_actions=[
                    "Block destination IP using firewall rules",
                    "Isolate the affected instance via VPC firewall",
                    "Snapshot the instance disk for forensic analysis",
                    "Rotate service account keys",
                    "Enable Private Google Access and restrict egress",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Baseline normal upload patterns; exclude CI/CD and backup systems",
            detection_coverage="60% - network-level upload detection",
            evasion_considerations="Low-and-slow exfiltration or use of fragmentation",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$10-20",
            prerequisites=[
                "VPC Flow Logs enabled for subnets",
                "Cloud Logging configured",
            ],
        ),
    ],
    recommended_order=[
        "t1567-003-aws-dns",
        "t1567-003-gcp-dns",
        "t1567-003-aws-guardduty",
        "t1567-003-aws-vpc",
        "t1567-003-gcp-vpc",
    ],
    total_effort_hours=4.0,
    coverage_improvement="+12% improvement for Exfiltration tactic",
)
