"""
T1090.003 - Proxy: Multi-hop Proxy

Adversaries chain multiple proxies to obscure malicious traffic origins,
complicating defender efforts to trace attacks through relay layers.
Used by APT28, APT29, Inception, Leviathan, Volt Typhoon.
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
    technique_id="T1090.003",
    technique_name="Proxy: Multi-hop Proxy",
    tactic_ids=["TA0011"],
    mitre_url="https://attack.mitre.org/techniques/T1090/003/",
    threat_context=ThreatContext(
        description=(
            "Adversaries chain multiple proxies to obscure malicious traffic origins, "
            "complicating defender efforts to trace attacks through relay layers. This includes "
            "onion routing networks like Tor, operational relay boxes (ORB) composed of VPS instances, "
            "compromised network devices chained together, and blockchain/P2P infrastructure for routing obfuscation."
        ),
        attacker_goal="Obscure command-and-control traffic origins through multiple proxy layers",
        why_technique=[
            "Extremely difficult to trace back to origin",
            "Anonymity networks like Tor readily available",
            "Can leverage compromised infrastructure",
            "Defeats traditional IP-based blocking",
            "Multiple relay layers provide redundancy",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="moderate",
        trend="increasing",
        severity_score=7,
        severity_reasoning=(
            "Multi-hop proxies significantly complicate attribution and network defence efforts. "
            "While detection is possible through traffic analysis, the technique provides adversaries "
            "with strong operational security against traditional IP-based blocking and attribution."
        ),
        business_impact=[
            "Difficult attribution and incident response",
            "Extended dwell time due to obscured C2",
            "Challenges in blocking malicious traffic",
            "Legal/jurisdictional complexities in investigation",
        ],
        typical_attack_phase="command_and_control",
        often_precedes=["T1041", "T1071"],
        often_follows=["T1071", "T1573"],
    ),
    detection_strategies=[
        DetectionStrategy(
            strategy_id="t1090-003-aws-tor",
            name="AWS Tor Traffic Detection",
            description="Detect connections to known Tor entry nodes and relays.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, srcaddr, dstaddr, dstport, protocol, bytes
| filter action = "ACCEPT"
| filter (dstport = 9001 or dstport = 9030 or dstport = 443)
| stats count(*) as connections, sum(bytes) as total_bytes by srcaddr, dstaddr, bin(5m)
| filter connections > 3
| sort total_bytes desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect Tor and multi-hop proxy traffic

Parameters:
  VPCFlowLogGroup:
    Type: String
    Description: VPC Flow Logs log group name
  AlertEmail:
    Type: String
    Description: Email for security alerts

Resources:
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  TorTrafficFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref VPCFlowLogGroup
      # Match Tor common ports: 9001 (relay), 9030 (directory), 443 (obfs)
      FilterPattern: '[version, account, eni, source, destination, srcport, destport="9001" || destport="9030", protocol, packets, bytes, start, end, action="ACCEPT", flowlogstatus]'
      MetricTransformations:
        - MetricName: TorConnections
          MetricNamespace: Security/Proxy
          MetricValue: "1"

  TorTrafficAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: MultiHopProxyDetected
      AlarmDescription: Detected connections to Tor network
      MetricName: TorConnections
      Namespace: Security/Proxy
      Statistic: Sum
      Period: 300
      Threshold: 5
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      TreatMissingData: notBreaching

      AlarmActions: [!Ref AlertTopic]""",
                terraform_template="""# Detect Tor and multi-hop proxy traffic

variable "vpc_flow_log_group" {
  type        = string
  description = "VPC Flow Logs log group name"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

resource "aws_sns_topic" "proxy_alerts" {
  name = "multi-hop-proxy-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.proxy_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_cloudwatch_log_metric_filter" "tor_traffic" {
  name           = "tor-connections"
  log_group_name = var.vpc_flow_log_group
  # Match Tor common ports: 9001 (relay), 9030 (directory), 443 (obfs)
  pattern = "[version, account, eni, source, destination, srcport, destport=9001 || destport=9030, protocol, packets, bytes, start, end, action=ACCEPT, flowlogstatus]"

  metric_transformation {
    name      = "TorConnections"
    namespace = "Security/Proxy"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "tor_detection" {
  alarm_name          = "MultiHopProxyDetected"
  alarm_description   = "Detected connections to Tor network"
  metric_name         = "TorConnections"
  namespace           = "Security/Proxy"
  statistic           = "Sum"
  period              = 300
  threshold           = 5
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.proxy_alerts.arn]
}""",
                alert_severity="high",
                alert_title="Multi-hop Proxy Traffic Detected",
                alert_description_template="Detected connections to Tor or proxy infrastructure from {srcaddr}.",
                investigation_steps=[
                    "Identify source instance and workload purpose",
                    "Review CloudTrail for API activity from instance",
                    "Check for unauthorised processes or binaries",
                    "Analyse full connection history and patterns",
                    "Review for data exfiltration indicators",
                ],
                containment_actions=[
                    "Block Tor entry nodes at security group/NACL",
                    "Isolate compromised instance",
                    "Capture memory and disk forensics",
                    "Review IAM credentials for exposure",
                    "Deploy DPI/SSL inspection if appropriate",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Legitimate Tor usage in enterprise is rare. Whitelist known privacy tools if used.",
            detection_coverage="60% - catches known Tor ports",
            evasion_considerations="Domain fronting and non-standard ports can evade detection",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes - 1 hour",
            estimated_monthly_cost="$5-10",
            prerequisites=["VPC Flow Logs enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1090-003-aws-suspicious-chains",
            name="AWS Suspicious Proxy Chain Detection",
            description="Detect suspicious multi-stage connection patterns indicating proxy chains.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, srcaddr, dstaddr, protocol, bytes
| filter action = "ACCEPT"
| filter protocol = 6
| stats count(*) as unique_destinations, sum(bytes) as total_bytes by srcaddr, bin(10m)
| filter unique_destinations > 20 and total_bytes < 1000000
| sort unique_destinations desc""",
                terraform_template="""# Detect suspicious proxy chain behaviour

variable "vpc_flow_log_group" {
  type        = string
  description = "VPC Flow Logs log group name"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

resource "aws_sns_topic" "proxy_alerts" {
  name = "proxy-chain-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.proxy_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# This requires CloudWatch Insights for complex analysis
# Deploy as scheduled query for regular scanning
resource "aws_cloudwatch_query_definition" "proxy_chains" {
  name = "suspicious-proxy-chains"

  log_group_names = [var.vpc_flow_log_group]

  query_string = <<-EOT
    fields @timestamp, srcaddr, dstaddr, protocol, bytes
    | filter action = "ACCEPT"
    | filter protocol = 6
    | stats count(*) as unique_destinations, sum(bytes) as total_bytes by srcaddr, bin(10m)
    | filter unique_destinations > 20 and total_bytes < 1000000
    | sort unique_destinations desc
  EOT
}

# Note: For automated alerting, consider using Lambda to run this query
# and publish metrics based on results""",
                alert_severity="medium",
                alert_title="Suspicious Proxy Chain Behaviour Detected",
                alert_description_template="Instance {srcaddr} showing proxy relay patterns with {unique_destinations} destinations.",
                investigation_steps=[
                    "Review instance role and purpose",
                    "Check for proxy software installation",
                    "Analyse connection destinations",
                    "Review for compromised credentials",
                    "Check application logs for anomalies",
                ],
                containment_actions=[
                    "Restrict outbound connections via security groups",
                    "Rotate IAM credentials",
                    "Isolate instance for investigation",
                    "Review for lateral movement",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Tune thresholds based on legitimate proxy/NAT infrastructure. Exclude known proxy servers.",
            detection_coverage="40% - pattern-based heuristic",
            evasion_considerations="Slow/low connections can evade volume thresholds",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$10-20",
            prerequisites=["VPC Flow Logs enabled", "CloudWatch Insights"],
        ),
        DetectionStrategy(
            strategy_id="t1090-003-aws-guardduty",
            name="AWS GuardDuty Tor Detection",
            description="Leverage GuardDuty's built-in Tor node detection.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="guardduty",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, type, severity, resource.instanceDetails.instanceId, service.action.networkConnectionAction.remoteIpDetails.ipAddressV4
| filter type like /Tor/
| sort @timestamp desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Alert on GuardDuty Tor detections

Parameters:
  AlertEmail:
    Type: String
    Description: Email for security alerts

Resources:
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # EventBridge rule to catch GuardDuty Tor findings
  TorFindingRule:
    Type: AWS::Events::Rule
    Properties:
      Name: GuardDutyTorDetection
      Description: Alert on Tor-related GuardDuty findings
      State: ENABLED
      EventPattern:
        source:
          - aws.guardduty
        detail-type:
          - GuardDuty Finding
        detail:
          type:
            - prefix: "Backdoor:EC2/C&CActivity.B!DNS"
            - prefix: "UnauthorizedAccess:EC2/TorRelay"
            - prefix: "UnauthorizedAccess:EC2/TorClient"
      Targets:
        - Arn: !Ref AlertTopic
          Id: TorAlertTarget""",
                terraform_template="""# Alert on GuardDuty Tor detections

variable "alert_email" {
  type        = string
  description = "Email for security alerts"

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
}

resource "aws_sns_topic" "guardduty_tor_alerts" {
  name = "guardduty-tor-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.guardduty_tor_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# EventBridge rule to catch GuardDuty Tor findings
resource "aws_cloudwatch_event_rule" "tor_findings" {
  name        = "guardduty-tor-detection"
  description = "Alert on Tor-related GuardDuty findings"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail = {
      type = [
        { prefix = "Backdoor:EC2/C&CActivity.B!DNS" },
        { prefix = "UnauthorizedAccess:EC2/TorRelay" },
        { prefix = "UnauthorizedAccess:EC2/TorClient" }
      ]
    }
  })
}

resource "aws_cloudwatch_event_target" "sns" {
  rule      = aws_cloudwatch_event_rule.tor_findings.name
  target_id = "TorAlertTarget"
  arn       = aws_sns_topic.guardduty_tor_alerts.arn
}

data "aws_caller_identity" "current" {}

resource "aws_sns_topic_policy" "guardduty_publish" {
  arn = aws_sns_topic.guardduty_tor_alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "events.amazonaws.com"
      }
      Action   = "SNS:Publish"
      Resource = aws_sns_topic.guardduty_tor_alerts.arn
    Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
      }
    }]
  })
}""",
                alert_severity="high",
                alert_title="GuardDuty: Tor Activity Detected",
                alert_description_template="GuardDuty detected Tor-related activity from instance {instanceId}.",
                investigation_steps=[
                    "Review GuardDuty finding details",
                    "Check instance for authorised Tor usage",
                    "Review CloudTrail for instance API activity",
                    "Analyse network connections",
                    "Check for indicators of compromise",
                ],
                containment_actions=[
                    "Isolate affected instance",
                    "Block Tor exit nodes at network level",
                    "Rotate IAM credentials",
                    "Perform forensic analysis",
                    "Review security group configurations",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="GuardDuty Tor detections are highly accurate. Suppress for legitimate use cases only.",
            detection_coverage="80% - GuardDuty maintains updated Tor node lists",
            evasion_considerations="Non-Tor multi-hop proxies will not trigger this detection",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$0 (GuardDuty costs separate)",
            prerequisites=["AWS GuardDuty enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1090-003-gcp-tor",
            name="GCP Tor Traffic Detection",
            description="Detect connections to known Tor infrastructure via VPC Flow Logs.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="gce_subnetwork"
jsonPayload.connection.dest_port=(9001 OR 9030 OR 443)
jsonPayload.reporter="SRC"
NOT jsonPayload.dest_instance.vm_name=""''',
                gcp_terraform_template="""# GCP: Detect Tor and multi-hop proxy traffic

variable "project_id" {
  type        = string
  description = "GCP project ID"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

resource "google_monitoring_notification_channel" "email" {
  display_name = "Proxy Security Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

resource "google_logging_metric" "tor_connections" {
  name   = "tor-proxy-connections"
  filter = <<-EOT
    resource.type="gce_subnetwork"
    jsonPayload.connection.dest_port=(9001 OR 9030 OR 443)
    jsonPayload.reporter="SRC"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "instance_name"
      value_type  = "STRING"
      description = "Source instance name"
    }
  }

  label_extractors = {
    "instance_name" = "EXTRACT(jsonPayload.src_instance.vm_name)"
  }
}

resource "google_monitoring_alert_policy" "tor_detected" {
  display_name = "Multi-hop Proxy (Tor) Traffic Detected"
  combiner     = "OR"

  conditions {
    display_name = "Tor connections detected"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.tor_connections.name}\""
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

  documentation {
    content = <<-EOT
      Detected connections to Tor network infrastructure (ports 9001, 9030, 443).
      This may indicate multi-hop proxy usage for command-and-control obfuscation.

      Investigation steps:
      1. Identify source VM and workload purpose
      2. Review audit logs for VM activity
      3. Check for unauthorised software
      4. Analyse connection patterns
      5. Look for data exfiltration indicators
    EOT
  }
}""",
                alert_severity="high",
                alert_title="GCP: Multi-hop Proxy Traffic Detected",
                alert_description_template="Detected Tor connections from instance {instance_name}.",
                investigation_steps=[
                    "Identify source VM and check authorisation",
                    "Review Cloud Audit Logs for VM activity",
                    "Check for proxy software installation",
                    "Analyse connection history",
                    "Review for data exfiltration patterns",
                ],
                containment_actions=[
                    "Update firewall rules to block Tor",
                    "Isolate compromised VM",
                    "Take VM snapshot for forensics",
                    "Rotate service account keys",
                    "Review VPC service controls",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Legitimate Tor usage is rare in GCP environments. Whitelist if privacy tools are authorised.",
            detection_coverage="60% - catches known Tor ports",
            evasion_considerations="Non-standard ports and domain fronting can evade",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes - 1 hour",
            estimated_monthly_cost="$5-10",
            prerequisites=["VPC Flow Logs enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1090-003-gcp-proxy-chains",
            name="GCP Suspicious Proxy Pattern Detection",
            description="Detect unusual connection patterns indicating proxy relay behaviour.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""resource.type="gce_subnetwork"
jsonPayload.reporter="SRC"
jsonPayload.bytes_sent<100000""",
                gcp_terraform_template="""# GCP: Detect suspicious proxy chain patterns

variable "project_id" {
  type        = string
  description = "GCP project ID"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

resource "google_monitoring_notification_channel" "email" {
  display_name = "Proxy Chain Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Log sink to BigQuery for advanced analysis
resource "google_bigquery_dataset" "flow_logs" {
  dataset_id = "vpc_flow_logs"
  location   = "US"

  default_table_expiration_ms = 2592000000 # 30 days
}

resource "google_logging_project_sink" "flow_logs_sink" {
  name        = "vpc-flow-logs-sink"
  destination = "bigquery.googleapis.com/projects/${var.project_id}/datasets/${google_bigquery_dataset.flow_logs.dataset_id}"

  filter = <<-EOT
    resource.type="gce_subnetwork"
    jsonPayload.reporter="SRC"
  EOT

  unique_writer_identity = true
}

# Grant BigQuery data editor role to log sink
resource "google_bigquery_dataset_iam_member" "log_sink_writer" {
  dataset_id = google_bigquery_dataset.flow_logs.dataset_id
  role       = "roles/bigquery.dataEditor"
  member     = google_logging_project_sink.flow_logs_sink.writer_identity
}

# Scheduled query to detect proxy patterns
resource "google_bigquery_job" "proxy_pattern_detection" {
  job_id = "proxy-pattern-detection"

  query {
    query = <<-EOT
      SELECT
        jsonPayload.src_instance.vm_name as instance_name,
        COUNT(DISTINCT jsonPayload.connection.dest_ip) as unique_destinations,
        SUM(CAST(jsonPayload.bytes_sent AS INT64)) as total_bytes,
        TIMESTAMP_TRUNC(timestamp, HOUR) as hour
      FROM `${var.project_id}.${google_bigquery_dataset.flow_logs.dataset_id}.*`
      WHERE jsonPayload.reporter = "SRC"
      GROUP BY instance_name, hour
      HAVING unique_destinations > 20 AND total_bytes < 1000000
      ORDER BY unique_destinations DESC
    EOT

    use_legacy_sql = false
  }
}""",
                alert_severity="medium",
                alert_title="GCP: Suspicious Proxy Chain Pattern",
                alert_description_template="Instance {instance_name} showing proxy relay behaviour with multiple destinations.",
                investigation_steps=[
                    "Review VM purpose and configuration",
                    "Check for proxy software installation",
                    "Analyse destination IPs and ports",
                    "Review service account permissions",
                    "Check for lateral movement indicators",
                ],
                containment_actions=[
                    "Restrict egress via firewall rules",
                    "Rotate service account keys",
                    "Isolate VM for investigation",
                    "Review IAM policies",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Exclude legitimate proxy/NAT VMs. Tune thresholds based on normal traffic patterns.",
            detection_coverage="40% - pattern-based heuristic",
            evasion_considerations="Slow/low-volume connections can evade detection",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2-3 hours",
            estimated_monthly_cost="$15-30",
            prerequisites=["VPC Flow Logs enabled", "BigQuery dataset"],
        ),
    ],
    recommended_order=[
        "t1090-003-aws-guardduty",
        "t1090-003-aws-tor",
        "t1090-003-gcp-tor",
        "t1090-003-aws-suspicious-chains",
        "t1090-003-gcp-proxy-chains",
    ],
    total_effort_hours=7.0,
    coverage_improvement="+15% improvement for Command and Control tactic",
)
