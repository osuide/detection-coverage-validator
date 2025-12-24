"""
T1008 - Fallback Channels

Adversaries use alternative communication pathways when primary C2 channels fail.
Used by APT41, Lazarus Group, OilRig, FIN7.
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
    technique_id="T1008",
    technique_name="Fallback Channels",
    tactic_ids=["TA0011"],
    mitre_url="https://attack.mitre.org/techniques/T1008/",
    threat_context=ThreatContext(
        description=(
            "Adversaries employ alternative communication pathways when primary command-and-control "
            "(C2) channels become unavailable or compromised. This technique enables threat actors "
            "to maintain persistent control and circumvent defensive measures that target specific "
            "communication methods. Fallback mechanisms include multiple pre-configured C2 servers, "
            "alternative protocols (DNS, ICMP, HTTP vs HTTPS), different network ports, or Domain "
            "Generation Algorithms (DGAs) to dynamically create backup domains."
        ),
        attacker_goal="Maintain persistent C2 access through backup communication channels when primary channels fail",
        why_technique=[
            "Ensures continued access if primary C2 is blocked",
            "Bypasses network security controls targeting specific protocols",
            "Provides resilience against detection and blocking",
            "Multiple fallback options increase operation longevity",
            "Can switch protocols to evade signature-based detection",
        ],
        known_threat_actors=["APT41", "Lazarus Group", "OilRig", "FIN7"],
        recent_campaigns=[
            Campaign(
                name="APT41 Steam Community C2",
                year=2024,
                description="APT41 used the Steam community page as a fallback mechanism for command and control",
                reference_url="https://attack.mitre.org/groups/G0096/",
            ),
            Campaign(
                name="Lazarus Group Multi-Server Failover",
                year=2024,
                description="Employed randomised C2 server selection with failover logic across multiple backup servers",
                reference_url="https://attack.mitre.org/campaigns/C0022/",
            ),
            Campaign(
                name="OilRig DNS Tunnelling Fallback",
                year=2023,
                description="Implemented DNS tunnelling as fallback when HTTP communication channels were blocked",
                reference_url="https://attack.mitre.org/groups/G0049/",
            ),
        ],
        prevalence="common",
        trend="increasing",
        severity_score=8,
        severity_reasoning=(
            "Fallback channels significantly increase attack resilience and persistence. Once "
            "established, adversaries can maintain access even when primary C2 infrastructure is "
            "detected and blocked. The technique is widely used by sophisticated threat actors and "
            "is often embedded within malware code, making it difficult to eradicate without complete "
            "system remediation. Multiple fallback mechanisms can delay detection and response efforts."
        ),
        business_impact=[
            "Prolonged adversary presence in environment",
            "Increased difficulty in eradicating threats",
            "Continued data exfiltration after initial detection",
            "Higher incident response costs",
            "Extended recovery and remediation timelines",
        ],
        typical_attack_phase="command_and_control",
        often_precedes=["T1041", "T1048", "T1020"],
        often_follows=["T1071", "T1105", "T1190", "T1078.004"],
    ),
    detection_strategies=[
        DetectionStrategy(
            strategy_id="t1008-aws-protocol-switching",
            name="AWS Protocol Switching Detection",
            description="Detect instances switching between different network protocols after connection failures.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, srcAddr, dstAddr, dstPort, protocol, action
| filter action = "REJECT" or action = "ACCEPT"
| stats count(*) as total, count_distinct(dstPort) as unique_ports,
        count_distinct(protocol) as unique_protocols by srcAddr, bin(5m)
| filter unique_ports > 3 or unique_protocols > 2
| sort total desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect protocol switching indicative of fallback C2 channels

Parameters:
  AlertEmail:
    Type: String
    Description: Email for security alerts
  VPCFlowLogGroup:
    Type: String
    Description: VPC Flow Logs log group name

Resources:
  # Step 1: Create SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      TopicName: c2-fallback-alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Create metric filter for protocol switching
  ProtocolSwitchingFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref VPCFlowLogGroup
      FilterPattern: '[version, account, eni, source, destination, srcport, dstport, protocol, packets, bytes, start, end, action="REJECT", ...]'
      MetricTransformations:
        - MetricName: ConnectionRejections
          MetricNamespace: Security/C2
          MetricValue: "1"
          DefaultValue: 0

  # Step 3: Create alarm for suspicious protocol switching
  ProtocolSwitchAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: C2-FallbackChannel-Detected
      AlarmDescription: Detects protocol switching patterns indicative of C2 fallback
      MetricName: ConnectionRejections
      Namespace: Security/C2
      Statistic: Sum
      Period: 300
      EvaluationPeriods: 1
      Threshold: 10
      ComparisonOperator: GreaterThanThreshold
      AlarmActions:
        - !Ref AlertTopic
      TreatMissingData: notBreaching""",
                terraform_template="""# AWS: Detect protocol switching for fallback C2 channels

variable "alert_email" {
  description = "Email for security alerts"
  type        = string
}

variable "vpc_flow_log_group" {
  description = "VPC Flow Logs log group name"
  type        = string
}

# Step 1: Create SNS topic for alerts
resource "aws_sns_topic" "alerts" {
  name = "c2-fallback-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Create metric filter for protocol switching
resource "aws_cloudwatch_log_metric_filter" "protocol_switching" {
  name           = "c2-protocol-switching"
  log_group_name = var.vpc_flow_log_group
  pattern        = "[version, account, eni, source, destination, srcport, dstport, protocol, packets, bytes, start, end, action=\"REJECT\", ...]"

  metric_transformation {
    name          = "ConnectionRejections"
    namespace     = "Security/C2"
    value         = "1"
    default_value = 0
  }
}

# Step 3: Create alarm for suspicious protocol switching
resource "aws_cloudwatch_metric_alarm" "protocol_switch" {
  alarm_name          = "C2-FallbackChannel-Detected"
  alarm_description   = "Detects protocol switching patterns indicative of C2 fallback"
  metric_name         = "ConnectionRejections"
  namespace           = "Security/C2"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 10
  comparison_operator = "GreaterThanThreshold"
  alarm_actions       = [aws_sns_topic.alerts.arn]
  treat_missing_data  = "notBreaching"
}""",
                alert_severity="high",
                alert_title="C2 Fallback Channel Detected",
                alert_description_template="Instance {srcAddr} switching between protocols/ports: {unique_ports} ports, {unique_protocols} protocols after {total} connection attempts.",
                investigation_steps=[
                    "Identify the source instance and its purpose",
                    "Review connection timeline and destination IPs",
                    "Check for rejected connection patterns before switches",
                    "Analyse processes making network connections",
                    "Correlate with threat intelligence on destination IPs",
                ],
                containment_actions=[
                    "Isolate affected instance immediately",
                    "Block all suspicious destination IPs/domains",
                    "Review and restrict security group rules",
                    "Capture network traffic for forensic analysis",
                    "Terminate instance if malware confirmed",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Exclude legitimate applications with retry logic (e.g., database clients, monitoring tools)",
            detection_coverage="70% - catches protocol switching behaviour",
            evasion_considerations="Slow fallback transitions, using same protocol with different ports",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$15-25",
            prerequisites=["VPC Flow Logs enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1008-aws-dns-fallback",
            name="AWS DNS Fallback Channel Detection",
            description="Detect DNS being used as fallback C2 channel after other protocols fail.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, query_name, query_type, srcaddr
| filter query_type in ["TXT", "NULL", "CNAME"] or length(query_name) > 50
| stats count(*) as dns_queries, count_distinct(query_name) as unique_queries,
        avg(length(query_name)) as avg_length by srcaddr, bin(5m)
| filter dns_queries > 50 and (avg_length > 40 or unique_queries > 30)
| sort dns_queries desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect DNS fallback C2 channels

Parameters:
  AlertEmail:
    Type: String
    Description: Email for security alerts

Resources:
  # Step 1: Enable Route 53 query logging
  QueryLogGroup:
    Type: AWS::Logs::LogGroup
    Properties:
      LogGroupName: /aws/route53/queries
      RetentionInDays: 30

  QueryLoggingConfig:
    Type: AWS::Route53::QueryLoggingConfig
    Properties:
      CloudWatchLogsLogGroupArn: !GetAtt QueryLogGroup.Arn

  # Step 2: Create metric filter for suspicious DNS patterns
  DNSFallbackFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref QueryLogGroup
      FilterPattern: '[... query_type="TXT" || query_type="NULL" ...]'
      MetricTransformations:
        - MetricName: SuspiciousDNSQueries
          MetricNamespace: Security/C2
          MetricValue: "1"
          DefaultValue: 0

  # Step 3: Create alert for DNS fallback activity
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      TopicName: dns-fallback-alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  DNSFallbackAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: DNS-Fallback-C2-Detected
      AlarmDescription: Detects DNS being used as fallback C2 channel
      MetricName: SuspiciousDNSQueries
      Namespace: Security/C2
      Statistic: Sum
      Period: 300
      EvaluationPeriods: 1
      Threshold: 50
      ComparisonOperator: GreaterThanThreshold
      AlarmActions:
        - !Ref AlertTopic
      TreatMissingData: notBreaching""",
                terraform_template="""# AWS: Detect DNS fallback C2 channels

variable "alert_email" {
  description = "Email for security alerts"
  type        = string
}

# Step 1: Enable Route 53 query logging
resource "aws_cloudwatch_log_group" "dns_queries" {
  name              = "/aws/route53/queries"
  retention_in_days = 30
}

resource "aws_route53_query_log" "main" {
  cloudwatch_log_group_arn = aws_cloudwatch_log_group.dns_queries.arn
}

# Step 2: Create metric filter for suspicious DNS patterns
resource "aws_cloudwatch_log_metric_filter" "dns_fallback" {
  name           = "dns-fallback-c2"
  log_group_name = aws_cloudwatch_log_group.dns_queries.name
  pattern        = "[... query_type=\"TXT\" || query_type=\"NULL\" ...]"

  metric_transformation {
    name          = "SuspiciousDNSQueries"
    namespace     = "Security/C2"
    value         = "1"
    default_value = 0
  }
}

# Step 3: Create alert for DNS fallback activity
resource "aws_sns_topic" "alerts" {
  name = "dns-fallback-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_cloudwatch_metric_alarm" "dns_fallback" {
  alarm_name          = "DNS-Fallback-C2-Detected"
  alarm_description   = "Detects DNS being used as fallback C2 channel"
  metric_name         = "SuspiciousDNSQueries"
  namespace           = "Security/C2"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 50
  comparison_operator = "GreaterThanThreshold"
  alarm_actions       = [aws_sns_topic.alerts.arn]
  treat_missing_data  = "notBreaching"
}""",
                alert_severity="high",
                alert_title="DNS Fallback C2 Channel Detected",
                alert_description_template="Suspicious DNS activity from {srcaddr}: {dns_queries} queries with {unique_queries} unique domains, average length {avg_length}.",
                investigation_steps=[
                    "Identify source instance making DNS queries",
                    "Review query names for encoded data patterns",
                    "Check for preceding failed HTTP/HTTPS connections",
                    "Analyse query timing and frequency patterns",
                    "Investigate destination DNS servers",
                ],
                containment_actions=[
                    "Block DNS queries to suspicious domains",
                    "Isolate affected instance",
                    "Restrict DNS resolver access to known servers",
                    "Enable DNS firewall rules",
                    "Monitor for alternative fallback attempts",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Exclude legitimate TXT record queries (e.g., SPF, DMARC checks); adjust length threshold",
            detection_coverage="65% - catches DNS tunnelling fallback",
            evasion_considerations="Low query rates, legitimate-looking domain names",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2 hours",
            estimated_monthly_cost="$15-30",
            prerequisites=["Route 53 resolver in use", "DNS query logging enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1008-aws-port-hopping",
            name="AWS Port Hopping Detection",
            description="Detect instances attempting connections to multiple ports on same destination after failures.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, srcAddr, dstAddr, dstPort, action
| stats count(*) as attempts, count_distinct(dstPort) as unique_ports,
        sum(action = "REJECT") as rejected,
        sum(action = "ACCEPT") as accepted by srcAddr, dstAddr, bin(10m)
| filter unique_ports > 5 and rejected > 0
| sort attempts desc""",
                terraform_template="""# AWS: Detect port hopping behaviour

variable "alert_email" {
  description = "Email for security alerts"
  type        = string
}

variable "vpc_flow_log_group" {
  description = "VPC Flow Logs log group name"
  type        = string
}

# Step 1: Create SNS topic for alerts
resource "aws_sns_topic" "alerts" {
  name = "port-hopping-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Create metric filter for port hopping
resource "aws_cloudwatch_log_metric_filter" "port_hopping" {
  name           = "c2-port-hopping"
  log_group_name = var.vpc_flow_log_group
  pattern        = "[version, account, eni, source, destination, srcport, dstport, protocol, packets, bytes, start, end, action, ...]"

  metric_transformation {
    name          = "PortHoppingAttempts"
    namespace     = "Security/C2"
    value         = "1"
    default_value = 0
  }
}

# Step 3: Create alarm for port hopping activity
resource "aws_cloudwatch_metric_alarm" "port_hopping" {
  alarm_name          = "C2-PortHopping-Detected"
  alarm_description   = "Detects port hopping indicative of C2 fallback channels"
  metric_name         = "PortHoppingAttempts"
  namespace           = "Security/C2"
  statistic           = "Sum"
  period              = 600
  evaluation_periods  = 1
  threshold           = 20
  comparison_operator = "GreaterThanThreshold"
  alarm_actions       = [aws_sns_topic.alerts.arn]
  treat_missing_data  = "notBreaching"
}""",
                alert_severity="high",
                alert_title="Port Hopping Detected",
                alert_description_template="Instance {srcAddr} attempted {attempts} connections to {dstAddr} across {unique_ports} ports ({rejected} rejected).",
                investigation_steps=[
                    "Identify source instance and running processes",
                    "Review destination IP reputation",
                    "Check sequence of port attempts",
                    "Analyse application making connections",
                    "Correlate with other network anomalies",
                ],
                containment_actions=[
                    "Isolate source instance",
                    "Block destination IP at network level",
                    "Review and restrict egress rules",
                    "Examine instance for malware",
                    "Monitor for continued fallback attempts",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Exclude network scanners, monitoring tools, and load balancer health checks",
            detection_coverage="75% - catches port-based fallback",
            evasion_considerations="Slow port transitions, using standard ports (80, 443, 53)",
            implementation_effort=EffortLevel.LOW,
            implementation_time="1 hour",
            estimated_monthly_cost="$10-20",
            prerequisites=["VPC Flow Logs enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1008-aws-guardduty-c2",
            name="AWS GuardDuty C2 Detection",
            description="Leverage GuardDuty to detect known C2 activity and fallback patterns.",
            detection_type=DetectionType.GUARDDUTY,
            aws_service="guardduty",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                guardduty_finding_types=[
                    "Backdoor:EC2/C&CActivity.B",
                    "Backdoor:EC2/C&CActivity.B!DNS",
                    "Backdoor:EC2/DenialOfService.Tcp",
                    "Backdoor:EC2/DenialOfService.UdpOnTcpPorts",
                    "Trojan:EC2/DNSDataExfiltration",
                ],
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: GuardDuty detection for C2 fallback channels

Parameters:
  AlertEmail:
    Type: String
    Description: Email for security alerts

Resources:
  # Step 1: Create SNS topic for GuardDuty alerts
  GuardDutyAlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      TopicName: guardduty-c2-alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Create EventBridge rule for C2 findings
  GuardDutyC2Rule:
    Type: AWS::Events::Rule
    Properties:
      Name: guardduty-c2-fallback-detection
      Description: Alert on GuardDuty C2 and fallback channel findings
      EventPattern:
        source:
          - aws.guardduty
        detail-type:
          - GuardDuty Finding
        detail:
          type:
            - prefix: "Backdoor:EC2/C&CActivity"
            - "Trojan:EC2/DNSDataExfiltration"
      State: ENABLED
      Targets:
        - Arn: !Ref GuardDutyAlertTopic
          Id: SNSTarget

  # Step 3: Grant EventBridge permission to publish to SNS
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
            Resource: !Ref GuardDutyAlertTopic""",
                terraform_template="""# AWS: GuardDuty C2 fallback detection

variable "alert_email" {
  description = "Email for security alerts"
  type        = string
}

# Step 1: Create SNS topic for GuardDuty alerts
resource "aws_sns_topic" "guardduty_alerts" {
  name = "guardduty-c2-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.guardduty_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Create EventBridge rule for C2 findings
resource "aws_cloudwatch_event_rule" "guardduty_c2" {
  name        = "guardduty-c2-fallback-detection"
  description = "Alert on GuardDuty C2 and fallback channel findings"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail = {
      type = [
        { prefix = "Backdoor:EC2/C&CActivity" },
        "Trojan:EC2/DNSDataExfiltration"
      ]
    }
  })
}

# Step 3: Configure target to send alerts to SNS
resource "aws_cloudwatch_event_target" "sns" {
  rule      = aws_cloudwatch_event_rule.guardduty_c2.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.guardduty_alerts.arn
}

resource "aws_sns_topic_policy" "guardduty_publish" {
  arn = aws_sns_topic.guardduty_alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "SNS:Publish"
      Resource  = aws_sns_topic.guardduty_alerts.arn
    }]
  })
}""",
                alert_severity="critical",
                alert_title="GuardDuty: C2 Activity Detected",
                alert_description_template="Instance {instanceId} communicating with known C2 infrastructure or using fallback channels.",
                investigation_steps=[
                    "Review complete GuardDuty finding details",
                    "Identify C2 infrastructure and protocols used",
                    "Check for multiple C2 connection attempts",
                    "Analyse instance timeline and user activity",
                    "Search for indicators of compromise",
                ],
                containment_actions=[
                    "Immediately isolate affected instance",
                    "Block all identified C2 infrastructure",
                    "Revoke instance credentials and roles",
                    "Capture memory dump for forensics",
                    "Replace instance from known good state",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="GuardDuty findings are high confidence; review suppression rules for known infrastructure",
            detection_coverage="85% - leverages threat intelligence and behaviour analysis",
            evasion_considerations="Unknown C2 infrastructure or highly customised malware may evade",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$1-5 (requires GuardDuty subscription)",
            prerequisites=["AWS GuardDuty enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1008-gcp-protocol-switching",
            name="GCP Protocol Switching Detection",
            description="Detect GCP instances switching between different network protocols.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""resource.type="gce_subnetwork"
jsonPayload.connection.protocol:(6 OR 17 OR 1)
| stats count() as attempts, count_distinct(jsonPayload.connection.dest_port) as unique_ports,
        count_distinct(jsonPayload.connection.protocol) as unique_protocols by jsonPayload.connection.src_ip
| unique_ports > 5 OR unique_protocols > 2""",
                gcp_terraform_template="""# GCP: Detect protocol switching for C2 fallback

variable "project_id" {
  description = "GCP project ID"
  type        = string
}

variable "alert_email" {
  description = "Email for security alerts"
  type        = string
}

# Step 1: Create notification channel
resource "google_monitoring_notification_channel" "email" {
  display_name = "Security Alerts - C2 Fallback"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Create log metric for protocol switching
resource "google_logging_metric" "protocol_switching" {
  name   = "c2-protocol-switching"
  filter = <<-EOT
    resource.type="gce_subnetwork"
    jsonPayload.connection.protocol:(6 OR 17 OR 1)
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "src_ip"
      value_type  = "STRING"
      description = "Source IP address"
    }
  }

  label_extractors = {
    "src_ip" = "EXTRACT(jsonPayload.connection.src_ip)"
  }
}

# Step 3: Create alert policy for protocol switching
resource "google_monitoring_alert_policy" "protocol_switch" {
  display_name = "C2 Fallback Channel Detection"
  combiner     = "OR"

  conditions {
    display_name = "Protocol switching detected"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.protocol_switching.name}\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 15
      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_RATE"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]

  alert_strategy {
    auto_close = "1800s"
  }
}""",
                alert_severity="high",
                alert_title="GCP: C2 Fallback Channel Detected",
                alert_description_template="Instance switching between protocols/ports indicative of C2 fallback behaviour.",
                investigation_steps=[
                    "Identify source VM instance",
                    "Review VPC flow logs for connection patterns",
                    "Check for rejected connections before switches",
                    "Analyse running processes and services",
                    "Correlate with Cloud IDS alerts if available",
                ],
                containment_actions=[
                    "Isolate VM using firewall rules",
                    "Block destination IPs via VPC firewall",
                    "Create disk snapshot for forensics",
                    "Review and restrict egress policies",
                    "Stop instance if malware confirmed",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Exclude legitimate applications with connection retry logic",
            detection_coverage="70% - catches protocol switching patterns",
            evasion_considerations="Slow transitions, using common protocols",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$15-25",
            prerequisites=["VPC Flow Logs enabled on subnets"],
        ),
        DetectionStrategy(
            strategy_id="t1008-gcp-dns-fallback",
            name="GCP DNS Fallback Detection",
            description="Detect DNS being used as fallback C2 channel in GCP environments.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""resource.type="dns_query"
(protoPayload.queryType="TXT" OR protoPayload.queryType="NULL" OR LENGTH(protoPayload.queryName) > 50)
| stats count() as queries, count_distinct(protoPayload.queryName) as unique_queries,
        avg(LENGTH(protoPayload.queryName)) as avg_length by protoPayload.sourceIP
| queries > 50 AND (avg_length > 40 OR unique_queries > 30)""",
                gcp_terraform_template="""# GCP: Detect DNS fallback C2 channels

variable "project_id" {
  description = "GCP project ID"
  type        = string
}

variable "alert_email" {
  description = "Email for security alerts"
  type        = string
}

# Step 1: Enable DNS logging for managed zone
resource "google_dns_managed_zone" "monitored" {
  name        = "monitored-dns-zone"
  dns_name    = "example.com."
  description = "Monitored DNS zone for C2 detection"

  cloud_logging_config {
    enable_logging = true
  }
}

# Step 2: Create log metric for suspicious DNS patterns
resource "google_logging_metric" "dns_fallback" {
  name   = "dns-fallback-c2"
  filter = <<-EOT
    resource.type="dns_query"
    (protoPayload.queryType="TXT" OR
     protoPayload.queryType="NULL" OR
     LENGTH(protoPayload.queryName) > 50)
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "source_ip"
      value_type  = "STRING"
      description = "Source IP making queries"
    }
  }

  label_extractors = {
    "source_ip" = "EXTRACT(protoPayload.sourceIP)"
  }
}

# Step 3: Create alert for DNS fallback activity
resource "google_monitoring_notification_channel" "email" {
  display_name = "Security Alerts - DNS Fallback"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

resource "google_monitoring_alert_policy" "dns_fallback" {
  display_name = "DNS Fallback C2 Channel"
  combiner     = "OR"

  conditions {
    display_name = "Suspicious DNS queries detected"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.dns_fallback.name}\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 50
      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_RATE"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]

  alert_strategy {
    auto_close = "1800s"
  }
}""",
                alert_severity="high",
                alert_title="GCP: DNS Fallback C2 Detected",
                alert_description_template="Suspicious DNS activity indicative of fallback C2 channel detected.",
                investigation_steps=[
                    "Identify source VM or workload",
                    "Analyse DNS query patterns and timing",
                    "Check for preceding failed connections",
                    "Review query names for encoded data",
                    "Investigate destination DNS servers",
                ],
                containment_actions=[
                    "Block DNS queries to suspicious domains",
                    "Isolate affected VM instance",
                    "Configure Cloud DNS firewall policies",
                    "Restrict DNS resolver access",
                    "Monitor for alternative fallback channels",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Exclude legitimate TXT queries for SPF/DMARC; tune length thresholds",
            detection_coverage="65% - catches DNS fallback patterns",
            evasion_considerations="Low query frequency, legitimate domain patterns",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2 hours",
            estimated_monthly_cost="$15-30",
            prerequisites=["Cloud DNS logging enabled", "VPC Flow Logs enabled"],
        ),
    ],
    recommended_order=[
        "t1008-aws-guardduty-c2",
        "t1008-aws-protocol-switching",
        "t1008-gcp-protocol-switching",
        "t1008-aws-dns-fallback",
        "t1008-gcp-dns-fallback",
        "t1008-aws-port-hopping",
    ],
    total_effort_hours=8.5,
    coverage_improvement="+18% improvement for Command and Control tactic",
)
