"""
T1001 - Data Obfuscation

Adversaries obfuscate command and control traffic to make detection more difficult.
Used by Gamaredon Group, APT34, OilRig, Operation Wocao.
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
    technique_id="T1001",
    technique_name="Data Obfuscation",
    tactic_ids=["TA0011"],
    mitre_url="https://attack.mitre.org/techniques/T1001/",
    threat_context=ThreatContext(
        description=(
            "Adversaries employ data obfuscation to conceal command and control communications, "
            "making detection more difficult. The technique involves hiding C2 traffic (though not "
            "necessarily encrypting it) to make content harder to discover, decipher, and recognise "
            "as malicious commands. This includes methods like adding junk data to protocols, using "
            "steganography to hide data within images or files, or impersonating legitimate protocols "
            "to blend with normal network traffic."
        ),
        attacker_goal="Hide command and control communications to evade detection and blend malicious traffic with legitimate activity",
        why_technique=[
            "Makes C2 traffic harder to detect and analyse",
            "Bypasses signature-based detection systems",
            "Blends malicious traffic with legitimate protocols",
            "Complicates network forensics and investigation",
            "Enables long-term persistence without detection",
        ],
        known_threat_actors=[
            "Gamaredon Group (G0047)",
            "APT34 (G0057)",
            "OilRig (G0049)",
            "Operation Wocao",
        ],
        recent_campaigns=[
            Campaign(
                name="Gamaredon VBScript Obfuscation",
                year=2024,
                description="Gamaredon Group used obfuscated VBScripts with randomised variable names to hide C2 communications",
                reference_url="https://attack.mitre.org/groups/G0047/",
            ),
            Campaign(
                name="APT34 Fake Webpage Embedding",
                year=2023,
                description="APT34 embedded C2 responses within fake webpages to appear as legitimate HTTP traffic",
                reference_url="https://attack.mitre.org/groups/G0057/",
            ),
            Campaign(
                name="OilRig DNS Subdomain Encoding",
                year=2023,
                description="OilRig utilised encoded data within DNS subdomains as ciphertext for C2 communications",
                reference_url="https://attack.mitre.org/groups/G0049/",
            ),
            Campaign(
                name="Operation Wocao RC4 Encryption",
                year=2022,
                description="Threat actors in Operation Wocao encrypted proxy IP addresses with RC4 to hide C2 infrastructure",
                reference_url="https://attack.mitre.org/techniques/T1001/",
            ),
        ],
        prevalence="common",
        trend="increasing",
        severity_score=8,
        severity_reasoning=(
            "Data obfuscation significantly complicates detection efforts and allows adversaries "
            "to maintain persistent C2 channels undetected. By hiding malicious traffic within "
            "legitimate protocols or encoding data, attackers can exfiltrate sensitive information, "
            "receive commands, and maintain control over compromised systems for extended periods. "
            "The technique's effectiveness against traditional signature-based detection makes it "
            "a preferred method for sophisticated threat actors."
        ),
        business_impact=[
            "Extended dwell time enabling further compromise",
            "Data exfiltration without detection",
            "Persistent unauthorised access to systems",
            "Increased incident response and forensics costs",
            "Potential regulatory violations from undetected breaches",
        ],
        typical_attack_phase="command_and_control",
        often_precedes=["T1041", "T1048", "T1567"],
        often_follows=["T1071", "T1090", "T1573"],
    ),
    detection_strategies=[
        DetectionStrategy(
            strategy_id="t1001-aws-http-anomaly",
            name="AWS Unusual HTTP Traffic Patterns",
            description="Detect excessive outbound HTTP/S traffic with unusual patterns indicative of obfuscated C2.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, srcAddr, dstAddr, dstPort, bytes, packets
| filter dstPort in [80, 443, 8080, 8443] and action = "ACCEPT"
| stats sum(bytes) as total_bytes, sum(packets) as total_packets,
        avg(bytes) as avg_bytes_per_flow by srcAddr, dstAddr, bin(5m)
| filter total_bytes > 10485760 and avg_bytes_per_flow < 500
| sort total_bytes desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detection of unusual HTTP traffic patterns indicative of obfuscated C2

Parameters:
  AlertEmail:
    Type: String
  VPCFlowLogGroup:
    Type: String

Resources:
  # Step 1: Create SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Create metric filter for suspicious HTTP patterns
  SuspiciousHTTPFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref VPCFlowLogGroup
      FilterPattern: '[version, account, eni, source, destination, srcport, dstport=80 || dstport=443 || dstport=8080 || dstport=8443, protocol, packets > 100, bytes > 10000000, ...]'
      MetricTransformations:
        - MetricName: SuspiciousHTTPTraffic
          MetricNamespace: Security
          MetricValue: "1"

  # Step 3: Alert on threshold breach
  HTTPAnomalyAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: HTTP-C2-Obfuscation-Detected
      MetricName: SuspiciousHTTPTraffic
      Namespace: Security
      Statistic: Sum
      Period: 300
      Threshold: 5
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      AlarmActions: [!Ref AlertTopic]""",
                terraform_template="""# Detection of unusual HTTP traffic patterns indicative of obfuscated C2

variable "alert_email" { type = string }
variable "vpc_flow_log_group" { type = string }

# Step 1: Create SNS topic for alerts
resource "aws_sns_topic" "alerts" {
  name = "http-c2-obfuscation-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Create metric filter for suspicious HTTP patterns
resource "aws_cloudwatch_log_metric_filter" "suspicious_http" {
  name           = "suspicious-http-traffic"
  log_group_name = var.vpc_flow_log_group
  pattern        = "[version, account, eni, source, destination, srcport, dstport=80 || dstport=443 || dstport=8080 || dstport=8443, protocol, packets > 100, bytes > 10000000, ...]"

  metric_transformation {
    name      = "SuspiciousHTTPTraffic"
    namespace = "Security"
    value     = "1"
  }
}

# Step 3: Alert on threshold breach
resource "aws_cloudwatch_metric_alarm" "http_anomaly" {
  alarm_name          = "HTTP-C2-Obfuscation-Detected"
  metric_name         = "SuspiciousHTTPTraffic"
  namespace           = "Security"
  statistic           = "Sum"
  period              = 300
  threshold           = 5
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  alarm_actions       = [aws_sns_topic.alerts.arn]
}""",
                alert_severity="high",
                alert_title="Potential C2 Obfuscation via HTTP Detected",
                alert_description_template="Unusual HTTP traffic pattern from {srcAddr} to {dstAddr}: {total_bytes} bytes in small packets, indicating potential C2 obfuscation.",
                investigation_steps=[
                    "Identify the source instance and running processes",
                    "Analyse HTTP request/response patterns for abnormalities",
                    "Check for uncommon user agents or HTTP headers",
                    "Review destination IP reputation and geolocation",
                    "Examine payload contents for encoded or obfuscated data",
                    "Correlate with other security events from the same source",
                ],
                containment_actions=[
                    "Isolate the source instance from network",
                    "Block communication to suspicious destination IPs",
                    "Terminate suspicious processes on the instance",
                    "Review and restrict security group rules",
                    "Collect forensic evidence before remediation",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Exclude known API endpoints with high request rates; adjust byte threshold for legitimate services",
            detection_coverage="70% - catches HTTP-based obfuscated C2",
            evasion_considerations="Using legitimate cloud services for C2, randomising traffic patterns",
            implementation_effort=EffortLevel.LOW,
            implementation_time="1 hour",
            estimated_monthly_cost="$10-20",
            prerequisites=["VPC Flow Logs enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1001-aws-dns-encoding",
            name="AWS DNS-Based Data Encoding Detection",
            description="Detect DNS queries with encoded data in subdomains or TXT records.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, query_name, query_type, rcode, srcaddr
| filter query_type = "TXT" or length(query_name) > 50 or query_name like /[A-Za-z0-9]{20,}[.]/
| stats count(*) as query_count, count_distinct(query_name) as unique_domains,
        avg(length(query_name)) as avg_length by srcaddr, bin(5m)
| filter query_count > 50 or avg_length > 40
| sort query_count desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: DNS-based data encoding detection for obfuscated C2

Parameters:
  AlertEmail:
    Type: String

Resources:
  # Step 1: Enable Route 53 query logging
  DNSQueryLogGroup:
    Type: AWS::Logs::LogGroup
    Properties:
      LogGroupName: /aws/route53/dns-queries
      RetentionInDays: 30

  QueryLoggingConfig:
    Type: AWS::Route53::QueryLoggingConfig
    Properties:
      CloudWatchLogsLogGroupArn: !GetAtt DNSQueryLogGroup.Arn

  # Step 2: Create metric filter for encoded DNS queries
  EncodedDNSFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref DNSQueryLogGroup
      FilterPattern: '[... query_name_length > 50 || query_type = "TXT" ...]'
      MetricTransformations:
        - MetricName: EncodedDNSQueries
          MetricNamespace: Security
          MetricValue: "1"

  # Step 3: Alert on suspicious DNS activity
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  EncodedDNSAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: DNS-Data-Encoding-Detected
      MetricName: EncodedDNSQueries
      Namespace: Security
      Statistic: Sum
      Period: 300
      Threshold: 50
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      AlarmActions: [!Ref AlertTopic]""",
                terraform_template="""# DNS-based data encoding detection for obfuscated C2

variable "alert_email" { type = string }

# Step 1: Enable Route 53 query logging
resource "aws_cloudwatch_log_group" "dns_queries" {
  name              = "/aws/route53/dns-queries"
  retention_in_days = 30
}

resource "aws_route53_query_log" "main" {
  cloudwatch_log_group_arn = aws_cloudwatch_log_group.dns_queries.arn
}

# Step 2: Create metric filter for encoded DNS queries
resource "aws_cloudwatch_log_metric_filter" "encoded_dns" {
  name           = "encoded-dns-queries"
  log_group_name = aws_cloudwatch_log_group.dns_queries.name
  pattern        = "[... query_name_length > 50 || query_type = \"TXT\" ...]"

  metric_transformation {
    name      = "EncodedDNSQueries"
    namespace = "Security"
    value     = "1"
  }
}

# Step 3: Alert on suspicious DNS activity
resource "aws_sns_topic" "alerts" {
  name = "dns-encoding-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_cloudwatch_metric_alarm" "encoded_dns" {
  alarm_name          = "DNS-Data-Encoding-Detected"
  metric_name         = "EncodedDNSQueries"
  namespace           = "Security"
  statistic           = "Sum"
  period              = 300
  threshold           = 50
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  alarm_actions       = [aws_sns_topic.alerts.arn]
}""",
                alert_severity="high",
                alert_title="DNS Data Encoding Detected",
                alert_description_template="Suspicious DNS query patterns from {srcaddr}: {query_count} queries with average length {avg_length}, suggesting data encoding.",
                investigation_steps=[
                    "Identify source instance making DNS queries",
                    "Analyse query name patterns for encoded data",
                    "Decode suspected Base64 or hex-encoded subdomains",
                    "Check destination DNS servers for legitimacy",
                    "Review process making DNS requests",
                    "Correlate with file access or data staging activity",
                ],
                containment_actions=[
                    "Isolate source instance immediately",
                    "Block DNS queries to suspicious domains",
                    "Restrict DNS resolver to internal/trusted only",
                    "Implement DNS firewall rules",
                    "Terminate suspicious processes",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Exclude legitimate long DNS records (DMARC, SPF); whitelist known TXT record queries",
            detection_coverage="75% - catches DNS-based obfuscation",
            evasion_considerations="Slow query rate, using legitimate DNS services, shorter query names",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2 hours",
            estimated_monthly_cost="$15-30",
            prerequisites=["Route 53 resolver in use", "DNS query logging enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1001-aws-protocol-anomaly",
            name="AWS Protocol Impersonation Detection",
            description="Detect traffic impersonating legitimate protocols but with unusual characteristics.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, srcAddr, dstAddr, dstPort, protocol, bytes, packets
| filter dstPort in [80, 443] and action = "ACCEPT"
| stats sum(bytes) as total_bytes, sum(packets) as total_packets,
        (sum(bytes) / sum(packets)) as bytes_per_packet by srcAddr, dstAddr, bin(10m)
| filter bytes_per_packet < 100 or bytes_per_packet > 1400
| sort total_bytes desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Protocol impersonation detection via VPC Flow Logs

Parameters:
  AlertEmail:
    Type: String
  VPCFlowLogGroup:
    Type: String

Resources:
  # Step 1: Create alert topic
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Monitor for unusual packet sizes on standard ports
  ProtocolAnomalyFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref VPCFlowLogGroup
      FilterPattern: '[version, account, eni, source, destination, srcport, dstport=80 || dstport=443, protocol, packets, bytes, ...]'
      MetricTransformations:
        - MetricName: ProtocolAnomalies
          MetricNamespace: Security
          MetricValue: "1"

  # Step 3: Alert on anomalous protocol behaviour
  ProtocolAnomalyAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: Protocol-Impersonation-Detected
      MetricName: ProtocolAnomalies
      Namespace: Security
      Statistic: Sum
      Period: 600
      Threshold: 20
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      AlarmActions: [!Ref AlertTopic]""",
                terraform_template="""# Protocol impersonation detection via VPC Flow Logs

variable "alert_email" { type = string }
variable "vpc_flow_log_group" { type = string }

# Step 1: Create alert topic
resource "aws_sns_topic" "alerts" {
  name = "protocol-impersonation-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Monitor for unusual packet sizes on standard ports
resource "aws_cloudwatch_log_metric_filter" "protocol_anomaly" {
  name           = "protocol-anomalies"
  log_group_name = var.vpc_flow_log_group
  pattern        = "[version, account, eni, source, destination, srcport, dstport=80 || dstport=443, protocol, packets, bytes, ...]"

  metric_transformation {
    name      = "ProtocolAnomalies"
    namespace = "Security"
    value     = "1"
  }
}

# Step 3: Alert on anomalous protocol behaviour
resource "aws_cloudwatch_metric_alarm" "protocol_anomaly" {
  alarm_name          = "Protocol-Impersonation-Detected"
  metric_name         = "ProtocolAnomalies"
  namespace           = "Security"
  statistic           = "Sum"
  period              = 600
  threshold           = 20
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  alarm_actions       = [aws_sns_topic.alerts.arn]
}""",
                alert_severity="medium",
                alert_title="Protocol Impersonation Detected",
                alert_description_template="Unusual traffic pattern from {srcAddr} to {dstAddr} on standard ports: {bytes_per_packet} bytes per packet, suggesting protocol impersonation.",
                investigation_steps=[
                    "Identify applications on source instance",
                    "Capture packet samples for deep inspection",
                    "Analyse protocol headers for inconsistencies",
                    "Compare with known good traffic patterns",
                    "Check for non-standard user agents or headers",
                    "Review destination IP and domain reputation",
                ],
                containment_actions=[
                    "Enable deep packet inspection on traffic",
                    "Block communication to suspicious destinations",
                    "Isolate affected instance for analysis",
                    "Update security group rules to restrict protocols",
                    "Deploy network IDS/IPS rules",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.HIGH,
            false_positive_tuning="Baseline normal traffic patterns; exclude known applications with unusual packet sizes",
            detection_coverage="55% - catches protocol impersonation",
            evasion_considerations="Perfect protocol mimicry, using legitimate cloud services",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2 hours",
            estimated_monthly_cost="$15-25",
            prerequisites=[
                "VPC Flow Logs enabled",
                "Baseline traffic analysis completed",
            ],
        ),
        DetectionStrategy(
            strategy_id="t1001-gcp-http-anomaly",
            name="GCP Unusual HTTP Traffic Patterns",
            description="Detect obfuscated C2 traffic via Cloud Logging and VPC Flow Logs.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""resource.type="gce_subnetwork"
jsonPayload.connection.dest_port:(80 OR 443 OR 8080 OR 8443)
jsonPayload.bytes_sent > 10485760
| stats sum(bytes_sent) as total_bytes, avg(bytes_sent) as avg_bytes by src_ip, dest_ip
| avg_bytes < 500 AND total_bytes > 10485760""",
                gcp_terraform_template="""# GCP: HTTP traffic anomaly detection for obfuscated C2

variable "project_id" { type = string }
variable "alert_email" { type = string }

# Step 1: Enable VPC Flow Logs (configured per subnet)
# Note: Flow logs must be enabled on individual subnets in GCP

# Step 2: Create log metric for suspicious HTTP patterns
resource "google_logging_metric" "http_anomaly" {
  name   = "http-c2-obfuscation"
  filter = <<-EOT
    resource.type="gce_subnetwork"
    (jsonPayload.connection.dest_port=80 OR
     jsonPayload.connection.dest_port=443 OR
     jsonPayload.connection.dest_port=8080 OR
     jsonPayload.connection.dest_port=8443)
    jsonPayload.bytes_sent > 10485760
  EOT
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Create alert policy
resource "google_monitoring_notification_channel" "email" {
  display_name = "Security Alerts"
  type         = "email"
  labels       = { email_address = var.alert_email }
}

resource "google_monitoring_alert_policy" "http_anomaly" {
  display_name = "HTTP C2 Obfuscation Detected"
  combiner     = "OR"
  conditions {
    display_name = "Suspicious HTTP traffic pattern"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.http_anomaly.name}\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 5
    }
  }
  notification_channels = [google_monitoring_notification_channel.email.id]
}""",
                alert_severity="high",
                alert_title="GCP: Potential C2 Obfuscation via HTTP Detected",
                alert_description_template="Unusual HTTP traffic pattern detected: {total_bytes} bytes in small packets from GCP instance.",
                investigation_steps=[
                    "Identify the source Compute Engine instance",
                    "Review running processes and services",
                    "Analyse HTTP request patterns in Cloud Logging",
                    "Check destination IP reputation",
                    "Examine payload contents for obfuscation",
                    "Correlate with Cloud Audit Logs for recent changes",
                ],
                containment_actions=[
                    "Isolate instance via VPC firewall rules",
                    "Block egress to suspicious destinations",
                    "Stop the affected instance if confirmed malicious",
                    "Create VM snapshot for forensic analysis",
                    "Review and update firewall rules",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Exclude known GCP services and APIs; adjust byte thresholds for legitimate traffic",
            detection_coverage="70% - catches HTTP-based obfuscated C2",
            evasion_considerations="Using Google Cloud services for C2, randomised traffic timing",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2 hours",
            estimated_monthly_cost="$15-25",
            prerequisites=["VPC Flow Logs enabled on subnets", "Cloud Logging enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1001-gcp-dns-encoding",
            name="GCP DNS Data Encoding Detection",
            description="Detect DNS-based data encoding via Cloud DNS logging.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""resource.type="dns_query"
(LENGTH(protoPayload.queryName) > 50 OR protoPayload.queryType="TXT")
| stats count() as query_count, avg(LENGTH(queryName)) as avg_length by sourceIP
| query_count > 50 OR avg_length > 40""",
                gcp_terraform_template="""# GCP: DNS data encoding detection

variable "project_id" { type = string }
variable "alert_email" { type = string }

# Step 1: Enable Cloud DNS logging
resource "google_dns_managed_zone" "monitored" {
  name        = "monitored-zone"
  dns_name    = "example.com."
  description = "Monitored DNS zone for security"

  cloud_logging_config {
    enable_logging = true
  }
}

# Step 2: Create log metric for encoded DNS queries
resource "google_logging_metric" "dns_encoding" {
  name   = "dns-data-encoding"
  filter = <<-EOT
    resource.type="dns_query"
    (LENGTH(protoPayload.queryName) > 50 OR protoPayload.queryType="TXT")
  EOT
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Create alert policy
resource "google_monitoring_notification_channel" "email" {
  display_name = "Security Alerts"
  type         = "email"
  labels       = { email_address = var.alert_email }
}

resource "google_monitoring_alert_policy" "dns_encoding" {
  display_name = "DNS Data Encoding Detected"
  combiner     = "OR"
  conditions {
    display_name = "Encoded DNS queries detected"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.dns_encoding.name}\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 50
    }
  }
  notification_channels = [google_monitoring_notification_channel.email.id]
}""",
                alert_severity="high",
                alert_title="GCP: DNS Data Encoding Detected",
                alert_description_template="Suspicious DNS queries detected: {query_count} queries with average length {avg_length}.",
                investigation_steps=[
                    "Identify the source Compute Engine instance",
                    "Analyse DNS query patterns for encoded data",
                    "Decode suspected Base64 or hex-encoded content",
                    "Review DNS resolver configuration",
                    "Check for unusual processes making DNS requests",
                    "Correlate with network egress logs",
                ],
                containment_actions=[
                    "Isolate source instance immediately",
                    "Block DNS queries to suspicious domains",
                    "Restrict Cloud DNS to authorised queries only",
                    "Implement Cloud DNS Security policies",
                    "Terminate malicious processes",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Exclude legitimate long DNS records; whitelist known TXT record services",
            detection_coverage="75% - catches DNS-based obfuscation",
            evasion_considerations="Using shorter query names, legitimate DNS services, slow query rates",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2 hours",
            estimated_monthly_cost="$15-30",
            prerequisites=["Cloud DNS logging enabled", "VPC Flow Logs enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1001-gcp-protocol-anomaly",
            name="GCP Protocol Anomaly Detection",
            description="Detect protocol impersonation via VPC Flow Logs analysis.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""resource.type="gce_subnetwork"
jsonPayload.connection.dest_port:(80 OR 443)
| stats sum(bytes_sent) as total_bytes, sum(packets_sent) as total_packets,
        (sum(bytes_sent) / sum(packets_sent)) as bytes_per_packet by src_ip, dest_ip
| bytes_per_packet < 100 OR bytes_per_packet > 1400""",
                gcp_terraform_template="""# GCP: Protocol anomaly detection

variable "project_id" { type = string }
variable "alert_email" { type = string }

# Step 1: VPC Flow Logs enabled per subnet (prerequisite)

# Step 2: Create metric for protocol anomalies
resource "google_logging_metric" "protocol_anomaly" {
  name   = "protocol-impersonation"
  filter = <<-EOT
    resource.type="gce_subnetwork"
    (jsonPayload.connection.dest_port=80 OR jsonPayload.connection.dest_port=443)
  EOT
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Create alert policy
resource "google_monitoring_notification_channel" "email" {
  display_name = "Security Alerts"
  type         = "email"
  labels       = { email_address = var.alert_email }
}

resource "google_monitoring_alert_policy" "protocol_anomaly" {
  display_name = "Protocol Impersonation Detected"
  combiner     = "OR"
  conditions {
    display_name = "Unusual protocol behaviour"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.protocol_anomaly.name}\""
      duration        = "600s"
      comparison      = "COMPARISON_GT"
      threshold_value = 20
    }
  }
  notification_channels = [google_monitoring_notification_channel.email.id]
}""",
                alert_severity="medium",
                alert_title="GCP: Protocol Impersonation Detected",
                alert_description_template="Unusual protocol behaviour detected on standard ports.",
                investigation_steps=[
                    "Identify source Compute Engine instance",
                    "Perform packet capture for deep inspection",
                    "Analyse protocol headers and payloads",
                    "Compare with baseline traffic patterns",
                    "Review application logs on instance",
                    "Check destination IP reputation",
                ],
                containment_actions=[
                    "Enable packet mirroring for analysis",
                    "Block suspicious destinations via firewall",
                    "Isolate instance for investigation",
                    "Update VPC firewall rules",
                    "Deploy Cloud IDS for deep inspection",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.HIGH,
            false_positive_tuning="Establish traffic baselines; exclude known applications with unusual patterns",
            detection_coverage="55% - catches protocol impersonation",
            evasion_considerations="Perfect protocol mimicry, using Google Cloud services",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2-3 hours",
            estimated_monthly_cost="$15-25",
            prerequisites=["VPC Flow Logs enabled", "Traffic baseline established"],
        ),
    ],
    recommended_order=[
        "t1001-aws-dns-encoding",
        "t1001-gcp-dns-encoding",
        "t1001-aws-http-anomaly",
        "t1001-gcp-http-anomaly",
        "t1001-aws-protocol-anomaly",
        "t1001-gcp-protocol-anomaly",
    ],
    total_effort_hours=11.0,
    coverage_improvement="+25% improvement for Command and Control tactic",
)
