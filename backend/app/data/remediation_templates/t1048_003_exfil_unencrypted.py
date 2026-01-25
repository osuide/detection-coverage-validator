"""
T1048.003 - Exfiltration Over Unencrypted Non-C2 Protocol

Adversaries exfiltrate data using unencrypted protocols like HTTP, FTP, and DNS.
Used by APT32, APT33, APT41, Lazarus Group, FIN6, FIN8, OilRig, Mustang Panda.
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
    technique_id="T1048.003",
    technique_name="Exfiltration Over Unencrypted Non-C2 Protocol",
    tactic_ids=["TA0010"],
    mitre_url="https://attack.mitre.org/techniques/T1048/003/",
    threat_context=ThreatContext(
        description=(
            "Adversaries steal data by transmitting it through unencrypted network protocols "
            "separate from their primary command and control channels. Rather than using encryption, "
            "threat actors may obfuscate data using encoding algorithms like base64 or embed information "
            "within protocol headers. Common protocols include HTTP, FTP, and DNS, which allow attackers "
            "to send data to locations distinct from their primary C2 infrastructure whilst blending with "
            "legitimate traffic."
        ),
        attacker_goal="Exfiltrate sensitive data using unencrypted protocols to avoid detection whilst maintaining separate exfiltration channels",
        why_technique=[
            "Unencrypted protocols are commonly permitted outbound",
            "DNS and HTTP traffic rarely blocked by firewalls",
            "Data can be encoded or obfuscated without encryption",
            "Blends with legitimate protocol usage",
            "Uses readily available tools (curl, wget, FTP clients)",
            "Separate exfiltration channel reduces C2 detection risk",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="common",
        trend="increasing",
        severity_score=9,
        severity_reasoning=(
            "Exfiltration over unencrypted protocols is highly effective and difficult to detect as it "
            "blends seamlessly with legitimate traffic. The use of common protocols like DNS, HTTP, and FTP "
            "means this traffic is rarely blocked by firewalls. Data loss can result in severe financial, "
            "regulatory, and reputational damage. The lack of encryption makes forensic analysis possible "
            "but detection requires active monitoring of traffic patterns and anomalies."
        ),
        business_impact=[
            "Data breach and loss of sensitive information",
            "Intellectual property theft and competitive disadvantage",
            "Regulatory fines and compliance violations (GDPR, HIPAA)",
            "Reputational damage and loss of customer trust",
            "Operational disruption from incident response activities",
            "Potential legal liability from data exposure",
        ],
        typical_attack_phase="exfiltration",
        often_precedes=[],
        often_follows=["T1530", "T1552.001", "T1005", "T1074", "T1560"],
    ),
    detection_strategies=[
        DetectionStrategy(
            strategy_id="t1048.003-aws-http",
            name="AWS Unencrypted HTTP Exfiltration Detection",
            description="Detect large HTTP transfers to external destinations via VPC Flow Logs and CloudWatch.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, srcAddr, dstAddr, dstPort, bytes, action
| filter dstPort = 80 and action = "ACCEPT"
| filter dstAddr not like /^10\\./ and dstAddr not like /^172\\.1[6-9]\\./
| filter dstAddr not like /^192\\.168\\./
| stats sum(bytes) as total_bytes, count(*) as connections by srcAddr, dstAddr, bin(1h)
| filter total_bytes > 10485760
| sort total_bytes desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Unencrypted HTTP exfiltration detection via VPC Flow Logs

Parameters:
  AlertEmail:
    Type: String
    Description: Email address for security alerts
  VPCFlowLogGroup:
    Type: String
    Description: CloudWatch Log Group for VPC Flow Logs

Resources:
  # Step 1: Create SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      DisplayName: HTTP Exfiltration Alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Create metric filter for HTTP traffic to external IPs
  HTTPExfilFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref VPCFlowLogGroup
      FilterPattern: '[version, account, eni, source, destination, srcport, dstport=80, protocol, packets, bytes > 10000000, ...]'
      MetricTransformations:
        - MetricName: UnencryptedHTTPTransfer
          MetricNamespace: Security/Exfiltration
          MetricValue: "$bytes"
          Unit: Bytes

  # Step 3: Create alarm for large HTTP transfers
  HTTPExfilAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: Unencrypted-HTTP-Exfiltration
      AlarmDescription: Large data transfer over unencrypted HTTP detected
      MetricName: UnencryptedHTTPTransfer
      Namespace: Security/Exfiltration
      Statistic: Sum
      Period: 300
      Threshold: 104857600
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      TreatMissingData: notBreaching

      AlarmActions:
        - !Ref AlertTopic

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
                AWS:SourceAccount: !Ref AWS::AccountId""",
                terraform_template="""# Unencrypted HTTP exfiltration detection via VPC Flow Logs

variable "alert_email" {
  type        = string
  description = "Email address for security alerts"
}

variable "location" {
  type        = string
  description = "Azure region for resources"
  default     = "uksouth"
}

variable "vpc_flow_log_group" {
  type        = string
  description = "CloudWatch Log Group for VPC Flow Logs"
}

# Step 1: Create SNS topic for alerts
resource "aws_sns_topic" "http_exfil_alerts" {
  name         = "http-exfiltration-alerts"
  kms_master_key_id = "alias/aws/sns"
  display_name = "HTTP Exfiltration Alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.http_exfil_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Create metric filter for HTTP traffic to external IPs
resource "aws_cloudwatch_log_metric_filter" "http_exfil" {
  name           = "unencrypted-http-transfer"
  log_group_name = var.vpc_flow_log_group
  pattern        = "[version, account, eni, source, destination, srcport, dstport=80, protocol, packets, bytes > 10000000, ...]"

  metric_transformation {
    name      = "UnencryptedHTTPTransfer"
    namespace = "Security/Exfiltration"
    value     = "$bytes"
    unit      = "Bytes"
  }
}

# Step 3: Create alarm for large HTTP transfers
resource "aws_cloudwatch_metric_alarm" "http_exfil" {
  alarm_name          = "Unencrypted-HTTP-Exfiltration"
  alarm_description   = "Large data transfer over unencrypted HTTP detected"
  metric_name         = "UnencryptedHTTPTransfer"
  namespace           = "Security/Exfiltration"
  statistic           = "Sum"
  period              = 300
  threshold           = 104857600
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.http_exfil_alerts.arn]
}

data "aws_caller_identity" "current" {}

resource "aws_sns_topic_policy" "allow_cloudwatch" {
  arn = aws_sns_topic.http_exfil_alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowCloudWatchPublish"
      Effect    = "Allow"
      Principal = { Service = "cloudwatch.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.http_exfil_alerts.arn
      Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
      }
    }]
  })
}""",
                alert_severity="high",
                alert_title="Unencrypted HTTP Exfiltration Detected",
                alert_description_template="Large unencrypted HTTP transfer detected from {srcAddr} to {dstAddr}: {total_bytes} bytes over {connections} connections.",
                investigation_steps=[
                    "Identify the source instance and its purpose",
                    "Review the destination IP and associated domain",
                    "Examine process-level activity on source instance",
                    "Check for file access patterns preceding the transfer",
                    "Correlate with authentication and user activity logs",
                    "Review CloudTrail for API calls from the instance",
                    "Analyse transferred data if possible (packet capture)",
                ],
                containment_actions=[
                    "Isolate the source instance from the network",
                    "Block HTTP traffic to destination IP via security group",
                    "Revoke instance IAM role credentials",
                    "Create VPC endpoint policies to restrict external access",
                    "Enable TLS inspection at network perimeter",
                    "Review and restrict outbound security group rules",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist known HTTP endpoints (package mirrors, update servers); exclude CDN and monitoring endpoints; adjust byte threshold based on environment",
            detection_coverage="75% - catches unencrypted HTTP exfiltration to external destinations",
            evasion_considerations="Attackers may use HTTPS instead, fragment transfers over time, or use non-standard ports",
            implementation_effort=EffortLevel.LOW,
            implementation_time="1 hour",
            estimated_monthly_cost="$10-20",
            prerequisites=["VPC Flow Logs enabled and sent to CloudWatch Logs"],
        ),
        DetectionStrategy(
            strategy_id="t1048.003-aws-ftp",
            name="AWS FTP Exfiltration Detection",
            description="Detect FTP-based data exfiltration via VPC Flow Logs monitoring.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, srcAddr, dstAddr, dstPort, bytes, action
| filter dstPort in [20, 21, 989, 990] and action = "ACCEPT"
| stats sum(bytes) as total_bytes, count(*) as sessions by srcAddr, dstAddr, dstPort, bin(1h)
| filter total_bytes > 5242880
| sort total_bytes desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: FTP exfiltration detection via VPC Flow Logs

Parameters:
  AlertEmail:
    Type: String
    Description: Email address for security alerts
  VPCFlowLogGroup:
    Type: String
    Description: CloudWatch Log Group for VPC Flow Logs

Resources:
  # Step 1: Create SNS topic for alerts
  FTPAlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      DisplayName: FTP Exfiltration Alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Create metric filter for FTP transfers
  FTPExfilFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref VPCFlowLogGroup
      FilterPattern: '[version, account, eni, source, destination, srcport, dstport=20 || dstport=21 || dstport=989 || dstport=990, protocol, packets, bytes > 5000000, ...]'
      MetricTransformations:
        - MetricName: FTPDataTransfer
          MetricNamespace: Security/Exfiltration
          MetricValue: "$bytes"
          Unit: Bytes

  # Step 3: Create alarm for FTP transfers
  FTPExfilAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: FTP-Exfiltration-Detected
      AlarmDescription: Suspicious FTP data transfer detected
      MetricName: FTPDataTransfer
      Namespace: Security/Exfiltration
      Statistic: Sum
      Period: 300
      Threshold: 52428800
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      TreatMissingData: notBreaching

      AlarmActions:
        - !Ref FTPAlertTopic

  TopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics: [!Ref FTPAlertTopic]
      PolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Sid: AllowCloudWatchPublish
            Effect: Allow
            Principal:
              Service: cloudwatch.amazonaws.com
            Action: sns:Publish
            Resource: !Ref FTPAlertTopic
            Condition:
              StringEquals:
                AWS:SourceAccount: !Ref AWS::AccountId""",
                terraform_template="""# FTP exfiltration detection via VPC Flow Logs

variable "alert_email" {
  type        = string
  description = "Email address for security alerts"
}

variable "location" {
  type        = string
  description = "Azure region for resources"
  default     = "uksouth"
}

variable "vpc_flow_log_group" {
  type        = string
  description = "CloudWatch Log Group for VPC Flow Logs"
}

# Step 1: Create SNS topic for alerts
resource "aws_sns_topic" "ftp_exfil_alerts" {
  name         = "ftp-exfiltration-alerts"
  kms_master_key_id = "alias/aws/sns"
  display_name = "FTP Exfiltration Alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.ftp_exfil_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Create metric filter for FTP transfers
resource "aws_cloudwatch_log_metric_filter" "ftp_exfil" {
  name           = "ftp-data-transfer"
  log_group_name = var.vpc_flow_log_group
  pattern        = "[version, account, eni, source, destination, srcport, dstport=20 || dstport=21 || dstport=989 || dstport=990, protocol, packets, bytes > 5000000, ...]"

  metric_transformation {
    name      = "FTPDataTransfer"
    namespace = "Security/Exfiltration"
    value     = "$bytes"
    unit      = "Bytes"
  }
}

# Step 3: Create alarm for FTP transfers
resource "aws_cloudwatch_metric_alarm" "ftp_exfil" {
  alarm_name          = "FTP-Exfiltration-Detected"
  alarm_description   = "Suspicious FTP data transfer detected"
  metric_name         = "FTPDataTransfer"
  namespace           = "Security/Exfiltration"
  statistic           = "Sum"
  period              = 300
  threshold           = 52428800
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.ftp_exfil_alerts.arn]
}

data "aws_caller_identity" "current" {}

resource "aws_sns_topic_policy" "allow_cloudwatch" {
  arn = aws_sns_topic.ftp_exfil_alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowCloudWatchPublish"
      Effect    = "Allow"
      Principal = { Service = "cloudwatch.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.ftp_exfil_alerts.arn
      Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
      }
    }]
  })
}""",
                alert_severity="high",
                alert_title="FTP Data Exfiltration Detected",
                alert_description_template="FTP transfer detected from {srcAddr} to {dstAddr}:{dstPort} - {total_bytes} bytes across {sessions} sessions.",
                investigation_steps=[
                    "Identify the source instance and its workload",
                    "Determine if FTP usage is authorised for this instance",
                    "Review FTP server destination and ownership",
                    "Check for compromised credentials or malware",
                    "Examine files accessed before transfer",
                    "Review authentication logs for suspicious activity",
                    "Analyse transfer timing and patterns",
                ],
                containment_actions=[
                    "Isolate the source instance immediately",
                    "Block FTP ports (20, 21) in security groups",
                    "Disable FTP services on the instance",
                    "Revoke instance credentials and rotate keys",
                    "Implement network ACLs to block FTP traffic",
                    "Review and restrict outbound connectivity",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Whitelist known FTP servers for legitimate backups or file transfers; exclude scheduled transfer jobs",
            detection_coverage="80% - catches FTP-based exfiltration",
            evasion_considerations="Attackers may use SFTP (port 22), FTPS over non-standard ports, or HTTP/HTTPS instead",
            implementation_effort=EffortLevel.LOW,
            implementation_time="1 hour",
            estimated_monthly_cost="$10-20",
            prerequisites=["VPC Flow Logs enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1048.003-aws-dns",
            name="AWS DNS Tunnelling Detection",
            description="Detect DNS tunnelling for data exfiltration via Route 53 query logging and pattern analysis.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, query_name, query_type, srcaddr, rcode
| filter query_type = "TXT" or length(query_name) > 50
| stats count(*) as query_count,
        avg(length(query_name)) as avg_length,
        count_distinct(query_name) as unique_queries
        by srcaddr, bin(5m)
| filter query_count > 100 or avg_length > 40
| sort query_count desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: DNS tunnelling detection via Route 53 query logging

Parameters:
  AlertEmail:
    Type: String
    Description: Email address for security alerts
  VPCId:
    Type: String
    Description: VPC ID to monitor DNS queries

Resources:
  # Step 1: Enable Route 53 query logging
  DNSQueryLogGroup:
    Type: AWS::Logs::LogGroup
    Properties:
      LogGroupName: /aws/route53/dns-queries
      RetentionInDays: 30

  Route53QueryLogging:
    Type: AWS::Route53::QueryLoggingConfig
    Properties:
      CloudWatchLogsLogGroupArn: !GetAtt DNSQueryLogGroup.Arn

  # Step 2: Create metric filter for suspicious DNS patterns
  DNSTunnelFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref DNSQueryLogGroup
      FilterPattern: '[timestamp, vpc_id, query_timestamp, hosted_zone, query_name, query_type="TXT", response_code, protocol, edge_location]'
      MetricTransformations:
        - MetricName: SuspiciousDNSQueries
          MetricNamespace: Security/Exfiltration
          MetricValue: "1"

  # Step 3: Create alarm for DNS tunnelling activity
  DNSTunnelAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: DNS-Tunnelling-Detected
      AlarmDescription: Suspicious DNS query patterns indicating possible tunnelling
      MetricName: SuspiciousDNSQueries
      Namespace: Security/Exfiltration
      Statistic: Sum
      Period: 300
      Threshold: 100
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      TreatMissingData: notBreaching

      AlarmActions:
        - !Ref DNSAlertTopic

  DNSAlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      DisplayName: DNS Tunnelling Alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  TopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics: [!Ref DNSAlertTopic]
      PolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Sid: AllowCloudWatchPublish
            Effect: Allow
            Principal:
              Service: cloudwatch.amazonaws.com
            Action: sns:Publish
            Resource: !Ref DNSAlertTopic
            Condition:
              StringEquals:
                AWS:SourceAccount: !Ref AWS::AccountId""",
                terraform_template="""# DNS tunnelling detection via Route 53 query logging

variable "alert_email" {
  type        = string
  description = "Email address for security alerts"
}

variable "location" {
  type        = string
  description = "Azure region for resources"
  default     = "uksouth"
}

variable "vpc_id" {
  type        = string
  description = "VPC ID to monitor DNS queries"
}

# Step 1: Enable Route 53 query logging
resource "aws_cloudwatch_log_group" "dns_queries" {
  name              = "/aws/route53/dns-queries"
  retention_in_days = 30
}

resource "aws_route53_query_log" "main" {
  cloudwatch_log_group_arn = aws_cloudwatch_log_group.dns_queries.arn
}

# Step 2: Create metric filter for suspicious DNS patterns
resource "aws_cloudwatch_log_metric_filter" "dns_tunnel" {
  name           = "suspicious-dns-queries"
  log_group_name = aws_cloudwatch_log_group.dns_queries.name
  pattern        = "[timestamp, vpc_id, query_timestamp, hosted_zone, query_name, query_type=\"TXT\", response_code, protocol, edge_location]"

  metric_transformation {
    name      = "SuspiciousDNSQueries"
    namespace = "Security/Exfiltration"
    value     = "1"
  }
}

# Step 3: Create alarm for DNS tunnelling activity
resource "aws_sns_topic" "dns_alerts" {
  name         = "dns-tunnelling-alerts"
  kms_master_key_id = "alias/aws/sns"
  display_name = "DNS Tunnelling Alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.dns_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_cloudwatch_metric_alarm" "dns_tunnel" {
  alarm_name          = "DNS-Tunnelling-Detected"
  alarm_description   = "Suspicious DNS query patterns indicating possible tunnelling"
  metric_name         = "SuspiciousDNSQueries"
  namespace           = "Security/Exfiltration"
  statistic           = "Sum"
  period              = 300
  threshold           = 100
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.dns_alerts.arn]
}

data "aws_caller_identity" "current" {}

resource "aws_sns_topic_policy" "allow_cloudwatch" {
  arn = aws_sns_topic.dns_alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowCloudWatchPublish"
      Effect    = "Allow"
      Principal = { Service = "cloudwatch.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.dns_alerts.arn
      Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
      }
    }]
  })
}""",
                alert_severity="high",
                alert_title="DNS Tunnelling Activity Detected",
                alert_description_template="Suspicious DNS query patterns from {srcaddr}: {query_count} queries with average length {avg_length} characters.",
                investigation_steps=[
                    "Identify the source instance generating queries",
                    "Review query names for encoded data patterns",
                    "Check query frequency and timing patterns",
                    "Examine destination DNS servers",
                    "Analyse query types (particularly TXT records)",
                    "Correlate with other network and system activity",
                    "Review running processes on source instance",
                ],
                containment_actions=[
                    "Isolate the source instance from network",
                    "Block suspicious DNS queries at resolver level",
                    "Implement DNS firewall rules",
                    "Restrict DNS resolver configuration",
                    "Block queries to suspicious domains",
                    "Review and update Route 53 Resolver rules",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Exclude legitimate long query names (DMARC, SPF records); whitelist known services with TXT queries; adjust query length and frequency thresholds",
            detection_coverage="70% - catches DNS tunnelling patterns",
            evasion_considerations="Low-frequency queries, using legitimate-looking domain names, splitting data across multiple domains",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2 hours",
            estimated_monthly_cost="$20-35",
            prerequisites=["Route 53 Resolver in use", "VPC DNS query logging enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1048.003-gcp-http",
            name="GCP Unencrypted HTTP Transfer Detection",
            description="Detect unencrypted HTTP data transfers via VPC Flow Logs in GCP.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="gce_subnetwork"
jsonPayload.connection.dest_port=80
jsonPayload.bytes_sent > 10485760
NOT jsonPayload.connection.dest_ip=~"^10\\."
NOT jsonPayload.connection.dest_ip=~"^172\\.1[6-9]\\."
NOT jsonPayload.connection.dest_ip=~"^192\\.168\\."''',
                gcp_terraform_template="""# GCP: Unencrypted HTTP exfiltration detection

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

# Step 1: Create log-based metric for HTTP transfers
resource "google_logging_metric" "http_exfil" {
  project = var.project_id
  name   = "unencrypted-http-transfer"
  filter = <<-EOT
    resource.type="gce_subnetwork"
    jsonPayload.connection.dest_port=80
    jsonPayload.bytes_sent > 10485760
    NOT jsonPayload.connection.dest_ip=~"^10\\."
    NOT jsonPayload.connection.dest_ip=~"^172\\.1[6-9]\\."
    NOT jsonPayload.connection.dest_ip=~"^192\\.168\\."
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    unit        = "1"
  }
}

# Step 2: Create notification channel
resource "google_monitoring_notification_channel" "email_s1" {
  project      = var.project_id
  display_name = "Security Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 3: Create alert policy
resource "google_monitoring_alert_policy" "http_exfil" {
  project      = var.project_id
  display_name = "Unencrypted HTTP Exfiltration"
  combiner     = "OR"

  conditions {
    display_name = "Large HTTP transfer detected"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.http_exfil.name}\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 10
    }
  }

  notification_channels = [google_monitoring_notification_channel.email_s1.id]

  alert_strategy {
    auto_close = "1800s"
    notification_rate_limit {
      period = "300s"
    }
  }

  documentation {
    content   = "Large unencrypted HTTP transfer detected. Investigate source instance for potential data exfiltration."
    mime_type = "text/markdown"
  }
}""",
                alert_severity="high",
                alert_title="GCP: Unencrypted HTTP Exfiltration Detected",
                alert_description_template="Large unencrypted HTTP transfer detected from GCP instance to external destination.",
                investigation_steps=[
                    "Identify the source Compute Engine instance",
                    "Review destination IP and associated domain",
                    "Examine instance service account permissions",
                    "Check for unusual process activity",
                    "Review Cloud Audit Logs for API activity",
                    "Analyse network traffic patterns",
                    "Check for data access preceding transfer",
                ],
                containment_actions=[
                    "Isolate the source instance using firewall rules",
                    "Block HTTP egress to destination IP",
                    "Revoke instance service account credentials",
                    "Implement VPC Service Controls",
                    "Enable Cloud Armor for traffic inspection",
                    "Review and restrict firewall egress rules",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist known HTTP endpoints; exclude package repositories and update servers; adjust byte threshold",
            detection_coverage="75% - catches unencrypted HTTP exfiltration",
            evasion_considerations="Using HTTPS, fragmenting transfers, non-standard ports",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$15-25",
            prerequisites=[
                "VPC Flow Logs enabled on subnets",
                "Cloud Logging API enabled",
            ],
        ),
        DetectionStrategy(
            strategy_id="t1048.003-gcp-dns",
            name="GCP DNS Tunnelling Detection",
            description="Detect DNS tunnelling via Cloud DNS query logging and pattern analysis.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="dns_query"
(protoPayload.queryName=~".{50,}" OR protoPayload.queryType="TXT")
protoPayload.responseCode="NOERROR"''',
                gcp_terraform_template="""# GCP: DNS tunnelling detection

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

variable "dns_zone_name" {
  type        = string
  description = "Cloud DNS managed zone to monitor"
}

# Step 1: Enable DNS query logging (assumes managed zone exists)
resource "google_dns_managed_zone" "monitored" {
  name        = var.dns_zone_name
  dns_name    = "example.com."
  description = "Monitored DNS zone with logging enabled"

  cloud_logging_config {
    enable_logging = true
  }
}

# Step 2: Create log-based metric for suspicious DNS patterns
resource "google_logging_metric" "dns_tunnel" {
  project = var.project_id
  name   = "dns-tunnelling-pattern"
  filter = <<-EOT
    resource.type="dns_query"
    (protoPayload.queryName=~".{50,}" OR protoPayload.queryType="TXT")
    protoPayload.responseCode="NOERROR"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    unit        = "1"
  }
}

# Step 3: Create alert for DNS tunnelling
resource "google_monitoring_notification_channel" "email_s2" {
  project      = var.project_id
  display_name = "Security Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

resource "google_monitoring_alert_policy" "dns_tunnel" {
  project      = var.project_id
  display_name = "DNS Tunnelling Detected"
  combiner     = "OR"

  conditions {
    display_name = "Suspicious DNS query patterns"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.dns_tunnel.name}\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 100
    }
  }

  notification_channels = [google_monitoring_notification_channel.email_s2.id]

  alert_strategy {
    auto_close = "1800s"
    notification_rate_limit {
      period = "300s"
    }
  }

  documentation {
    content   = "Suspicious DNS query patterns detected. Potential DNS tunnelling for data exfiltration."
    mime_type = "text/markdown"
  }
}""",
                alert_severity="high",
                alert_title="GCP: DNS Tunnelling Activity Detected",
                alert_description_template="Suspicious DNS query patterns detected indicating potential DNS tunnelling exfiltration.",
                investigation_steps=[
                    "Identify source instances generating queries",
                    "Review query names for encoded data patterns",
                    "Analyse query frequency and timing",
                    "Examine destination DNS servers",
                    "Check for TXT record queries with unusual content",
                    "Correlate with VPC Flow Logs",
                    "Review instance workload and processes",
                ],
                containment_actions=[
                    "Isolate source instances via firewall rules",
                    "Block suspicious domains at Cloud DNS",
                    "Implement DNS firewall policies",
                    "Restrict DNS resolver configuration",
                    "Review and update VPC DNS settings",
                    "Enable Cloud IDS for DNS inspection",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Exclude legitimate services with long DNS names (DMARC, SPF); whitelist known TXT query services; adjust thresholds",
            detection_coverage="70% - catches DNS tunnelling patterns",
            evasion_considerations="Low-frequency queries, legitimate domain patterns, using multiple domains",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2 hours",
            estimated_monthly_cost="$20-30",
            prerequisites=[
                "Cloud DNS managed zone with logging enabled",
                "Cloud Logging API enabled",
            ],
        ),
        # Azure Strategy: Exfiltration Over Unencrypted Non-C2 Protocol
        DetectionStrategy(
            strategy_id="t1048003-azure",
            name="Azure Exfiltration Over Unencrypted Non-C2 Protocol Detection",
            description=(
                "Azure detection for Exfiltration Over Unencrypted Non-C2 Protocol. "
                "Provides native Azure detection using Log Analytics and Defender for Cloud."
            ),
            detection_type=DetectionType.LOG_ANALYTICS_QUERY,
            aws_service="n/a",
            azure_service="log_analytics",
            cloud_provider=CloudProvider.AZURE,
            implementation=DetectionImplementation(
                azure_kql_query="""// Exfiltration Over Unencrypted Non-C2 Protocol Detection
// Technique: T1048.003
// Detects HTTP, FTP, DNS tunnelling, and unencrypted data exfiltration
// Prerequisites: AzureNetworkAnalytics_CL, DnsEvents, AzureDiagnostics

// Large HTTP (Unencrypted) Egress
let HTTPExfiltration = AzureNetworkAnalytics_CL
| where TimeGenerated > ago(24h)
| where DestPort_d == 80  // Unencrypted HTTP
| where FlowDirection_s == "O"  // Outbound
| where FlowStatus_s == "A"  // Allowed
| where FlowType_s in ("ExternalPublic", "ExternalVirtual")
| summarize
    TotalBytes = sum(todouble(OutboundBytes_d)),
    Connections = count(),
    UniqueDestinations = dcount(DestIP_s),
    Destinations = make_set(DestIP_s, 10)
    by SrcIP_s, bin(TimeGenerated, 1h)
| where TotalBytes > 10485760  // > 10 MB unencrypted
| extend AlertType = "UnencryptedHTTPEgress";

// FTP Exfiltration (Unencrypted File Transfer)
let FTPExfiltration = AzureNetworkAnalytics_CL
| where TimeGenerated > ago(24h)
| where DestPort_d in (20, 21)  // FTP data and control ports
| where FlowDirection_s == "O"
| where FlowStatus_s == "A"
| where FlowType_s in ("ExternalPublic", "ExternalVirtual")
| summarize
    TotalBytes = sum(todouble(OutboundBytes_d)),
    Sessions = count(),
    UniqueFTPServers = dcount(DestIP_s)
    by SrcIP_s, bin(TimeGenerated, 1h)
| where TotalBytes > 5242880  // > 5 MB
| extend AlertType = "FTPExfiltration";

// DNS Tunnelling Detection
let DNSTunnelling = DnsEvents
| where TimeGenerated > ago(24h)
| where QueryType in ("TXT", "NULL", "CNAME", "MX")
| extend QueryNameLength = strlen(Name)
| where QueryNameLength > 50  // Unusually long DNS queries
| summarize
    QueryCount = count(),
    AvgQueryLength = avg(QueryNameLength),
    UniqueQueries = dcount(Name),
    MaxLength = max(QueryNameLength),
    SampleQueries = make_set(Name, 10)
    by ClientIP, bin(TimeGenerated, 5m)
| where QueryCount > 50 or AvgQueryLength > 60 or MaxLength > 100
| extend AlertType = "DNSTunnelling";

// SMTP (Unencrypted Email) Exfiltration - Port 25
let SMTPExfiltration = AzureNetworkAnalytics_CL
| where TimeGenerated > ago(24h)
| where DestPort_d == 25  // Unencrypted SMTP
| where FlowDirection_s == "O"
| where FlowStatus_s == "A"
| where FlowType_s in ("ExternalPublic", "ExternalVirtual")
| summarize
    TotalBytes = sum(todouble(OutboundBytes_d)),
    EmailConnections = count(),
    UniqueMailServers = dcount(DestIP_s)
    by SrcIP_s, bin(TimeGenerated, 1h)
| where TotalBytes > 5242880 or EmailConnections > 50
| extend AlertType = "UnencryptedSMTPExfiltration";

// Base64 Encoded DNS Queries (common tunnelling pattern)
let EncodedDNSQueries = DnsEvents
| where TimeGenerated > ago(24h)
| where Name matches regex @"^[A-Za-z0-9+/=]{20,}\\."
| summarize
    EncodedQueryCount = count(),
    UniqueDomains = dcount(Name),
    SampleQueries = make_set(Name, 5)
    by ClientIP, bin(TimeGenerated, 5m)
| where EncodedQueryCount > 20
| extend AlertType = "Base64EncodedDNS";

// Azure Firewall HTTP/FTP Detection (if using Azure Firewall)
let FirewallUnencryptedTraffic = AzureDiagnostics
| where TimeGenerated > ago(24h)
| where Category == "AzureFirewallApplicationRule"
| where msg_s has_any ("HTTP", "FTP") and msg_s has "Allow"
| extend DestURL = extract(@"to (.+?):", 1, msg_s)
| extend Protocol = extract(@"^(HTTP|FTP)", 1, msg_s)
| summarize
    Requests = count(),
    UniqueURLs = dcount(DestURL)
    by SrcIP = extract(@"from (.+?):", 1, msg_s), Protocol, bin(TimeGenerated, 1h)
| where Requests > 50
| extend AlertType = "FirewallUnencryptedTraffic";

// Combine all detection signals
HTTPExfiltration
| union FTPExfiltration
| union DNSTunnelling
| union SMTPExfiltration
| union EncodedDNSQueries
| union FirewallUnencryptedTraffic
| project
    TimeGenerated,
    AlertType,
    SourceIP = coalesce(SrcIP_s, ClientIP, SrcIP),
    Details = pack_all()
| order by TimeGenerated desc""",
                azure_terraform_template="""# Azure Detection for Exfiltration Over Unencrypted Non-C2 Protocol
# MITRE ATT&CK: T1048.003

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
  name                = "t1048-003-unencrypted-alerts"
  resource_group_name = var.resource_group_name
  short_name          = "T1048003"

  email_receiver {
    name          = "security-team"
    email_address = var.alert_email
  }
}

# Alert 1: Large HTTP (Unencrypted) Egress
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "http_exfiltration" {
  name                = "t1048-003-http-exfiltration"
  resource_group_name = var.resource_group_name
  location            = var.location

  evaluation_frequency = "PT5M"
  window_duration      = "PT1H"
  scopes               = [var.log_analytics_workspace_id]
  severity             = 2

  criteria {
    query = <<-QUERY
AzureNetworkAnalytics_CL
| where TimeGenerated > ago(1h)
| where DestPort_d == 80
| where FlowDirection_s == "O"
| where FlowStatus_s == "A"
| where FlowType_s in ("ExternalPublic", "ExternalVirtual")
| summarize
    TotalBytes = sum(todouble(OutboundBytes_d)),
    Connections = count(),
    UniqueDestinations = dcount(DestIP_s)
    by SrcIP_s, bin(TimeGenerated, 1h)
| where TotalBytes > 10485760
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
  action { action_groups = [azurerm_monitor_action_group.security_alerts.id] }
  description  = "Detects large unencrypted HTTP egress (>10MB) to external destinations (T1048.003)"
  display_name = "Unencrypted HTTP Exfiltration Detected"
  enabled      = true
  tags         = { "mitre-technique" = "T1048.003", "detection-type" = "security" }
}

# Alert 2: FTP Exfiltration
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "ftp_exfiltration" {
  name                = "t1048-003-ftp-exfiltration"
  resource_group_name = var.resource_group_name
  location            = var.location

  evaluation_frequency = "PT5M"
  window_duration      = "PT1H"
  scopes               = [var.log_analytics_workspace_id]
  severity             = 2

  criteria {
    query = <<-QUERY
AzureNetworkAnalytics_CL
| where TimeGenerated > ago(1h)
| where DestPort_d in (20, 21)
| where FlowDirection_s == "O"
| where FlowStatus_s == "A"
| where FlowType_s in ("ExternalPublic", "ExternalVirtual")
| summarize
    TotalBytes = sum(todouble(OutboundBytes_d)),
    Sessions = count(),
    UniqueFTPServers = dcount(DestIP_s)
    by SrcIP_s, bin(TimeGenerated, 1h)
| where TotalBytes > 5242880
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
  action { action_groups = [azurerm_monitor_action_group.security_alerts.id] }
  description  = "Detects FTP exfiltration (>5MB) to external servers (T1048.003)"
  display_name = "FTP Exfiltration Detected"
  enabled      = true
  tags         = { "mitre-technique" = "T1048.003", "detection-type" = "security" }
}

# Alert 3: DNS Tunnelling Detection
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "dns_tunnelling" {
  name                = "t1048-003-dns-tunnelling"
  resource_group_name = var.resource_group_name
  location            = var.location

  evaluation_frequency = "PT5M"
  window_duration      = "PT5M"
  scopes               = [var.log_analytics_workspace_id]
  severity             = 2

  criteria {
    query = <<-QUERY
DnsEvents
| where TimeGenerated > ago(5m)
| where QueryType in ("TXT", "NULL", "CNAME", "MX")
| extend QueryNameLength = strlen(Name)
| where QueryNameLength > 50
| summarize
    QueryCount = count(),
    AvgQueryLength = avg(QueryNameLength),
    MaxLength = max(QueryNameLength)
    by ClientIP, bin(TimeGenerated, 5m)
| where QueryCount > 50 or AvgQueryLength > 60 or MaxLength > 100
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
  action { action_groups = [azurerm_monitor_action_group.security_alerts.id] }
  description  = "Detects DNS tunnelling patterns with long query names (T1048.003)"
  display_name = "DNS Tunnelling Detected"
  enabled      = true
  tags         = { "mitre-technique" = "T1048.003", "detection-type" = "security" }
}

# Alert 4: Unencrypted SMTP Exfiltration (Port 25)
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "smtp_exfiltration" {
  name                = "t1048-003-smtp-exfiltration"
  resource_group_name = var.resource_group_name
  location            = var.location

  evaluation_frequency = "PT5M"
  window_duration      = "PT1H"
  scopes               = [var.log_analytics_workspace_id]
  severity             = 2

  criteria {
    query = <<-QUERY
AzureNetworkAnalytics_CL
| where TimeGenerated > ago(1h)
| where DestPort_d == 25
| where FlowDirection_s == "O"
| where FlowStatus_s == "A"
| where FlowType_s in ("ExternalPublic", "ExternalVirtual")
| summarize
    TotalBytes = sum(todouble(OutboundBytes_d)),
    EmailConnections = count(),
    UniqueMailServers = dcount(DestIP_s)
    by SrcIP_s, bin(TimeGenerated, 1h)
| where TotalBytes > 5242880 or EmailConnections > 50
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
  action { action_groups = [azurerm_monitor_action_group.security_alerts.id] }
  description  = "Detects unencrypted SMTP exfiltration on port 25 (T1048.003)"
  display_name = "Unencrypted SMTP Exfiltration Detected"
  enabled      = true
  tags         = { "mitre-technique" = "T1048.003", "detection-type" = "security" }
}

# Alert 5: Base64 Encoded DNS Queries
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "encoded_dns" {
  name                = "t1048-003-encoded-dns"
  resource_group_name = var.resource_group_name
  location            = var.location

  evaluation_frequency = "PT5M"
  window_duration      = "PT5M"
  scopes               = [var.log_analytics_workspace_id]
  severity             = 2

  criteria {
    query = <<-QUERY
DnsEvents
| where TimeGenerated > ago(5m)
| where Name matches regex @"^[A-Za-z0-9+/=]{20,}\\."
| summarize
    EncodedQueryCount = count(),
    UniqueDomains = dcount(Name)
    by ClientIP, bin(TimeGenerated, 5m)
| where EncodedQueryCount > 20
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
  action { action_groups = [azurerm_monitor_action_group.security_alerts.id] }
  description  = "Detects base64-encoded DNS queries indicating tunnelling (T1048.003)"
  display_name = "Base64 Encoded DNS Queries Detected"
  enabled      = true
  tags         = { "mitre-technique" = "T1048.003", "detection-type" = "security" }
}

# Alert 6: Azure Firewall HTTP/FTP Detection
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "firewall_unencrypted" {
  name                = "t1048-003-firewall-unencrypted"
  resource_group_name = var.resource_group_name
  location            = var.location

  evaluation_frequency = "PT5M"
  window_duration      = "PT1H"
  scopes               = [var.log_analytics_workspace_id]
  severity             = 2

  criteria {
    query = <<-QUERY
AzureDiagnostics
| where TimeGenerated > ago(1h)
| where Category == "AzureFirewallApplicationRule"
| where msg_s has_any ("HTTP", "FTP") and msg_s has "Allow"
| extend Protocol = extract(@"^(HTTP|FTP)", 1, msg_s)
| extend SrcIP = extract(@"from (.+?):", 1, msg_s)
| summarize
    Requests = count(),
    UniqueURLs = dcount(extract(@"to (.+?):", 1, msg_s))
    by SrcIP, Protocol, bin(TimeGenerated, 1h)
| where Requests > 50
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
  action { action_groups = [azurerm_monitor_action_group.security_alerts.id] }
  description  = "Detects high-volume unencrypted HTTP/FTP traffic via Azure Firewall (T1048.003)"
  display_name = "Firewall Unencrypted Traffic Detected"
  enabled      = true
  tags         = { "mitre-technique" = "T1048.003", "detection-type" = "security" }
}

output "alert_rule_ids" {
  value = {
    http_exfiltration     = azurerm_monitor_scheduled_query_rules_alert_v2.http_exfiltration.id
    ftp_exfiltration      = azurerm_monitor_scheduled_query_rules_alert_v2.ftp_exfiltration.id
    dns_tunnelling        = azurerm_monitor_scheduled_query_rules_alert_v2.dns_tunnelling.id
    smtp_exfiltration     = azurerm_monitor_scheduled_query_rules_alert_v2.smtp_exfiltration.id
    encoded_dns           = azurerm_monitor_scheduled_query_rules_alert_v2.encoded_dns.id
    firewall_unencrypted  = azurerm_monitor_scheduled_query_rules_alert_v2.firewall_unencrypted.id
  }
}""",
                alert_severity="high",
                alert_title="Azure: Exfiltration Over Unencrypted Non-C2 Protocol Detected",
                alert_description_template=(
                    "Exfiltration Over Unencrypted Non-C2 Protocol activity detected. "
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
        "t1048.003-aws-http",
        "t1048.003-aws-ftp",
        "t1048.003-aws-dns",
        "t1048.003-gcp-http",
        "t1048.003-gcp-dns",
    ],
    total_effort_hours=7.5,
    coverage_improvement="+22% improvement for Exfiltration tactic (T1048.003)",
)
