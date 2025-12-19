"""
T1132 - Data Encoding

Adversaries encode command and control traffic to evade detection by making malicious
communications appear as benign data. Standard and non-standard encoding schemes are used
to obfuscate C2 communications, making network inspection more difficult.
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
    technique_id="T1132",
    technique_name="Data Encoding",
    tactic_ids=["TA0011"],  # Command and Control
    mitre_url="https://attack.mitre.org/techniques/T1132/",

    threat_context=ThreatContext(
        description=(
            "Adversaries encode command and control traffic to make detection more difficult. "
            "This includes standard encoding systems like ASCII, Unicode, Base64, MIME, and "
            "binary-to-text encodings, which may also compress data using algorithms like gzip. "
            "Non-standard encoding schemes are also employed to further obfuscate malicious "
            "communications. In cloud environments, encoded data may be transmitted via HTTP "
            "headers, URL parameters, DNS queries, or API requests, blending with legitimate traffic."
        ),
        attacker_goal="Obfuscate command and control communications to evade network detection and inspection",
        why_technique=[
            "Bypasses signature-based detection systems",
            "Makes malicious traffic appear as legitimate encoded data",
            "Evades content inspection and data loss prevention tools",
            "Enables exfiltration of sensitive data without detection",
            "Allows commands to pass through security controls",
            "Compression reduces network footprint and improves stealth"
        ],
        known_threat_actors=[
            "Velvet Ant",
            "APT groups using encoded C2"
        ],
        recent_campaigns=[
            Campaign(
                name="Velvet Ant F5 BIG-IP Compromise",
                year=2024,
                description="Velvet Ant sent commands to compromised F5 BIG-IP devices in an encoded format requiring a passkey before interpretation",
                reference_url="https://attack.mitre.org/groups/G1047/"
            ),
            Campaign(
                name="BADNEWS Base64 Encoding",
                year=2023,
                description="BADNEWS malware converts encrypted C2 data to hexadecimal format, then encodes it as base64 for transmission",
                reference_url="https://attack.mitre.org/software/S0128/"
            ),
            Campaign(
                name="H1N1 Modified Base64",
                year=2023,
                description="H1N1 malware uses altered base64 obfuscation for C2 traffic to evade detection",
                reference_url="https://attack.mitre.org/software/S0132/"
            ),
            Campaign(
                name="Ursnif URL Encoding",
                year=2022,
                description="Ursnif banking trojan employs encoded data in HTTP URLs for command and control communications",
                reference_url="https://attack.mitre.org/software/S0386/"
            )
        ],
        prevalence="common",
        trend="increasing",
        severity_score=7,
        severity_reasoning=(
            "Data encoding is widely used by adversaries to evade network-based detection. "
            "Whilst encoding itself is not malicious, its abuse for C2 communications enables "
            "persistent unauthorised access and data exfiltration. The technique is effective "
            "because encoded data is common in legitimate applications, making it difficult to "
            "distinguish malicious activity from normal operations. Medium-high severity due to "
            "detection evasion capabilities and widespread adoption by threat actors."
        ),
        business_impact=[
            "Undetected command and control communications",
            "Data exfiltration through encoded channels",
            "Prolonged adversary persistence in environment",
            "Bypassed security controls and monitoring",
            "Compliance violations from undetected malicious activity"
        ],
        typical_attack_phase="command_and_control",
        often_precedes=["T1041", "T1048", "T1567"],  # Exfiltration techniques
        often_follows=["T1071", "T1573"]  # Application Layer Protocol, Encrypted Channel
    ),

    detection_strategies=[
        # Strategy 1: AWS - Base64 Encoding in HTTP Traffic
        DetectionStrategy(
            strategy_id="t1132-aws-base64-http",
            name="AWS Base64 Encoded HTTP Traffic Detection",
            description="Detect unusual Base64 encoded data in HTTP requests and responses via VPC Flow Logs and application logs.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query='''fields @timestamp, @message
| filter @message like /[A-Za-z0-9+/]{100,}={0,2}/
| filter @message like /POST|GET|PUT/
| parse @message /(?<method>GET|POST|PUT)[ ]+(?<uri>[^ ]+)[ ]+HTTP/
| parse @message /(?<base64_data>[A-Za-z0-9+/]{100,}={0,2})/
| stats count() as encoded_requests by sourceIP, uri, bin(5m)
| filter encoded_requests > 20
| sort encoded_requests desc''',
                cloudformation_template='''AWSTemplateFormatVersion: '2010-09-09'
Description: Detect Base64 encoded HTTP traffic for C2 detection

Parameters:
  AlertEmail:
    Type: String
    Description: Email address for security alerts
  ApplicationLogGroup:
    Type: String
    Description: CloudWatch Log Group containing application logs

Resources:
  # Step 1: SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Metric filter for Base64 patterns
  Base64Filter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref ApplicationLogGroup
      FilterPattern: '[... request_data = *[A-Za-z0-9+/]{100,}* ...]'
      MetricTransformations:
        - MetricName: Base64EncodedRequests
          MetricNamespace: Security/C2Detection
          MetricValue: "1"
          DefaultValue: 0

  # Step 3: CloudWatch alarm for encoded traffic
  Base64Alarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: High-Volume-Base64-Traffic
      AlarmDescription: Alert on high volume of Base64 encoded HTTP traffic
      MetricName: Base64EncodedRequests
      Namespace: Security/C2Detection
      Statistic: Sum
      Period: 300
      EvaluationPeriods: 1
      Threshold: 50
      ComparisonOperator: GreaterThanThreshold
      AlarmActions:
        - !Ref AlertTopic''',
                terraform_template='''# Detect Base64 encoded HTTP traffic

variable "alert_email" {
  type        = string
  description = "Email address for security alerts"
}

variable "application_log_group" {
  type        = string
  description = "CloudWatch Log Group containing application logs"
}

# Step 1: SNS topic for alerts
resource "aws_sns_topic" "base64_alerts" {
  name = "base64-encoding-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.base64_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: CloudWatch metric filter for Base64 patterns
resource "aws_cloudwatch_log_metric_filter" "base64_traffic" {
  name           = "base64-encoded-requests"
  log_group_name = var.application_log_group
  pattern        = "[... request_data = *[A-Za-z0-9+/]{100,}* ...]"

  metric_transformation {
    name      = "Base64EncodedRequests"
    namespace = "Security/C2Detection"
    value     = "1"
  }
}

# Step 3: CloudWatch alarm
resource "aws_cloudwatch_metric_alarm" "base64_traffic" {
  alarm_name          = "High-Volume-Base64-Traffic"
  alarm_description   = "Alert on high volume of Base64 encoded HTTP traffic"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "Base64EncodedRequests"
  namespace           = "Security/C2Detection"
  period              = 300
  statistic           = "Sum"
  threshold           = 50
  alarm_actions       = [aws_sns_topic.base64_alerts.arn]
}''',
                alert_severity="high",
                alert_title="High Volume Base64 Encoded HTTP Traffic Detected",
                alert_description_template="Unusual volume of Base64 encoded HTTP traffic detected from {sourceIP}. May indicate encoded C2 communications.",
                investigation_steps=[
                    "Identify the source instance generating encoded traffic",
                    "Decode sample Base64 strings to analyse content",
                    "Review application purpose and expected encoding usage",
                    "Check for unusual user agents or HTTP headers",
                    "Analyse destination IPs and domains for reputation",
                    "Correlate with other suspicious activities from source",
                    "Review process list and running applications on instance"
                ],
                containment_actions=[
                    "Isolate the source instance from network",
                    "Block suspicious destination IPs via security groups",
                    "Enable AWS WAF with Base64 decoding rules",
                    "Deploy network intrusion detection systems",
                    "Review and restrict instance IAM permissions",
                    "Implement content inspection at application layer"
                ]
            ),
            estimated_false_positive_rate=FalsePositiveRate.HIGH,
            false_positive_tuning="Whitelist legitimate applications using Base64 (APIs, file uploads, authentication). Establish baselines for expected encoding patterns.",
            detection_coverage="60% - detects Base64 encoding but legitimate use is common",
            evasion_considerations="Attackers may use non-standard encoding, compression, or chunked encoding to evade detection",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$10-25",
            prerequisites=["Application logs in CloudWatch", "VPC Flow Logs enabled"]
        ),

        # Strategy 2: AWS - Encoded DNS Queries
        DetectionStrategy(
            strategy_id="t1132-aws-dns-encoding",
            name="AWS Encoded DNS Query Detection",
            description="Detect encoded or obfuscated data in DNS queries that may indicate DNS tunnelling with encoding.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query='''fields @timestamp, query_name, query_type, srcaddr
| filter query_name like /[A-Za-z0-9]{32,}[.]/
| filter query_name like /[A-Fa-f0-9]{40,}[.]/ or query_name like /[A-Za-z0-9+/]{40,}[.]/
| stats count() as query_count, avg(length(query_name)) as avg_length,
        count_distinct(query_name) as unique_queries by srcaddr, bin(5m)
| filter query_count > 50 or avg_length > 60
| sort query_count desc''',
                cloudformation_template='''AWSTemplateFormatVersion: '2010-09-09'
Description: Detect encoded data in DNS queries for C2 and tunnelling detection

Parameters:
  AlertEmail:
    Type: String
    Description: Email address for security alerts

Resources:
  # Step 1: Route 53 query logging
  QueryLogGroup:
    Type: AWS::Logs::LogGroup
    Properties:
      LogGroupName: /aws/route53/encoded-query-detection
      RetentionInDays: 30

  # Step 2: SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 3: Metric filter for encoded DNS patterns
  EncodedDnsFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref QueryLogGroup
      FilterPattern: '[... query_name_length > 60 ...]'
      MetricTransformations:
        - MetricName: EncodedDNSQueries
          MetricNamespace: Security/C2Detection
          MetricValue: "1"
          Unit: Count

  EncodedDnsAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: Encoded-DNS-Queries-Detected
      AlarmDescription: Detect encoded data in DNS queries
      MetricName: EncodedDNSQueries
      Namespace: Security/C2Detection
      Statistic: Sum
      Period: 300
      EvaluationPeriods: 1
      Threshold: 50
      ComparisonOperator: GreaterThanThreshold
      AlarmActions:
        - !Ref AlertTopic''',
                terraform_template='''# Detect encoded data in DNS queries

variable "alert_email" {
  type        = string
  description = "Email address for security alerts"
}

# Step 1: CloudWatch Log Group for Route 53 queries
resource "aws_cloudwatch_log_group" "dns_queries" {
  name              = "/aws/route53/encoded-query-detection"
  retention_in_days = 30
}

# Step 2: SNS topic for alerts
resource "aws_sns_topic" "dns_encoding_alerts" {
  name = "dns-encoding-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.dns_encoding_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 3: Metric filter for encoded DNS patterns
resource "aws_cloudwatch_log_metric_filter" "encoded_dns" {
  name           = "encoded-dns-queries"
  log_group_name = aws_cloudwatch_log_group.dns_queries.name
  pattern        = "[... query_name_length > 60 ...]"

  metric_transformation {
    name      = "EncodedDNSQueries"
    namespace = "Security/C2Detection"
    value     = "1"
    unit      = "Count"
  }
}

resource "aws_cloudwatch_metric_alarm" "encoded_dns" {
  alarm_name          = "Encoded-DNS-Queries-Detected"
  alarm_description   = "Detect encoded data in DNS queries"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "EncodedDNSQueries"
  namespace           = "Security/C2Detection"
  period              = 300
  statistic           = "Sum"
  threshold           = 50
  alarm_actions       = [aws_sns_topic.dns_encoding_alerts.arn]
}''',
                alert_severity="high",
                alert_title="Encoded DNS Queries Detected",
                alert_description_template="Encoded or suspicious DNS queries detected from {srcaddr}. Query pattern may indicate DNS tunnelling with encoded C2 data.",
                investigation_steps=[
                    "Identify the source instance making encoded DNS queries",
                    "Analyse query names for encoding patterns (Base64, hex, custom)",
                    "Attempt to decode query strings to identify data type",
                    "Review query frequency and timing patterns",
                    "Check destination DNS servers for legitimacy",
                    "Examine instance processes and network connections",
                    "Correlate with threat intelligence on DNS tunnelling domains"
                ],
                containment_actions=[
                    "Isolate the source instance immediately",
                    "Block suspicious DNS queries via Route 53 Resolver DNS Firewall",
                    "Implement DNS sinkholing for identified C2 domains",
                    "Restrict DNS resolver access to approved servers only",
                    "Enable enhanced DNS query logging across all VPCs",
                    "Review instance security and IAM permissions"
                ]
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist legitimate services with long DNS queries (CDNs, monitoring tools). Tune query length thresholds based on environment.",
            detection_coverage="70% - detects DNS-based encoded C2 effectively",
            evasion_considerations="Low and slow tunnelling with shorter query names may evade detection",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2 hours",
            estimated_monthly_cost="$15-30",
            prerequisites=["Route 53 Query Logging enabled", "VPC DNS resolver in use"]
        ),

        # Strategy 3: AWS - Unusual Encoding Utilities Detection
        DetectionStrategy(
            strategy_id="t1132-aws-encoding-tools",
            name="AWS Encoding Utility Execution Detection",
            description="Detect execution of encoding utilities and scripts that may be used for C2 or exfiltration.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query='''fields @timestamp, userIdentity.principalId, requestParameters
| filter eventName in ["RunInstances", "SendCommand", "ExecuteCommand"]
| filter requestParameters like /base64|xxd|openssl enc|gzip|gunzip|uuencode|uudecode/
| stats count() as encoding_commands by userIdentity.principalId, eventName
| sort encoding_commands desc''',
                cloudformation_template='''AWSTemplateFormatVersion: '2010-09-09'
Description: Detect execution of encoding utilities via CloudTrail

Parameters:
  AlertEmail:
    Type: String
    Description: Email address for security alerts
  CloudTrailLogGroup:
    Type: String
    Description: CloudWatch Log Group for CloudTrail logs

Resources:
  # Step 1: SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: EventBridge rule for encoding commands
  EncodingToolsRule:
    Type: AWS::Events::Rule
    Properties:
      Description: Detect encoding utility execution
      EventPattern:
        source:
          - aws.ssm
        detail-type:
          - AWS API Call via CloudTrail
        detail:
          eventName:
            - SendCommand
            - StartSession
          requestParameters:
            commands:
              - prefix: base64
              - prefix: xxd
              - prefix: openssl enc
              - prefix: gzip

      State: ENABLED
      Targets:
        - Id: AlertTopic
          Arn: !Ref AlertTopic

  # Step 3: Topic policy
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
            Resource: !Ref AlertTopic''',
                terraform_template='''# Detect encoding utility execution

variable "alert_email" {
  type        = string
  description = "Email address for security alerts"
}

variable "cloudtrail_log_group" {
  type        = string
  description = "CloudWatch Log Group for CloudTrail logs"
}

# Step 1: SNS topic for alerts
resource "aws_sns_topic" "encoding_tools_alerts" {
  name = "encoding-tools-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.encoding_tools_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: EventBridge rule for encoding commands
resource "aws_cloudwatch_event_rule" "encoding_tools" {
  name        = "encoding-utility-detection"
  description = "Detect encoding utility execution"

  event_pattern = jsonencode({
    source      = ["aws.ssm"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = ["SendCommand", "StartSession"]
      requestParameters = {
        commands = [
          { prefix = "base64" },
          { prefix = "xxd" },
          { prefix = "openssl enc" },
          { prefix = "gzip" }
        ]
      }
    }
  })
}

resource "aws_cloudwatch_event_target" "sns" {
  rule = aws_cloudwatch_event_rule.encoding_tools.name
  arn  = aws_sns_topic.encoding_tools_alerts.arn
}

# Step 3: SNS topic policy
resource "aws_sns_topic_policy" "allow_events" {
  arn = aws_sns_topic.encoding_tools_alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.encoding_tools_alerts.arn
    }]
  })
}''',
                alert_severity="medium",
                alert_title="Encoding Utility Execution Detected",
                alert_description_template="Encoding utility executed by {userIdentity.principalId} via {eventName}. May indicate preparation for encoded C2 or exfiltration.",
                investigation_steps=[
                    "Identify the user or role executing encoding commands",
                    "Review the complete command executed and parameters",
                    "Determine business justification for encoding usage",
                    "Check for subsequent network activity or file transfers",
                    "Review user's recent activity and access patterns",
                    "Analyse files being encoded or decoded",
                    "Correlate with other suspicious activities"
                ],
                containment_actions=[
                    "Disable compromised credentials immediately",
                    "Review and restrict SSM access permissions",
                    "Implement session manager logging and monitoring",
                    "Block unnecessary command execution capabilities",
                    "Enable OS-level process monitoring and EDR",
                    "Review and audit all recent commands from user"
                ]
            ),
            estimated_false_positive_rate=FalsePositiveRate.HIGH,
            false_positive_tuning="Whitelist legitimate use cases (backup scripts, deployment automation, development activities). Document approved encoding usage.",
            detection_coverage="55% - detects utility execution but many legitimate uses exist",
            evasion_considerations="Attackers may use custom encoding tools or built-in language features (Python, PowerShell) to evade detection",
            implementation_effort=EffortLevel.LOW,
            implementation_time="45 minutes",
            estimated_monthly_cost="$5-15",
            prerequisites=["CloudTrail enabled", "SSM Session Manager logging"]
        ),

        # Strategy 4: GCP - Encoded HTTP Traffic Detection
        DetectionStrategy(
            strategy_id="t1132-gcp-http-encoding",
            name="GCP Encoded HTTP Traffic Detection",
            description="Detect Base64 and other encoded data patterns in HTTP traffic via Cloud Logging.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="http_load_balancer"
httpRequest.requestUrl=~"[A-Za-z0-9+/]{100,}={0,2}"
OR httpRequest.requestUrl=~"[A-Fa-f0-9]{100,}"
| stats count() as encoded_requests by httpRequest.remoteIp, bin(5m)
| encoded_requests > 20''',
                gcp_terraform_template='''# GCP: Detect encoded HTTP traffic

variable "project_id" {
  type        = string
  description = "GCP project ID"
}

variable "alert_email" {
  type        = string
  description = "Email address for security alerts"
}

# Step 1: Notification channel
resource "google_monitoring_notification_channel" "email" {
  display_name = "Security Alerts - Encoding Detection"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Log-based metric for encoded HTTP traffic
resource "google_logging_metric" "encoded_http" {
  name   = "encoded-http-traffic"
  filter = <<-EOT
    resource.type="http_load_balancer"
    (httpRequest.requestUrl=~"[A-Za-z0-9+/]{100,}={0,2}"
     OR httpRequest.requestUrl=~"[A-Fa-f0-9]{100,}")
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Alert policy for encoded traffic
resource "google_monitoring_alert_policy" "encoded_http" {
  display_name = "Encoded HTTP Traffic Detected"
  combiner     = "OR"

  conditions {
    display_name = "High volume of encoded HTTP requests"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.encoded_http.name}\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 50
      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_RATE"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]

  alert_strategy {
    auto_close = "86400s"
  }

  documentation {
    content = "Encoded HTTP traffic detected. Investigate for potential C2 or data exfiltration activity."
  }
}''',
                alert_severity="high",
                alert_title="GCP: Encoded HTTP Traffic Detected",
                alert_description_template="High volume of encoded HTTP traffic detected. May indicate encoded C2 communications or data exfiltration.",
                investigation_steps=[
                    "Identify source VM instances and their purpose",
                    "Decode sample Base64 or hex strings from traffic",
                    "Review application architecture and expected encoding",
                    "Check destination URLs and IP reputation",
                    "Analyse Cloud Logging for application-level logs",
                    "Review VM instance metadata and configurations",
                    "Correlate with other security findings"
                ],
                containment_actions=[
                    "Isolate affected VM instances using firewall rules",
                    "Deploy Cloud Armor rules to block encoded patterns",
                    "Create snapshots for forensic analysis",
                    "Revoke service account credentials",
                    "Enable VPC Service Controls for data exfiltration prevention",
                    "Review and restrict egress firewall rules"
                ]
            ),
            estimated_false_positive_rate=FalsePositiveRate.HIGH,
            false_positive_tuning="Whitelist legitimate API endpoints using encoding. Establish baselines for expected encoded traffic patterns.",
            detection_coverage="60% - detects common encoding patterns in HTTP traffic",
            evasion_considerations="Custom encoding schemes or chunked data may evade pattern matching",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$10-25",
            prerequisites=["Cloud Load Balancer logging enabled", "VPC Flow Logs"]
        ),

        # Strategy 5: GCP - Encoded DNS Query Detection
        DetectionStrategy(
            strategy_id="t1132-gcp-dns-encoding",
            name="GCP Encoded DNS Query Detection",
            description="Detect encoded or obfuscated DNS queries via Cloud DNS logging.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="dns_query"
(LENGTH(protoPayload.queryName) > 60
 OR protoPayload.queryName=~"[A-Za-z0-9]{40,}\\."
 OR protoPayload.queryName=~"[A-Fa-f0-9]{40,}\\.")
| stats count() as query_count, avg(LENGTH(protoPayload.queryName)) as avg_length
  by sourceIP, bin(5m)
| query_count > 50 OR avg_length > 60''',
                gcp_terraform_template='''# GCP: Detect encoded DNS queries

variable "project_id" {
  type        = string
  description = "GCP project ID"
}

variable "alert_email" {
  type        = string
  description = "Email address for security alerts"
}

# Step 1: Enable Cloud DNS logging (manual or via DNS policy)
resource "google_dns_managed_zone" "monitored" {
  name        = "monitored-dns-zone"
  dns_name    = "example.com."
  description = "DNS zone with logging for encoding detection"

  cloud_logging_config {
    enable_logging = true
  }
}

# Step 2: Notification channel
resource "google_monitoring_notification_channel" "email" {
  display_name = "Security Alerts - DNS Encoding"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 3: Log-based metric for encoded DNS queries
resource "google_logging_metric" "encoded_dns" {
  name   = "encoded-dns-queries"
  filter = <<-EOT
    resource.type="dns_query"
    (LENGTH(protoPayload.queryName) > 60
     OR protoPayload.queryName=~"[A-Za-z0-9]{40,}\\."
     OR protoPayload.queryName=~"[A-Fa-f0-9]{40,}\\.")
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

resource "google_monitoring_alert_policy" "encoded_dns" {
  display_name = "Encoded DNS Queries Detected"
  combiner     = "OR"

  conditions {
    display_name = "Suspicious encoded DNS query patterns"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.encoded_dns.name}\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 50
      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_RATE"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]

  alert_strategy {
    auto_close = "86400s"
  }

  documentation {
    content = "Encoded DNS queries detected. Investigate for DNS tunnelling or encoded C2 activity."
  }
}''',
                alert_severity="high",
                alert_title="GCP: Encoded DNS Queries Detected",
                alert_description_template="Encoded or suspicious DNS queries detected. Query patterns may indicate DNS tunnelling with encoded C2 data.",
                investigation_steps=[
                    "Identify source VM instances making encoded queries",
                    "Analyse DNS query names for encoding patterns",
                    "Attempt to decode query strings to identify content type",
                    "Review query frequency and timing for tunnelling patterns",
                    "Check destination DNS servers and domain reputation",
                    "Examine VM processes and network connections",
                    "Correlate with threat intelligence feeds"
                ],
                containment_actions=[
                    "Isolate source VM instances immediately",
                    "Configure Cloud DNS policy to block suspicious queries",
                    "Implement DNS firewall rules via VPC",
                    "Restrict DNS resolver access to approved servers",
                    "Enable VPC Service Controls to prevent data exfiltration",
                    "Review and revoke compromised credentials"
                ]
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist legitimate long DNS queries (CDNs, DDoS protection services). Tune query length thresholds based on baseline.",
            detection_coverage="70% - effectively detects DNS-based encoded traffic",
            evasion_considerations="Low frequency queries with shorter encoding may evade thresholds",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$15-30",
            prerequisites=["Cloud DNS logging enabled", "VPC Flow Logs enabled"]
        ),

        # Strategy 6: GCP - Encoding Process Detection
        DetectionStrategy(
            strategy_id="t1132-gcp-encoding-tools",
            name="GCP Encoding Utility Execution Detection",
            description="Detect execution of encoding utilities on GCP instances via OS logging.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="gce_instance"
logName=~"projects/.*/logs/syslog"
(textPayload=~"base64"
 OR textPayload=~"xxd"
 OR textPayload=~"openssl enc"
 OR textPayload=~"gzip.*-c"
 OR textPayload=~"uuencode")
severity>=WARNING''',
                gcp_terraform_template='''# GCP: Detect encoding utility execution

variable "project_id" {
  type        = string
  description = "GCP project ID"
}

variable "alert_email" {
  type        = string
  description = "Email address for security alerts"
}

# Step 1: Notification channel
resource "google_monitoring_notification_channel" "email" {
  display_name = "Security Alerts - Encoding Tools"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Log-based metric for encoding tools
resource "google_logging_metric" "encoding_tools" {
  name   = "encoding-utility-execution"
  filter = <<-EOT
    resource.type="gce_instance"
    logName=~"projects/.*/logs/syslog"
    (textPayload=~"base64"
     OR textPayload=~"xxd"
     OR textPayload=~"openssl enc"
     OR textPayload=~"gzip.*-c"
     OR textPayload=~"uuencode")
    severity>=WARNING
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Alert policy
resource "google_monitoring_alert_policy" "encoding_tools" {
  display_name = "Encoding Utility Execution Detected"
  combiner     = "OR"

  conditions {
    display_name = "Encoding utilities executed on instances"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.encoding_tools.name}\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 10
      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_RATE"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]

  alert_strategy {
    auto_close = "86400s"
  }

  documentation {
    content = "Encoding utility execution detected. Investigate for potential encoded C2 or data preparation for exfiltration."
  }
}''',
                alert_severity="medium",
                alert_title="GCP: Encoding Utility Execution Detected",
                alert_description_template="Encoding utilities executed on GCP instances. May indicate preparation for encoded C2 or exfiltration.",
                investigation_steps=[
                    "Identify VM instances executing encoding utilities",
                    "Review complete command executed and parameters",
                    "Determine business justification for encoding",
                    "Check for subsequent network activity or transfers",
                    "Review user activity and authentication logs",
                    "Analyse files being encoded or decoded",
                    "Correlate with other suspicious activities"
                ],
                containment_actions=[
                    "Isolate affected VM instances",
                    "Revoke compromised service account keys",
                    "Enable OS Config for patch management and compliance",
                    "Deploy endpoint detection and response (EDR) agents",
                    "Review and restrict IAM permissions",
                    "Implement application whitelisting where possible"
                ]
            ),
            estimated_false_positive_rate=FalsePositiveRate.HIGH,
            false_positive_tuning="Whitelist legitimate encoding usage (backup scripts, application deployment, development). Document approved use cases.",
            detection_coverage="55% - detects utility execution but many legitimate uses",
            evasion_considerations="Custom encoding tools or language built-ins (Python, Node.js) may evade syslog detection",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$10-20",
            prerequisites=["Cloud Logging agent installed on VMs", "OS logging enabled"]
        )
    ],

    recommended_order=[
        "t1132-aws-dns-encoding",
        "t1132-gcp-dns-encoding",
        "t1132-aws-base64-http",
        "t1132-gcp-http-encoding",
        "t1132-aws-encoding-tools",
        "t1132-gcp-encoding-tools"
    ],
    total_effort_hours=8.5,
    coverage_improvement="+18% improvement for Command and Control tactic detection"
)
