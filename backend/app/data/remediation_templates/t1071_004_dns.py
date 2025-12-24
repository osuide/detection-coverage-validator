"""
T1071.004 - Application Layer Protocol: DNS

Adversaries exploit DNS for command and control communications by embedding commands and
data within DNS queries and responses. DNS tunnelling enables covert C2 channels that blend
with legitimate network traffic, making detection challenging.
Used by APT18, APT39, APT41, OilRig, FIN7, Cobalt Group, and over 40 malware families.
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
    technique_id="T1071.004",
    technique_name="Application Layer Protocol: DNS",
    tactic_ids=["TA0011"],  # Command and Control
    mitre_url="https://attack.mitre.org/techniques/T1071/004/",
    threat_context=ThreatContext(
        description=(
            "Adversaries exploit DNS protocol for command and control communications by "
            "embedding commands and responses within DNS packet fields and headers. DNS tunnelling "
            "allows bidirectional communication through standard DNS infrastructure whilst evading "
            "detection, as DNS traffic typically receives minimal scrutiny and may be allowed before "
            "network authentication completes. Attackers encode payloads within subdomain portions of "
            "DNS queries and use various record types—particularly TXT and A records—to exfiltrate data "
            "and receive commands. This technique proves particularly effective in cloud environments "
            "where DNS is essential for service discovery and inter-service communication."
        ),
        attacker_goal="Establish covert command and control channels using DNS protocol to evade detection",
        why_technique=[
            "DNS traffic typically allowed through firewalls by default",
            "Minimal inspection of DNS queries in most environments",
            "DNS available before network authentication in many cases",
            "Blends with legitimate DNS service discovery traffic",
            "Supports bidirectional communication for C2 operations",
            "Enables data exfiltration through encoded subdomains",
            "Difficult to distinguish from normal application behaviour",
            "Multiple DNS record types available for data encoding",
        ],
        known_threat_actors=[],
        recent_campaigns=[
            Campaign(
                name="SUNBURST SolarWinds Supply Chain",
                year=2020,
                description="SUNBURST malware mimicked legitimate SolarWinds API communications via DNS, using DNS queries to communicate with C2 infrastructure whilst evading detection",
                reference_url="https://attack.mitre.org/campaigns/C0024/",
            ),
            Campaign(
                name="Cobalt Strike DNS Beaconing",
                year=2024,
                description="Cobalt Strike framework deployed with DNS beaconing profiles, encapsulating C2 communications in DNS traffic using custom protocols",
                reference_url="https://attack.mitre.org/software/S0154/",
            ),
            Campaign(
                name="APT39 DNS Tunnelling Operations",
                year=2023,
                description="APT39 utilised DNS tunnelling techniques for covert C2 communications in targeted intelligence gathering operations",
                reference_url="https://attack.mitre.org/groups/G0087/",
            ),
            Campaign(
                name="OilRig DNS C2 Infrastructure",
                year=2022,
                description="OilRig APT group deployed DNS-based C2 infrastructure for persistent access in Middle Eastern targets",
                reference_url="https://attack.mitre.org/groups/G0049/",
            ),
        ],
        prevalence="common",
        trend="increasing",
        severity_score=8,
        severity_reasoning=(
            "DNS-based C2 is highly prevalent across advanced threat actors and commodity malware. "
            "Its effectiveness in evading traditional security controls combined with difficulty in detection "
            "makes it a persistent threat. Cloud environments amplify risk due to heavy reliance on DNS for "
            "service discovery. High severity due to enabling persistent unauthorised access and data exfiltration "
            "whilst remaining largely undetected by conventional network security measures."
        ),
        business_impact=[
            "Covert command and control channels enabling persistent access",
            "Data exfiltration through DNS tunnelling",
            "Prolonged attacker dwell time due to detection challenges",
            "Compliance violations from undetected malicious communications",
            "Potential for lateral movement and privilege escalation",
            "Reputation damage if DNS infrastructure is compromised",
        ],
        typical_attack_phase="command_and_control",
        often_precedes=["T1041", "T1567", "T1048"],  # Exfiltration techniques
        often_follows=["T1078.004", "T1190", "T1566"],  # Initial Access techniques
    ),
    detection_strategies=[
        # Strategy 1: AWS - DNS Query Anomaly Detection
        DetectionStrategy(
            strategy_id="t1071-004-aws-dns-anomaly",
            name="AWS Route 53 DNS Tunnelling Detection",
            description="Detect DNS tunnelling patterns including unusual query types, long subdomain strings, and high-entropy domain names indicative of DNS-based C2.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query=r"""fields @timestamp, query_name, query_type, srcaddr, srcport
| filter query_type in ["TXT", "NULL", "ANY", "MX"]
| filter query_name like /[a-f0-9]{32,}/ or query_name like /[A-Za-z0-9+\/=]{40,}/ or strlen(query_name) > 60
| stats count() as query_count, dc(query_name) as unique_queries by srcaddr, query_type, bin(5m)
| filter query_count > 20 or unique_queries > 15
| sort query_count desc
| limit 100""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect DNS tunnelling and C2 communications via Route 53

Parameters:
  Route53LogGroup:
    Type: String
    Description: CloudWatch Log Group for Route 53 Query Logging
  AlertEmail:
    Type: String
    Description: Email address for security alerts

Resources:
  # Step 1: SNS topic for DNS tunnelling alerts
  DnsTunnellingAlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      DisplayName: DNS Tunnelling Detection Alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Metric filter for suspicious DNS patterns
  SuspiciousDnsMetric:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref Route53LogGroup
      FilterPattern: '[..., query_type=TXT || query_type=NULL || query_type=ANY, ...]'
      MetricTransformations:
        - MetricName: SuspiciousDnsQueries
          MetricNamespace: Security/DnsTunnelling
          MetricValue: '1'
          DefaultValue: 0

  # Step 3: CloudWatch alarm for DNS tunnelling
  DnsTunnellingAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: DnsTunnellingDetected
      AlarmDescription: Alert on potential DNS tunnelling activity
      MetricName: SuspiciousDnsQueries
      Namespace: Security/DnsTunnelling
      Statistic: Sum
      Period: 300
      EvaluationPeriods: 1
      Threshold: 50
      ComparisonOperator: GreaterThanThreshold
      AlarmActions:
        - !Ref DnsTunnellingAlertTopic

  TopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics:
        - !Ref DnsTunnellingAlertTopic
      PolicyDocument:
        Statement:
          - Effect: Allow
            Principal:
              Service: cloudwatch.amazonaws.com
            Action: sns:Publish
            Resource: !Ref DnsTunnellingAlertTopic""",
                terraform_template="""# Detect DNS tunnelling via Route 53 query logs

variable "route53_log_group" {
  type        = string
  description = "CloudWatch Log Group for Route 53 Query Logging"
}

variable "alert_email" {
  type        = string
  description = "Email address for security alerts"
}

# Step 1: SNS topic for alerts
resource "aws_sns_topic" "dns_tunnelling" {
  name         = "dns-tunnelling-alerts"
  display_name = "DNS Tunnelling Detection Alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.dns_tunnelling.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: CloudWatch metric filter for suspicious DNS queries
resource "aws_cloudwatch_log_metric_filter" "suspicious_dns" {
  name           = "suspicious-dns-queries"
  log_group_name = var.route53_log_group
  pattern        = "[..., query_type=TXT || query_type=NULL || query_type=ANY, ...]"

  metric_transformation {
    name      = "SuspiciousDnsQueries"
    namespace = "Security/DnsTunnelling"
    value     = "1"
  }
}

# Step 3: CloudWatch alarm
resource "aws_cloudwatch_metric_alarm" "dns_tunnelling" {
  alarm_name          = "DnsTunnellingDetected"
  alarm_description   = "Alert on potential DNS tunnelling activity"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "SuspiciousDnsQueries"
  namespace           = "Security/DnsTunnelling"
  period              = 300
  statistic           = "Sum"
  threshold           = 50
  alarm_actions       = [aws_sns_topic.dns_tunnelling.arn]
}

resource "aws_sns_topic_policy" "allow_cloudwatch" {
  arn = aws_sns_topic.dns_tunnelling.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "cloudwatch.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.dns_tunnelling.arn
    }]
  })
}""",
                alert_severity="high",
                alert_title="DNS Tunnelling Pattern Detected",
                alert_description_template="Suspicious DNS query patterns detected from {srcaddr}. Unusual record types, long subdomains, or high-entropy queries may indicate DNS tunnelling or C2 activity.",
                investigation_steps=[
                    "Identify the source instance or service making the queries",
                    "Analyse DNS query patterns: frequency, timing, record types",
                    "Check query strings for Base64, hexadecimal, or encoded data",
                    "Calculate subdomain length and entropy to detect data encoding",
                    "Review destination DNS servers and domain ownership",
                    "Examine instance processes and network connections",
                    "Correlate with other suspicious activities (unusual network traffic, process execution)",
                    "Check CloudTrail for recent API calls from the source",
                ],
                containment_actions=[
                    "Isolate affected instances from the network immediately",
                    "Block suspicious DNS queries via Route 53 Resolver DNS Firewall",
                    "Add malicious domains to DNS firewall block list",
                    "Review and restrict instance IAM roles and security groups",
                    "Enable enhanced DNS query logging for affected resources",
                    "Implement DNS sinkholing for identified C2 domains",
                    "Review outbound security group rules and remove unnecessary egress",
                    "Rotate credentials for potentially compromised resources",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist legitimate use of TXT records for SPF, DKIM, DMARC, and service discovery (e.g., SRV records). Establish baseline for normal DNS patterns in your environment. Tune entropy thresholds based on legitimate application behaviour.",
            detection_coverage="80% - detects most DNS tunnelling patterns but may miss low-and-slow techniques",
            evasion_considerations="Attackers may use low-frequency queries, legitimate DNS services, or mimic normal query patterns to evade detection",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-1.5 hours",
            estimated_monthly_cost="$10-25",
            prerequisites=[
                "Route 53 Resolver Query Logging enabled",
                "CloudWatch Logs",
                "CloudTrail enabled",
            ],
        ),
        # Strategy 2: AWS - GuardDuty DNS C2 Detection
        DetectionStrategy(
            strategy_id="t1071-004-aws-guardduty",
            name="AWS GuardDuty DNS C2 Activity Detection",
            description="Leverage AWS GuardDuty to detect DNS-based C2 communications and DNS data exfiltration using threat intelligence and machine learning.",
            detection_type=DetectionType.GUARDDUTY,
            aws_service="guardduty",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                guardduty_finding_types=[
                    "Backdoor:EC2/C&CActivity.B!DNS",
                    "Trojan:EC2/DNSDataExfiltration",
                    "Backdoor:EC2/DenialOfService.Dns",
                    "Trojan:EC2/BlackholeTraffic!DNS",
                    "Trojan:EC2/DropPoint!DNS",
                ],
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Configure GuardDuty alerts for DNS-based C2 detection

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
      DataSources:
        S3Logs:
          Enable: true
        Kubernetes:
          AuditLogs:
            Enable: true
        MalwareProtection:
          ScanEc2InstanceWithFindings:
            EbsVolumes:
              Enable: true

  # Step 2: SNS topic for GuardDuty findings
  GuardDutyAlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      DisplayName: GuardDuty DNS C2 Alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 3: EventBridge rule for DNS C2 findings
  DnsC2FindingRule:
    Type: AWS::Events::Rule
    Properties:
      Description: Alert on GuardDuty DNS C2 findings
      EventPattern:
        source:
          - aws.guardduty
        detail-type:
          - GuardDuty Finding
        detail:
          type:
            - prefix: Backdoor:EC2/C&CActivity.B!DNS
            - prefix: Trojan:EC2/DNSDataExfiltration
            - prefix: Backdoor:EC2/DenialOfService.Dns
            - prefix: Trojan:EC2/BlackholeTraffic!DNS
      State: ENABLED
      Targets:
        - Id: AlertTopic
          Arn: !Ref GuardDutyAlertTopic

  TopicPolicy:
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
                terraform_template="""# Configure GuardDuty for DNS C2 detection

variable "alert_email" {
  type        = string
  description = "Email address for security alerts"
}

# Step 1: Enable GuardDuty with enhanced detection
resource "aws_guardduty_detector" "main" {
  enable                       = true
  finding_publishing_frequency = "FIFTEEN_MINUTES"

  datasources {
    s3_logs {
      enable = true
    }
    kubernetes {
      audit_logs {
        enable = true
      }
    }
    malware_protection {
      scan_ec2_instance_with_findings {
        ebs_volumes {
          enable = true
        }
      }
    }
  }
}

# Step 2: SNS topic for alerts
resource "aws_sns_topic" "guardduty_dns" {
  name         = "guardduty-dns-c2-alerts"
  display_name = "GuardDuty DNS C2 Alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.guardduty_dns.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 3: EventBridge rule for DNS C2 findings
resource "aws_cloudwatch_event_rule" "guardduty_dns_c2" {
  name        = "guardduty-dns-c2-detection"
  description = "Alert on GuardDuty DNS C2 findings"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail = {
      type = [
        { prefix = "Backdoor:EC2/C&CActivity.B!DNS" },
        { prefix = "Trojan:EC2/DNSDataExfiltration" },
        { prefix = "Backdoor:EC2/DenialOfService.Dns" },
        { prefix = "Trojan:EC2/BlackholeTraffic!DNS" }
      ]
    }
  })
}

resource "aws_cloudwatch_event_target" "sns" {
  rule = aws_cloudwatch_event_rule.guardduty_dns_c2.name
  arn  = aws_sns_topic.guardduty_dns.arn
}

resource "aws_sns_topic_policy" "allow_events" {
  arn = aws_sns_topic.guardduty_dns.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.guardduty_dns.arn
    }]
  })
}""",
                alert_severity="critical",
                alert_title="GuardDuty DNS C2 Activity Detected",
                alert_description_template="GuardDuty detected {type} on instance {resource.instanceDetails.instanceId}. This indicates DNS-based command and control or data exfiltration activity.",
                investigation_steps=[
                    "Review GuardDuty finding details including severity and confidence",
                    "Identify affected EC2 instances and their IAM roles",
                    "Analyse DNS query logs for the affected instance",
                    "Check destination domains and IPs against threat intelligence",
                    "Review instance processes and running services",
                    "Examine CloudTrail logs for API activity from the instance",
                    "Check VPC Flow Logs for correlated network activity",
                    "Investigate for signs of initial compromise or lateral movement",
                ],
                containment_actions=[
                    "Isolate affected instances immediately using security groups",
                    "Create forensic snapshots and memory dumps before changes",
                    "Revoke IAM role credentials for affected instances",
                    "Block malicious domains via Route 53 Resolver DNS Firewall",
                    "Add C2 domains to AWS Network Firewall block list",
                    "Review and rotate any credentials accessible to the instance",
                    "Terminate compromised instances and deploy from clean AMIs",
                    "Update security group rules to prevent similar attacks",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Review findings for legitimate security tools, monitoring agents, and development environments. Create suppression rules for known benign DNS patterns. Update threat intelligence lists regularly.",
            detection_coverage="90% - GuardDuty uses threat intelligence, ML, and behavioural analysis for high accuracy DNS C2 detection",
            evasion_considerations="Zero-day C2 infrastructure not yet in threat intelligence feeds may evade detection initially. Custom or private DNS servers may not be monitored.",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30-45 minutes",
            estimated_monthly_cost="$30-100 depending on data volume and resources",
            prerequisites=[
                "GuardDuty enabled",
                "VPC Flow Logs",
                "DNS Logs",
                "CloudTrail enabled",
            ],
        ),
        # Strategy 3: AWS - DNS Beaconing Detection
        DetectionStrategy(
            strategy_id="t1071-004-aws-dns-beaconing",
            name="AWS DNS Beaconing Pattern Detection",
            description="Detect DNS beaconing behaviour characterised by regular, periodic DNS queries indicative of C2 check-ins using dnscat2, Iodine, or similar tools.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query=r"""fields @timestamp, query_name, query_type, srcaddr
| filter ispresent(query_name)
| stats count() as query_count by srcaddr, query_name, bin(60s)
| filter query_count >= 3 and query_count <= 10
| stats count() as beacon_intervals by srcaddr
| filter beacon_intervals > 5
| sort beacon_intervals desc
| limit 100""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect DNS beaconing patterns indicative of C2 activity

Parameters:
  Route53LogGroup:
    Type: String
    Description: CloudWatch Log Group for Route 53 Query Logging
  AlertEmail:
    Type: String
    Description: Email address for security alerts

Resources:
  # Step 1: SNS topic for beaconing alerts
  BeaconingAlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      DisplayName: DNS Beaconing Detection Alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: CloudWatch Insights scheduled query
  BeaconingQuery:
    Type: AWS::Logs::QueryDefinition
    Properties:
      Name: DNS-Beaconing-Detection
      QueryString: |
        fields @timestamp, query_name, srcaddr
        | stats count() as query_count by srcaddr, query_name, bin(60s)
        | filter query_count >= 3 and query_count <= 10
        | stats count() as beacon_intervals by srcaddr
        | filter beacon_intervals > 5
      LogGroupNames:
        - !Ref Route53LogGroup

  # Step 3: EventBridge scheduled rule to run query
  ScheduledQueryRule:
    Type: AWS::Events::Rule
    Properties:
      Description: Run DNS beaconing detection query every 15 minutes
      ScheduleExpression: rate(15 minutes)
      State: ENABLED
      Targets:
        - Id: AlertTopic
          Arn: !Ref BeaconingAlertTopic

  TopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics:
        - !Ref BeaconingAlertTopic
      PolicyDocument:
        Statement:
          - Effect: Allow
            Principal:
              Service: events.amazonaws.com
            Action: sns:Publish
            Resource: !Ref BeaconingAlertTopic""",
                terraform_template="""# Detect DNS beaconing patterns

variable "route53_log_group" {
  type        = string
  description = "CloudWatch Log Group for Route 53 Query Logging"
}

variable "alert_email" {
  type        = string
  description = "Email address for security alerts"
}

# Step 1: SNS topic for alerts
resource "aws_sns_topic" "dns_beaconing" {
  name         = "dns-beaconing-alerts"
  display_name = "DNS Beaconing Detection Alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.dns_beaconing.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: CloudWatch Logs Insights query definition
resource "aws_cloudwatch_query_definition" "beaconing" {
  name = "DNS-Beaconing-Detection"

  query_string = <<-EOQ
    fields @timestamp, query_name, srcaddr
    | stats count() as query_count by srcaddr, query_name, bin(60s)
    | filter query_count >= 3 and query_count <= 10
    | stats count() as beacon_intervals by srcaddr
    | filter beacon_intervals > 5
  EOQ

  log_group_names = [var.route53_log_group]
}

# Step 3: Lambda function to run scheduled query and alert
# Note: This requires custom Lambda implementation for automated alerting
# For production use, consider AWS Security Hub or SIEM integration

resource "aws_sns_topic_policy" "allow_events" {
  arn = aws_sns_topic.dns_beaconing.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.dns_beaconing.arn
    }]
  })
}""",
                alert_severity="high",
                alert_title="DNS Beaconing Activity Detected",
                alert_description_template="Regular, periodic DNS queries detected from {srcaddr}. Beaconing pattern may indicate DNS-based C2 check-ins using tools like dnscat2 or Iodine.",
                investigation_steps=[
                    "Analyse query timing intervals and regularity",
                    "Identify the source instance making periodic queries",
                    "Review queried domains and their ownership",
                    "Check for known DNS C2 tools (dnscat2, Iodine, dns2tcp)",
                    "Examine instance processes for suspicious executables",
                    "Correlate with network traffic for additional C2 indicators",
                    "Review instance CloudTrail logs for API anomalies",
                    "Check for data encoding in DNS query strings",
                ],
                containment_actions=[
                    "Isolate the beaconing instance from the network",
                    "Block destination DNS servers via Route 53 Resolver DNS Firewall",
                    "Create forensic image of affected instance",
                    "Revoke instance IAM credentials and rotate keys",
                    "Review security group rules and remove unnecessary egress",
                    "Deploy endpoint detection tools on affected instances",
                    "Implement DNS firewall rules to block C2 domains",
                    "Monitor for similar patterns from other instances",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Establish baselines for legitimate periodic DNS queries (health checks, monitoring tools, CDN queries). Whitelist known monitoring agents and scheduled tasks. Adjust timing thresholds based on environment.",
            detection_coverage="75% - detects regular beaconing but may miss randomised or irregular C2 patterns",
            evasion_considerations="Attackers may randomise beacon intervals, use jitter, or vary query timing to evade pattern detection",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-1.5 hours",
            estimated_monthly_cost="$5-15",
            prerequisites=[
                "Route 53 Resolver Query Logging enabled",
                "CloudWatch Logs Insights",
            ],
        ),
        # Strategy 4: GCP - Cloud Logging DNS Anomaly Detection
        DetectionStrategy(
            strategy_id="t1071-004-gcp-dns-anomaly",
            name="GCP Cloud DNS Query Anomaly Detection",
            description="Detect unusual DNS query patterns in GCP including suspicious record types, long queries, and high-entropy domain names.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="dns_query"
logName="projects/PROJECT_ID/logs/dns.googleapis.com%2Fdns_queries"
(
  jsonPayload.queryType="TXT" OR
  jsonPayload.queryType="NULL" OR
  jsonPayload.queryType="ANY" OR
  length(jsonPayload.queryName) > 60
)
jsonPayload.responseCode="NOERROR"''',
                gcp_terraform_template="""# GCP: Detect DNS tunnelling via Cloud DNS logs

variable "project_id" {
  type        = string
  description = "GCP project ID"
}

variable "alert_email" {
  type        = string
  description = "Email address for security alerts"
}

# Step 1: Notification channel for alerts
resource "google_monitoring_notification_channel" "email" {
  display_name = "DNS Tunnelling Detection Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
  project = var.project_id
}

# Step 2: Log-based metric for suspicious DNS queries
resource "google_logging_metric" "dns_tunnelling" {
  name   = "dns-tunnelling-queries"
  filter = <<-EOT
    resource.type="dns_query"
    logName=~"projects/.*/logs/dns.googleapis.com%2Fdns_queries"
    (
      jsonPayload.queryType="TXT" OR
      jsonPayload.queryType="NULL" OR
      jsonPayload.queryType="ANY"
    )
    jsonPayload.responseCode="NOERROR"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "source_ip"
      value_type  = "STRING"
      description = "Source IP making DNS queries"
    }
  }

  label_extractors = {
    source_ip = "EXTRACT(jsonPayload.sourceIP)"
  }

  project = var.project_id
}

# Step 3: Alert policy for DNS tunnelling
resource "google_monitoring_alert_policy" "dns_tunnelling" {
  display_name = "DNS Tunnelling Pattern Detected"
  combiner     = "OR"
  project      = var.project_id

  conditions {
    display_name = "Suspicious DNS query volume"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.dns_tunnelling.name}\""
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
    content   = "Suspicious DNS query patterns detected. This may indicate DNS tunnelling or C2 activity."
    mime_type = "text/markdown"
  }
}""",
                alert_severity="high",
                alert_title="GCP: DNS Tunnelling Pattern Detected",
                alert_description_template="Unusual DNS queries detected in Cloud DNS logs. Suspicious record types or long query strings may indicate DNS tunnelling or C2 communications.",
                investigation_steps=[
                    "Identify source VM or service making the queries",
                    "Review DNS query logs for patterns and frequency",
                    "Analyse query strings for encoded data (Base64, hex)",
                    "Calculate query entropy to detect data exfiltration",
                    "Check destination DNS servers and domain ownership",
                    "Review VM instance metadata and service accounts",
                    "Examine Cloud Logging for correlated suspicious activity",
                    "Check VPC Flow Logs for additional network indicators",
                ],
                containment_actions=[
                    "Isolate affected VM instances using VPC firewall rules",
                    "Block suspicious domains via Cloud DNS policies",
                    "Create VM snapshots for forensic analysis",
                    "Revoke service account credentials for affected resources",
                    "Implement VPC Service Controls to restrict egress",
                    "Enable Private Google Access to control DNS resolution",
                    "Review and restrict firewall rules for DNS traffic",
                    "Deploy Cloud IDS for enhanced network monitoring",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist legitimate TXT record usage for email authentication (SPF, DKIM, DMARC) and service discovery. Establish baselines for normal DNS query patterns. Tune thresholds based on application behaviour.",
            detection_coverage="80% - detects most DNS tunnelling techniques but may miss low-frequency attacks",
            evasion_considerations="Attackers may use legitimate DNS services, low query rates, or standard record types to evade detection",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-1.5 hours",
            estimated_monthly_cost="$10-25",
            prerequisites=[
                "Cloud DNS Query Logging enabled",
                "Cloud Logging",
                "Cloud Monitoring",
            ],
        ),
        # Strategy 5: GCP - Security Command Centre DNS Threat Detection
        DetectionStrategy(
            strategy_id="t1071-004-gcp-scc",
            name="GCP Security Command Centre DNS Threat Detection",
            description="Leverage Security Command Centre Event Threat Detection to identify DNS-based C2 communications and malicious domain queries.",
            detection_type=DetectionType.SECURITY_COMMAND_CENTER,
            aws_service="n/a",
            gcp_service="security_command_center",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                scc_finding_categories=[
                    "Malware: Cryptomining Bad Domain",
                    "Malware: Bad Domain",
                    "Malware: Bad IP",
                    "Malware: Outgoing DoS",
                    "Initial Access: Suspicious Login",
                ],
                gcp_terraform_template="""# GCP: Configure Security Command Centre for DNS threat detection

variable "organization_id" {
  type        = string
  description = "GCP organisation ID"
}

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
  display_name = "SCC DNS Threat Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
  project = var.project_id
}

# Step 2: Pub/Sub topic for SCC findings
resource "google_pubsub_topic" "scc_dns_findings" {
  name    = "scc-dns-threat-findings"
  project = var.project_id
}

resource "google_pubsub_subscription" "scc_dns_findings" {
  name    = "scc-dns-threat-findings-sub"
  topic   = google_pubsub_topic.scc_dns_findings.name
  project = var.project_id

  ack_deadline_seconds = 20

  push_config {
    push_endpoint = "https://example.com/webhook"  # Replace with SIEM/SOAR endpoint
  }
}

# Step 3: Log-based metric for SCC DNS findings
resource "google_logging_metric" "scc_dns_threats" {
  name    = "scc-dns-malware-detections"
  project = var.project_id
  filter  = <<-EOT
    resource.type="threat_detector"
    protoPayload.metadata.finding.category=~"Malware.*Domain"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 4: Alert policy for DNS threats
resource "google_monitoring_alert_policy" "scc_dns_threats" {
  display_name = "SCC DNS Malware Detection"
  combiner     = "OR"
  project      = var.project_id

  conditions {
    display_name = "DNS-based malware or C2 detected"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.scc_dns_threats.name}\""
      duration        = "60s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0

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
    content   = "Security Command Centre detected DNS-based malware or C2 activity. Immediate investigation required."
    mime_type = "text/markdown"
  }
}

# Note: SCC notification configs require organization-level access
# Configure via: gcloud scc notifications create --organization=ORG_ID""",
                alert_severity="critical",
                alert_title="GCP: DNS-Based Malware or C2 Detected",
                alert_description_template="Security Command Centre detected {category} on {resourceName}. This indicates DNS-based command and control or malware communications.",
                investigation_steps=[
                    "Review Security Command Centre finding details and severity",
                    "Identify affected GCP resources (VMs, GKE, Cloud Functions)",
                    "Analyse Cloud DNS query logs for malicious domains",
                    "Check Cloud Audit Logs for suspicious API activity",
                    "Review VPC Flow Logs for correlated network activity",
                    "Examine VM instance processes and configurations",
                    "Check service account permissions and recent usage",
                    "Investigate for signs of lateral movement or privilege escalation",
                ],
                containment_actions=[
                    "Isolate affected resources immediately using firewall rules",
                    "Create snapshots for forensic analysis before remediation",
                    "Revoke compromised service account keys and credentials",
                    "Block malicious domains via Cloud DNS policies",
                    "Enable VPC Service Controls to prevent data exfiltration",
                    "Review and update firewall rules to block C2 infrastructure",
                    "Deploy Cloud IDS for enhanced threat detection",
                    "Apply organisation policy constraints to prevent recurrence",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Review findings for legitimate security tools, development environments, and known services. Configure SCC muting rules for confirmed benign activities. Update threat intelligence feeds regularly.",
            detection_coverage="85% - SCC uses threat intelligence, behavioural analysis, and Google's threat research for accurate DNS threat detection",
            evasion_considerations="Zero-day C2 infrastructure or custom DNS tunnelling tools not yet in threat intelligence may evade initial detection",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$50-150 depending on assets and organisation size",
            prerequisites=[
                "Security Command Centre enabled",
                "Event Threat Detection enabled",
                "Cloud DNS Query Logging",
                "VPC Flow Logs",
            ],
        ),
    ],
    recommended_order=[
        "t1071-004-aws-guardduty",
        "t1071-004-gcp-scc",
        "t1071-004-aws-dns-anomaly",
        "t1071-004-gcp-dns-anomaly",
        "t1071-004-aws-dns-beaconing",
    ],
    total_effort_hours=6.0,
    coverage_improvement="+30% improvement for DNS-based Command and Control detection",
)
