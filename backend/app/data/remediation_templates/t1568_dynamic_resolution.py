"""
T1568 - Dynamic Resolution

Adversaries dynamically establish connections to command and control infrastructure to evade detection.
Includes Fast Flux DNS, Domain Generation Algorithms (DGAs), and DNS Calculation techniques.
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
    technique_id="T1568",
    technique_name="Dynamic Resolution",
    tactic_ids=["TA0011"],  # Command and Control
    mitre_url="https://attack.mitre.org/techniques/T1568/",
    threat_context=ThreatContext(
        description=(
            "Adversaries dynamically establish connections to command and control infrastructure "
            "to evade common detections and blacklists. Dynamic resolution techniques include Fast "
            "Flux DNS (rapidly changing IP addresses), Domain Generation Algorithms (DGAs) where "
            "malware algorithmically generates domain names for C2, and DNS Calculation where C2 "
            "addresses are computed through mathematical operations. In cloud environments, attackers "
            "leverage dynamic DNS services and frequently rotate infrastructure to maintain persistent "
            "access whilst avoiding static indicator-based detection."
        ),
        attacker_goal="Maintain persistent C2 connectivity through dynamic infrastructure that evades static detection",
        why_technique=[
            "Evades domain-based blacklists and reputation systems",
            "Provides resilience against infrastructure takedowns",
            "Enables rapid rotation of C2 endpoints",
            "Blends with legitimate dynamic DNS usage",
            "Bypasses signature-based network security controls",
            "Facilitates long-term persistent access",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="common",
        trend="increasing",
        severity_score=8,
        severity_reasoning=(
            "Dynamic resolution is a sophisticated C2 technique that significantly hampers detection "
            "and response efforts. Its ability to evade static indicators and adapt to defensive "
            "measures makes it particularly dangerous. High severity due to enabling persistent "
            "access, complicating incident response, and being commonly observed in advanced persistent "
            "threat campaigns. The technique's prevalence in major campaigns including SolarWinds "
            "demonstrates its effectiveness."
        ),
        business_impact=[
            "Prolonged undetected adversary presence",
            "Difficulty in blocking C2 communications",
            "Increased incident response complexity and costs",
            "Potential for data exfiltration over extended periods",
            "Reduced effectiveness of threat intelligence feeds",
            "Compliance violations from undetected malicious traffic",
        ],
        typical_attack_phase="command_and_control",
        often_precedes=["T1041", "T1567", "T1071"],  # Exfiltration and C2 techniques
        often_follows=["T1078.004", "T1190", "T1566"],  # Initial Access techniques
    ),
    detection_strategies=[
        # Strategy 1: AWS - Domain Generation Algorithm (DGA) Detection
        DetectionStrategy(
            strategy_id="t1568-aws-dga",
            name="AWS DGA Domain Detection via Route 53",
            description="Detect Domain Generation Algorithm (DGA) activity by identifying high-entropy, pseudo-random domain queries that indicate algorithmically-generated C2 domains.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query=r"""fields @timestamp, query_name, query_type, srcaddr, rcode
| filter query_type in ["A", "AAAA"]
| filter query_name like /[a-z]{10,}\.(?:com|net|org|info|biz)$/
| filter query_name like /[bcdfghjklmnpqrstvwxyz]{5,}/
| stats count() as query_count, count_distinct(query_name) as unique_domains by srcaddr, bin(5m)
| filter query_count > 20 and unique_domains > 15
| sort query_count desc
| limit 100""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect DGA domain queries indicating potential malware C2 activity

Parameters:
  AlertEmail:
    Type: String
    Description: Email address for security alerts

Resources:
  # Step 1: Enable Route 53 query logging
  QueryLogGroup:
    Type: AWS::Logs::LogGroup
    Properties:
      LogGroupName: /aws/route53/dga-detection
      RetentionInDays: 30

  # Step 2: SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      KmsMasterKeyId: alias/aws/sns
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 3: Metric filter for DGA patterns
  DGAMetricFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref QueryLogGroup
      FilterPattern: '[version, account_id, region, vpc_id, query_timestamp, query_name, query_type="A" || query_type="AAAA", ..., rcode="NXDOMAIN"]'
      MetricTransformations:
        - MetricName: DGADomainQueries
          MetricNamespace: Security/C2Detection
          MetricValue: '1'
          DefaultValue: 0

  DGAAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: DGA-Domain-Queries-Detected
      AlarmDescription: Alert on potential DGA activity
      MetricName: DGADomainQueries
      Namespace: Security/C2Detection
      Statistic: Sum
      Period: 300
      Threshold: 50
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      AlarmActions:
        - !Ref AlertTopic

  TopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics:
        - !Ref AlertTopic
      PolicyDocument:
        Statement:
          - Effect: Allow
            Principal:
              Service: cloudwatch.amazonaws.com
            Action: sns:Publish
            Resource: !Ref AlertTopic""",
                terraform_template="""# Detect DGA domain queries indicating malware C2

variable "alert_email" {
  type        = string
  description = "Email address for security alerts"
}

# Step 1: CloudWatch Log Group for Route 53 queries
resource "aws_cloudwatch_log_group" "dga_detection" {
  name              = "/aws/route53/dga-detection"
  retention_in_days = 30
}

# Step 2: SNS topic for alerts
resource "aws_sns_topic" "dga_alerts" {
  name = "dga-domain-detection-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.dga_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 3: Metric filter for DGA patterns
resource "aws_cloudwatch_log_metric_filter" "dga_queries" {
  name           = "dga-domain-queries"
  log_group_name = aws_cloudwatch_log_group.dga_detection.name

  pattern = "[version, account_id, region, vpc_id, query_timestamp, query_name, query_type=\"A\" || query_type=\"AAAA\", ..., rcode=\"NXDOMAIN\"]"

  metric_transformation {
    name      = "DGADomainQueries"
    namespace = "Security/C2Detection"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "dga_detection" {
  alarm_name          = "DGA-Domain-Queries-Detected"
  alarm_description   = "Alert on potential DGA activity"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "DGADomainQueries"
  namespace           = "Security/C2Detection"
  period              = 300
  statistic           = "Sum"
  threshold           = 50
  alarm_actions       = [aws_sns_topic.dga_alerts.arn]
}""",
                alert_severity="high",
                alert_title="Domain Generation Algorithm (DGA) Activity Detected",
                alert_description_template="DGA-like behaviour detected from {srcaddr}: {query_count} queries to {unique_domains} unique pseudo-random domains. This may indicate malware C2 activity.",
                investigation_steps=[
                    "Identify the source instance generating the DNS queries",
                    "Review the specific domain names being queried for patterns",
                    "Check for high NXDOMAIN (non-existent domain) response rates",
                    "Analyse query timing patterns (steady stream vs bursts)",
                    "Examine instance processes and running applications",
                    "Correlate with endpoint detection and response (EDR) alerts",
                    "Check threat intelligence feeds for known DGA families",
                ],
                containment_actions=[
                    "Isolate the source instance from the network immediately",
                    "Block DNS queries to DGA domains via Route 53 Resolver DNS Firewall",
                    "Capture forensic memory dump before shutdown",
                    "Revoke instance IAM credentials and rotate any exposed secrets",
                    "Review security group rules and restrict egress traffic",
                    "Deploy endpoint detection and response (EDR) for detailed analysis",
                    "Implement DNS sinkholing for known malware families",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Exclude legitimate services that generate similar patterns (CDNs, analytics). Establish baseline for normal DNS query patterns per instance type.",
            detection_coverage="75% - detects DGA activity but requires tuning for specific malware families",
            evasion_considerations="Attackers may use low-frequency queries, legitimate domains, or pre-generated domain lists to evade detection",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$15-30",
            prerequisites=[
                "Route 53 Resolver Query Logging enabled",
                "CloudTrail enabled",
            ],
        ),
        # Strategy 2: AWS - Dynamic DNS Provider Detection
        DetectionStrategy(
            strategy_id="t1568-aws-ddns",
            name="AWS Dynamic DNS Provider Usage Detection",
            description="Detect usage of dynamic DNS services (No-IP, DynDNS, Duck DNS) commonly leveraged by threat actors for C2 infrastructure.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query=r"""fields @timestamp, query_name, srcaddr, query_type
| filter query_name like /\.no-ip\.(com|org|net|biz|info)$/
   or query_name like /\.duckdns\.org$/
   or query_name like /\.ddns\.net$/
   or query_name like /\.dyndns\.(org|com)$/
   or query_name like /\.freedns\.afraid\.org$/
   or query_name like /\.changeip\.com$/
   or query_name like /\.3322\.org$/
   or query_name like /\.dnsexit\.com$/
| stats count() as query_count by srcaddr, query_name, bin(5m)
| filter query_count > 5
| sort query_count desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect usage of dynamic DNS providers for C2

Parameters:
  AlertEmail:
    Type: String
    Description: Email address for security alerts
  VPCId:
    Type: String
    Description: VPC ID to monitor

Resources:
  # Step 1: Route 53 Query Log Group
  QueryLogGroup:
    Type: AWS::Logs::LogGroup
    Properties:
      LogGroupName: /aws/route53/ddns-detection
      RetentionInDays: 30

  # Step 2: SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      KmsMasterKeyId: alias/aws/sns
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 3: EventBridge rule for dynamic DNS queries
  DDNSDetectionRule:
    Type: AWS::Events::Rule
    Properties:
      Description: Detect queries to dynamic DNS providers
      EventPattern:
        source:
          - aws.route53
        detail-type:
          - AWS API Call via CloudTrail
        detail:
          eventName:
            - Query
          requestParameters:
            queryName:
              - suffix: .no-ip.com
              - suffix: .duckdns.org
              - suffix: .ddns.net
              - suffix: .dyndns.org
              - suffix: .3322.org
              - suffix: .dnsexit.com
      State: ENABLED
      Targets:
        - Id: AlertTopic
          Arn: !Ref AlertTopic

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
            Resource: !Ref AlertTopic""",
                terraform_template="""# Detect usage of dynamic DNS providers

variable "alert_email" {
  type        = string
  description = "Email address for security alerts"
}

variable "vpc_id" {
  type        = string
  description = "VPC ID to monitor"
}

# Step 1: CloudWatch Log Group for Route 53 queries
resource "aws_cloudwatch_log_group" "ddns_detection" {
  name              = "/aws/route53/ddns-detection"
  retention_in_days = 30
}

# Step 2: SNS topic for alerts
resource "aws_sns_topic" "ddns_alerts" {
  name = "dynamic-dns-detection-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.ddns_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 3: Metric filter for dynamic DNS queries
resource "aws_cloudwatch_log_metric_filter" "ddns_queries" {
  name           = "dynamic-dns-queries"
  log_group_name = aws_cloudwatch_log_group.ddns_detection.name

  # Pattern matches common dynamic DNS providers
  pattern = "[..., query_name=*.no-ip.com || query_name=*.duckdns.org || query_name=*.ddns.net || query_name=*.dyndns.org || query_name=*.3322.org || query_name=*.dnsexit.com, ...]"

  metric_transformation {
    name      = "DynamicDNSQueries"
    namespace = "Security/C2Detection"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "ddns_detection" {
  alarm_name          = "Dynamic-DNS-Usage-Detected"
  alarm_description   = "Alert on queries to dynamic DNS providers"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "DynamicDNSQueries"
  namespace           = "Security/C2Detection"
  period              = 300
  statistic           = "Sum"
  threshold           = 5
  alarm_actions       = [aws_sns_topic.ddns_alerts.arn]
}""",
                alert_severity="high",
                alert_title="Dynamic DNS Provider Usage Detected",
                alert_description_template="Instance {srcaddr} queried dynamic DNS domain {query_name}. Dynamic DNS services are commonly used by threat actors for C2 infrastructure.",
                investigation_steps=[
                    "Identify the source instance making the queries",
                    "Determine the specific dynamic DNS provider being used",
                    "Review instance purpose and expected network behaviour",
                    "Check for any legitimate business use of dynamic DNS",
                    "Analyse CloudTrail logs for suspicious API activity",
                    "Examine instance for malware or unauthorised software",
                    "Check threat intelligence for the specific domain",
                ],
                containment_actions=[
                    "Block dynamic DNS domains via Route 53 Resolver DNS Firewall",
                    "Isolate affected instances from production network",
                    "Review and restrict security group egress rules",
                    "Revoke instance credentials and rotate secrets",
                    "Create forensic snapshots for investigation",
                    "Implement DNS filtering for known dynamic DNS providers",
                    "Enable GuardDuty for enhanced threat detection",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Verify legitimate use cases for dynamic DNS in your environment. Some IoT devices and remote access solutions may use dynamic DNS legitimately.",
            detection_coverage="80% - high coverage for known dynamic DNS providers",
            evasion_considerations="Attackers may use lesser-known dynamic DNS providers or custom domain infrastructure",
            implementation_effort=EffortLevel.LOW,
            implementation_time="1 hour",
            estimated_monthly_cost="$10-20",
            prerequisites=[
                "Route 53 Resolver Query Logging enabled",
                "VPC DNS logging enabled",
            ],
        ),
        # Strategy 3: AWS - Fast Flux DNS Detection
        DetectionStrategy(
            strategy_id="t1568-aws-fastflux",
            name="AWS Fast Flux DNS Detection",
            description="Detect Fast Flux DNS behaviour where domain-to-IP mappings change rapidly to evade blacklists and maintain C2 resilience.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, query_name, answers.Rdata as ip_address, srcaddr
| filter query_type = "A"
| stats count_distinct(ip_address) as unique_ips, count() as query_count by query_name, bin(10m)
| filter unique_ips > 5 and query_count > 10
| sort unique_ips desc
| limit 100""",
                terraform_template="""# Detect Fast Flux DNS patterns

variable "alert_email" {
  type        = string
  description = "Email address for security alerts"
}

# Step 1: CloudWatch Log Group for Route 53 queries
resource "aws_cloudwatch_log_group" "fastflux_detection" {
  name              = "/aws/route53/fastflux-detection"
  retention_in_days = 30
}

# Step 2: SNS topic for alerts
resource "aws_sns_topic" "fastflux_alerts" {
  name = "fast-flux-detection-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.fastflux_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 3: CloudWatch Insights query scheduled execution
# Note: Fast Flux requires advanced pattern matching
# Consider using Lambda for complex analysis

resource "aws_cloudwatch_log_metric_filter" "rapid_dns_changes" {
  name           = "rapid-dns-ip-changes"
  log_group_name = aws_cloudwatch_log_group.fastflux_detection.name

  # Simplified pattern - production should use Lambda for complex logic
  pattern = "[..., query_type=\"A\", ...]"

  metric_transformation {
    name      = "DNSQueryVolume"
    namespace = "Security/C2Detection"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "fastflux_detection" {
  alarm_name          = "Fast-Flux-DNS-Pattern"
  alarm_description   = "Alert on rapid DNS resolution changes"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "DNSQueryVolume"
  namespace           = "Security/C2Detection"
  period              = 600
  statistic           = "Sum"
  threshold           = 100
  alarm_actions       = [aws_sns_topic.fastflux_alerts.arn]
}""",
                alert_severity="critical",
                alert_title="Fast Flux DNS Activity Detected",
                alert_description_template="Fast Flux behaviour detected for domain {query_name}: {unique_ips} unique IP addresses in 10 minutes. This indicates potential malicious infrastructure.",
                investigation_steps=[
                    "Analyse the domain name and registration details",
                    "Check the IP addresses returned for geographic distribution",
                    "Review TTL values for the DNS records (short TTL indicates Fast Flux)",
                    "Identify all instances querying this domain",
                    "Check threat intelligence feeds for the domain and IPs",
                    "Examine network traffic to the resolved IP addresses",
                    "Review instance processes and running applications",
                ],
                containment_actions=[
                    "Block the domain via Route 53 Resolver DNS Firewall",
                    "Isolate all instances querying the Fast Flux domain",
                    "Block all resolved IP addresses at security group level",
                    "Create network ACL rules to prevent connections",
                    "Deploy DNS sinkhole for the domain",
                    "Review and revoke credentials for affected instances",
                    "Enable enhanced network monitoring and logging",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Exclude legitimate CDN and load-balanced services that may have multiple IPs. Consider geographic distribution patterns as additional context.",
            detection_coverage="70% - detects Fast Flux but requires tuning for CDN patterns",
            evasion_considerations="Attackers may use slower rotation rates or combine with other techniques",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2 hours",
            estimated_monthly_cost="$20-40",
            prerequisites=[
                "Route 53 Resolver Query Logging enabled",
                "CloudWatch Logs Insights",
            ],
        ),
        # Strategy 4: AWS - GuardDuty C2 Domain Detection
        DetectionStrategy(
            strategy_id="t1568-aws-guardduty",
            name="AWS GuardDuty Malicious Domain Detection",
            description="Leverage AWS GuardDuty to detect communication with known malicious domains and C2 infrastructure using threat intelligence.",
            detection_type=DetectionType.GUARDDUTY,
            aws_service="guardduty",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                guardduty_finding_types=[
                    "Backdoor:EC2/C&CActivity.B!DNS",
                    "Backdoor:EC2/C&CActivity.B",
                    "Trojan:EC2/DNSDataExfiltration",
                    "Trojan:EC2/DGADomainRequest.B",
                    "Trojan:EC2/DGADomainRequest.C!DNS",
                ],
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: GuardDuty detection for malicious domains and DGA activity

Parameters:
  AlertEmail:
    Type: String
    Description: Email address for security alerts

Resources:
  # Step 1: Enable GuardDuty
  GuardDutyDetector:
    Type: AWS::GuardDuty::Detector
    Properties:
      Enable: true
      FindingPublishingFrequency: FIFTEEN_MINUTES

  # Step 2: SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      KmsMasterKeyId: alias/aws/sns
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 3: EventBridge rule for malicious domain findings
  MaliciousDomainRule:
    Type: AWS::Events::Rule
    Properties:
      Description: Alert on GuardDuty malicious domain findings
      EventPattern:
        source:
          - aws.guardduty
        detail-type:
          - GuardDuty Finding
        detail:
          type:
            - prefix: Backdoor:EC2/C&CActivity
            - prefix: Trojan:EC2/DNSDataExfiltration
            - prefix: Trojan:EC2/DGADomainRequest
      State: ENABLED
      Targets:
        - Id: AlertTopic
          Arn: !Ref AlertTopic

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
            Resource: !Ref AlertTopic""",
                terraform_template="""# GuardDuty detection for malicious domains

variable "alert_email" {
  type        = string
  description = "Email address for security alerts"
}

# Step 1: Enable GuardDuty
resource "aws_guardduty_detector" "main" {
  enable                       = true
  finding_publishing_frequency = "FIFTEEN_MINUTES"
}

# Step 2: SNS topic for alerts
resource "aws_sns_topic" "guardduty_alerts" {
  name = "guardduty-malicious-domain-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.guardduty_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 3: EventBridge rule for malicious domain findings
resource "aws_cloudwatch_event_rule" "malicious_domain" {
  name        = "guardduty-malicious-domain-detection"
  description = "Alert on GuardDuty malicious domain findings"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail = {
      type = [
        { prefix = "Backdoor:EC2/C&CActivity" },
        { prefix = "Trojan:EC2/DNSDataExfiltration" },
        { prefix = "Trojan:EC2/DGADomainRequest" }
      ]
    }
  })
}

resource "aws_cloudwatch_event_target" "sns" {
  rule = aws_cloudwatch_event_rule.malicious_domain.name
  arn  = aws_sns_topic.guardduty_alerts.arn
}

resource "aws_sns_topic_policy" "allow_events" {
  arn = aws_sns_topic.guardduty_alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.guardduty_alerts.arn
    }]
  })
}""",
                alert_severity="critical",
                alert_title="GuardDuty: Malicious Domain Communication Detected",
                alert_description_template="GuardDuty detected {type} on instance {resource.instanceDetails.instanceId}. The instance communicated with known malicious infrastructure.",
                investigation_steps=[
                    "Review GuardDuty finding details including domain and IP addresses",
                    "Identify the affected EC2 instance and its role",
                    "Check threat intelligence for the domain and associated malware families",
                    "Review CloudTrail logs for API activity from the instance",
                    "Examine VPC Flow Logs for all network connections",
                    "Analyse instance processes and memory for malware artefacts",
                    "Check for lateral movement from the compromised instance",
                ],
                containment_actions=[
                    "Isolate the affected instance immediately",
                    "Create forensic snapshots and memory dumps",
                    "Revoke all IAM credentials associated with the instance",
                    "Block the malicious domain via Route 53 Resolver DNS Firewall",
                    "Block destination IPs via security groups and NACLs",
                    "Review and rotate all secrets accessible from the instance",
                    "Deploy replacement instance from clean, verified AMI",
                    "Implement automated remediation via Security Hub",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="GuardDuty uses advanced threat intelligence with low false positive rates. Review and suppress findings for known security testing.",
            detection_coverage="90% - comprehensive coverage using AWS threat intelligence",
            evasion_considerations="Zero-day domains and custom C2 infrastructure may not be in threat feeds initially",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$30-100 depending on data volume",
            prerequisites=[
                "GuardDuty enabled",
                "VPC Flow Logs enabled",
                "DNS Logs enabled",
            ],
        ),
        # Strategy 5: GCP - DGA and Dynamic DNS Detection
        DetectionStrategy(
            strategy_id="t1568-gcp-dga",
            name="GCP Domain Generation Algorithm Detection",
            description="Detect DGA and dynamic DNS activity in GCP using Cloud DNS logging and VPC Flow Logs.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query=r'''resource.type="dns_query"
(protoPayload.queryName=~"[a-z]{10,}\.(com|net|org|info|biz)$"
OR protoPayload.queryName=~"(no-ip|duckdns|ddns|dyndns|3322|dnsexit)\.")
protoPayload.responseCode="NXDOMAIN"''',
                gcp_terraform_template="""# GCP: DGA and Dynamic DNS detection

variable "project_id" {
  type        = string
  description = "GCP project ID"
}

variable "alert_email" {
  type        = string
  description = "Email address for security alerts"
}

# Step 1: Enable Cloud DNS logging (assumes DNS zone exists)
resource "google_dns_managed_zone" "monitored" {
  name        = "monitored-zone"
  dns_name    = "example.com."
  description = "Monitored DNS zone for security"

  cloud_logging_config {
    enable_logging = true
  }
}

# Step 2: Create log metric for DGA patterns
resource "google_logging_metric" "dga_detection" {
  name   = "dga-domain-queries"
  filter = <<-EOT
    resource.type="dns_query"
    (protoPayload.queryName=~"[a-z]{10,}\\.(com|net|org|info|biz)$"
    OR protoPayload.queryName=~"(no-ip|duckdns|ddns|dyndns|3322|dnsexit)\\.")
    protoPayload.responseCode="NXDOMAIN"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Create notification channel and alert policy
resource "google_monitoring_notification_channel" "email" {
  display_name = "Security Alerts - DGA Detection"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

resource "google_monitoring_alert_policy" "dga_detection" {
  display_name = "DGA or Dynamic DNS Activity Detected"
  combiner     = "OR"

  conditions {
    display_name = "Suspicious domain query patterns"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.dga_detection.name}\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 20
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
    content = "DGA or dynamic DNS activity detected. Investigate source VM for potential malware."
  }
}""",
                alert_severity="high",
                alert_title="GCP: DGA or Dynamic DNS Activity Detected",
                alert_description_template="Suspicious domain query patterns detected indicating potential DGA malware or dynamic DNS C2 activity.",
                investigation_steps=[
                    "Identify the source VM instance or workload",
                    "Review Cloud DNS query logs for specific domain patterns",
                    "Check for high NXDOMAIN response rates",
                    "Analyse query timing and frequency patterns",
                    "Examine VM metadata and startup scripts",
                    "Review Cloud Audit Logs for suspicious API activity",
                    "Check Security Command Centre for related findings",
                ],
                containment_actions=[
                    "Isolate the source VM using VPC firewall rules",
                    "Create VM snapshots for forensic analysis",
                    "Block malicious domains using Cloud DNS policies",
                    "Revoke service account credentials",
                    "Review and restrict IAM permissions",
                    "Enable VPC Service Controls to prevent data exfiltration",
                    "Deploy replacement VM from verified image",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Exclude legitimate services with random-looking domain names. Establish baseline DNS patterns per workload type.",
            detection_coverage="75% - detects DGA and dynamic DNS but requires environment-specific tuning",
            evasion_considerations="Attackers may use legitimate domains or slow-query rates to evade detection",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$15-30",
            prerequisites=["Cloud DNS logging enabled", "VPC Flow Logs enabled"],
        ),
        # Strategy 6: GCP - Security Command Centre Threat Detection
        DetectionStrategy(
            strategy_id="t1568-gcp-scc",
            name="GCP Security Command Centre Malware Detection",
            description="Leverage Security Command Centre Event Threat Detection to identify malicious domain communications and C2 activity.",
            detection_type=DetectionType.SECURITY_COMMAND_CENTER,
            aws_service="n/a",
            gcp_service="security_command_center",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                scc_finding_categories=[
                    "Malware: Bad Domain",
                    "Malware: Bad IP",
                    "Malware: Cryptomining Bad Domain",
                    "Persistence: IAM Anomalous Grant",
                    "Initial Access: Suspicious Login",
                ],
                gcp_terraform_template="""# GCP: Security Command Centre for C2 detection

variable "organization_id" {
  type        = string
  description = "GCP organisation ID"
}

variable "alert_email" {
  type        = string
  description = "Email address for security alerts"
}

# Step 1: Notification channel
resource "google_monitoring_notification_channel" "email" {
  display_name = "Security Alerts - SCC C2 Detection"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Pub/Sub topic for SCC findings
resource "google_pubsub_topic" "scc_findings" {
  name = "scc-c2-detection-findings"
}

resource "google_pubsub_subscription" "scc_findings" {
  name  = "scc-c2-findings-subscription"
  topic = google_pubsub_topic.scc_findings.name

  ack_deadline_seconds = 20

  # Configure push to SIEM/SOAR if available
  # push_config {
  #   push_endpoint = "https://your-siem-endpoint.com/webhook"
  # }
}

# Step 3: Log sink for SCC findings
resource "google_logging_project_sink" "scc_findings" {
  name        = "scc-c2-findings-sink"
  destination = "pubsub.googleapis.com/${google_pubsub_topic.scc_findings.id}"

  filter = <<-EOT
    resource.type="security_command_center_finding"
    (finding.category="Malware: Bad Domain"
    OR finding.category="Malware: Bad IP"
    OR finding.category="Malware: Cryptomining Bad Domain")
  EOT

  unique_writer_identity = true
}

# Note: SCC notification configs require organisation-level permissions
# Configure via: gcloud scc notifications create --organization=ORG_ID
# Or use google_scc_notification_config with appropriate permissions""",
                alert_severity="critical",
                alert_title="GCP: Malicious Domain Communication Detected",
                alert_description_template="Security Command Centre detected {category} on {resourceName}. This indicates potential C2 activity or malware infection.",
                investigation_steps=[
                    "Review Security Command Centre finding details",
                    "Identify affected GCP resources and projects",
                    "Check Cloud Audit Logs for suspicious API calls from the resource",
                    "Review VPC Flow Logs for network connections",
                    "Analyse Cloud DNS query logs for the timeframe",
                    "Examine VM instance metadata and configurations",
                    "Check for lateral movement across projects or organisations",
                ],
                containment_actions=[
                    "Isolate affected resources immediately using VPC firewall rules",
                    "Create snapshots for forensic investigation",
                    "Revoke compromised service account keys and credentials",
                    "Block malicious domains and IPs using Cloud Armor",
                    "Enable VPC Service Controls perimeter for affected projects",
                    "Review and rotate any exposed credentials or secrets",
                    "Apply organisation policy constraints to prevent recurrence",
                    "Enable Enhanced SCC features for advanced detection",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Review findings for legitimate security tools and development environments. Configure SCC muting rules for validated benign activities.",
            detection_coverage="85% - SCC uses Google's threat intelligence and behavioural analysis",
            evasion_considerations="Custom or zero-day C2 infrastructure may not initially appear in threat feeds",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$50-150 depending on assets",
            prerequisites=[
                "Security Command Centre enabled",
                "Event Threat Detection enabled",
                "VPC Flow Logs enabled",
            ],
        ),
    ],
    recommended_order=[
        "t1568-aws-guardduty",
        "t1568-gcp-scc",
        "t1568-aws-ddns",
        "t1568-aws-dga",
        "t1568-gcp-dga",
        "t1568-aws-fastflux",
    ],
    total_effort_hours=8.0,
    coverage_improvement="+30% improvement for Command and Control tactic detection",
)
